//! Message processing for different DIDComm message types

use hyper::Method;
use serde_json::Value;
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::sync::OnceCell;
use tracing::{debug, error, info, instrument, warn};

use super::messages::ReceivedMessage;
use crate::messages::MessageType;
use crate::surfaces::AgentSurfaceStore;
use crate::{channel_debug, channel_error, channel_info, channel_warn};

/// Global metrics store for GW2 - set during initialization
static GLOBAL_METRICS_STORE: OnceCell<Arc<crate::metrics::MetricsStore>> = OnceCell::const_new();

/// Global WebSocket state for GW2 - set during initialization for payload capture broadcasting
static GLOBAL_WS_STATE: OnceCell<Arc<crate::server::WsState>> = OnceCell::const_new();

/// Global VC issuer for GW2 - separate identity space from GW1
static GLOBAL_VC_ISSUER: OnceCell<Arc<crate::identity::VCIssuer>> = OnceCell::const_new();

/// Public accessor for the process-global VC issuer, so non-fabric layers (e.g.
/// the HTTP surface PEP verifying inbound VP evidence) can reuse the same
/// verifier. `None` before the gateway subsystem initialises it at startup.
pub fn global_vc_issuer() -> Option<Arc<crate::identity::VCIssuer>> {
    GLOBAL_VC_ISSUER
        .get()
        .cloned()
}

/// Global policy manager for GW2 - for handling rate limiting and policies
static GLOBAL_POLICY_MANAGER: OnceCell<Arc<crate::policies::SurfacePolicyManager>> = OnceCell::const_new();

/// Global task monitor for GW2 - for tracking bytes and throughput
static GLOBAL_TASK_MONITOR: OnceCell<Arc<crate::observability::TaskMonitor>> = OnceCell::const_new();

/// Global HTTP client for GW2 outbound requests with policies
static GLOBAL_HTTP_CLIENT: OnceCell<reqwest::Client> = OnceCell::const_new();

/// Global notification store for GW2 - for integration triggers
static GLOBAL_NOTIFICATION_STORE: OnceCell<Arc<crate::integrations::FileSystemNotificationStore>> =
    OnceCell::const_new();

/// Global unified source authentication middleware for GW2.
static GLOBAL_SOURCE_AUTH_MIDDLEWARE: OnceCell<Arc<crate::source_auth::SourceAuthMiddleware>> = OnceCell::const_new();

/// Global gateway-level OPA policy manager for GW2 - for gateway-wide policy enforcement on fabric requests
static GLOBAL_GATEWAY_POLICY_MANAGER: OnceCell<Arc<crate::policies::GatewayPolicyManager>> = OnceCell::const_new();

/// Global secrets store for GW2 - for target_auth and credential delegation secret resolution
static GLOBAL_SECRETS_STORE: OnceCell<Arc<dyn crate::secrets::SecretsStore>> = OnceCell::const_new();

/// Global credential provider store for GW2 - for outbound credential delegation
static GLOBAL_CREDENTIAL_PROVIDER_STORE: OnceCell<
    Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>,
> = OnceCell::const_new();

/// Global delegation vault store for GW2 - for outbound credential delegation token lookup
static GLOBAL_DELEGATION_VAULT_STORE: OnceCell<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>> =
    OnceCell::const_new();

/// Gateway base URL for GW2 — used to build OAuth authorization redirect URLs
static GLOBAL_GATEWAY_BASE_URL: OnceCell<String> = OnceCell::const_new();

/// How GW2 reaches the Agent Pay surface a paid surface delegates payment to.
static GLOBAL_AGENT_PAY_RELAY: OnceCell<Arc<dyn super::payment_gate::AgentPayRelay>> = OnceCell::const_new();

/// Initialize the global metrics store for GW2
pub async fn init_metrics_store(metrics_store: Arc<crate::metrics::MetricsStore>) {
    let _ = GLOBAL_METRICS_STORE.set(metrics_store);
    info!("GW2: Global metrics store initialized");
}

/// Initialize the global WebSocket state for GW2
pub async fn init_ws_state(ws_state: Arc<crate::server::WsState>) {
    let _ = GLOBAL_WS_STATE.set(ws_state);
    info!("GW2: Global WebSocket state initialized for payload capture broadcasting");
}

/// Initialize the global VC issuer for GW2 (separate identity space)
pub async fn init_vc_issuer(
    vc_issuer: Arc<crate::identity::VCIssuer>,
    did_cache: Option<Arc<crate::gateways::did_cache::DIDCache>>,
) {
    // Set DID cache if available
    if let Some(cache) = did_cache {
        info!("GW2: Setting DID cache for VC issuer to enable cached DID resolution");
        vc_issuer
            .set_did_cache(cache)
            .await;
    } else {
        warn!("GW2: No DID cache provided - VP verification will use temporary resolver");
    }

    let _ = GLOBAL_VC_ISSUER.set(vc_issuer);
    info!("GW2: Global VC issuer initialized for agent identity tracking");
}

/// Initialize the global policy manager for GW2
pub async fn init_policy_manager(policy_manager: Arc<crate::policies::SurfacePolicyManager>) {
    let _ = GLOBAL_POLICY_MANAGER.set(policy_manager);
    info!("GW2: Global policy manager initialized for rate limiting and policies");
}

/// Access the process-global surface policy manager, if initialized. Used by the
/// policy-definition CRUD handlers to recompile the surfaces that reference a
/// mutated reusable policy definition.
pub fn get_policy_manager() -> Option<Arc<crate::policies::SurfacePolicyManager>> {
    GLOBAL_POLICY_MANAGER
        .get()
        .cloned()
}

/// Initialize the global task monitor for GW2
pub async fn init_task_monitor(task_monitor: Arc<crate::observability::TaskMonitor>) {
    let _ = GLOBAL_TASK_MONITOR.set(task_monitor);
    info!("GW2: Global task monitor initialized for bytes and throughput tracking");
}

/// Initialize the global notification store for GW2
pub async fn init_notification_store(notification_store: Arc<crate::integrations::FileSystemNotificationStore>) {
    let _ = GLOBAL_NOTIFICATION_STORE.set(notification_store);
    info!("GW2: Global notification store initialized for integration triggers");
}

/// Initialize the global HTTP client for GW2
pub async fn init_http_client(client: reqwest::Client) {
    let _ = GLOBAL_HTTP_CLIENT.set(client);
    info!("GW2: Global HTTP client initialized for outbound requests");
}

/// Timeout of the client fabric requests use before the shared one is set up.
const FABRIC_FALLBACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The client fabric requests go out on: the shared pooled one, or, before it
/// is set up, a new one with the same rules
/// ([`crate::http_client::proxy_with_timeout`]: no redirects, cloud metadata
/// addresses refused). `None` only when that client cannot be built.
fn fabric_http_client() -> Option<reqwest::Client> {
    if let Some(client) = GLOBAL_HTTP_CLIENT.get() {
        return Some(client.clone());
    }
    crate::http_client::proxy_with_timeout(FABRIC_FALLBACK_TIMEOUT)
        .inspect_err(|e| warn!("GW2: Failed to build the fabric HTTP client: {e:#}"))
        .ok()
}

/// Initialize the global unified source authentication middleware for GW2.
pub async fn init_source_auth_middleware(middleware: Arc<crate::source_auth::SourceAuthMiddleware>) {
    let _ = GLOBAL_SOURCE_AUTH_MIDDLEWARE.set(middleware);
    info!("GW2: Global source auth middleware initialized");
}

/// Get the global unified source authentication middleware.
pub fn get_source_auth_middleware() -> Option<Arc<crate::source_auth::SourceAuthMiddleware>> {
    GLOBAL_SOURCE_AUTH_MIDDLEWARE
        .get()
        .cloned()
}

/// Initialize the global gateway-level OPA policy manager for GW2.
pub async fn init_gateway_policy_manager(manager: Arc<crate::policies::GatewayPolicyManager>) {
    let _ = GLOBAL_GATEWAY_POLICY_MANAGER.set(manager);
    info!("GW2: Global gateway policy manager initialized for gateway-level OPA enforcement");
}

/// Get the global gateway-level OPA policy manager, if initialized. Used for
/// out-of-band recompiles such as the policy-definition change fan-out.
pub fn get_gateway_policy_manager() -> Option<Arc<crate::policies::GatewayPolicyManager>> {
    GLOBAL_GATEWAY_POLICY_MANAGER
        .get()
        .cloned()
}

/// Initialize the global secrets store for GW2.
pub async fn init_secrets_store(store: Arc<dyn crate::secrets::SecretsStore>) {
    let _ = GLOBAL_SECRETS_STORE.set(store);
    info!("GW2: Global secrets store initialized for credential delegation");
}

/// Get the global secrets store.
pub(crate) fn get_secrets_store() -> Option<Arc<dyn crate::secrets::SecretsStore>> {
    GLOBAL_SECRETS_STORE
        .get()
        .cloned()
}

/// Initialize the global credential provider store for GW2.
pub async fn init_credential_provider_store(
    store: Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>
) {
    let _ = GLOBAL_CREDENTIAL_PROVIDER_STORE.set(store);
    info!("GW2: Global credential provider store initialized");
}

/// Get the global credential provider store.
fn get_credential_provider_store() -> Option<Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>> {
    GLOBAL_CREDENTIAL_PROVIDER_STORE
        .get()
        .cloned()
}

/// Initialize the global delegation vault store for GW2.
pub async fn init_delegation_vault_store(store: Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>) {
    let _ = GLOBAL_DELEGATION_VAULT_STORE.set(store);
    info!("GW2: Global delegation vault store initialized");
}

/// Get the global delegation vault store.
fn get_delegation_vault_store() -> Option<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>> {
    GLOBAL_DELEGATION_VAULT_STORE
        .get()
        .cloned()
}

/// Initialize the gateway base URL for GW2 OAuth authorization URLs.
pub async fn init_gateway_base_url(url: String) {
    let _ = GLOBAL_GATEWAY_BASE_URL.set(url);
    info!("GW2: Gateway base URL initialized for credential delegation");
}

/// Get the gateway base URL.
fn get_gateway_base_url() -> Option<String> {
    GLOBAL_GATEWAY_BASE_URL
        .get()
        .cloned()
}

/// Initialize the fabric GW2 relays paid requests to Agent Pay over.
pub async fn init_agent_pay_relay(listener_manager: Arc<super::ConnectionPointListenerManager>) {
    let _ = GLOBAL_AGENT_PAY_RELAY.set(listener_manager);
    info!("GW2: Agent Pay relay initialized for paid surfaces");
}

/// The process-wide state the fabric receive path reads, gathered so tests can
/// supply their own.
struct ForwardDependencies {
    appliance_policies: Arc<crate::pipes::PipePolicyManager>,
    source_auth: Option<Arc<crate::source_auth::SourceAuthMiddleware>>,
    delegation: Option<DelegationStores>,
    vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    agent_pay: Option<Arc<dyn super::payment_gate::AgentPayRelay>>,
}

/// The stores credential delegation resolves delegated credentials from.
struct DelegationStores {
    vault: Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>,
    providers: Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>,
    secrets: Arc<dyn crate::secrets::SecretsStore>,
    base_url: String,
}

impl ForwardDependencies {
    fn from_process() -> Self {
        let delegation = match (
            get_delegation_vault_store(),
            get_credential_provider_store(),
            get_secrets_store(),
            get_gateway_base_url(),
        ) {
            (Some(vault), Some(providers), Some(secrets), Some(base_url)) => Some(DelegationStores {
                vault,
                providers,
                secrets,
                base_url,
            }),
            _ => None,
        };
        Self {
            appliance_policies: crate::pipes::PIPE_POLICY_MANAGER.clone(),
            source_auth: get_source_auth_middleware(),
            delegation,
            vc_issuer: GLOBAL_VC_ISSUER
                .get()
                .cloned(),
            agent_pay: GLOBAL_AGENT_PAY_RELAY
                .get()
                .cloned(),
        }
    }
}

/// Ensure a channel task is registered in the TaskMonitor for bytes tracking.
/// Returns the `task_id` of the AP TaskInfo for this surface (existing or
/// newly created) so callers can route bytes/connection metrics to the
/// correct entry without having to guess the id scheme.
async fn ensure_task_registered(surface: &crate::config::agent_surface::AgentSurface) -> Option<String> {
    let task_monitor = GLOBAL_TASK_MONITOR.get()?;
    let config_id = surface.config_id();

    // Prefer matching an already-registered AP task by config_id so we
    // don't insert a second entry alongside the one created by the port
    // listener at startup (which uses a `task-<config_id>-<uuid>` id).
    if let Some(cid) = config_id
        && let Some(existing) = task_monitor
            .find_ap_task_id_by_config_id(cid)
            .await
    {
        return Some(existing);
    }

    let task_id = config_id
        .unwrap_or(&surface.name)
        .to_string();
    if task_monitor
        .get_task(&task_id)
        .await
        .is_none()
    {
        let listen_address = surface.listen_address();
        let route = surface.route();
        // Register the task
        let task_info = crate::observability::TaskInfo {
            task_id: task_id.to_string(),
            config_id: surface
                .config_id()
                .map(str::to_string),
            channel_name: surface.name.clone(),
            listen_address: crate::proxy::server::join_host_and_route(listen_address, route),
            target_endpoint: surface
                .target_endpoint()
                .to_string(),
            started_at: chrono::Utc::now(),
            status: crate::observability::TaskStatus::Running,
            total_connections: 0,
            active_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            last_activity: None,
            error_count: 0,
            recent_bytes_sent: 0,
            recent_bytes_received: 0,
            recent_window_start: chrono::Utc::now(),
        };

        task_monitor
            .register_task(task_info)
            .await;
        debug!("GW2: Registered task {} in TaskMonitor for bytes tracking", task_id);
    }
    Some(task_id)
}

/// Process a received DIDComm message based on its type
///
/// This is the legacy entry point. New code should use the dispatcher module.
#[allow(dead_code)]
pub async fn process_message(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Processing message type: {}", message.message_type);

    let message_type = MessageType::from_str(&message.message_type);
    process_message_internal(message, &message_type).await
}

/// Internal message processor that uses the MessageType enum
///
/// This is called by the dispatcher and provides type-safe routing
#[instrument(name = "didcomm.process_message", skip(message), fields(msg.type = %message.message_type, msg.id = %message.didcomm_message_id, msg.from = ?message.from_did))]
pub async fn process_message_internal(
    message: &ReceivedMessage,
    message_type: &MessageType,
) -> ProcessingResult {
    match message_type {
        // Trust ping protocol
        MessageType::TrustPing => process_trust_ping(message).await,
        MessageType::TrustPingResponse => {
            info!("Received trust-ping response from {:?}", message.from_did);
            ProcessingResult::ProcessedNoResponse
        }

        // Forward protocol - handle forwarded messages
        MessageType::Forward => process_forward(message).await,

        // Problem reports
        MessageType::ProblemReport => process_problem_report(message).await,

        // Basic message protocol
        MessageType::BasicMessage => process_basic_message(message).await,

        // Discover features protocol
        MessageType::DiscoverFeaturesQuery => process_discover_features(message).await,
        MessageType::DiscoverFeaturesDisclose => process_feature_disclosure(message).await,

        // Out of band invitations
        MessageType::OOBInvitation => process_oob_invitation(message).await,

        // Connection setup protocol (Affinidi custom)
        MessageType::ConnectionSetup => process_connection_setup(message).await,
        MessageType::ConnectionAccepted => process_connection_accepted(message).await,
        MessageType::ConnectionRejected => process_connection_rejected(message).await,

        // Gateway ping protocol (Affinidi custom)
        MessageType::GatewayPing => process_gateway_ping(message).await,
        MessageType::GatewayPong => process_gateway_pong(message).await,

        // Gateway channel query protocol (Affinidi custom)
        MessageType::GetSurfaces => process_get_surfaces(message).await,
        MessageType::GetSurfacesResponse => process_get_surfaces_response(message).await,

        // Gateway request forwarding protocol (Affinidi custom)
        // Box::pin moves the large future (~2700 lines) to the heap to prevent
        // tokio worker thread stack overflow.
        MessageType::ForwardRequest => Box::pin(process_forward_request(message)).await,
        MessageType::ForwardResponse => process_forward_response(message).await,

        // Message pickup protocol
        MessageType::MessagePickupStatusRequest => process_status_request(message).await,
        MessageType::MessagePickupStatus => process_status_response(message).await,
        MessageType::MessagePickupDeliveryRequest => process_delivery_request(message).await,
        MessageType::MessagePickupDelivery => process_delivery_response(message).await,
        MessageType::MessagePickupMessagesReceived => process_messages_received(message).await,
        MessageType::MessagePickupLiveDeliveryChange => process_live_delivery_change(message).await,

        // Presentation protocols
        MessageType::PresentProofRequestPresentation => process_presentation_request(message).await,
        MessageType::PresentProofPresentation => process_presentation(message).await,

        // Issuance protocols
        MessageType::IssueCredentialOffer => process_credential_offer(message).await,
        MessageType::IssueCredentialRequest => process_credential_request(message).await,
        MessageType::IssueCredentialIssue => process_credential_issuance(message).await,

        // AccountManagement
        MessageType::AccountManagement => process_account_management(message).await,

        // Unknown message types - store but don't process
        MessageType::Unknown(type_str) => {
            info!("Received unknown message type: {}", type_str);
            ProcessingResult::Stored
        }
    }
}

/// Result of message processing
#[derive(Debug, Clone)]
pub enum ProcessingResult {
    /// Message was stored only
    Stored,
    /// Message was processed and requires a response
    RequiresResponse { response_type: String, response_body: Value },
    /// Message was processed successfully with no response needed
    ProcessedNoResponse,
    /// Message processing failed
    Failed { reason: String },
    /// OOB connection-accepted received - needs gateway finalization
    OOBConnectionAccepted { inviter_temporary_did: String, inviter_secure_did: String },
    /// OOB connection-setup received - needs to send connection-accepted
    OOBConnectionSetup { acceptor_temporary_did: String, acceptor_secure_did: String, invitation_id: String },
    /// OOB connection-rejected received - connection failed
    OOBConnectionRejected { reason: String },
}

// Trust Ping Protocol
async fn process_trust_ping(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing trust-ping from {:?}", message.from_did);

    // Check if response_requested field is true
    let response_requested = message
        .message_body
        .get("response_requested")
        .and_then(|v| v.as_bool())
        .unwrap_or(true); // Default to true if not specified

    if response_requested {
        // Return ping-response (note: mediator stores and sends back to sender)
        info!("Trust-ping requests response - acknowledging");
        ProcessingResult::ProcessedNoResponse
    } else {
        info!("Trust-ping does not request response");
        ProcessingResult::ProcessedNoResponse
    }
}

// Forward Protocol
async fn process_forward(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing forwarded message from {:?}", message.from_did);

    // Extract the forwarded message
    if let Some(forwarded_msg) = message
        .message_body
        .get("next")
    {
        debug!("Extracted forwarded message: {:?}", forwarded_msg);
        // In a real implementation, you would decrypt and process the forwarded message
        ProcessingResult::ProcessedNoResponse
    } else {
        ProcessingResult::Failed {
            reason: "Forward message missing 'next' field".to_string(),
        }
    }
}

// Problem Report
async fn process_problem_report(message: &ReceivedMessage) -> ProcessingResult {
    warn!("Received problem report from {:?}: {:?}", message.from_did, message.message_body);

    // Extract problem code and description
    let code = message
        .message_body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let comment = message
        .message_body
        .get("comment")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    info!("Problem code: {}, comment: {}", code, comment);

    ProcessingResult::ProcessedNoResponse
}

// Basic Message
async fn process_basic_message(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing basic message from {:?}", message.from_did);

    if let Some(content) = message
        .message_body
        .get("content")
        .and_then(|v| v.as_str())
    {
        info!("Basic message content: {}", content);
    }

    ProcessingResult::ProcessedNoResponse
}

// Discover Features
async fn process_discover_features(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing discover features query from {:?}", message.from_did);

    // Respond with supported protocols
    let response = serde_json::json!({
        "type": "https://didcomm.org/discover-features/2.0/disclose",
        "id": uuid::Uuid::new_v4().to_string(),
        "thid": message.didcomm_message_id,
        "body": {
            "disclosures": [
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/trust-ping/2.0"
                },
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/routing/2.0"
                },
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/messagepickup/3.0"
                },
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/present-proof/3.0"
                },
                {
                    "feature-type": "protocol",
                    "id": "https://didcomm.org/issue-credential/3.0"
                }
            ]
        }
    });

    ProcessingResult::RequiresResponse {
        response_type: "discover-features-disclose".to_string(),
        response_body: response,
    }
}

async fn process_feature_disclosure(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received feature disclosure from {:?}", message.from_did);
    ProcessingResult::ProcessedNoResponse
}

// Out of Band Invitation
async fn process_oob_invitation(message: &ReceivedMessage) -> ProcessingResult {
    info!("Processing out-of-band invitation from {:?}", message.from_did);
    // Store the invitation for potential connection establishment
    ProcessingResult::ProcessedNoResponse
}

// Connection Setup Protocol (Affinidi custom)
async fn process_connection_setup(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Processing connection-setup (INVITER receiving request from ACCEPTOR)");

    // Extract the acceptor's secure DID from the message body
    let acceptor_secure_did = message
        .message_body
        .get("channel_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if acceptor_secure_did.is_none() {
        warn!("connection-setup missing 'channel_did' field");
        return ProcessingResult::Failed {
            reason: "Missing channel_did in connection-setup message".to_string(),
        };
    }

    let acceptor_secure_did = acceptor_secure_did.unwrap();

    if message
        .context
        .get("invitation_capability_consumed")
        .and_then(|value| value.as_bool())
        != Some(true)
    {
        return ProcessingResult::Failed {
            reason: "Connection setup invitation capability was not consumed".to_string(),
        };
    }

    // Get the acceptor's temporary DID (the sender of this message)
    let acceptor_temporary_did = match &message.from_did {
        Some(did) => did.clone(),
        None => {
            warn!("connection-setup missing 'from' DID");
            return ProcessingResult::Failed {
                reason: "Missing from DID in connection-setup message".to_string(),
            };
        }
    };

    let invitation_id = match &message.didcomm_pthid {
        Some(parent_thread_id) => parent_thread_id.clone(),
        None => {
            return ProcessingResult::Failed {
                reason: "Connection setup is missing its invitation parent thread".to_string(),
            };
        }
    };

    debug!(
        invitation_id = %invitation_id,
        "Validated OOB setup payload after invitation capability consumption"
    );

    // Return special result type to trigger connection-accepted response and gateway creation
    ProcessingResult::OOBConnectionSetup {
        acceptor_temporary_did,
        acceptor_secure_did,
        invitation_id,
    }
}

async fn process_connection_accepted(message: &ReceivedMessage) -> ProcessingResult {
    info!("🎉 Processing connection-accepted (ACCEPTOR receiving final confirmation from INVITER)");

    // Extract the inviter's secure DID from the message body
    let inviter_secure_did = message
        .message_body
        .get("channel_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if inviter_secure_did.is_none() {
        warn!("connection-accepted missing 'channel_did' field");
        return ProcessingResult::Failed {
            reason: "Missing channel_did in connection-accepted message".to_string(),
        };
    }

    let inviter_secure_did = inviter_secure_did.unwrap();

    // Get the inviter's temporary DID (the sender of this message)
    let inviter_temporary_did = match &message.from_did {
        Some(did) => did.clone(),
        None => {
            warn!("connection-accepted missing 'from' DID");
            return ProcessingResult::Failed {
                reason: "Missing from DID in connection-accepted message".to_string(),
            };
        }
    };

    info!("✓ Inviter temporary DID: {}", inviter_temporary_did);
    info!("✓ Inviter secure DID: {}", inviter_secure_did);

    // Return special result type to trigger gateway finalization
    ProcessingResult::OOBConnectionAccepted {
        inviter_temporary_did,
        inviter_secure_did,
    }
}

async fn process_connection_rejected(message: &ReceivedMessage) -> ProcessingResult {
    info!("❌ Processing connection-rejected (ACCEPTOR receiving rejection from INVITER)");

    // Extract the rejection reason from the message body
    let reason = message
        .message_body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown reason")
        .to_string();

    error!("Connection rejected by inviter: {}", reason);

    // Return special result type to trigger pending connection cleanup
    ProcessingResult::OOBConnectionRejected { reason }
}

// Message Pickup Protocol
async fn process_status_request(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Processing message pickup status request from {:?}", message.from_did);

    // In a real implementation, check how many messages are queued
    let response = serde_json::json!({
        "type": "https://didcomm.org/messagepickup/3.0/status",
        "id": uuid::Uuid::new_v4().to_string(),
        "thid": message.didcomm_message_id,
        "body": {
            "message_count": 0,
            "longest_waited_seconds": 0,
            "newest_received_time": null,
            "oldest_received_time": null,
            "total_bytes": 0
        }
    });

    ProcessingResult::RequiresResponse {
        response_type: "message-pickup-status".to_string(),
        response_body: response,
    }
}

async fn process_status_response(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Received message pickup status response");

    // Extract status information
    let message_count = message
        .message_body
        .get("message_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let live_delivery = message
        .message_body
        .get("live_delivery")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    debug!("Message pickup status: {} messages queued, live_delivery: {}", message_count, live_delivery);

    if let Some(recipient_did) = message
        .message_body
        .get("recipient_did")
        .and_then(|v| v.as_str())
    {
        debug!("Status for recipient DID: {}", recipient_did);
    }

    // This is a response from the mediator - no further action needed
    ProcessingResult::ProcessedNoResponse
}

async fn process_delivery_request(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Processing message pickup delivery request from {:?}", message.from_did);
    // Deliver any queued messages
    ProcessingResult::ProcessedNoResponse
}

async fn process_delivery_response(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Received message pickup delivery response");

    // Extract delivered messages from attachments
    if let Some(attachments) = message
        .message_body
        .get("attachments")
        .and_then(|v| v.as_array())
    {
        debug!("Received {} message(s) from mediator", attachments.len());
        // In a real implementation, unpack and process each attached message
    } else {
        debug!("No messages in delivery response");
    }

    ProcessingResult::ProcessedNoResponse
}

async fn process_messages_received(message: &ReceivedMessage) -> ProcessingResult {
    debug!("Processing messages-received acknowledgment from {:?}", message.from_did);
    // Mark messages as delivered
    ProcessingResult::ProcessedNoResponse
}

async fn process_live_delivery_change(message: &ReceivedMessage) -> ProcessingResult {
    let live_delivery = message
        .message_body
        .get("live_delivery")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    debug!("Live delivery change request: {}", live_delivery);

    // Mediator will respond with a status message
    ProcessingResult::ProcessedNoResponse
}

// Presentation Protocol
async fn process_presentation_request(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received presentation request from {:?}", message.from_did);
    // Store for user/agent to respond
    ProcessingResult::ProcessedNoResponse
}

async fn process_presentation(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received presentation from {:?}", message.from_did);
    // Verify and process presentation
    ProcessingResult::ProcessedNoResponse
}

// Credential Issuance Protocol
async fn process_credential_offer(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received credential offer from {:?}", message.from_did);
    // Store for user/agent to accept
    ProcessingResult::ProcessedNoResponse
}

async fn process_credential_request(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received credential request from {:?}", message.from_did);
    // Process and issue credential
    ProcessingResult::ProcessedNoResponse
}

async fn process_credential_issuance(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received credential issuance from {:?}", message.from_did);
    // Store received credential
    ProcessingResult::ProcessedNoResponse
}

// Account Management Protocol
async fn process_account_management(message: &ReceivedMessage) -> ProcessingResult {
    info!("Received account management message from {:?}", message.from_did);
    // no need to process it
    ProcessingResult::ProcessedNoResponse
}

// Gateway Ping Protocol (Affinidi custom)
async fn process_gateway_ping(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received gateway-ping from {:?}", message.from_did);

    // Respond with gateway-pong using MessageType enum
    let response_body = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "original_timestamp": message.message_body.get("timestamp"),
    });

    info!("📤 Sending gateway-pong response");

    ProcessingResult::RequiresResponse {
        response_type: MessageType::GatewayPong.to_string(),
        response_body,
    }
}

async fn process_gateway_pong(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received gateway-pong from {:?}", message.from_did);
    // Pong is handled by the live_stream_get waiting for it
    ProcessingResult::ProcessedNoResponse
}

// Gateway Channel Query Protocol (Affinidi custom)
async fn process_get_surfaces(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received get-channels query from {:?}", message.from_did);

    // Load channels from the configured channel storage file
    let channels: Vec<serde_json::Value> = match load_channels_from_config(message).await {
        Ok(channel_list) => {
            info!("Found {} total channels", channel_list.len());

            let exposure = match surface_exposure(message) {
                Ok(exposure) => Some(exposure),
                Err(e) => {
                    warn!("Failed to resolve surface exposure: {} - returning empty channel list", e);
                    None
                }
            };

            let filtered_channels: Vec<serde_json::Value> = channel_list
                .iter()
                .filter(|ch| {
                    ch.status == crate::config::agent_surface::SurfaceStatus::Enabled
                        && exposure
                            .as_ref()
                            .is_some_and(|exposure| exposure.allows(ch))
                })
                .map(|ch| {
                    serde_json::json!({
                        "config_id": ch.config_id(),
                        "name": ch.name,
                        "description": ch.description,
                        "listen_address": ch.listen_address(),
                        "protocol": ch.channel_protocol().to_string(),
                    })
                })
                .collect();

            info!("Filtered to {} channels based on connection point configuration", filtered_channels.len());
            filtered_channels
        }
        Err(e) => {
            warn!("Failed to load channels: {} - returning empty channel list", e);
            Vec::new()
        }
    };

    let response_body = serde_json::json!({
        "channels": channels,
        "count": channels.len(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    info!("📤 Sending get-channels-response with {} channels", channels.len());

    ProcessingResult::RequiresResponse {
        response_type: MessageType::GetSurfacesResponse.to_string(),
        response_body,
    }
}

/// Context key under which the listener hands the processor the exposure of
/// the connection point a message arrived on.
pub(crate) const SURFACE_EXPOSURE_CONTEXT_KEY: &str = "surface_exposure";

/// The surfaces a peer may list and forward to through one connection point:
/// those the connection point and its gateway both expose (an empty list
/// exposes everything) and that the gateway's tenant may reference.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SurfaceExposure {
    tenant_id: Option<String>,
    gateway_surfaces: Vec<String>,
    connection_point_surfaces: Vec<String>,
}

impl SurfaceExposure {
    pub(crate) fn new(
        gateway: &crate::gateways::types::Gateway,
        connection_point: &super::types::GatewayConnectionPoint,
    ) -> Self {
        Self {
            tenant_id: gateway.tenant_id.clone(),
            gateway_surfaces: gateway
                .exposed_channels
                .clone(),
            connection_point_surfaces: connection_point
                .exposed_channels
                .clone(),
        }
    }

    fn allows(
        &self,
        surface: &crate::config::agent_surface::AgentSurface,
    ) -> bool {
        let Some(config_id) = surface.config_id() else {
            return false;
        };
        let listed = |ids: &[String]| {
            ids.is_empty()
                || ids
                    .iter()
                    .any(|id| id == config_id)
        };
        crate::tenancy::can_reference(self.tenant_id.as_deref(), surface.tenant_id.as_deref())
            && listed(&self.gateway_surfaces)
            && listed(&self.connection_point_surfaces)
    }
}

/// The exposure the listener attached to the message. A missing or unreadable
/// one is an error, so callers deny rather than widen.
fn surface_exposure(message: &ReceivedMessage) -> Result<SurfaceExposure, String> {
    let value = message
        .context
        .get(SURFACE_EXPOSURE_CONTEXT_KEY)
        .ok_or_else(|| format!("{SURFACE_EXPOSURE_CONTEXT_KEY} not found in message context"))?;
    serde_json::from_value(value.clone()).map_err(|e| format!("Invalid {SURFACE_EXPOSURE_CONTEXT_KEY}: {e}"))
}

/// Load channels from the configured storage location
async fn load_channels_from_config(
    message: &ReceivedMessage
) -> Result<Vec<crate::config::agent_surface::AgentSurface>, String> {
    // Get surface storage path from message context
    let storage_path = message
        .context
        .get("agent_surface_storage_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Agent surface storage path not found in message context".to_string())?;

    info!("Loading surfaces from: {}", storage_path);

    let agent_surface_store = crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(storage_path))
        .await
        .map_err(|e| format!("Failed to create agent surface store: {}", e))?;

    let channels = agent_surface_store
        .list_all()
        .await
        .map_err(|e| format!("Failed to load surfaces: {}", e))?;

    Ok(channels)
}

/// Resolve the surface `channel_id` names, only when it is exposed to the
/// connection point the message arrived on.
async fn lookup_channel(
    message: &ReceivedMessage,
    channel_id: &str,
) -> Result<Option<crate::config::agent_surface::AgentSurface>, String> {
    let exposure = surface_exposure(message)?;
    let channels = load_channels_from_config(message).await?;
    Ok(channels
        .into_iter()
        .find(|ch| ch.config_id() == Some(channel_id) && exposure.allows(ch)))
}

async fn process_get_surfaces_response(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received get-channels-response from {:?}", message.from_did);
    // Response is handled by whoever initiated the query
    ProcessingResult::ProcessedNoResponse
}

/// Extract caller identity from inbound fabric request (VP, extensions, MCP _meta).
/// Extracted from `process_forward_request` to reduce async state-machine size.
/// Outcome of inbound caller-identity extraction on the fabric (GW2) path: the
/// caller identity string used for `extension_identity`, plus the verified VP
/// `identity_binding` (holder / issuer / claims) when a presentation was
/// cryptographically verified, so the surface policy can gate on it.
#[derive(Default)]
struct InboundCallerIdentity {
    identity: Option<String>,
    binding: Option<crate::surface_context::IdentityBindingContext>,
}

/// The holder DID of a cryptographically verified VP, the only caller DID that
/// may key the delegation vault. A DID read from the request body without a
/// verified VP is telemetry only.
fn verified_caller_did(binding: Option<&crate::surface_context::IdentityBindingContext>) -> Option<String> {
    binding
        .filter(|b| b.verified && !b.agent_did.is_empty())
        .map(|b| b.agent_did.clone())
}

/// The delegation vault key for a fabric request: the verified VP holder DID,
/// else the source-auth principal, else none (delegation is skipped).
fn delegation_user_hash(
    verified_caller_did: Option<&str>,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> Option<String> {
    if let Some(did) = verified_caller_did {
        return Some(did.to_string());
    }
    authenticated_identity.map(|id| {
        let raw = match id {
            crate::source_auth::AuthenticatedIdentity::JwtBearer { subject, .. } => subject.clone(),
            crate::source_auth::AuthenticatedIdentity::ApiKey { key_name } => key_name.clone(),
            crate::source_auth::AuthenticatedIdentity::Mtls { principal, .. } => principal.clone(),
        };
        crate::identity::calculate_identity_hash(&serde_json::json!({
            "source_auth": raw,
        }))
    })
}

/// `None`, so nothing the message carries verifies, when either DID is unknown.
fn envelope_challenge(message: &ReceivedMessage) -> Option<crate::identity::ExpectedChallenge<'_>> {
    let sender = message
        .from_did
        .as_deref()
        .filter(|did| !did.is_empty())?;
    let recipient = message
        .receiving_connection_point_did
        .as_deref()
        .filter(|did| !did.is_empty())?;
    Some(crate::identity::ExpectedChallenge::Envelope {
        id: &message.didcomm_message_id,
        sender,
        recipient,
    })
}

async fn verify_fabric_presentation(
    vc_issuer: &crate::identity::VCIssuer,
    vp_jwt: &str,
    envelope: Option<crate::identity::ExpectedChallenge<'_>>,
) -> anyhow::Result<(String, Option<String>, std::collections::HashMap<String, serde_json::Value>)> {
    let expected =
        envelope.ok_or_else(|| anyhow::anyhow!("the envelope's sender or receiving Connection Point is unknown"))?;
    vc_issuer
        .verify_presentation_with_issuer(vp_jwt, expected)
        .await
}

async fn extract_caller_identity_inbound(
    surface: &crate::config::agent_surface::AgentSurface,
    channel_id: &str,
    config_id: &str,
    body_bytes: &[u8],
    identity_ext_rules: Option<&crate::config::types::ExtensionRules>,
    vc_issuer: Option<&Arc<crate::identity::VCIssuer>>,
    envelope: Option<crate::identity::ExpectedChallenge<'_>>,
) -> InboundCallerIdentity {
    let mut caller_identity: Option<String> = None;
    let mut identity_binding: Option<crate::surface_context::IdentityBindingContext> = None;

    channel_info!(
        config_id,
        "Checking for identity extraction - has_identity_ext_rules: {}, body_empty: {}",
        identity_ext_rules.is_some(),
        body_bytes.is_empty()
    );

    if body_bytes.is_empty() {
        channel_info!(config_id, "GW2: Body is empty, cannot extract identity");
        return InboundCallerIdentity::default();
    }

    let body_json = match serde_json::from_slice::<serde_json::Value>(body_bytes) {
        Ok(j) => j,
        Err(_) => {
            channel_info!(config_id, "GW2: Failed to parse body as JSON");
            return InboundCallerIdentity::default();
        }
    };
    info!("GW2: Successfully parsed body as JSON, checking for extensions");

    let message = body_json
        .get("params")
        .and_then(|p| p.get("message"))
        .or_else(|| body_json.get("message"));

    if let Some(msg) = message {
        if let Some(extensions) = msg
            .get("extensions")
            .and_then(|e| e.as_array())
        {
            channel_info!(config_id, "GW2: Found {} extension URIs in request", extensions.len());

            // Check if GW1 sent a VP credential (preferred method)
            let has_credential_ext = extensions
                .iter()
                .any(|ext| ext.as_str() == Some(crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION));

            if has_credential_ext {
                channel_debug!(config_id, "GW2: Found identity credential extension (VP) from GW1");

                if let Some(metadata) = msg.get("metadata")
                    && let Some(credential_ext) =
                        metadata.get(crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION)
                {
                    channel_debug!(config_id, "GW2: Found credential extension in metadata");

                    if let Some(vp_jwt) = credential_ext
                        .get("verifiablePresentation")
                        .and_then(|v| v.as_str())
                        && let Some(vc_issuer) = vc_issuer
                    {
                        match verify_fabric_presentation(vc_issuer, vp_jwt, envelope).await {
                            Ok((verified_did, issuer_did, identity_fields)) => {
                                caller_identity = Some(verified_did.clone());
                                identity_binding = Some(crate::surface_context::IdentityBindingContext {
                                    verified: true,
                                    agent_did: verified_did.clone(),
                                    gateway_did: String::new(),
                                    issuer_did,
                                    identity_fields: identity_fields.clone(),
                                });
                                channel_info!(config_id, "✓ GW2: VP verification succeeded for DID: {}", verified_did);
                                let identity_store = vc_issuer.get_identity_store();
                                if let Err(e) = identity_store
                                    .store_external_did(
                                        &verified_did,
                                        identity_fields,
                                        surface
                                            .config_id()
                                            .map(str::to_string),
                                        true,
                                    )
                                    .await
                                {
                                    channel_warn!(config_id, "GW2: Failed to store external DID reference: {}", e);
                                }
                            }
                            Err(e) => {
                                channel_warn!(
                                    config_id,
                                    "✗ GW2: VP verification FAILED: {} - identity will be marked as unverified",
                                    e
                                );
                                if let Some(did) = credential_ext
                                    .get("did")
                                    .and_then(|d| d.as_str())
                                {
                                    let identity_store = vc_issuer.get_identity_store();
                                    if let Err(store_err) = identity_store
                                        .store_external_did(
                                            did,
                                            std::collections::HashMap::new(),
                                            surface
                                                .config_id()
                                                .map(str::to_string),
                                            false,
                                        )
                                        .await
                                    {
                                        channel_warn!(config_id, "GW2: Failed to store unverified DID: {}", store_err);
                                    }
                                }
                            }
                        }
                    }

                    if caller_identity.is_none()
                        && let Some(did) = credential_ext
                            .get("did")
                            .and_then(|d| d.as_str())
                    {
                        caller_identity = Some(did.to_string());
                        channel_info!(
                            config_id,
                            "⚠ GW2: Using DID from credential extension without VP verification: {}",
                            did
                        );
                        if let Some(vc_issuer) = vc_issuer {
                            let identity_store = vc_issuer.get_identity_store();
                            if let Err(e) = identity_store
                                .store_external_did(
                                    did,
                                    std::collections::HashMap::new(),
                                    surface
                                        .config_id()
                                        .map(str::to_string),
                                    false,
                                )
                                .await
                            {
                                channel_warn!(config_id, "GW2: Failed to store external DID reference: {}", e);
                            }
                        }
                    }
                }
            }

            // If no credential extension or verification failed, check for raw identity extension
            if caller_identity.is_none() {
                let has_identity_ext = extensions
                    .iter()
                    .any(|ext| ext.as_str() == Some(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION));

                if has_identity_ext {
                    channel_info!(config_id, "GW2: No VP found, checking raw identity extension");

                    if let Some(metadata) = msg.get("metadata") {
                        if let Some(identity_ext) = metadata.get(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION) {
                            channel_info!(
                                config_id,
                                "GW2: Found identity extension in metadata: {}",
                                serde_json::to_string_pretty(identity_ext).unwrap_or_default()
                            );

                            if let Some(did) = identity_ext
                                .get("did")
                                .and_then(|d| d.as_str())
                            {
                                caller_identity = Some(did.to_string());
                                channel_info!(config_id, "GW2: Caller identity from GW1 (existing DID): {}", did);
                            } else {
                                let identity_selector = if let (Some(ext_rules), Some(vc_issuer)) =
                                    (identity_ext_rules, vc_issuer)
                                {
                                    if let Some(json_schema) = &ext_rules.json_schema {
                                        match crate::identity::IdentitySelector::new(json_schema, vc_issuer.clone()) {
                                            Ok(selector) if selector.has_identity_fields() => Some(Arc::new(selector)),
                                            _ => None,
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                if let Some(ref selector) = identity_selector {
                                    channel_info!(config_id, "GW2: Computing caller identity using IdentitySelector");
                                    match selector
                                        .compute_identity(
                                            identity_ext,
                                            channel_id,
                                            surface
                                                .config_id()
                                                .map(str::to_string),
                                        )
                                        .await
                                    {
                                        Ok(identity_result) => {
                                            caller_identity = Some(identity_result.did.clone());
                                            channel_info!(
                                                config_id,
                                                "GW2: Caller identity computed: {} (is_new: {})",
                                                identity_result.did,
                                                identity_result.is_new
                                            );
                                            if identity_result.is_new
                                                && let Some(notif_store) = GLOBAL_NOTIFICATION_STORE.get()
                                            {
                                                let did_clone = identity_result.did.clone();
                                                let channel_id_clone = channel_id.to_string();
                                                let notif = (*notif_store).clone();
                                                crate::observability::spawn_traced_task(
                                                    "integration.identity_appeared",
                                                    async move {
                                                        crate::integrations::async_triggers::trigger_identity_appeared(
                                                            Some(notif.clone()),
                                                            &did_clone,
                                                            &channel_id_clone,
                                                        )
                                                        .await;
                                                    },
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            channel_warn!(config_id, "GW2: Failed to compute caller identity: {}", e);
                                        }
                                    }
                                }

                                if caller_identity.is_none() {
                                    channel_info!(
                                        config_id,
                                        "GW2: No IdentitySelector available, using peppered identity hash fallback"
                                    );
                                    let identity_value = identity_ext
                                        .get("agentIdentity")
                                        .or_else(|| identity_ext.get("agentId"))
                                        .or_else(|| identity_ext.get("id"))
                                        .or_else(|| identity_ext.get("agent_id"))
                                        .cloned()
                                        .unwrap_or_else(|| identity_ext.clone());

                                    let hash_str = crate::identity::calculate_identity_hash(&serde_json::json!({
                                        "caller_identity": identity_value,
                                    }));
                                    caller_identity = Some(hash_str.clone());
                                    channel_info!(
                                        config_id,
                                        "GW2: Caller identity computed from peppered hash: {}",
                                        hash_str
                                    );
                                }
                            }
                        } else {
                            channel_info!(config_id, "GW2: Raw identity extension declared but not found in metadata");
                        }
                    } else {
                        channel_info!(config_id, "GW2: No metadata found for raw identity extension");
                    }
                } else {
                    channel_info!(config_id, "GW2: No raw identity extension declared (VP or raw)");
                }
            }
        } else {
            channel_info!(config_id, "GW2: No extensions array found in message");
        }
    } else {
        channel_info!(config_id, "GW2: No message object found in body");

        // If no message object, this might be MCP protocol — check _meta field
        if let Some(_meta) = body_json.get("_meta") {
            channel_info!(config_id, "GW2: Found _meta field, checking for identity credential (MCP format)");

            if let Some(credential_ext) = _meta.get(crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION) {
                channel_info!(config_id, "GW2: Found identity credential extension in _meta (MCP format)");

                if let Some(vp_jwt) = credential_ext
                    .get("verifiablePresentation")
                    .and_then(|v| v.as_str())
                    && let Some(vc_issuer) = vc_issuer
                {
                    match verify_fabric_presentation(vc_issuer, vp_jwt, envelope).await {
                        Ok((verified_did, issuer_did, identity_fields)) => {
                            caller_identity = Some(verified_did.clone());
                            identity_binding = Some(crate::surface_context::IdentityBindingContext {
                                verified: true,
                                agent_did: verified_did.clone(),
                                gateway_did: String::new(),
                                issuer_did,
                                identity_fields: identity_fields.clone(),
                            });
                            channel_info!(
                                config_id,
                                "✓ GW2: VP verification succeeded for DID (from _meta): {}",
                                verified_did
                            );
                            let identity_store = vc_issuer.get_identity_store();
                            if let Err(e) = identity_store
                                .store_external_did(
                                    &verified_did,
                                    identity_fields,
                                    surface
                                        .config_id()
                                        .map(str::to_string),
                                    true,
                                )
                                .await
                            {
                                channel_warn!(config_id, "GW2: Failed to store external DID reference: {}", e);
                            }
                        }
                        Err(e) => {
                            channel_warn!(
                                config_id,
                                "✗ GW2: VP verification FAILED (from _meta): {} - identity will be marked as unverified",
                                e
                            );
                            if let Some(did) = credential_ext
                                .get("did")
                                .and_then(|d| d.as_str())
                            {
                                let identity_store = vc_issuer.get_identity_store();
                                if let Err(store_err) = identity_store
                                    .store_external_did(
                                        did,
                                        std::collections::HashMap::new(),
                                        surface
                                            .config_id()
                                            .map(str::to_string),
                                        false,
                                    )
                                    .await
                                {
                                    channel_warn!(config_id, "GW2: Failed to store unverified DID: {}", store_err);
                                }
                            }
                        }
                    }
                }

                if caller_identity.is_none()
                    && let Some(did) = credential_ext
                        .get("did")
                        .and_then(|d| d.as_str())
                {
                    caller_identity = Some(did.to_string());
                    channel_info!(
                        config_id,
                        "⚠ GW2: Using DID from _meta credential extension without VP verification: {}",
                        did
                    );
                    if let Some(vc_issuer) = vc_issuer {
                        let identity_store = vc_issuer.get_identity_store();
                        if let Err(e) = identity_store
                            .store_external_did(
                                did,
                                std::collections::HashMap::new(),
                                surface
                                    .config_id()
                                    .map(str::to_string),
                                false,
                            )
                            .await
                        {
                            channel_warn!(config_id, "GW2: Failed to store external DID reference: {}", e);
                        }
                    }
                }
            } else {
                channel_info!(config_id, "GW2: No identity credential found in _meta field");
            }
        }
    }

    channel_info!(config_id, "Request inspection - caller_identity: {:?}", caller_identity);
    InboundCallerIdentity {
        identity: caller_identity,
        binding: identity_binding,
    }
}

/// Gateway-level OPA on the fabric receive path: two layers, both
/// deny-overrides and fail-closed. The appliance-wide Trust Fabric baseline
/// runs on every fabric request, a public discovery read included, which it
/// sees as `input.request.purpose == "discovery"` with no `input.source_auth`.
/// This gateway's own policy set skips a public discovery read.
fn enforce_gateway_policies(
    appliance_policies: &crate::pipes::PipePolicyManager,
    gateway_policies: Option<&crate::policies::GatewayPolicyManager>,
    surface: &crate::config::agent_surface::AgentSurface,
    config_id: &str,
    method: &str,
    path: &str,
    headers: Option<&serde_json::Map<String, Value>>,
    from_did: Option<&str>,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> Result<(), ProcessingResult> {
    let public_read = crate::proxy::paths::is_public_request(method, path);
    let enforce_appliance_global = appliance_policies.has_global("appliance");
    let own_gateway = gateway_policies
        .filter(|_| !public_read)
        .and_then(|m| {
            m.get_self_gateway_id()
                .map(|id| (m, id))
        })
        .filter(|(m, id)| m.is_enforced(id));

    if !enforce_appliance_global && own_gateway.is_none() {
        info!(
            channel = config_id,
            path = path,
            public_read,
            has_manager = gateway_policies.is_some(),
            "[GW-POLICY] GW2 fabric path: no gateway-level OPA policy applies, allowing"
        );
        return Ok(());
    }

    let denied = || ProcessingResult::RequiresResponse {
        response_type: MessageType::ForwardResponse.to_string(),
        response_body: serde_json::json!({
            "status": 403,
            "body": r#"{"error":"Forbidden","message":"Request blocked by gateway policy"}"#,
            "error": "Request blocked by gateway policy",
        }),
    };

    let http_headers = crate::surface_context::filter_sensitive_json_headers(headers);
    let mut gw_input = crate::surface_context::PolicyInput::new(
        method,
        path,
        http_headers,
        "inbound",
        from_did.map(str::to_string),
        None,
        surface
            .config_id()
            .map(str::to_string),
        &surface.name,
    );
    gw_input.source_auth = authenticated_identity.map(crate::surface_context::SourceAuthContext::from);
    if public_read {
        gw_input.request = Some(crate::surface_context::RequestContext {
            purpose: crate::surface_context::RequestPurpose::Discovery,
            forwarded_upstream_auth: false,
        });
    }
    let mut gw_input_value = match serde_json::to_value(&gw_input) {
        Ok(value) => value,
        Err(e) => {
            warn!(
                channel = config_id,
                public_read, "[GW-POLICY] GW2: gateway policy input could not be built (denying): {}", e
            );
            return Err(denied());
        }
    };

    if enforce_appliance_global {
        let input = if own_gateway.is_some() {
            gw_input_value.clone()
        } else {
            std::mem::take(&mut gw_input_value)
        };
        let (decision, _evidence) =
            crate::observability::request_context::with_tenant(surface.tenant_id.as_deref(), || {
                appliance_policies.evaluate_global("appliance", input)
            });
        match decision {
            Ok(true) => {
                info!(
                    channel = config_id,
                    public_read, "[GW-POLICY] GW2: appliance-wide gateway policy allowed request"
                );
            }
            Ok(false) => {
                info!(
                    channel = config_id,
                    public_read, "[GW-POLICY] GW2: appliance-wide gateway policy DENIED request"
                );
                return Err(denied());
            }
            Err(e) => {
                info!(
                    channel = config_id,
                    public_read, "[GW-POLICY] GW2: appliance-wide gateway policy error (denying): {}", e
                );
                return Err(denied());
            }
        }
    }

    if let Some((gw_pm, self_gateway_id)) = own_gateway {
        info!(
            channel = config_id,
            path = path,
            self_gateway_id = %self_gateway_id,
            "[GW-POLICY] GW2 fabric path: evaluating gateway-level OPA policy"
        );

        match crate::observability::request_context::with_tenant(surface.tenant_id.as_deref(), || {
            gw_pm.evaluate_policy(&self_gateway_id, gw_input_value)
        }) {
            Ok(true) => {
                info!(channel = config_id, "[GW-POLICY] GW2: gateway-level policy allowed request");
            }
            Ok(false) => {
                info!(channel = config_id, "[GW-POLICY] GW2: gateway-level policy DENIED request");
                return Err(denied());
            }
            Err(e) => {
                info!(channel = config_id, "[GW-POLICY] GW2: gateway-level policy evaluation error (denying): {}", e);
                return Err(denied());
            }
        }
    }

    Ok(())
}

/// Injects custom metadata and trust registry extensions into the request body,
/// then evaluates gateway-level and channel-level OPA policies. Returns the
/// (potentially modified) body bytes on allow, or a deny `ProcessingResult`.
async fn enrich_and_evaluate_policies(
    appliance_policies: &crate::pipes::PipePolicyManager,
    surface: &crate::config::agent_surface::AgentSurface,
    channel_id: &str,
    config_id: &str,
    method: &str,
    path: &str,
    body_bytes: bytes::Bytes,
    headers: Option<&serde_json::Map<String, Value>>,
    from_did: Option<String>,
    caller_identity: Option<&String>,
    identity_binding: Option<crate::surface_context::IdentityBindingContext>,
    authenticated_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    variant_alias: Option<&str>,
) -> Result<bytes::Bytes, ProcessingResult> {
    let mut body_bytes = body_bytes;

    // Inject custom metadata if enabled on THIS gateway (GW2)
    if let Some(custom_metadata) = surface.custom_metadata()
        && custom_metadata.enabled
        && method.to_uppercase() == "POST"
        && !body_bytes.is_empty()
    {
        channel_info!(config_id, "Attempting to inject custom metadata for channel {}", channel_id);
        match crate::protocols::inject_custom_metadata_extension(&body_bytes, custom_metadata, channel_id, &None).await
        {
            Ok(modified_bytes) => {
                channel_info!(
                    config_id,
                    "GW2: Custom metadata extension injected (original: {} bytes, new: {} bytes)",
                    body_bytes.len(),
                    modified_bytes.len()
                );
                body_bytes = modified_bytes;
            }
            Err(e) => {
                channel_warn!(config_id, "GW2: Failed to inject custom metadata extension, using original body: {}", e);
            }
        }
    }

    let is_agent_card_request = crate::proxy::paths::is_public_request(method, path);

    enforce_gateway_policies(
        appliance_policies,
        GLOBAL_GATEWAY_POLICY_MANAGER
            .get()
            .map(Arc::as_ref),
        surface,
        config_id,
        method,
        path,
        headers,
        from_did.as_deref(),
        authenticated_identity,
    )?;

    // Channel-Level OPA Policy evaluation (GW2 / message processor path)
    let has_compiled_policy = GLOBAL_POLICY_MANAGER
        .get()
        .is_some_and(|pm| pm.has_policy(config_id));
    channel_info!(
        config_id,
        "GW2: opa_enabled={} trust_registry_verification.enabled={} has_compiled_policy={}",
        surface.opa_enabled(),
        surface
            .trust_registry_verification()
            .enabled,
        has_compiled_policy
    );
    // Fail closed: OPA enabled for the surface but no compiled policy (the Rego
    // failed to compile, or the config backend cannot carry the policy ref) →
    // deny rather than silently skip enforcement.
    if surface.opa_enabled() && !is_agent_card_request && !has_compiled_policy {
        channel_warn!(config_id, "GW2: surface OPA enabled but no compiled policy; denying request (fail-closed)");
        return Err(ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: serde_json::json!({
                "status": 403,
                "body": r#"{"error":"Forbidden","message":"Agent trust policy could not be evaluated"}"#,
                "error": "Agent trust policy could not be evaluated",
            }),
        });
    }
    // OPA runs whenever it is enabled and compiled — independent of trust-registry
    // verification. The agent context is still built best-effort so a policy that
    // wants trust-registry signals can read them, but OPA is no longer silently
    // gated off when trust-registry verification is disabled.
    if surface.opa_enabled() && !is_agent_card_request && has_compiled_policy {
        channel_info!(config_id, "GW2: Starting channel-level OPA policy evaluation");

        let body_json: Option<serde_json::Value> = serde_json::from_slice(&body_bytes).ok();
        channel_info!(config_id, "GW2: Body parsed for OPA: {}", body_json.is_some());
        let body_ref = body_json.as_ref();

        // Fetch agent card from the backend target endpoint,
        // respecting override_agent_card_location if configured.
        let card_url = if surface.override_agent_card_location()
            && surface
                .agent_card_location_path()
                .is_some()
        {
            let custom_path = surface
                .agent_card_location_path()
                .unwrap();
            let target_endpoint = surface.target_endpoint();
            let origin = if let Some(scheme_end) = target_endpoint.find("://") {
                let after_scheme = &target_endpoint[scheme_end + 3..];
                let authority_end = after_scheme
                    .find('/')
                    .unwrap_or(after_scheme.len());
                &target_endpoint[..scheme_end + 3 + authority_end]
            } else {
                target_endpoint
            };
            if custom_path.starts_with('/') {
                format!("{}{}", origin, custom_path)
            } else {
                format!("{}/{}", origin, custom_path)
            }
        } else {
            format!(
                "{}/.well-known/agent.json",
                surface
                    .target_endpoint()
                    .trim_end_matches('/')
            )
        };
        channel_info!(
            config_id,
            "GW2: Fetching agent card from: {}",
            crate::url_validation::redact_url_for_logging(&card_url)
        );
        let client = fabric_http_client();
        // An IP-literal URL never reaches the shared client's DNS resolver, so
        // refuse a cloud metadata target before fetching.
        let refused = crate::url_validation::reject_cloud_metadata_url(&card_url).err();
        if let Some(ref e) = refused {
            channel_warn!(config_id, "GW2: Not fetching agent card: {}", e);
        }
        let card_json: Option<serde_json::Value> = if refused.is_some() {
            None
        } else if let Some(client) = client {
            match client
                .get(&card_url)
                .send()
                .await
            {
                Ok(resp) => {
                    channel_info!(config_id, "GW2: Agent card fetch HTTP status: {}", resp.status());
                    if resp.status().is_success() {
                        match resp
                            .json::<serde_json::Value>()
                            .await
                        {
                            Ok(card) => {
                                channel_info!(
                                    config_id,
                                    "GW2: Agent card fetched successfully: name={:?} url={:?}",
                                    card.get("name"),
                                    card.get("url")
                                );
                                Some(card)
                            }
                            Err(e) => {
                                channel_warn!(config_id, "GW2: Failed to parse agent card JSON: {}", e);
                                None
                            }
                        }
                    } else {
                        channel_warn!(
                            config_id,
                            "GW2: Agent card fetch returned non-success status: {}",
                            resp.status()
                        );
                        None
                    }
                }
                Err(e) => {
                    channel_warn!(
                        config_id,
                        "GW2: Agent card fetch request failed (url={}): {}",
                        crate::url_validation::redact_url_for_logging(&card_url),
                        e
                    );
                    None
                }
            }
        } else {
            None
        };
        channel_info!(config_id, "GW2: Agent card obtained: {}", card_json.is_some());
        let agent_ctx = crate::policies::build_agent_context(body_ref, card_json.as_ref()).await;
        channel_info!(config_id, "GW2: Agent context built: trust_verification={:?}", agent_ctx.trust_verification);

        // Build HTTP headers map (filter sensitive headers)
        let http_headers = crate::surface_context::filter_sensitive_json_headers(headers);

        // Build extension identity from caller_identity (DID extracted from VP/credential extension)
        let ext_identity = caller_identity.map(|id| {
            let did = if id.starts_with("did:") {
                Some(id.to_string())
            } else {
                None
            };
            crate::surface_context::ExtensionIdentityContext {
                did,
                identity_hash: Some(id.to_string()),
            }
        });

        let mut policy_input = crate::surface_context::PolicyInput::new(
            method,
            path,
            http_headers,
            "inbound",
            from_did.clone(),
            None,
            surface
                .config_id()
                .map(str::to_string),
            &surface.name,
        );
        if let Some(ref mut ch) = policy_input.channel {
            ch.variant_alias = variant_alias.map(|s| s.to_string());
        }
        policy_input.extension_identity = ext_identity;
        policy_input.source_auth = authenticated_identity.map(crate::surface_context::SourceAuthContext::from);
        policy_input.agent = Some(agent_ctx);
        if let Some(mut binding) = identity_binding {
            if binding.gateway_did.is_empty()
                && let Some(ref gw) = from_did
            {
                binding.gateway_did = gw.clone();
            }
            policy_input.identity_binding = Some(binding);
        }
        let denied = || ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: serde_json::json!({
                "status": 403,
                "body": r#"{"error":"Forbidden","message":"Agent trust policy denied the request"}"#,
                "error": "Agent trust policy denied the request",
            }),
        };
        let input_value = match serde_json::to_value(&policy_input) {
            Ok(value) => value,
            Err(e) => {
                channel_warn!(
                    config_id,
                    "GW2: Channel-level OPA policy input could not be built (denying request): {}",
                    e
                );
                return Err(denied());
            }
        };

        if let Some(policy_manager) = GLOBAL_POLICY_MANAGER.get() {
            match crate::observability::request_context::with_tenant(surface.tenant_id.as_deref(), || {
                policy_manager.evaluate_policy(config_id, input_value)
            }) {
                Ok(true) => {
                    channel_info!(config_id, "GW2: Channel-level OPA policy allowed request");
                }
                Ok(false) => {
                    channel_warn!(config_id, "GW2: Channel-level OPA policy denied request");
                    return Err(denied());
                }
                Err(e) => {
                    channel_warn!(config_id, "GW2: Channel-level OPA policy evaluation error (denying request): {}", e);
                    return Err(denied());
                }
            }
        }
    }

    Ok(body_bytes)
}

/// Source authentication on the fabric receive path. A public discovery read
/// (a `GET` or `HEAD` of a discovery document) skips it. Any other request on
/// a surface that declares source auth must pass it, and is refused when the
/// source-auth middleware failed to start (`middleware` is `None`).
async fn authenticate_fabric_caller(
    surface: &crate::config::agent_surface::AgentSurface,
    config_id: &str,
    method: &str,
    path: &str,
    headers: Option<&serde_json::Map<String, Value>>,
    body_bytes: &[u8],
    middleware: Option<&crate::source_auth::SourceAuthMiddleware>,
) -> Result<Option<crate::source_auth::AuthenticatedIdentity>, ProcessingResult> {
    if crate::proxy::paths::is_public_request(method, path) {
        channel_info!(config_id, "Public discovery read: source authentication skipped");
        return Ok(None);
    }
    let refuse = |status: u16, message: &'static str| {
        let json_rpc = crate::protocols::channel_protocol_family(&surface.channel_protocol()).is_some();
        let request_id = crate::gateways::connection_points::forward_errors::extract_json_rpc_id(body_bytes);
        ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: crate::gateways::connection_points::forward_errors::safe_forward_error(
                status, message, json_rpc, request_id,
            ),
        }
    };
    let (sa_middleware, auth_config) = match crate::source_auth::source_auth_gate(surface.source_auth(), middleware) {
        crate::source_auth::SourceAuthGate::Open => return Ok(None),
        crate::source_auth::SourceAuthGate::Unavailable => {
            channel_warn!(
                config_id,
                "Source authentication is configured but its middleware is not running - refusing"
            );
            return Err(refuse(503, "Source authentication is unavailable"));
        }
        crate::source_auth::SourceAuthGate::Required(sa_middleware, auth_config) => (sa_middleware, auth_config),
    };
    // Rebuild an axum HeaderMap from the JSON headers map so the middleware
    // can use the same extract_bearer path as the direct handler.
    let axum_headers: axum::http::HeaderMap = headers
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| {
            Some((
                axum::http::HeaderName::from_bytes(k.as_bytes()).ok()?,
                axum::http::HeaderValue::from_str(v.as_str()?).ok()?,
            ))
        })
        .collect();
    match sa_middleware
        .authenticate(auth_config, &axum_headers, &surface.name, surface.tenant_id.as_deref(), None)
        .await
    {
        Ok(identity) => Ok(Some(identity)),
        Err(e) => {
            // Log the auth failure detail internally; return a generic 403.
            channel_warn!(config_id, "Source authentication failed: {}", e);
            Err(refuse(403, "Source authentication failed"))
        }
    }
}

/// The URL a fabric forward sends `path` to under `target_endpoint`: joined
/// with [`crate::proxy::handler::join_endpoint_path`], so a path can never
/// change the target's host, without a trailing `/`.
fn fabric_target_url(
    target_endpoint: &str,
    path: &str,
) -> String {
    crate::proxy::handler::join_endpoint_path(target_endpoint, path)
        .trim_end_matches('/')
        .to_string()
}

/// Headers some frameworks read as the request's real method.
const METHOD_OVERRIDE_HEADERS: &[&str] = &["x-http-method-override", "x-http-method", "x-method-override"];

/// Whether a fabric forward may carry upstream credentials: the surface's
/// target credential and any delegated credentials. On a surface that declares
/// source authentication only a caller it identified may; a public discovery
/// read skips source authentication, so there it reaches the target without
/// them, whatever identity its body claims.
fn may_send_upstream_credentials(
    surface: &crate::config::agent_surface::AgentSurface,
    caller: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> bool {
    surface
        .source_auth()
        .is_none()
        || caller.is_some()
}

/// The caller headers a fabric forward passes to the target: all of them but
/// `content-length` and `host` (derived from the body and the target URL), the
/// source-auth credential header (consumed here, never forwarded), and, on a
/// public discovery read, any method-override header, so a public read stays
/// a read at the target.
fn forwarded_headers<'a>(
    headers: &'a serde_json::Map<String, Value>,
    source_cred_header: Option<&str>,
    public_read: bool,
) -> Vec<(&'a str, &'a str)> {
    headers
        .iter()
        .filter(|(key, _)| {
            let key = key.to_ascii_lowercase();
            key != "content-length"
                && key != "host"
                && source_cred_header.is_none_or(|cred| !key.eq_ignore_ascii_case(cred))
                && !(public_read && METHOD_OVERRIDE_HEADERS.contains(&key.as_str()))
        })
        .filter_map(|(key, value)| Some((key.as_str(), value.as_str()?)))
        .collect()
}

/// Payment enforcement on the fabric receive path, run once nothing local can
/// refuse the request any more. On a paid surface, every request but a read of
/// the surface's own discovery document ([`is_free_discovery_read`]) is relayed
/// to Agent Pay with only its payment headers
/// ([`super::payment_gate::is_relayed_header`]) and `body_bytes`, within what is
/// left of the caller's `deadline_ms`. Returns the receipt headers to add to the
/// response (`None` when the request is not charged), or the answer that ends
/// the request: Agent Pay's challenge, or a refusal.
async fn enforce_payment(
    surface: &crate::config::agent_surface::AgentSurface,
    config_id: &str,
    method: &str,
    path: &str,
    headers: Option<&serde_json::Map<String, Value>>,
    body_bytes: &[u8],
    agent_pay: Option<&dyn super::payment_gate::AgentPayRelay>,
    deadline_ms: Option<u64>,
) -> Result<Option<std::collections::HashMap<String, String>>, ProcessingResult> {
    use super::payment_gate::PaymentDecision;

    let Some(policy) = surface
        .target
        .payment_policy
        .as_ref()
    else {
        return Ok(None);
    };
    if is_free_discovery_read(surface, method, path) {
        return Ok(None);
    }
    let timeout = match deadline_ms.map(time_left) {
        None => crate::fabric_marketplace::FABRIC_FORWARD_TIMEOUT,
        Some(Some(left)) => left.min(crate::fabric_marketplace::FABRIC_FORWARD_TIMEOUT),
        Some(None) => {
            channel_warn!(config_id, "💳 Caller deadline elapsed before Agent Pay was asked — 504");
            return Err(deadline_elapsed(None));
        }
    };
    let agent_pay_headers = headers
        .into_iter()
        .flatten()
        .filter_map(|(name, value)| Some((name, value.as_str()?)))
        .filter(|(name, value)| super::payment_gate::is_relayed_header(name, value))
        .map(|(name, value)| (name.clone(), value.to_string()))
        .collect();
    match super::payment_gate::enforce(policy, agent_pay, method, path, agent_pay_headers, body_bytes, timeout).await {
        PaymentDecision::Proceed { receipt_headers } => {
            channel_info!(config_id, "💳 Agent Pay accepted the payment");
            Ok(Some(receipt_headers))
        }
        PaymentDecision::Challenge { status, headers, body } => {
            channel_info!(config_id, "💳 Payment required: returning the Agent Pay challenge ({})", status);
            Err(ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: serde_json::json!({
                    "status": status,
                    "headers": headers,
                    "body": body,
                }),
            })
        }
        PaymentDecision::Refuse { status, reason } => {
            channel_warn!(config_id, "💳 Payment enforcement refused the request: {}", reason);
            let json_rpc = crate::protocols::channel_protocol_family(&surface.channel_protocol()).is_some();
            let request_id = crate::gateways::connection_points::forward_errors::extract_json_rpc_id(body_bytes);
            Err(ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: crate::gateways::connection_points::forward_errors::safe_forward_error(
                    status,
                    "Payment could not be verified",
                    json_rpc,
                    request_id,
                ),
            })
        }
    }
}

/// `headers` of a charged request's response with every receipt header the
/// target set removed and Agent Pay's `receipts` added in place of any header of
/// the same name (in any case), so only Agent Pay can supply a receipt.
/// Unchanged when the request was not charged (`receipts` is `None`).
fn with_payment_receipts(
    mut headers: std::collections::HashMap<String, String>,
    receipts: Option<std::collections::HashMap<String, String>>,
) -> std::collections::HashMap<String, String> {
    let Some(receipts) = receipts else {
        return headers;
    };
    headers.retain(|name, _| {
        !super::payment_gate::is_receipt_header(name)
            && !receipts
                .keys()
                .any(|receipt| receipt.eq_ignore_ascii_case(name))
    });
    headers.extend(receipts);
    headers
}

/// A `ForwardResponse` body with the receipt headers of a charged request, so a
/// caller whose request fails after it has paid can still prove the payment.
fn error_with_payment_receipts(
    mut response: Value,
    receipts: Option<std::collections::HashMap<String, String>>,
) -> Value {
    if receipts.is_some() {
        let headers = serde_json::from_value(response["headers"].take()).unwrap_or_default();
        response["headers"] = serde_json::json!(with_payment_receipts(headers, receipts));
    }
    response
}

/// Time left before `deadline_ms` (Unix milliseconds), or `None` once it has passed.
fn time_left(deadline_ms: u64) -> Option<std::time::Duration> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    deadline_ms
        .checked_sub(now_ms)
        .filter(|left| *left > 0)
        .map(std::time::Duration::from_millis)
}

/// Whether a request reads the surface's own discovery document, which is never
/// charged: a public read of a root discovery path, or any public read when the
/// surface serves its agent card from a configured location (every such read
/// then fetches that card). A target route that only ends like a discovery
/// document is charged.
fn is_free_discovery_read(
    surface: &crate::config::agent_surface::AgentSurface,
    method: &str,
    path: &str,
) -> bool {
    crate::proxy::paths::is_public_request(method, path)
        && (crate::proxy::paths::is_root_discovery_document(path)
            || surface.override_agent_card_location()
                && surface
                    .agent_card_location_path()
                    .is_some())
}

/// The caller's body as Agent Pay may see it. On a surface that strips the raw
/// identity from MCP `_meta` before the target sees it, Agent Pay gets the same
/// stripped body, and an empty one when the strip cannot be done (the target is
/// then refused too).
fn body_for_agent_pay(
    surface: &crate::config::agent_surface::AgentSurface,
    managed_identity: Option<&crate::source_auth::ManagedIdentityConfig>,
    body: bytes::Bytes,
) -> bytes::Bytes {
    let Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(pe)) = managed_identity else {
        return body;
    };
    if surface.channel_protocol() != crate::config::ChannelProtocol::Mcp || !pe.strip_raw_meta {
        return body;
    }
    if pe.meta_field.is_empty() {
        return bytes::Bytes::new();
    }
    match crate::protocols::strip_raw_identity_from_meta(&body, &pe.meta_field) {
        crate::protocols::MetaStripOutcome::Removed(stripped) => stripped,
        crate::protocols::MetaStripOutcome::Nothing => body,
        _ => bytes::Bytes::new(),
    }
}

/// The `504` for a request whose caller deadline passed before it was sent on.
fn deadline_elapsed(receipts: Option<std::collections::HashMap<String, String>>) -> ProcessingResult {
    ProcessingResult::RequiresResponse {
        response_type: MessageType::ForwardResponse.to_string(),
        response_body: error_with_payment_receipts(
            serde_json::json!({
                "status": 504,
                "error": "Caller deadline elapsed before GW2 dispatched the upstream request",
            }),
            receipts,
        ),
    }
}

async fn process_forward_request(message: &ReceivedMessage) -> ProcessingResult {
    forward_request(message, &ForwardDependencies::from_process()).await
}

async fn forward_request(
    message: &ReceivedMessage,
    deps: &ForwardDependencies,
) -> ProcessingResult {
    use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};
    use tracing::Instrument;

    // Extract channel_id early for span creation
    let channel_id = message
        .message_body
        .get("channel_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let trace_id_field = message
        .message_body
        .get("trace_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract and parse OpenTelemetry parent context from GW1 BEFORE creating the span
    let parent_context = if let Some(otel_ctx) = message
        .message_body
        .get("otel_context")
    {
        info!("📊 GW2: Received otel_context from GW1: {:?}", otel_ctx);

        if let (Some(trace_id_str), Some(span_id_str), Some(trace_flags)) = (
            otel_ctx
                .get("trace_id")
                .and_then(|v| v.as_str()),
            otel_ctx
                .get("span_id")
                .and_then(|v| v.as_str()),
            otel_ctx
                .get("trace_flags")
                .and_then(|v| v.as_u64()),
        ) {
            info!(
                "📊 GW2: Parsing OTel context - trace_id: {}, span_id: {}, flags: {}",
                trace_id_str, span_id_str, trace_flags
            );

            if let (Ok(trace_id), Ok(span_id)) = (TraceId::from_hex(trace_id_str), SpanId::from_hex(span_id_str)) {
                let remote_context = SpanContext::new(
                    trace_id,
                    span_id,
                    TraceFlags::new(trace_flags as u8),
                    true,
                    TraceState::default(),
                );

                info!("📊 GW2: Created remote SpanContext for parent linkage");
                Some(opentelemetry::Context::current().with_remote_span_context(remote_context))
            } else {
                warn!("📊 GW2: Failed to parse trace_id or span_id from hex strings");
                None
            }
        } else {
            warn!("📊 GW2: otel_context missing required fields (trace_id, span_id, or trace_flags)");
            None
        }
    } else {
        info!("📊 GW2: No otel_context in message body");
        None
    };

    // Create span manually with parent context attached from the start
    let span = if let Some(ref parent_cx) = parent_context {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        info!("📊 GW2: Creating fabric.forward_request span with parent context");
        let span = tracing::info_span!(
            "fabric.forward_request",
            channel_id = channel_id,
            trace_id = trace_id_field,
            from_did = ?message.from_did,
            msg.id = %message.didcomm_message_id,
            otel.kind = "server"
        );
        let _ = span.set_parent(parent_cx.clone());

        // Log span details for debugging
        use opentelemetry::trace::TraceContextExt;
        let otel_context = span.context();
        let span_ref = otel_context.span();
        let span_ctx = span_ref.span_context();
        info!(
            "📊 GW2: Span created - trace_id: {}, span_id: {}, sampled: {}",
            span_ctx.trace_id(),
            span_ctx.span_id(),
            span_ctx.is_sampled()
        );

        span
    } else {
        tracing::info_span!(
            "fabric.forward_request",
            channel_id = channel_id,
            trace_id = trace_id_field,
            from_did = ?message.from_did,
            msg.id = %message.didcomm_message_id,
            otel.kind = "server"
        )
    };

    // Execute the rest of the function within the span context
    async move {
        info!("📥 Received forward-request from {:?}", message.from_did);

    if channel_id.is_empty() {
        warn!("Invalid forward-request: Missing channel_id");
        let error_body = serde_json::json!({
            "error": "Missing channel_id in forward-request",
            "status": 400,
        });
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: error_body,
        };
    }

    // Extract request details
    let method = message
        .message_body
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET");
    let path = message
        .message_body
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    let headers = message
        .message_body
        .get("headers")
        .and_then(|v| v.as_object())
        .cloned();

    // Extract body from DIDComm message - it's stored as a JSON value, not a string
    let body_bytes = match message.message_body.get("body") {
        Some(serde_json::Value::String(s)) => {
            // Legacy: body stored as string
            bytes::Bytes::from(s.clone())
        }
        Some(val) if !val.is_null() => {
            // New: body stored as JSON value, serialize it back to bytes
            bytes::Bytes::from(serde_json::to_vec(val).unwrap_or_default())
        }
        _ => bytes::Bytes::new(),
    };

    info!(
        "📤 Forwarding {} {} to channel {} (headers: {}, body: {} bytes)",
        method,
        path,
        channel_id,
        headers.as_ref().map(|h| h.len()).unwrap_or(0),
        body_bytes.len()
    );

    debug!("  ↳ Received path from gateway 1: '{}'", path);

    // Resolve the target channel from the cached store (no per-request disk reload).
    let surface = match lookup_channel(message, channel_id).await {
        Ok(Some(ch)) => ch,
        Ok(None) => {
            // Log the internal channel id; the caller gets only a generic 404.
            warn!("Channel {} not found", channel_id);
            let json_rpc =
                crate::protocols::detect_request_protocol_family(&body_bytes).is_some();
            let request_id = crate::gateways::connection_points::forward_errors::extract_json_rpc_id(&body_bytes);
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: crate::gateways::connection_points::forward_errors::safe_forward_error(
                    404,
                    "Requested target was not found",
                    json_rpc,
                    request_id,
                ),
            };
        }
        Err(e) => {
            // Log the resolve error internally; do not echo it (or the channel
            // id) to the caller.
            warn!("Failed to resolve channel {}: {}", channel_id, e);
            let json_rpc =
                crate::protocols::detect_request_protocol_family(&body_bytes).is_some();
            let request_id = crate::gateways::connection_points::forward_errors::extract_json_rpc_id(&body_bytes);
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: crate::gateways::connection_points::forward_errors::safe_forward_error(
                    502,
                    "Unable to resolve the requested target",
                    json_rpc,
                    request_id,
                ),
            };
        }
    };

    // Extract config_id for channel-specific logging
    let config_id = surface.config_id().unwrap_or("unknown");

    // Apply virtual channel variant override if specified by GW1
    let variant_alias = message
        .message_body
        .get("virtual_channel_alias")
        .or_else(|| message.message_body.get("active_variant_alias"))
        .and_then(|v| v.as_str());

    let surface = match surface.resolve_variant(variant_alias) {
        Ok(s) => {
            if let Some(alias) = variant_alias {
                channel_info!(config_id, "GW2: Applied variant '{}'", alias);
            }
            s
        }
        // A disabled variant is a disabled transit target and must reject
        // consistently with a disabled surface (503) — never silently degrade to
        // the default, which would serve a target the operator turned off.
        Err(crate::config::agent_surface_variants::VariantResolveError::DisabledVariant(alias)) => {
            channel_warn!(
                config_id,
                "GW2: Variant '{}' is disabled; rejecting request",
                alias
            );
            let json_rpc =
                crate::protocols::channel_protocol_family(&surface.channel_protocol()).is_some();
            let request_id = crate::gateways::connection_points::forward_errors::extract_json_rpc_id(&body_bytes);
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: crate::gateways::connection_points::forward_errors::safe_forward_error(
                    503,
                    "Requested variant is not active",
                    json_rpc,
                    request_id,
                ),
            };
        }
        // Unknown alias / misconfigured default are not operator "off" signals —
        // preserve the existing fall-back to the surface default.
        Err(e) => {
            channel_warn!(
                config_id,
                "GW2: Variant '{}' not found ({}), using default",
                variant_alias.unwrap_or(""),
                e
            );
            surface.resolve_variant(None).unwrap_or_else(|_| surface.clone())
        }
    };

    // Check if channel is active
    if surface.status != crate::config::agent_surface::SurfaceStatus::Enabled {
        channel_warn!(
            config_id,
            "Channel {} is not active (status: {:?})",
            channel_id,
            surface.status
        );
        let json_rpc =
            crate::protocols::channel_protocol_family(&surface.channel_protocol()).is_some();
        let request_id = crate::gateways::connection_points::forward_errors::extract_json_rpc_id(&body_bytes);
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: crate::gateways::connection_points::forward_errors::safe_forward_error(
                503,
                "Target is not active",
                json_rpc,
                request_id,
            ),
        };
    }

    // ── Protocol boundary checks (Gateway interoperability, not a runtime) ──────
    // Agent Stream does not own A2A/MCP runtime behaviour; it only forwards traffic to
    // a Gateway target. Reject requests that cannot be safely forwarded *before*
    // any upstream dial: a JSON-RPC shape that contradicts the surface's declared
    // protocol, an unsupported target scheme, or an unknown HTTP method.
    {
        let boundary_protocol = surface.channel_protocol();
        let boundary_family = crate::protocols::channel_protocol_family(&boundary_protocol);
        if let Some(rejection) = crate::gateways::connection_points::forward_errors::evaluate_forward_boundary(
            boundary_family,
            &body_bytes,
            surface.target_endpoint(),
            method,
        ) {
            channel_warn!(
                config_id,
                "Rejecting forward request at boundary ({}): {}",
                rejection.status,
                rejection.message
            );
            let request_id = crate::gateways::connection_points::forward_errors::extract_json_rpc_id(&body_bytes);
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: crate::gateways::connection_points::forward_errors::safe_forward_error(
                    rejection.status,
                    rejection.message,
                    boundary_family.is_some(),
                    request_id,
                ),
            };
        }
    }

    // A public discovery read is a read: nothing past this point reads its body,
    // so no caller identity is extracted or stored from it.
    let is_agent_card_request = crate::proxy::paths::is_public_request(method, path);
    let body_bytes = if is_agent_card_request && !body_bytes.is_empty() {
        channel_info!(config_id, "  ↳ Dropping the {} byte body of a public discovery read", body_bytes.len());
        bytes::Bytes::new()
    } else {
        body_bytes
    };

    // ── Unified source authentication ──────────────────────────────────────────
    let authenticated_identity = match Box::pin(authenticate_fabric_caller(
        &surface,
        config_id,
        method,
        path,
        headers.as_ref(),
        &body_bytes,
        deps.source_auth.as_deref(),
    ))
    .await
    {
        Ok(identity) => identity,
        Err(result) => return result,
    };

    let managed_id = surface.managed_identity();
    let identity_ext_rules = managed_id.as_ref().and_then(|mi| match mi {
        crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg.extension_rules.as_ref(),
        _ => None,
    });
    let InboundCallerIdentity {
        identity: caller_identity,
        binding: identity_binding,
    } = Box::pin(extract_caller_identity_inbound(
        &surface,
        channel_id,
        config_id,
        &body_bytes,
        identity_ext_rules,
        deps.vc_issuer.as_ref(),
        envelope_challenge(message),
    ))
    .await;
    let verified_caller_did = verified_caller_did(identity_binding.as_ref());

    let agent_pay_body = body_for_agent_pay(&surface, managed_id.as_ref(), body_bytes.clone());
    let mut body_bytes = match Box::pin(enrich_and_evaluate_policies(
        &deps.appliance_policies,
        &surface,
        channel_id,
        config_id,
        method,
        path,
        body_bytes,
        headers.as_ref(),
        message.from_did.clone(),
        caller_identity.as_ref(),
        identity_binding,
        authenticated_identity.as_ref(),
        variant_alias,
    ))
    .await
    {
        Ok(bytes) => bytes,
        Err(result) => return result,
    };

    // Derived variables used by the forwarding and response-processing code below.
    let surface_protocol = surface.channel_protocol();
    let outbound_creds = surface.outbound_credentials();
    let active_variant_alias = variant_alias.map(|s| s.to_string());
    let resolved_surface = surface.clone();
    let deadline_ms: Option<u64> = message
        .message_body
        .get("deadline_ms")
        .and_then(|v| v.as_u64());
    let charge = || {
        Box::pin(enforce_payment(
            &surface,
            config_id,
            method,
            path,
            headers.as_ref(),
            &agent_pay_body,
            deps.agent_pay.as_deref(),
            deadline_ms,
        ))
    };

    // Forward the request to the channel's target endpoint
    channel_info!(
        config_id,
        "🎯 Forwarding to channel target: {}",
        surface.target_endpoint()
    );

    // Check if this channel uses an embedded marketplace backend
    if surface.target_endpoint() == "embedded://marketplace" {
        channel_info!(config_id, "🛒 Channel uses embedded marketplace backend");

        let marketplace_models_path = message
            .context
            .get("marketplace_models_path")
            .and_then(|v| v.as_str())
            .unwrap_or("config/marketplace-models.json");

        let payment_receipt_headers = match charge().await {
            Ok(receipt_headers) => receipt_headers,
            Err(result) => return result,
        };
        let response = crate::embedded_marketplace::handle_embedded_marketplace(
            marketplace_models_path,
            method,
            path,
        )
        .await;

        return ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: serde_json::json!({
                "status": response.status,
                "body": response.body,
                "headers": with_payment_receipts(response.headers, payment_receipt_headers),
            }),
        };
    }

    // Build the target URL (path includes query params if present)
    // When override_agent_card_location is enabled and this is an agent card request,
    // use the custom path relative to the target's origin (scheme + host + port),
    // stripping any sub-path from target_endpoint.
    let target_url = if is_agent_card_request
        && surface.override_agent_card_location()
        && surface.agent_card_location_path().is_some()
    {
        let custom_path = surface.agent_card_location_path().unwrap();
        let target_endpoint = surface.target_endpoint();
        let origin = if let Some(scheme_end) = target_endpoint.find("://") {
            let after_scheme = &target_endpoint[scheme_end + 3..];
            let authority_end = after_scheme.find('/').unwrap_or(after_scheme.len());
            &target_endpoint[..scheme_end + 3 + authority_end]
        } else {
            target_endpoint
        };
        let url = if custom_path.starts_with('/') {
            format!("{}{}", origin, custom_path)
        } else {
            format!("{}/{}", origin, custom_path)
        };
        channel_info!(
            config_id,
            "Agent card location override applied: {} (origin={}, custom_path={})",
            url, origin, custom_path
        );
        url
    } else {
        let url = fabric_target_url(surface.target_endpoint(), path);
        if let Some(rejection) =
            crate::gateways::connection_points::forward_errors::evaluate_forward_target(surface.target_endpoint(), &url)
        {
            channel_warn!(config_id, "Refusing fabric forward: the request path leaves the target endpoint");
            let json_rpc = crate::protocols::channel_protocol_family(&surface.channel_protocol()).is_some();
            let request_id = crate::gateways::connection_points::forward_errors::extract_json_rpc_id(&body_bytes);
            return ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: crate::gateways::connection_points::forward_errors::safe_forward_error(
                    rejection.status,
                    rejection.message,
                    json_rpc,
                    request_id,
                ),
            };
        }
        url
    };

    channel_info!(
        config_id,
        "🌐 Making HTTP request: {} {}",
        method.to_uppercase(),
        crate::url_validation::redact_url_for_logging(&target_url)
    );

    // reqwest does not resolve an IP-literal target, so the shared client's
    // ForwardingDnsResolver never sees one: refuse a cloud metadata target here.
    if let Err(e) = crate::url_validation::reject_cloud_metadata_url(&target_url) {
        channel_warn!(config_id, "Refusing fabric forward: {}", e);
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: serde_json::json!({
                "status": 502,
                "error": "Target endpoint is not allowed",
            }),
        };
    }

    // Start timer for latency measurement
    let start_time = std::time::Instant::now();

    // Reuse the pooled global HTTP client so we don't pay the connection /
    // TLS-handshake cost on every fabric forward.
    let Some(client) = fabric_http_client() else {
        return ProcessingResult::RequiresResponse {
            response_type: MessageType::ForwardResponse.to_string(),
            response_body: serde_json::json!({
                "status": 502,
                "error": "Target endpoint is not reachable",
            }),
        };
    };

    // Build the request
    let http_method = match method.to_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let mut req = client.request(http_method.clone(), &target_url);

    // Track if content-type was set
    let mut has_content_type = false;

    // Determine the source-auth credential header to strip (must not leak upstream).
    let source_cred_header = surface.source_auth().and_then(|sa| sa.credential_header_name());

    // Add headers if provided
    if let Some(ref headers_map) = headers {
        channel_info!(config_id, "  ↳ Adding {} headers", headers_map.len());
        for (key, value) in forwarded_headers(headers_map, source_cred_header, is_agent_card_request) {
            if key.eq_ignore_ascii_case("content-type") {
                has_content_type = true;
            }
            channel_info!(config_id, "    Header: {}: {}", key, value);
            req = req.header(key, value);
        }
    } else {
        channel_info!(config_id, "  ↳ No headers to add");
    }

    let send_upstream_credentials = may_send_upstream_credentials(&surface, authenticated_identity.as_ref());
    if !send_upstream_credentials && (surface.target_auth().is_some() || !outbound_creds.is_empty()) {
        channel_info!(
            config_id,
            "No caller identity on a source-authenticated surface; forwarding without upstream credentials"
        );
    }

    // Inject target authentication credentials (if configured on the channel)
    if let Some(target_auth) = surface
        .target_auth()
        .filter(|_| send_upstream_credentials)
    {
        // Build a secrets store from the storage path passed via message context
        let secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>> = match message
            .context
            .get("secrets_storage_path")
            .and_then(|v| v.as_str())
        {
            Some(path) => match crate::secrets::FilesystemSecretsStore::new_async(path).await {
                Ok(store) => Some(Arc::new(store) as Arc<dyn crate::secrets::SecretsStore>),
                Err(e) => {
                    channel_warn!(config_id, "Failed to create secrets store for target auth: {}", e);
                    None
                }
            },
            None => {
                channel_warn!(config_id, "No secrets_storage_path in message context for target auth");
                None
            }
        };

        match crate::proxy::handler::inject_target_auth_header(target_auth, &secrets_store, &surface.name).await {
            Ok(Some((header_name, header_value))) => {
                req = req.header(&header_name, &header_value);
                channel_info!(config_id, "Injected target authentication header: {}", header_name);
            }
            Ok(None) => {
                // CredentialLookup method not implemented, skip
            }
            Err(e) => {
                channel_error!(config_id, "Failed to resolve target authentication: {}", e);
                match target_auth.fallback {
                    crate::config::TargetAuthFallback::Reject => {
                        return ProcessingResult::RequiresResponse {
                            response_type: MessageType::ForwardResponse.to_string(),
                            response_body: serde_json::json!({
                                "status": 502,
                                "error": "Target authentication configuration error",
                            }),
                        };
                    }
                    crate::config::TargetAuthFallback::Passthrough => {
                        channel_warn!(
                            config_id,
                            "Target auth failed but passthrough enabled, continuing without credentials"
                        );
                    }
                }
            }
        }
    }

    // Inject custom metadata for MCP protocol
    if surface_protocol == crate::config::ChannelProtocol::Mcp
        && let Some(custom_metadata) = surface.custom_metadata()
        && custom_metadata.enabled
    {
        use crate::config::MetadataInjectionTarget;
        let injection_target = custom_metadata
            .injection_target
            .as_ref()
            .unwrap_or(&MetadataInjectionTarget::Both);

        // Inject into HTTP headers if requested
        if (*injection_target == MetadataInjectionTarget::Headers
            || *injection_target == MetadataInjectionTarget::Both)
            && let Some(ref payload) = custom_metadata.payload
            && let Some(payload_obj) = (payload as &serde_json::Value).as_object()
        {
            for (key, value) in payload_obj {
                let header_name = format!("X-Gateway-{}", key.replace("_", "-"));
                if let Some(value_str) = value.as_str() {
                    req = req.header(&header_name, value_str);
                    channel_info!(
                        config_id,
                        "Injected custom metadata to HTTP header: {}",
                        header_name
                    );
                }
            }
            channel_info!(
                config_id,
                "Custom metadata injected as HTTP headers for MCP request"
            );
        }

        // Inject into JSON-RPC _meta field if requested
        if (*injection_target == MetadataInjectionTarget::Meta
            || *injection_target == MetadataInjectionTarget::Both)
            && let Ok(mut json_body) = serde_json::from_slice::<serde_json::Value>(&body_bytes)
            && let Some(obj) = json_body.as_object_mut()
        {
            // Get or create _meta field
            let meta = obj.entry("_meta").or_insert(serde_json::json!({}));
            if let Some(meta_obj) = meta.as_object_mut() {
                // Inject custom metadata into _meta
                if let Some(ref payload) = custom_metadata.payload
                    && let Some(payload_obj) = (payload as &serde_json::Value).as_object()
                {
                    for (key, value) in payload_obj {
                        meta_obj.insert(key.clone(), value.clone());
                        channel_info!(
                            config_id,
                            "GW2: Injected custom metadata to _meta field: {}",
                            key
                        );
                    }
                }
            }
            // Update the body bytes with modified JSON
            if let Ok(new_body) = serde_json::to_vec(&json_body) {
                body_bytes = bytes::Bytes::from(new_body);
                channel_info!(
                    config_id,
                    "GW2: Custom metadata injected into _meta field for MCP request"
                );
            }
        }
    }

    // ── Strip raw identity from the forwarded MCP request `_meta` ──
    // Once the caller identity has been extracted above, a surface configured
    // with `strip_raw_meta` must not forward the raw identity block to the
    // target alongside the verified credential. Scoped to the MCP surface: only
    // MCP request egress parses/rewrites `_meta`, so other protocols (A2A/
    // DIDComm) are never subject to the parse/size rejections below.
    if surface_protocol == crate::config::ChannelProtocol::Mcp
        && let Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(pe)) =
            managed_id.as_ref()
        && pe.strip_raw_meta
    {
        if pe.meta_field.is_empty() {
            // Misconfiguration: redaction requested but no field configured to
            // strip. Nothing can be redacted, so forwarding would leak the raw
            // identity block — fail closed (like the parse/size paths below)
            // rather than warn and forward on a redaction-enabled surface.
            channel_warn!(
                config_id,
                "GW2: strip_raw_meta enabled but meta_field is empty — refusing to forward (fail closed) [channel_id={} trace_id={}]",
                channel_id,
                trace_id_field
            );
            return ProcessingResult::Failed {
                reason: "strip_raw_meta misconfigured: empty meta_field on a redaction-enabled surface".to_string(),
            };
        } else {
            match crate::protocols::strip_raw_identity_from_meta(&body_bytes, &pe.meta_field) {
                crate::protocols::MetaStripOutcome::Removed(stripped) => {
                    channel_info!(
                        config_id,
                        "GW2: Stripped raw identity '{}' from MCP request _meta (strip_raw_meta) [channel_id={} trace_id={}]",
                        pe.meta_field,
                        channel_id,
                        trace_id_field
                    );
                    body_bytes = stripped;
                }
                crate::protocols::MetaStripOutcome::Nothing => {
                    // No raw identity field present to strip — benign.
                }
                crate::protocols::MetaStripOutcome::MetaNotObject => {
                    // `_meta` present but non-object: malformed for MCP and defeats
                    // the redaction guarantee. Fail closed rather than forward.
                    channel_warn!(
                        config_id,
                        "GW2: strip_raw_meta enabled but request _meta is not an object — refusing to forward (fail closed) [channel_id={} trace_id={}]",
                        channel_id,
                        trace_id_field
                    );
                    return ProcessingResult::Failed {
                        reason: "malformed MCP _meta (non-object) on a redaction-enabled surface".to_string(),
                    };
                }
                crate::protocols::MetaStripOutcome::ParseFailed => {
                    // Body could not be parsed/redacted: redaction cannot be
                    // verified, so do not forward the original (potentially
                    // identity-bearing) body. Fail closed.
                    channel_warn!(
                        config_id,
                        "GW2: strip_raw_meta enabled but request body failed to parse/redact — refusing to forward (fail closed) [channel_id={} trace_id={}]",
                        channel_id,
                        trace_id_field
                    );
                    return ProcessingResult::Failed {
                        reason: "malformed MCP body on a redaction-enabled surface".to_string(),
                    };
                }
                crate::protocols::MetaStripOutcome::BodyTooLarge => {
                    // Body exceeds the redaction parse bound. Reject rather than
                    // parse+re-serialize it — defense-in-depth against resource
                    // exhaustion on the fabric-forward path.
                    channel_warn!(
                        config_id,
                        "GW2: strip_raw_meta enabled but request body exceeds {} bytes — refusing to forward (fail closed) [channel_id={} trace_id={}]",
                        crate::protocols::MAX_REDACTION_BODY_BYTES,
                        channel_id,
                        trace_id_field
                    );
                    return ProcessingResult::Failed {
                        reason: "MCP body too large on a redaction-enabled surface".to_string(),
                    };
                }
            }
        }
    }

    // ── Credential delegation: inject delegated OAuth tokens or signal consent ──
    if send_upstream_credentials && !outbound_creds.is_empty() {
        let delegation_user_hash =
            delegation_user_hash(verified_caller_did.as_deref(), authenticated_identity.as_ref());

        if let (Some(user_hash), Some(stores)) = (&delegation_user_hash, &deps.delegation) {
            channel_info!(
                config_id,
                "GW2: Resolving credential delegation for {} bindings (user_hash={})",
                outbound_creds.len(),
                &user_hash[..8.min(user_hash.len())]
            );

            let delegation_results =
                crate::proxy::credential_delegation::resolve_delegation_credentials(
                    &outbound_creds,
                    user_hash,
                    surface.target_endpoint(),
                    config_id,
                    None, // MCP tool name not available in DIDComm path
                    &stores.vault,
                    &stores.providers,
                    &stores.secrets,
                    &stores.base_url,
                    true, // via_fabric = true (G2G path)
                    Some(&crate::proxy::credential_delegation::DelegationAuditContext {
                        tenant_id: surface.tenant_id.clone(),
                        ..Default::default()
                    }),
                )
                .await;

            // Check for consent_required — if any binding needs consent, return immediately as ForwardResponse
            let mut consent_entries = Vec::new();
            for resolution in &delegation_results {
                if let crate::proxy::credential_delegation::DelegationLookupResult::ConsentRequired {
                    authorization_url,
                    provider_name,
                    scopes,
                } = resolution
                {
                    consent_entries.push(serde_json::json!({
                        "provider_name": provider_name,
                        "authorization_url": authorization_url,
                        "scopes": scopes,
                    }));
                }
            }

            if !consent_entries.is_empty() {
                channel_info!(
                    config_id,
                    "GW2: Credential delegation requires consent for {} providers — returning consent_required via DIDComm",
                    consent_entries.len()
                );
                let consent_body = serde_json::json!({
                    "type": "https://affinidi.com/atg/errors/consent-required",
                    "title": "Credential Delegation Consent Required",
                    "status": 401,
                    "detail": "This channel requires delegated credentials. The user must authorize access via the provided URLs.",
                    "consent_required": consent_entries,
                });
                return ProcessingResult::RequiresResponse {
                    response_type: MessageType::ForwardResponse.to_string(),
                    response_body: serde_json::json!({
                        "status": 401,
                        "headers": {
                            "content-type": "application/problem+json",
                        },
                        "body": consent_body.to_string(),
                    }),
                };
            }

            // Inject delegated credential headers into the upstream request
            for resolution in &delegation_results {
                if let crate::proxy::credential_delegation::DelegationLookupResult::Inject(
                    headers,
                ) = resolution
                {
                    for (name, value) in headers {
                        req = req.header(name, value);
                        channel_info!(
                            config_id,
                            "GW2: Injected delegated credential header: {}",
                            name
                        );
                    }
                }
            }
        } else {
            channel_warn!(
                config_id,
                "GW2: Credential delegation configured but stores or a verified caller identity are not available — skipping"
            );
        }
    }

    // Add body if provided and not empty
    let request_bytes = body_bytes.len() as u64;
    if !body_bytes.is_empty() {
        channel_info!(
            config_id,
            "  ↳ Adding request body: {} bytes",
            body_bytes.len()
        );
        // Ensure Content-Type is set BEFORE adding body
        if !has_content_type {
            req = req.header("Content-Type", "application/json");
        }

        // Use String - reqwest will automatically set correct Content-Length
        req = req.body(String::from_utf8_lossy(&body_bytes).to_string());
    } else {
        channel_info!(config_id, "  ↳ No request body");
    }

    // Send the request
    channel_debug!(
        config_id,
        "Sending request to {}",
        crate::url_validation::redact_url_for_logging(&target_url)
    );

    let payment_receipt_headers = match charge().await {
        Ok(receipt_headers) => receipt_headers,
        Err(result) => return result,
    };

    // Apply the caller-deadline as a hard reqwest timeout so a hung upstream
    // cannot keep the dispatch task alive past the caller's wait window.
    if let Some(deadline) = deadline_ms {
        match time_left(deadline) {
            Some(remaining) => {
                req = req.timeout(remaining);
            }
            None => {
                channel_warn!(config_id, "Deadline already elapsed at reqwest dispatch (deadline={deadline}ms) — 504");
                return deadline_elapsed(payment_receipt_headers);
            }
        }
    }

    match req.send().await {
        Ok(response) => {
            // Start response timer (measures response processing time)
            let response_start = std::time::Instant::now();
            let status = response.status().as_u16();

            // Filter out hop-by-hop headers and content-length that should not be forwarded
            // content-length will be set automatically by the HTTP layer based on actual body
            let response_headers: std::collections::HashMap<String, String> = response
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    let key_lower = k.as_str().to_lowercase();

                    // Skip hop-by-hop headers and content-length
                    if key_lower == "transfer-encoding"
                        || key_lower == "connection"
                        || key_lower == "keep-alive"
                        || key_lower == "proxy-authenticate"
                        || key_lower == "proxy-authorization"
                        || key_lower == "te"
                        || key_lower == "trailers"
                        || key_lower == "upgrade"
                        || key_lower == "content-length"
                    // Skip content-length - will be set by HTTP layer
                    {
                        None
                    } else {
                        v.to_str()
                            .ok()
                            .map(|v| (k.as_str().to_string(), v.to_string()))
                    }
                })
                .collect();

            let mut response_body = response.text().await.unwrap_or_else(|_| String::new());
            let mut body_modified = false;

            // Inject response custom metadata if enabled (separate from request metadata)
            if !response_body.is_empty()
                && let Some(response_custom_metadata) = surface.response_custom_metadata()
                && response_custom_metadata.enabled
            {
                match surface_protocol {
                    crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::DIDComm => {
                        // For A2A protocol, inject into message.metadata
                        channel_info!(config_id, "GW2: Injecting response custom metadata (A2A)");
                        match crate::protocols::inject_custom_metadata_extension(
                            &bytes::Bytes::from(response_body.clone()),
                            response_custom_metadata,
                            channel_id,
                            &None,
                        )
                        .await
                        {
                            Ok(modified_body) => {
                                response_body = String::from_utf8_lossy(&modified_body).to_string();
                                body_modified = true;
                                channel_info!(
                                    config_id,
                                    "GW2: Response custom metadata extension injected (A2A)"
                                );
                            }
                            Err(e) => {
                                channel_warn!(
                                    config_id,
                                    "GW2: Failed to inject response custom metadata extension: {}",
                                    e
                                );
                            }
                        }
                    }
                    crate::config::ChannelProtocol::Mcp => {
                        // For MCP protocol, inject into _meta field
                        if let Ok(mut json_body) =
                            serde_json::from_str::<serde_json::Value>(&response_body)
                        {
                            use crate::config::MetadataInjectionTarget;
                            let injection_target = response_custom_metadata
                                .injection_target
                                .as_ref()
                                .unwrap_or(&MetadataInjectionTarget::Both);

                            if (*injection_target == MetadataInjectionTarget::Meta
                                || *injection_target == MetadataInjectionTarget::Both)
                                && let Some(payload) = &response_custom_metadata.payload
                                && let Some(payload_obj) = payload.as_object()
                                && let Some(obj) = json_body.as_object_mut()
                            {
                                let meta = obj.entry("_meta").or_insert(serde_json::json!({}));
                                if let Some(meta_obj) = meta.as_object_mut() {
                                    for (key, value) in payload_obj {
                                        meta_obj.insert(key.clone(), value.clone());
                                        channel_debug!(
                                            config_id,
                                            "GW2: Injected response custom metadata to _meta.{}",
                                            key
                                        );
                                    }
                                    channel_info!(
                                        config_id,
                                        "GW2: Response custom metadata injected into _meta field for MCP response"
                                    );
                                }
                            }

                            if let Ok(new_body) = serde_json::to_string(&json_body) {
                                response_body = new_body;
                                body_modified = true;
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Inject responding gateway DID for fabric-to-fabric connections
            // This allows tracking gateway-to-gateway communication in metrics
            // Use the actual gateway DID (not connection point DID) to avoid information leakage
            if !response_body.is_empty() {
                // Get the local gateway DID from the global VC issuer (if available)
                let local_gateway_did = if let Some(vc_issuer) = GLOBAL_VC_ISSUER.get() {
                    vc_issuer.get_issuer_did().await.ok()
                } else {
                    None
                };

                if let Some(gateway_did) = local_gateway_did
                    && let Ok(mut json_body) =
                        serde_json::from_str::<serde_json::Value>(&response_body)
                    && let Some(obj) = json_body.as_object_mut()
                {
                    let gateway_did_field = "x-affinidi-fabric-gateway-did";

                    match surface_protocol {
                        crate::config::ChannelProtocol::Mcp => {
                            // For MCP, inject into _meta field
                            let meta = obj.entry("_meta").or_insert(serde_json::json!({}));
                            if let Some(meta_obj) = meta.as_object_mut() {
                                meta_obj.insert(
                                    gateway_did_field.to_string(),
                                    serde_json::json!(gateway_did),
                                );
                                channel_debug!(
                                    config_id,
                                    "GW2: Injected responding gateway DID into _meta.{}: {}",
                                    gateway_did_field,
                                    gateway_did
                                );
                            }
                        }
                        crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::DIDComm => {
                            // For A2A, inject into result.history[0].metadata if it exists
                            // Otherwise inject into top-level metadata
                            if let Some(result) = obj.get_mut("result") {
                                if let Some(history) =
                                    result.get_mut("history").and_then(|h| h.as_array_mut())
                                    && let Some(first_msg) = history.first_mut()
                                    && let Some(msg_obj) = first_msg.as_object_mut()
                                {
                                    let metadata =
                                        msg_obj.entry("metadata").or_insert(serde_json::json!({}));
                                    if let Some(metadata_obj) = metadata.as_object_mut() {
                                        let did_array = metadata_obj
                                            .entry(gateway_did_field.to_string())
                                            .or_insert_with(|| serde_json::json!([]));

                                        if let Some(arr) = did_array.as_array_mut() {
                                            arr.push(serde_json::json!(gateway_did));
                                            channel_debug!(
                                                config_id,
                                                "GW2: Appended responding gateway DID to result.history[0].metadata.{} array: {}",
                                                gateway_did_field,
                                                gateway_did
                                            );
                                        } else {
                                            // If it exists but is not an array, convert it to array
                                            let existing_value = did_array.clone();
                                            *did_array =
                                                serde_json::json!([existing_value, gateway_did]);
                                            channel_debug!(
                                                config_id,
                                                "GW2: Converted result.history[0].metadata.{} to array and appended DID: {}",
                                                gateway_did_field,
                                                gateway_did
                                            );
                                        }
                                    }
                                }
                            } else if let Some(message) =
                                obj.get_mut("message").and_then(|m| m.as_object_mut())
                            {
                                // Fallback: inject into message.metadata
                                let metadata =
                                    message.entry("metadata").or_insert(serde_json::json!({}));
                                if let Some(metadata_obj) = metadata.as_object_mut() {
                                    metadata_obj.insert(
                                        gateway_did_field.to_string(),
                                        serde_json::json!(gateway_did),
                                    );
                                    channel_debug!(
                                        config_id,
                                        "GW2: Injected responding gateway DID into message.metadata.{}: {}",
                                        gateway_did_field,
                                        gateway_did
                                    );
                                }
                            }
                        }
                        _ => {}
                    }

                    // Update response_body with modified JSON
                    if let Ok(new_body) = serde_json::to_string(&json_body) {
                        response_body = new_body;
                        body_modified = true;
                        channel_info!(
                            config_id,
                            "GW2: Responding gateway DID injected into fabric response"
                        );
                    }
                }
            }

            // Update Content-Length header if body was modified
            // This prevents hyper panics due to Content-Length mismatch
            // NOTE: We don't actually need to set this header in response_headers
            // because when we return the response through DIDComm, the HTTP layer
            // will set Content-Length automatically based on the actual JSON payload size.
            // Including it here causes mismatches when the response is serialized to JSON.
            if body_modified {
                channel_debug!(
                    config_id,
                    "GW2: Body was modified (new length: {} bytes), Content-Length will be set automatically by HTTP layer",
                    response_body.len()
                );
            }

            channel_info!(config_id, "✅ Forward completed with status {}", status);

            // Broadcast payload capture if enabled
            if let Some(ws_state) = GLOBAL_WS_STATE.get()
                && let Some(metrics_store) = GLOBAL_METRICS_STORE.get()
            {
                let config_id = surface
                    .config_id()
                    .map(str::to_string)
                    .unwrap_or_else(|| channel_id.to_string());

                // Prepare request payload as JSON
                let request_payload: serde_json::Value = if !body_bytes.is_empty() {
                    // Try to parse as JSON, otherwise create synthetic JSON
                    serde_json::from_slice(&body_bytes).unwrap_or_else(|_| {
                        serde_json::json!({
                            "_raw_body": String::from_utf8_lossy(&body_bytes).to_string(),
                            "method": method.to_uppercase()
                        })
                    })
                } else {
                    // Create synthetic JSON for empty bodies like handler.rs does
                    serde_json::json!({
                        "method": method.to_uppercase(),
                        "_no_body": true
                    })
                };

                // Response payload as JSON
                let response_payload: Option<serde_json::Value> = if !response_body.is_empty() {
                    serde_json::from_str(&response_body).ok()
                } else {
                    Some(serde_json::json!({
                        "status": status,
                        "_no_body": true
                    }))
                };

                // Determine validation status based on HTTP status code
                let validation_status = if (200..300).contains(&status) {
                    "success"
                } else if (400..500).contains(&status) {
                    "client_error"
                } else if status >= 500 {
                    "server_error"
                } else {
                    "unknown"
                };

                // Broadcast the payload capture
                crate::observability::payload_capture::broadcast_payload_capture_async(
                    &Some(ws_state.clone()),
                    &Some(metrics_store.clone()),
                    channel_id,
                    &config_id,
                    &request_payload,
                    response_payload,
                    validation_status,
                    None,                    // validation_error
                    caller_identity.clone(), // identity_hash
                    active_variant_alias.as_deref(),
                )
                .await;

                channel_info!(config_id, "📡 Broadcast payload capture for fabric flow");
            }

            // GW2: Extract agent identity from response extensions (before metrics recording)
            let mut agent_identity: Option<String> = None;
            channel_info!(
                config_id,
                "GW2: Checking for agent identity extraction - has_identity_ext_rules: {}, response_empty: {}",
                identity_ext_rules.is_some(),
                response_body.is_empty()
            );

            if !response_body.is_empty() {
                // Try to extract agent identity from response
                if let Ok(response_json) = serde_json::from_str::<serde_json::Value>(&response_body)
                {
                    channel_info!(config_id, "GW2: Successfully parsed response as JSON");

                    // Build identity selector from managed_identity.extension_rules
                    let identity_selector = match (identity_ext_rules, GLOBAL_VC_ISSUER.get()) {
                        (None, _) => {
                            channel_info!(
                                config_id,
                                "GW2: Identity selector unavailable - no managed_identity.extension_rules on channel"
                            );
                            None
                        }
                        (_, None) => {
                            channel_info!(
                                config_id,
                                "GW2: Identity selector unavailable - GLOBAL_VC_ISSUER not initialized"
                            );
                            None
                        }
                        (Some(ext_rules), Some(vc_issuer)) => {
                            match &ext_rules.json_schema {
                                None => {
                                    channel_info!(
                                        config_id,
                                        "GW2: Identity selector unavailable - managed_identity.extension_rules has no json_schema"
                                    );
                                    None
                                }
                                Some(json_schema) => {
                                    match crate::identity::IdentitySelector::new(
                                        json_schema,
                                        vc_issuer.clone(),
                                    ) {
                                        Ok(selector) if selector.has_identity_fields() => {
                                            channel_info!(
                                                config_id,
                                                "GW2: Identity selector built from managed_identity.extension_rules"
                                            );
                                            Some(Arc::new(selector))
                                        }
                                        Ok(_) => {
                                            channel_info!(
                                                config_id,
                                                "GW2: Identity selector unavailable - schema has no x-identity fields"
                                            );
                                            None
                                        }
                                        Err(e) => {
                                            channel_info!(
                                                config_id,
                                                "GW2: Identity selector unavailable - schema compilation failed: {}",
                                                e
                                            );
                                            None
                                        }
                                    }
                                }
                            }
                        }
                    };

                    // Look for agent identity in response - extensions array contains URIs, data is in metadata
                    // Response structure can be either:
                    // - Multi-message: result.history[0].metadata[extension_uri]
                    // - Single message: result.metadata[extension_uri] (direct Message response)
                    let message_obj = response_json.get("result").and_then(|r| {
                        // Try history first (multi-message response)
                        if let Some(history) = r.get("history").and_then(|h| h.as_array()).and_then(|arr| arr.first()) {
                            info!("GW2: Found response in result.history[0]");
                            Some(history)
                        } else if r.get("metadata").is_some() || r.get("extensions").is_some() {
                            // Direct message response (single message completion)
                            info!("GW2: Found response directly in result");
                            Some(r)
                        } else {
                            warn!("GW2: Response has result but no history or metadata");
                            None
                        }
                    });

                    if let Some(message_msg) = message_obj {
                        if let Some(extensions) =
                            message_msg.get("extensions").and_then(|e| e.as_array())
                        {
                            channel_info!(
                                config_id,
                                "GW2: Found {} extension URIs in response",
                                extensions.len()
                            );

                            // Check if agent-identity extension is declared
                            let has_identity_ext = extensions.iter().any(|ext| {
                                ext.as_str()
                                    == Some(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION)
                            });

                            if has_identity_ext {
                                channel_info!(
                                    config_id,
                                    "GW2: Agent identity extension is declared in response"
                                );

                                // Get the actual extension data from metadata
                                if let Some(metadata) = message_msg.get("metadata") {
                                    if let Some(identity_ext) = metadata
                                        .get(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION)
                                    {
                                        channel_info!(
                                            config_id,
                                            "GW2: Found identity extension in response metadata: {}",
                                            serde_json::to_string_pretty(identity_ext)
                                                .unwrap_or_default()
                                                .chars()
                                                .take(500)
                                                .collect::<String>()
                                        );

                                        // Check if agent already sent a DID
                                        if let Some(did) =
                                            identity_ext.get("did").and_then(|d| d.as_str())
                                        {
                                            agent_identity = Some(did.to_string());
                                            channel_info!(
                                                config_id,
                                                "GW2: Agent identity from DID: {}",
                                                did
                                            );
                                        } else {
                                            // Agent sent raw payload - compute identity using IdentitySelector
                                            if let Some(ref selector) = identity_selector {
                                                channel_info!(
                                                    config_id,
                                                    "GW2: Computing agent identity using IdentitySelector"
                                                );
                                                match selector
                                                    .compute_identity(
                                                        identity_ext,
                                                        channel_id,
                                                        surface.config_id().map(str::to_string),
                                                    )
                                                    .await
                                                {
                                                    Ok(identity_result) => {
                                                        agent_identity =
                                                            Some(identity_result.did.clone());
                                                        channel_info!(
                                                            config_id,
                                                            "GW2: Agent identity computed: {} (is_new: {})",
                                                            identity_result.did,
                                                            identity_result.is_new
                                                        );

                                                        // Trigger identity.appeared if this is a new identity appearing on the channel
                                                        if identity_result.is_new
                                                            && let Some(notif_store) =
                                                                GLOBAL_NOTIFICATION_STORE.get()
                                                        {
                                                            let did_clone =
                                                                identity_result.did.clone();
                                                            let channel_id_clone =
                                                                channel_id.to_string();
                                                            let notif = (*notif_store).clone();
                                                            tokio::spawn(async move {
                                                                crate::integrations::async_triggers::trigger_identity_appeared(
                                                                        Some(notif.clone()),
                                                                        &did_clone,
                                                                        &channel_id_clone,
                                                                    ).await;
                                                            });
                                                        }
                                                    }
                                                    Err(e) => {
                                                        channel_warn!(
                                                            config_id,
                                                            "GW2: Failed to compute agent identity: {}",
                                                            e
                                                        );
                                                    }
                                                }
                                            }

                                            if agent_identity.is_none() {
                                                channel_info!(
                                                    config_id,
                                                    "GW2: No IdentitySelector available for response, using peppered identity hash fallback"
                                                );
                                                let identity_value = identity_ext
                                                    .get("agentIdentity")
                                                    .or_else(|| identity_ext.get("agentId"))
                                                    .or_else(|| identity_ext.get("id"))
                                                    .or_else(|| identity_ext.get("agent_id"))
                                                    .cloned()
                                                    .unwrap_or_else(|| identity_ext.clone());

                                                let hash_str = crate::identity::calculate_identity_hash(&serde_json::json!({
                                                    "agent_identity": identity_value,
                                                }));
                                                agent_identity = Some(hash_str.clone());
                                                channel_info!(
                                                    config_id,
                                                    "GW2: Agent identity computed from peppered hash: {}",
                                                    hash_str
                                                );
                                            }
                                        }
                                    } else {
                                        channel_info!(
                                            config_id,
                                            "GW2: Identity extension declared but not found in response metadata"
                                        );
                                    }
                                } else {
                                    channel_info!(
                                        config_id,
                                        "GW2: No metadata found in response history message"
                                    );
                                }
                            } else {
                                channel_info!(
                                    config_id,
                                    "GW2: Agent identity extension not declared in response"
                                );
                            }
                        } else {
                            channel_info!(
                                config_id,
                                "GW2: No extensions array found in response history"
                            );
                        }
                    } else {
                        channel_info!(config_id, "GW2: No history found in response");
                    }
                } else {
                    channel_info!(config_id, "GW2: Failed to parse response as JSON");
                }

                channel_info!(
                    config_id,
                    "GW2: Response inspection - agent_identity: {:?}",
                    agent_identity
                );
            } else {
                channel_info!(
                    config_id,
                    "GW2: Response body is empty, cannot extract agent identity"
                );
            }

            // GW2: Record request and response metrics (after extracting agent identity)
            let request_latency_ms = start_time.elapsed().as_millis() as u64;
            let response_latency_ms = response_start.elapsed().as_millis() as u64;
            let response_bytes = response_body.len() as u64;

            // Detect UCP operation for fabric-forwarded requests (same two-pass logic as handler.rs)
            let method_result = Method::from_bytes(method.as_bytes());
            let ucp_operation = match method_result {
                Ok(ref m) => crate::proxy::handler::extract_ucp_operation(path, m),
                Err(_) => None,
            }
            .inspect(|op| channel_info!(config_id, "🛒 GW2: UCP operation detected in method: {}", op))
            .or_else(|| crate::proxy::handler::extract_ucp_operation_from_body(&body_bytes, config_id))
            .inspect(|op| channel_info!(config_id, "🛒 GW2: UCP operation detected in body: {}", op))
            // Fallback: if the request had no UCP data, inspect the upstream response body.
            // This handles the common A2A pattern where the client sends a plain text message/send
            // and the upstream returns UCP-structured data (e.g. a2a.ucp.checkout, a2a.product_results).
            .or_else(|| crate::proxy::handler::extract_ucp_operation_from_body(response_body.as_bytes(), config_id))
            .inspect(|op| channel_info!(config_id, "🛒 GW2: UCP operation detected in response: {}", op))
            .inspect(|op| channel_info!(config_id, "🛒 GW2 UCP operation detected: {}", op))
            .or_else(|| {
                channel_info!(config_id, "🛒 GW2: No UCP operation detected in request or response");
                None
            });

            if let Some(metrics_store) = GLOBAL_METRICS_STORE.get() {
                let request_status = if (200..300).contains(&status) {
                    crate::metrics::ConnectionStatus::Success
                } else if (400..500).contains(&status) {
                    crate::metrics::ConnectionStatus::Failed
                } else {
                    crate::metrics::ConnectionStatus::GatewayFault
                };

                // Record request metrics (GW1 -> GW2 -> target)
                let source = message.from_did.as_deref().unwrap_or("unknown").to_string();
                let dest = target_url.clone();

                metrics_store
                    .record_connection_with_bytes_and_ucp(
                        surface
                            .config_id()
                            .map(str::to_string)
                            .unwrap_or_else(|| channel_id.to_string()),
                        source.clone(),
                        dest.clone(),
                        request_status,
                        Some(request_latency_ms),
                        caller_identity.clone(),
                        crate::metrics::ConnectionDirection::Request,
                        uuid::Uuid::new_v4().to_string(),
                        request_bytes,
                        0, // No bytes received in request direction
                        ucp_operation.clone(),
                        None,
                        None,
                        request_latency_ms,
                        None,
                    )
                    .await;

                channel_info!(
                    config_id,
                    "Recorded request metrics - status: {:?}, latency: {}ms, bytes: {}, caller: {:?}",
                    request_status,
                    request_latency_ms,
                    request_bytes,
                    caller_identity
                );

                // Record response metrics (target -> GW2 -> GW1)
                let response_status = request_status; // Use same status for both directions

                metrics_store
                    .record_connection_with_bytes(
                        surface
                            .config_id()
                            .map(str::to_string)
                            .unwrap_or_else(|| channel_id.to_string()),
                        dest,
                        source,
                        response_status,
                        Some(response_latency_ms),
                        agent_identity.clone(),
                        crate::metrics::ConnectionDirection::Response,
                        uuid::Uuid::new_v4().to_string(),
                        0, // No bytes sent in response direction
                        response_bytes,
                        None,
                        None,
                        response_latency_ms,
                        None,
                    )
                    .await;

                channel_info!(
                    config_id,
                    "Recorded response metrics - status: {:?}, latency: {}ms, bytes: {}, agent: {:?}",
                    response_status,
                    response_latency_ms,
                    response_bytes,
                    agent_identity
                );

                // Ensure task is registered before tracking bytes
                let tracked_task_id = ensure_task_registered(&resolved_surface).await;

                // Track connection and bytes in TaskMonitor
                if let (Some(task_monitor), Some(task_id)) = (GLOBAL_TASK_MONITOR.get(), tracked_task_id.as_deref()) {
                    task_monitor.increment_connections(task_id).await;
                    task_monitor
                        .record_bytes(task_id, request_bytes, response_bytes)
                        .await;
                    task_monitor.decrement_active_connections(task_id).await;
                }
            }

            // GW2: Inject backend agent VP into response if identity was extracted
            // This mirrors the inbound VP injection pattern from handler.rs:2074-2132
            info!("GW2: VP injection check - agent_identity: {:?}", agent_identity);
            if let Some(ref agent_did) = agent_identity {
                info!(
                    "GW2: VP injection check - agent_did.starts_with('did:'): {}, has_identity_ext_rules: {}",
                    agent_did.starts_with("did:"),
                    identity_ext_rules.is_some()
                );
                if agent_did.starts_with("did:") && identity_ext_rules.is_some() {
                    info!("GW2: Backend agent DID found, injecting VP into response for DID: {}", agent_did);

                    // Get the VC issuer
                    if let Some(vc_issuer) = GLOBAL_VC_ISSUER.get() {
                        // Retrieve identity record from store
                        match vc_issuer.get_identity_store().find_by_did(agent_did).await {
                            Ok(Some(identity_record)) => {
                                // Extract identity fields from the record
                                let identity_fields: std::collections::HashMap<String, serde_json::Value> =
                                    identity_record
                                        .identity_fields
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.clone()))
                                        .collect();

                                // Convert response_body String to Bytes for injection
                                let response_bytes = bytes::Bytes::from(response_body.clone());

                                // No workload_binding plumbed here yet — this GW2 path
                                // doesn't currently have access to the channel's transit
                                // config or authenticated caller, so the legacy
                                // `identityFields` VC shape is preserved.
                                let inject_result = match message.from_did.as_deref() {
                                    Some(requester_did) => {
                                        crate::protocols::inject_vp_into_response(
                                            &response_bytes,
                                            agent_did,
                                            &identity_fields,
                                            None,
                                            vc_issuer,
                                            channel_id,
                                            crate::protocols::AnsweredRequest {
                                                id: &message.didcomm_message_id,
                                                requester_did,
                                            },
                                        )
                                        .await
                                    }
                                    None => Err(anyhow::anyhow!(
                                        "the forward-request has no sender to bind the presentation to"
                                    )),
                                };

                                match inject_result {
                                    Ok((modified_bytes, _vp_jwt)) => {
                                        // Replace response_body with VP-injected version
                                        response_body = String::from_utf8_lossy(&modified_bytes).to_string();
                                        info!(
                                            "GW2: Successfully injected backend agent VP into response for DID: {}",
                                            agent_did
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            "GW2: Failed to inject backend agent VP into response: {}, using original body",
                                            e
                                        );
                                        // Keep original response_body
                                    }
                                }
                            }
                            Ok(None) => {
                                warn!(
                                    "GW2: Identity record not found for backend agent DID: {}, skipping VP injection",
                                    agent_did
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "GW2: Error retrieving identity record for DID {}: {}, skipping VP injection",
                                    agent_did, e
                                );
                            }
                        }
                    } else {
                        warn!("GW2: VC issuer not available, cannot inject backend agent VP");
                    }
                } else if !agent_did.starts_with("did:") {
                    debug!("GW2: Backend agent identity is not a DID (identity hash), skipping VP injection");
                } else {
                    debug!("GW2: No managed_identity.extension_rules configured, skipping backend agent VP injection");
                }
            }

            let response_json = serde_json::json!({
                "status": status,
                "headers": with_payment_receipts(response_headers, payment_receipt_headers),
                "body": response_body,
            });

            ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: response_json,
            }
        }
        Err(e) => {
            channel_error!(
                config_id,
                "❌ Forward failed: {} {} - {}",
                http_method,
                target_url,
                e
            );

            // Provide detailed error information
            let mut error_details = vec![format!("Error: {}", e)];

            // Check error type and add specific details
            if e.is_timeout() {
                error_details.push("Type: Request timeout".to_string());
            } else if e.is_connect() {
                error_details.push("Type: Connection failed".to_string());
                error_details.push(
                    "Possible causes: Service not running, firewall blocking, wrong port"
                        .to_string(),
                );
            } else if e.is_request() {
                error_details.push("Type: Request build error".to_string());
            } else if e.is_body() {
                error_details.push("Type: Body error".to_string());
            } else if e.is_decode() {
                error_details.push("Type: Response decode error".to_string());
            }

            // Add source error if available
            if let Some(source) = e.source() {
                error_details.push(format!("Source: {}", source));
                // Walk the full error chain for deeper diagnostics
                let mut current: &dyn std::error::Error = source;
                while let Some(inner) = current.source() {
                    error_details.push(format!("  Caused by: {}", inner));
                    current = inner;
                }
            }
            // Full debug representation
            error_details.push(format!("Debug: {:?}", e));

            // Log all error details
            for detail in &error_details {
                channel_warn!(config_id, "  ↳ {}", detail);
            }

            // Return a generic, protocol-appropriate error. The target endpoint,
            // resolved URL, port, method, and the reqwest error chain are logged
            // above (`error_details`) but MUST NOT be echoed to the caller.
            let (error_msg, status_code) = if e.is_timeout() {
                ("Upstream request timed out", 504)
            } else if e.is_connect() {
                ("Unable to reach the target", 502)
            } else {
                ("Failed to forward request to the target", 502)
            };

            let json_rpc =
                crate::protocols::channel_protocol_family(&surface_protocol).is_some();
            let request_id = crate::gateways::connection_points::forward_errors::extract_json_rpc_id(&body_bytes);
            ProcessingResult::RequiresResponse {
                response_type: MessageType::ForwardResponse.to_string(),
                response_body: error_with_payment_receipts(
                    crate::gateways::connection_points::forward_errors::safe_forward_error(
                        status_code,
                        error_msg,
                        json_rpc,
                        request_id,
                    ),
                    payment_receipt_headers,
                ),
            }
        }
    }
    }.instrument(span).await
}

async fn process_forward_response(message: &ReceivedMessage) -> ProcessingResult {
    info!("📥 Received forward-response from {:?}", message.from_did);
    // Response is handled by whoever initiated the forward request
    ProcessingResult::ProcessedNoResponse
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::messages::MessageMetadata;

    fn setup_message(consumed: bool) -> ReceivedMessage {
        let mut message = ReceivedMessage::new(
            "connection-point-1".to_string(),
            "gateway-1".to_string(),
            MessageType::ConnectionSetup.to_string(),
            "message-1".to_string(),
            None,
            Some("invitation-1".to_string()),
            Some("did:example:acceptor-temp".to_string()),
            vec!["did:example:inviter-temp".to_string()],
            serde_json::json!({"channel_did": "did:example:acceptor"}),
            MessageMetadata {
                encrypted: true,
                authenticated: false,
                from_key: None,
                non_repudiation: false,
                anonymous_sender: true,
                extra: serde_json::json!({}),
            },
        );
        if consumed {
            message
                .context
                .insert("invitation_capability_consumed".to_string(), serde_json::json!(true));
        }
        message
    }

    // ── Fabric forward: discovery reads, source auth, target URL ──

    const CALLER_KEY: &str = "fabric-caller-key";

    /// A surface on `endpoint` whose callers must present `CALLER_KEY` in
    /// `X-API-Key`.
    fn keyed_surface(endpoint: &str) -> crate::config::agent_surface::AgentSurface {
        crate::config::agent_surface::AgentSurface {
            surface_id: "fabric-surface".to_string(),
            name: "fabric".to_string(),
            access_point: crate::config::agent_surface::AccessPoint {
                route: "/fabric".to_string(),
                caller_authentication: Some(crate::config::agent_surface::CallerAuthentication {
                    methods: vec![crate::source_auth::SourceAuthConfig::ApiKey(
                        crate::source_auth::models::ApiKeyAuthConfig {
                            extraction: crate::source_auth::models::CredentialExtraction::HttpHeader {
                                field: "X-API-Key".to_string(),
                            },
                            secret_id: "fabric-caller-keys".to_string(),
                        },
                    )],
                }),
                ..Default::default()
            },
            target: crate::config::agent_surface::Target {
                endpoint: endpoint.to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Surfaces for one received fabric message, and the exposure the listener
    /// attaches for the connection point it arrived on.
    struct FabricStorage {
        dir: tempfile::TempDir,
        exposure: SurfaceExposure,
    }

    impl FabricStorage {
        async fn new(
            surfaces: &[crate::config::agent_surface::AgentSurface],
            gateway_tenant: Option<&str>,
            gateway_surfaces: &[&str],
            connection_point_surfaces: &[&str],
        ) -> Self {
            let dir = tempfile::tempdir().expect("fabric storage");
            let surface_store = crate::surfaces::FileSystemAgentSurfaceStore::new(
                dir.path()
                    .join("agent_surfaces"),
            )
            .await
            .expect("surface store");
            for surface in surfaces {
                crate::surfaces::AgentSurfaceStore::save(&surface_store, surface)
                    .await
                    .expect("save surface");
            }
            let ids = |ids: &[&str]| {
                ids.iter()
                    .map(|id| id.to_string())
                    .collect()
            };
            Self {
                dir,
                exposure: SurfaceExposure {
                    tenant_id: gateway_tenant.map(str::to_string),
                    gateway_surfaces: ids(gateway_surfaces),
                    connection_point_surfaces: ids(connection_point_surfaces),
                },
            }
        }

        fn attach(
            &self,
            message: &mut ReceivedMessage,
        ) {
            message.context.insert(
                "agent_surface_storage_path".to_string(),
                serde_json::json!(
                    self.dir
                        .path()
                        .join("agent_surfaces")
                        .to_string_lossy()
                ),
            );
            message
                .context
                .insert(SURFACE_EXPOSURE_CONTEXT_KEY.to_string(), serde_json::json!(self.exposure));
        }
    }

    fn surface_named(
        id: &str,
        tenant_id: Option<&str>,
    ) -> crate::config::agent_surface::AgentSurface {
        crate::config::agent_surface::AgentSurface {
            surface_id: id.to_string(),
            name: id.to_string(),
            tenant_id: tenant_id.map(str::to_string),
            ..keyed_surface("https://agent.example.test")
        }
    }

    fn forward_message(channel_id: &str) -> ReceivedMessage {
        let mut message = setup_message(false);
        message.message_body = serde_json::json!({
            "channel_id": channel_id,
            "method": "GET",
            "path": "/agent.json",
        });
        message
    }

    fn listed_ids(result: &ProcessingResult) -> Vec<String> {
        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected a get-surfaces response, got {result:?}");
        };
        let mut ids: Vec<String> = response_body["channels"]
            .as_array()
            .expect("channels")
            .iter()
            .filter_map(|ch| {
                ch["config_id"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect();
        ids.sort();
        ids
    }

    async fn lookup_id(
        storage: &FabricStorage,
        channel_id: &str,
    ) -> Result<Option<String>, String> {
        let mut message = forward_message(channel_id);
        storage.attach(&mut message);
        lookup_channel(&message, channel_id)
            .await
            .map(|surface| surface.map(|s| s.surface_id))
    }

    #[tokio::test]
    async fn a_forward_reaches_only_surfaces_the_connection_point_exposes() {
        let storage = FabricStorage::new(
            &[surface_named("exposed", None), surface_named("hidden", None)],
            None,
            &[],
            &["exposed"],
        )
        .await;

        assert_eq!(lookup_id(&storage, "exposed").await, Ok(Some("exposed".to_string())));
        assert_eq!(lookup_id(&storage, "hidden").await, Ok(None));
    }

    #[tokio::test]
    async fn a_forward_reaches_only_surfaces_the_gateway_exposes() {
        let storage = FabricStorage::new(
            &[surface_named("exposed", None), surface_named("hidden", None)],
            None,
            &["exposed"],
            &[],
        )
        .await;

        assert_eq!(lookup_id(&storage, "exposed").await, Ok(Some("exposed".to_string())));
        assert_eq!(lookup_id(&storage, "hidden").await, Ok(None));
    }

    #[tokio::test]
    async fn a_forward_never_crosses_into_another_tenants_surface() {
        let storage = FabricStorage::new(
            &[
                surface_named("own", Some("tenant-a")),
                surface_named("shared", None),
                surface_named("other", Some("tenant-b")),
            ],
            Some("tenant-a"),
            &[],
            &[],
        )
        .await;

        assert_eq!(lookup_id(&storage, "own").await, Ok(Some("own".to_string())));
        assert_eq!(lookup_id(&storage, "shared").await, Ok(Some("shared".to_string())));
        assert_eq!(lookup_id(&storage, "other").await, Ok(None));

        let untenanted = FabricStorage::new(&[surface_named("tenanted", Some("tenant-a"))], None, &[], &[]).await;
        assert_eq!(lookup_id(&untenanted, "tenanted").await, Ok(None));
    }

    #[tokio::test]
    async fn an_empty_exposure_list_still_reaches_every_untenanted_surface() {
        let storage = FabricStorage::new(&[surface_named("a", None), surface_named("b", None)], None, &[], &[]).await;

        assert_eq!(lookup_id(&storage, "a").await, Ok(Some("a".to_string())));
        assert_eq!(lookup_id(&storage, "b").await, Ok(Some("b".to_string())));
        assert_eq!(lookup_id(&storage, "missing").await, Ok(None));
    }

    #[tokio::test]
    async fn a_forward_is_denied_without_a_readable_exposure() {
        let storage = FabricStorage::new(&[surface_named("a", None)], None, &[], &[]).await;

        for (case, exposure) in
            [("a missing exposure", None), ("an unreadable exposure", Some(serde_json::json!("all")))]
        {
            let mut message = forward_message("a");
            storage.attach(&mut message);
            message
                .context
                .remove(SURFACE_EXPOSURE_CONTEXT_KEY);
            if let Some(exposure) = exposure {
                message
                    .context
                    .insert(SURFACE_EXPOSURE_CONTEXT_KEY.to_string(), exposure);
            }
            assert!(
                lookup_channel(&message, "a")
                    .await
                    .is_err(),
                "{case}"
            );
            assert_eq!(forward_status(&process_forward_request(&message).await), Some(502), "{case}");
            assert!(listed_ids(&process_get_surfaces(&message).await).is_empty(), "{case}");
        }
    }

    #[tokio::test]
    async fn a_forward_to_an_unexposed_surface_is_answered_not_found() {
        let storage = FabricStorage::new(
            &[surface_named("exposed", None), surface_named("hidden", None)],
            None,
            &[],
            &["exposed"],
        )
        .await;
        let mut message = forward_message("hidden");
        storage.attach(&mut message);

        assert_eq!(forward_status(&process_forward_request(&message).await), Some(404));
    }

    #[tokio::test]
    async fn the_surface_listing_applies_the_same_exposure_as_the_forward() {
        let storage = FabricStorage::new(
            &[
                surface_named("both", Some("tenant-a")),
                surface_named("gateway-only", Some("tenant-a")),
                surface_named("other-tenant", Some("tenant-b")),
            ],
            Some("tenant-a"),
            &["both", "gateway-only", "other-tenant"],
            &["both", "other-tenant"],
        )
        .await;
        let mut message = forward_message("");
        storage.attach(&mut message);

        assert_eq!(listed_ids(&process_get_surfaces(&message).await), vec!["both".to_string()]);
    }

    async fn caller_key_middleware() -> (crate::source_auth::SourceAuthMiddleware, tempfile::TempDir) {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        let dir = tempfile::tempdir().expect("temporary strategy store");
        let strategies = crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(dir.path().join("jwt"))
            .await
            .expect("jwt strategy store");
        let middleware = crate::source_auth::SourceAuthMiddleware::new(
            Arc::new(strategies),
            Arc::new(crate::jwt_bearer::JwksClient::new(reqwest::Client::new())),
            Some(Arc::new(MemorySecretsStore::with(vec![secret(
                "uuid-fabric-caller-keys",
                "fabric-caller-keys",
                CALLER_KEY,
                None,
            )]))),
            Arc::new(dashmap::DashMap::new()),
            None,
            None,
        );
        (middleware, dir)
    }

    fn forward_status(result: &ProcessingResult) -> Option<u64> {
        match result {
            ProcessingResult::RequiresResponse { response_body, .. } => response_body["status"].as_u64(),
            _ => None,
        }
    }

    fn header_map(pairs: &[(&str, &str)]) -> serde_json::Map<String, Value> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), Value::String(value.to_string())))
            .collect()
    }

    /// A `POST` that only ends like a discovery document authenticates like any
    /// other request; only a `GET` or `HEAD` of one is a public read.
    #[tokio::test]
    async fn a_fabric_post_to_a_discovery_path_must_authenticate() {
        let surface = keyed_surface("https://agent.example.test");
        let (middleware, _dir) = caller_key_middleware().await;
        let body = br#"{"messages":[]}"#;

        for path in ["/agent.json", "/.well-known/agent-card.json", "/.well-known/ucp"] {
            let refused =
                authenticate_fabric_caller(&surface, "test", "POST", path, None, body, Some(&middleware)).await;
            assert_eq!(
                refused
                    .as_ref()
                    .err()
                    .and_then(forward_status),
                Some(403),
                "POST {path} without a key"
            );

            let keyed = header_map(&[("X-API-Key", CALLER_KEY)]);
            let admitted =
                authenticate_fabric_caller(&surface, "test", "POST", path, Some(&keyed), body, Some(&middleware)).await;
            assert!(matches!(admitted, Ok(Some(_))), "POST {path} with the key");

            for method in ["GET", "HEAD"] {
                let public =
                    authenticate_fabric_caller(&surface, "test", method, path, None, b"", Some(&middleware)).await;
                assert!(matches!(public, Ok(None)), "{method} {path} is a public read");
            }
        }
    }

    #[tokio::test]
    async fn a_fabric_read_of_a_discovery_path_must_authenticate() {
        let surface = keyed_surface("https://agent.example.test");
        let (middleware, _dir) = caller_key_middleware().await;

        for method in ["GET", "HEAD"] {
            let refused =
                authenticate_fabric_caller(&surface, "test", method, "/discovery", None, b"", Some(&middleware)).await;
            assert_eq!(
                refused
                    .as_ref()
                    .err()
                    .and_then(forward_status),
                Some(403),
                "{method} /discovery without a key"
            );
        }
    }

    #[tokio::test]
    async fn a_fabric_request_is_refused_when_source_auth_middleware_is_missing() {
        let surface = keyed_surface("https://agent.example.test");
        let keyed = header_map(&[("X-API-Key", CALLER_KEY)]);

        let refused = authenticate_fabric_caller(&surface, "test", "POST", "/a2a", Some(&keyed), b"{}", None).await;
        assert_eq!(
            refused
                .as_ref()
                .err()
                .and_then(forward_status),
            Some(503)
        );

        let public = authenticate_fabric_caller(&surface, "test", "GET", "/agent.json", None, b"", None).await;
        assert!(matches!(public, Ok(None)), "a public read needs no middleware");
    }

    #[test]
    fn a_fabric_path_never_changes_the_target_host() {
        for path in [
            "@attacker.example/agent.json",
            ".attacker.example/agent.json",
            ":8443@attacker.example/x",
            "attacker.example/x",
            "/a2a",
        ] {
            let url = fabric_target_url("https://agent.example.com", path);
            let parsed = url::Url::parse(&url).expect("a URL");
            assert_eq!(parsed.host_str(), Some("agent.example.com"), "{path} gave {url}");
            assert_eq!(parsed.port(), None, "{path} gave {url}");
        }
        assert_eq!(fabric_target_url("https://agent.example.com/api/", "/v1/x"), "https://agent.example.com/api/v1/x");
        assert_eq!(fabric_target_url("https://agent.example.com/api", "/"), "https://agent.example.com/api");
    }

    #[test]
    fn a_public_read_forwards_no_method_override() {
        let headers = header_map(&[
            ("X-HTTP-Method-Override", "POST"),
            ("x-http-method", "DELETE"),
            ("X-Method-Override", "PUT"),
            ("X-API-Key", CALLER_KEY),
            ("Host", "attacker.example"),
            ("Content-Length", "9"),
            ("Accept", "application/json"),
        ]);
        let names = |public_read| -> Vec<String> {
            let mut names: Vec<String> = forwarded_headers(&headers, Some("X-API-Key"), public_read)
                .into_iter()
                .map(|(name, _)| name.to_ascii_lowercase())
                .collect();
            names.sort();
            names
        };
        assert_eq!(names(true), vec!["accept".to_string()]);
        assert_eq!(
            names(false),
            vec![
                "accept".to_string(),
                "x-http-method".to_string(),
                "x-http-method-override".to_string(),
                "x-method-override".to_string()
            ]
        );
    }

    /// The origin of `upstream`, as a surface's target endpoint.
    fn target_origin(upstream: &crate::pipes::test_upstreams::CaptureUpstream) -> String {
        upstream
            .url
            .trim_end_matches("/v1/chat/completions")
            .to_string()
    }

    /// Forward dependencies with no appliance-wide policy, no source-auth
    /// middleware, no delegation stores and no VC issuer.
    fn bare_dependencies() -> ForwardDependencies {
        ForwardDependencies {
            appliance_policies: Arc::new(crate::pipes::PipePolicyManager::new()),
            source_auth: None,
            delegation: None,
            vc_issuer: None,
            agent_pay: None,
        }
    }

    /// Run a fabric `ForwardRequest` carrying `body` against `surface`, stored
    /// where the receive path looks it up and exposed to the receiving
    /// connection point, with `context` added to the message.
    async fn forward_to_stored_surface(
        deps: &ForwardDependencies,
        surface: &crate::config::agent_surface::AgentSurface,
        body: Value,
        context: &[(&str, Value)],
    ) -> ProcessingResult {
        let storage = FabricStorage::new(std::slice::from_ref(surface), None, &[], &[]).await;

        let mut message = setup_message(false);
        message.message_body = body;
        storage.attach(&mut message);
        for (key, value) in context {
            message
                .context
                .insert(key.to_string(), value.clone());
        }
        forward_request(&message, deps).await
    }

    /// End to end through `process_forward_request`: a public discovery read
    /// whose path does not start with `/` still reaches the surface's own target,
    /// and carries neither the caller's body nor a method override.
    #[tokio::test]
    async fn a_public_fabric_read_reaches_the_target_without_a_body_or_method_override() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("an agent card").await;

        let result = forward_to_stored_surface(
            &bare_dependencies(),
            &keyed_surface(&target_origin(&upstream)),
            serde_json::json!({
                "channel_id": "fabric-surface",
                "method": "GET",
                "path": "@attacker.invalid/agent.json",
                "headers": { "X-HTTP-Method-Override": "POST", "Accept": "application/json" },
                "body": { "smuggled": true },
            }),
            &[],
        )
        .await;

        assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");
        assert_eq!(upstream.requests(), 1, "the read did not reach the surface's own target");
        assert!(
            upstream
                .header_values("x-http-method-override")
                .is_empty(),
            "the method override was forwarded"
        );
        assert_eq!(upstream.header_values("accept"), vec!["application/json".to_string()]);
        assert_eq!(upstream.bodies(), vec![Value::Null], "the public read carried a body");
    }

    /// reqwest never resolves an IP-literal target, so the shared client's DNS
    /// check cannot see one: a surface pointing at a metadata IP is refused
    /// before anything is sent.
    #[tokio::test]
    async fn a_fabric_forward_to_a_metadata_ip_literal_is_refused() {
        let storage = FabricStorage::new(&[keyed_surface("http://169.254.169.254")], None, &[], &[]).await;

        let mut message = setup_message(false);
        message.message_body = serde_json::json!({
            "channel_id": "fabric-surface",
            "method": "GET",
            "path": "/agent.json",
        });
        storage.attach(&mut message);

        let result = process_forward_request(&message).await;

        assert_eq!(forward_status(&result), Some(502), "unexpected result: {result:?}");
        let ProcessingResult::RequiresResponse { response_body, .. } = &result else {
            panic!("expected a forward response, got {result:?}");
        };
        assert_eq!(response_body["error"], "Target endpoint is not allowed");
    }

    /// A surface on `endpoint` with no caller authentication and a target
    /// credential that must never travel off the endpoint.
    fn credentialed_surface(endpoint: &str) -> crate::config::agent_surface::AgentSurface {
        let mut surface = keyed_surface(endpoint);
        surface
            .access_point
            .caller_authentication = None;
        surface.target.auth = Some(crate::config::TargetAuthConfig {
            method: crate::config::TargetAuthMethod::StaticSecret {
                secret_id: "target-key".to_string(),
                header_name: "Authorization".to_string(),
                header_format: "Bearer {value}".to_string(),
            },
            auth_type: None,
            target_identifier: None,
            fallback: crate::config::TargetAuthFallback::Reject,
        });
        surface
    }

    async fn forward_get(
        storage: &FabricStorage,
        path: &str,
    ) -> ProcessingResult {
        let mut message = setup_message(false);
        message.message_body = serde_json::json!({
            "channel_id": "fabric-surface",
            "method": "GET",
            "path": path,
        });
        storage.attach(&mut message);
        process_forward_request(&message).await
    }

    /// End to end through `process_forward_request`: a path that climbs out of
    /// the target endpoint is refused with 400 before target auth runs, so no
    /// request, and no credential, reaches any upstream. A path that stays under
    /// the endpoint gets past the check to target auth, which refuses here
    /// because no secrets store is configured.
    #[tokio::test]
    async fn a_fabric_path_leaving_the_target_is_refused_before_target_auth() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("ok").await;
        let origin = upstream
            .url
            .trim_end_matches("/v1/chat/completions")
            .to_string();
        let storage = FabricStorage::new(&[credentialed_surface(&format!("{origin}/api"))], None, &[], &[]).await;

        for path in ["/../admin", "/v1/../../admin", "/v1/%2e%2e%2fadmin", "/v1/..%5cadmin", "/v1/..;/admin"] {
            let result = forward_get(&storage, path).await;
            assert_eq!(forward_status(&result), Some(400), "{path}: {result:?}");
        }
        assert_eq!(upstream.requests(), 0, "a refused path reached the upstream");

        let allowed = forward_get(&storage, "/v1/messages").await;
        assert_eq!(forward_status(&allowed), Some(502), "an allowed path reaches target auth: {allowed:?}");
        assert_eq!(upstream.requests(), 0);
    }

    // ── Fabric forward: gateway policy layers and upstream credentials ──

    const TARGET_KEY: &str = "fabric-target-key-value";

    /// A policy manager whose appliance-wide Trust Fabric baseline is `rego`.
    async fn appliance_policies(rego: &str) -> (crate::pipes::PipePolicyManager, tempfile::TempDir) {
        use crate::policies::global_policy::GlobalAssignment;
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};
        use crate::policies::{FileSystemPolicyDefinitionStore, GlobalPolicyAssignments};

        let dir = tempfile::tempdir().expect("policy definition store");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("policy definition store");
        store
            .save(PolicyDefinition {
                id: "baseline".to_string(),
                name: "baseline".to_string(),
                description: String::new(),
                policy_type: PolicyType::Appliance,
                policy: rego.to_string(),
                enabled: true,
                created_at: "2026-10-19T00:00:00Z".to_string(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
                tenant_id: None,
            })
            .await
            .expect("save baseline");
        let policies = crate::pipes::PipePolicyManager::new();
        policies.set_policy_definition_store(Arc::new(store));
        let mut assignments = GlobalPolicyAssignments::default();
        assignments
            .assignments
            .insert(
                "appliance".to_string(),
                vec![GlobalAssignment {
                    policy_id: "baseline".to_string(),
                    monitor_only: false,
                }],
            );
        for _ in 0..COMPILE_ATTEMPTS {
            policies
                .refresh_global(&assignments)
                .await
                .expect("refresh baseline");
            if !policies.global_is_broken("appliance") {
                return (policies, dir);
            }
            tokio::time::sleep(COMPILE_RETRY_DELAY).await;
        }
        panic!("the appliance baseline did not compile");
    }

    /// The policy engine allows only a few compilations at a time across the
    /// process, so under parallel tests a compile can fail for want of a slot
    /// and leave a set that denies everything; the policy helpers retry.
    const COMPILE_ATTEMPTS: usize = 200;
    const COMPILE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(5);

    /// The status the gateway policy layers refuse an unauthenticated fabric
    /// request with, or `None` when they admit it.
    fn gateway_policy_refusal(
        appliance: &crate::pipes::PipePolicyManager,
        own_gateway: Option<&crate::policies::GatewayPolicyManager>,
        method: &str,
        path: &str,
    ) -> Option<u64> {
        let surface = keyed_surface("https://agent.example.test");
        enforce_gateway_policies(appliance, own_gateway, &surface, "test", method, path, None, None, None)
            .err()
            .as_ref()
            .and_then(forward_status)
    }

    #[tokio::test]
    async fn the_appliance_wide_policy_runs_on_a_public_fabric_read() {
        let (deny_all, _dir) = appliance_policies("package agentstream.policy\ndefault allow = false").await;

        for (method, path) in [("GET", "/agent.json"), ("HEAD", "/.well-known/agent-card.json"), ("POST", "/a2a")] {
            assert_eq!(gateway_policy_refusal(&deny_all, None, method, path), Some(403), "{method} {path}");
        }
    }

    #[tokio::test]
    async fn the_gateways_own_policy_skips_only_a_public_fabric_read() {
        let own = own_gateway_policies("package agentstream.policy\ndefault allow = false").await;
        let no_baseline = crate::pipes::PipePolicyManager::new();

        assert_eq!(gateway_policy_refusal(&no_baseline, Some(&own), "GET", "/agent.json"), None);
        for (method, path) in [("POST", "/agent.json"), ("GET", "/v1/tasks"), ("GET", "/discovery")] {
            assert_eq!(gateway_policy_refusal(&no_baseline, Some(&own), method, path), Some(403), "{method} {path}");
        }
    }

    /// With both layers in force, each sees the full policy input.
    #[tokio::test]
    async fn both_gateway_policy_layers_see_the_request() {
        let inbound_only = "package agentstream.policy\nimport rego.v1\ndefault allow := false\nallow if input.gateway.direction == \"inbound\"";
        let (baseline, _dir) = appliance_policies(inbound_only).await;
        let own = own_gateway_policies(inbound_only).await;

        for (method, path) in [("GET", "/agent.json"), ("POST", "/a2a")] {
            assert_eq!(gateway_policy_refusal(&baseline, Some(&own), method, path), None, "{method} {path}");
        }
    }

    /// A gateway policy manager enforcing `rego` as this appliance's own Trust
    /// Fabric policy.
    async fn own_gateway_policies(rego: &str) -> crate::policies::GatewayPolicyManager {
        use crate::gateways::types::{
            Gateway, GatewayCreationType, GatewayOpaPolicyConfig, GatewayStatus, GatewayType,
        };

        let own = crate::policies::GatewayPolicyManager::new();
        own.set_self_gateway_id("self-gateway".to_string());
        let gateway = Gateway {
            id: "self-gateway".to_string(),
            name: "self-gateway".to_string(),
            description: String::new(),
            did: "did:example:self-gateway".to_string(),
            gateway_type: GatewayType::SelfGateway,
            status: GatewayStatus::Active,
            tenant_id: None,
            creation_type: GatewayCreationType::User,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            exposed_channels: Vec::new(),
            opa_policy_config: Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: rego.to_string(),
                policy_definition_id: None,
                policy_definition_ids: Vec::new(),
            }),
        };
        let mut last_error = String::new();
        for _ in 0..COMPILE_ATTEMPTS {
            match own
                .update_gateway_policy(&gateway)
                .await
            {
                Ok(()) => return own,
                Err(e) => last_error = e,
            }
            tokio::time::sleep(COMPILE_RETRY_DELAY).await;
        }
        panic!("the gateway's own policy did not compile: {last_error}");
    }

    #[tokio::test]
    async fn the_appliance_wide_policy_sees_a_public_fabric_read_as_discovery() {
        let (discovery_only, _dir) = appliance_policies(
            "package agentstream.policy\nimport rego.v1\ndefault allow := false\nallow if input.request.purpose == \"discovery\"",
        )
        .await;

        for path in ["/agent.json", "/.well-known/agent-card.json", "/.well-known/ucp"] {
            assert_eq!(gateway_policy_refusal(&discovery_only, None, "GET", path), None, "GET {path}");
        }
        for (method, path) in [("POST", "/agent.json"), ("GET", "/v1/tasks"), ("GET", "/discovery")] {
            assert_eq!(gateway_policy_refusal(&discovery_only, None, method, path), Some(403), "{method} {path}");
        }
    }

    /// The discovery-friendly baseline `docs/POLICY.md` documents.
    #[tokio::test]
    async fn the_documented_baseline_admits_discovery_and_signed_in_callers_only() {
        let (baseline, _dir) = appliance_policies(
            "package agentstream.policy\n\nimport rego.v1\n\ndefault allow := false\n\nallow if input.request.purpose == \"discovery\"\n\nallow if input.source_auth\n",
        )
        .await;
        let surface = keyed_surface("https://agent.example.test");
        let (middleware, _keys) = caller_key_middleware().await;
        let keyed = header_map(&[("X-API-Key", CALLER_KEY)]);
        let caller =
            match authenticate_fabric_caller(&surface, "test", "POST", "/a2a", Some(&keyed), b"{}", Some(&middleware))
                .await
            {
                Ok(Some(caller)) => caller,
                other => panic!("expected an identified caller, got {other:?}"),
            };

        assert_eq!(gateway_policy_refusal(&baseline, None, "GET", "/.well-known/agent-card.json"), None);
        assert_eq!(gateway_policy_refusal(&baseline, None, "POST", "/a2a"), Some(403));
        let signed_in =
            enforce_gateway_policies(&baseline, None, &surface, "test", "POST", "/a2a", None, None, Some(&caller));
        assert!(signed_in.is_ok(), "a signed-in caller was refused: {signed_in:?}");
    }

    #[test]
    fn a_fabric_request_is_admitted_when_no_gateway_policy_applies() {
        let none = crate::pipes::PipePolicyManager::new();

        for (method, path) in [("GET", "/agent.json"), ("POST", "/a2a")] {
            assert_eq!(gateway_policy_refusal(&none, None, method, path), None, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn only_an_identified_caller_gets_upstream_credentials_on_a_source_authenticated_surface() {
        let surface = keyed_surface("https://agent.example.test");
        let (middleware, _dir) = caller_key_middleware().await;
        let keyed = header_map(&[("X-API-Key", CALLER_KEY)]);
        let caller =
            match authenticate_fabric_caller(&surface, "test", "POST", "/a2a", Some(&keyed), b"{}", Some(&middleware))
                .await
            {
                Ok(Some(caller)) => caller,
                other => panic!("expected an identified caller, got {other:?}"),
            };

        assert!(may_send_upstream_credentials(&surface, Some(&caller)));
        assert!(!may_send_upstream_credentials(&surface, None));

        let mut open = surface;
        open.access_point
            .caller_authentication = None;
        assert!(may_send_upstream_credentials(&open, None));
    }

    /// The `X-Target-Key` values a public `GET /agent.json` over the fabric to
    /// `surface` carried to its target, when the surface sends `TARGET_KEY`
    /// there.
    async fn target_keys_on_a_public_read(mut surface: crate::config::agent_surface::AgentSurface) -> Vec<String> {
        use crate::secrets::SecretsStore;

        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("an agent card").await;
        surface.target = crate::config::agent_surface::Target {
            endpoint: target_origin(&upstream),
            auth: Some(crate::config::TargetAuthConfig {
                method: crate::config::TargetAuthMethod::StaticSecret {
                    secret_id: "fabric-target-key".to_string(),
                    header_name: "X-Target-Key".to_string(),
                    header_format: "{value}".to_string(),
                },
                auth_type: None,
                target_identifier: None,
                fallback: crate::config::TargetAuthFallback::Reject,
            }),
            ..Default::default()
        };

        let secrets = tempfile::tempdir().expect("secrets store");
        let secrets_path = secrets
            .path()
            .to_string_lossy()
            .to_string();
        crate::secrets::FilesystemSecretsStore::new_async(&secrets_path)
            .await
            .expect("secrets store")
            .create(crate::secrets::CreateSecretRequest {
                name: "fabric target key".to_string(),
                secret_id: "fabric-target-key".to_string(),
                description: None,
                value: TARGET_KEY.to_string(),
                secret_type: "General".to_string(),
                tags: Vec::new(),
                tenant_id: None,
            })
            .await
            .expect("save target key");

        let result = forward_to_stored_surface(
            &bare_dependencies(),
            &surface,
            serde_json::json!({
                "channel_id": "fabric-surface",
                "method": "GET",
                "path": "/agent.json",
                "headers": {},
            }),
            &[("secrets_storage_path", serde_json::json!(secrets_path))],
        )
        .await;

        assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");
        assert_eq!(upstream.requests(), 1, "the read did not reach the surface's own target");
        upstream.header_values("x-target-key")
    }

    #[tokio::test]
    async fn a_public_fabric_read_on_a_source_authenticated_surface_carries_no_target_credential() {
        let keys = target_keys_on_a_public_read(keyed_surface("")).await;

        assert!(keys.is_empty(), "the target credential reached the target: {keys:?}");
    }

    #[tokio::test]
    async fn a_public_fabric_read_on_an_open_surface_carries_the_target_credential() {
        let mut open = keyed_surface("");
        open.access_point
            .caller_authentication = None;

        assert_eq!(target_keys_on_a_public_read(open).await, vec![TARGET_KEY.to_string()]);
    }

    #[tokio::test]
    async fn the_forward_path_refuses_a_public_read_the_appliance_wide_policy_denies() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("an agent card").await;
        let (deny_all, _dir) = appliance_policies("package agentstream.policy\ndefault allow = false").await;
        let deps = ForwardDependencies {
            appliance_policies: Arc::new(deny_all),
            ..bare_dependencies()
        };

        let result = forward_to_stored_surface(
            &deps,
            &keyed_surface(&target_origin(&upstream)),
            serde_json::json!({ "channel_id": "fabric-surface", "method": "GET", "path": "/agent.json" }),
            &[],
        )
        .await;

        assert_eq!(forward_status(&result), Some(403), "unexpected result: {result:?}");
        assert_eq!(upstream.requests(), 0, "a refused read reached the target");
    }

    // ── Fabric forward: whose delegated credentials are sent ──

    const DELEGATED_KEY: &str = "delegated-key-value";

    /// Delegation stores holding one API-key credential provider,
    /// `delegated-api`, whose key is `DELEGATED_KEY`. An API-key provider sends
    /// its key for any identity it is resolved for.
    async fn api_key_delegation() -> (DelegationStores, tempfile::TempDir) {
        use crate::credential_providers::storage::CredentialProviderStorage;
        use crate::secrets::store::memory::{MemorySecretsStore, secret};

        let dir = tempfile::tempdir().expect("delegation stores");
        let providers =
            crate::credential_providers::storage::FileSystemCredentialProviderStore::new(dir.path().join("providers"))
                .await
                .expect("credential provider store");
        providers
            .create(crate::credential_providers::CredentialProvider {
                id: "delegated-api".to_string(),
                name: "Delegated API".to_string(),
                provider_id: "delegated-api".to_string(),
                provider_type: crate::credential_providers::CredentialProviderType::ApiKey,
                authorization_endpoint: None,
                token_endpoint: None,
                client_id_secret_ref: None,
                client_secret_secret_ref: None,
                default_scopes: Vec::new(),
                callback_path: String::new(),
                token_refresh_enabled: false,
                additional_params: std::collections::HashMap::new(),
                api_key_secret_ref: Some("delegated-api-key".to_string()),
                description: None,
                tenant_id: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                callback_url: None,
            })
            .await
            .expect("save credential provider");
        let vault = crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(dir.path().join("vault"))
            .await
            .expect("delegation vault");
        let stores = DelegationStores {
            vault: Arc::new(vault),
            providers: Arc::new(providers),
            secrets: Arc::new(MemorySecretsStore::with(vec![secret(
                "uuid-delegated-api-key",
                "delegated-api-key",
                DELEGATED_KEY,
                None,
            )])),
            base_url: "https://appliance.example.test".to_string(),
        };
        (stores, dir)
    }

    /// `surface` with the `delegated-api` provider bound for outbound
    /// delegation, sent as a bearer token.
    fn with_delegation(
        mut surface: crate::config::agent_surface::AgentSurface
    ) -> crate::config::agent_surface::AgentSurface {
        surface.outbound_credentials = vec![crate::config::types::OutboundCredentialBinding {
            credential_provider_id: "delegated-api".to_string(),
            scopes: Vec::new(),
            required_for: crate::config::types::CredentialRequirement::All,
            consent_mode: crate::config::types::ConsentMode::default(),
            inject_as: crate::config::types::CredentialInjection::BearerHeader,
            elicit_timeout_secs: 300,
            elicit_fallback: crate::config::types::ElicitFallback::default(),
        }];
        surface
    }

    /// An MCP-style body that claims a caller DID in `_meta` with no
    /// presentation to back it.
    fn claimed_did_body() -> Value {
        serde_json::json!({
            "_meta": {
                (crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION): { "did": "did:example:someone-else" }
            }
        })
    }

    /// The `Authorization` values a fabric request `body` to `surface` (built on
    /// the upstream's origin) carried to its target.
    async fn delegated_headers_reaching_the_target(
        deps: &ForwardDependencies,
        surface: impl FnOnce(&str) -> crate::config::agent_surface::AgentSurface,
        body: Value,
    ) -> Vec<String> {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("ok").await;

        let result = forward_to_stored_surface(deps, &surface(&target_origin(&upstream)), body, &[]).await;

        assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");
        upstream.header_values("authorization")
    }

    #[tokio::test]
    async fn only_a_signed_in_caller_gets_delegated_credentials_on_a_signed_in_surface() {
        let (middleware, _keys) = caller_key_middleware().await;
        let (delegation, _stores) = api_key_delegation().await;
        let deps = ForwardDependencies {
            source_auth: Some(Arc::new(middleware)),
            delegation: Some(delegation),
            ..bare_dependencies()
        };
        let signed_in = |origin: &str| with_delegation(keyed_surface(origin));

        let signed_in_call = delegated_headers_reaching_the_target(
            &deps,
            signed_in,
            serde_json::json!({
                "channel_id": "fabric-surface",
                "method": "POST",
                "path": "/a2a",
                "headers": { "X-API-Key": CALLER_KEY, "Content-Type": "application/json" },
                "body": claimed_did_body(),
            }),
        )
        .await;
        assert_eq!(signed_in_call, vec![format!("Bearer {DELEGATED_KEY}")]);

        let public_read = delegated_headers_reaching_the_target(
            &deps,
            signed_in,
            serde_json::json!({
                "channel_id": "fabric-surface",
                "method": "GET",
                "path": "/agent.json",
                "headers": {},
                "body": claimed_did_body(),
            }),
        )
        .await;
        assert!(public_read.is_empty(), "a public read got a delegated credential: {public_read:?}");
    }

    /// A public read's body is dropped before identity extraction, so the DID
    /// it claims is never stored; the same body on a write still is.
    #[tokio::test]
    async fn a_public_fabric_read_stores_no_caller_identity() {
        let (vc_issuer, _issuer_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let vc_issuer = Arc::new(vc_issuer);
        let deps = ForwardDependencies {
            vc_issuer: Some(Arc::clone(&vc_issuer)),
            ..bare_dependencies()
        };
        let mut open = keyed_surface("");
        open.access_point
            .caller_authentication = None;
        let stored_dids = || async {
            vc_issuer
                .get_identity_store()
                .list_all()
                .await
                .expect("identity store")
                .into_iter()
                .map(|record| record.did)
                .collect::<Vec<_>>()
        };
        let forward = |method: &'static str, path: &'static str| {
            let deps = &deps;
            let mut surface = open.clone();
            async move {
                let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("ok").await;
                surface.target.endpoint = target_origin(&upstream);
                let result = forward_to_stored_surface(
                    deps,
                    &surface,
                    serde_json::json!({
                        "channel_id": "fabric-surface",
                        "method": method,
                        "path": path,
                        "headers": { "Content-Type": "application/json" },
                        "body": claimed_did_body(),
                    }),
                    &[],
                )
                .await;
                assert_eq!(forward_status(&result), Some(200), "{method} {path}: {result:?}");
            }
        };

        forward("GET", "/agent.json").await;
        assert!(stored_dids().await.is_empty(), "a public read stored a caller identity");

        forward("POST", "/a2a").await;
        assert_eq!(stored_dids().await, vec!["did:example:someone-else".to_string()]);
    }

    // ── Fabric forward: payment enforcement on a paid surface ──

    use super::super::payment_gate::tests::{FakeAgentPay, agent_pay_policy};

    /// An open surface on `origin` whose payments Agent Pay handles.
    fn paid_surface(origin: &str) -> crate::config::agent_surface::AgentSurface {
        let mut surface = keyed_surface(origin);
        surface
            .access_point
            .caller_authentication = None;
        surface.target.payment_policy = Some(agent_pay_policy());
        surface
    }

    fn with_agent_pay(agent_pay: &Arc<FakeAgentPay>) -> ForwardDependencies {
        ForwardDependencies {
            agent_pay: Some(Arc::clone(agent_pay) as Arc<dyn super::super::payment_gate::AgentPayRelay>),
            ..bare_dependencies()
        }
    }

    fn paid_call(headers: Value) -> Value {
        serde_json::json!({
            "channel_id": "fabric-surface",
            "method": "POST",
            "path": "/a2a",
            "headers": headers,
            "body": { "ask": "paid" },
        })
    }

    fn response_header<'a>(
        result: &'a ProcessingResult,
        name: &str,
    ) -> Option<&'a str> {
        match result {
            ProcessingResult::RequiresResponse { response_body, .. } => response_body["headers"]
                .as_object()?
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))?
                .1
                .as_str(),
            _ => None,
        }
    }

    #[tokio::test]
    async fn an_unpaid_request_to_a_paid_surface_gets_the_agent_pay_challenge_and_never_reaches_the_target() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(
            402,
            &[("PAYMENT-REQUIRED", "challenge"), ("Set-Cookie", "sid=agent-pay")],
            r#"{"accepts":[]}"#,
        ));

        let result = forward_to_stored_surface(
            &with_agent_pay(&agent_pay),
            &paid_surface(&target_origin(&upstream)),
            paid_call(serde_json::json!({ "Content-Type": "application/json" })),
            &[],
        )
        .await;

        assert_eq!(forward_status(&result), Some(402), "unexpected result: {result:?}");
        assert_eq!(response_header(&result, "payment-required"), Some("challenge"));
        assert_eq!(response_header(&result, "set-cookie"), None);
        assert_eq!(upstream.requests(), 0, "an unpaid request reached the target");
        let relayed = agent_pay.received();
        assert_eq!(relayed.len(), 1);
        assert_eq!(relayed[0].fabric_target, "fabric://gw-pay/pay-surface");
        assert_eq!(relayed[0].path, "/a2a");
        assert_eq!(relayed[0].body, br#"{"ask":"paid"}"#.to_vec());
    }

    #[tokio::test]
    async fn a_paid_request_reaches_the_target_and_the_caller_gets_the_agent_pay_receipt() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(200, &[("PAYMENT-RESPONSE", "settled")], ""));

        let result = forward_to_stored_surface(
            &with_agent_pay(&agent_pay),
            &paid_surface(&target_origin(&upstream)),
            paid_call(serde_json::json!({ "PAYMENT-SIGNATURE": "signed", "Content-Type": "application/json" })),
            &[],
        )
        .await;

        assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");
        assert_eq!(upstream.requests(), 1);
        assert_eq!(response_header(&result, "payment-response"), Some("settled"));
        assert_eq!(
            agent_pay.received()[0]
                .headers
                .get("PAYMENT-SIGNATURE")
                .map(String::as_str),
            Some("signed")
        );
    }

    #[tokio::test]
    async fn a_paid_surface_refuses_when_agent_pay_cannot_be_reached() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;

        for (deps, expected) in [
            (with_agent_pay(&Arc::new(FakeAgentPay::unreachable())), 502),
            (with_agent_pay(&Arc::new(FakeAgentPay::answering(500, &[], ""))), 502),
            (bare_dependencies(), 503),
        ] {
            let result = forward_to_stored_surface(
                &deps,
                &paid_surface(&target_origin(&upstream)),
                paid_call(serde_json::json!({})),
                &[],
            )
            .await;

            assert_eq!(forward_status(&result), Some(expected), "unexpected result: {result:?}");
        }
        assert_eq!(upstream.requests(), 0, "a request Agent Pay did not accept reached the target");
    }

    #[tokio::test]
    async fn a_public_read_of_a_paid_surface_is_not_charged() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("an agent card").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(402, &[], ""));

        let result = forward_to_stored_surface(
            &with_agent_pay(&agent_pay),
            &paid_surface(&target_origin(&upstream)),
            serde_json::json!({ "channel_id": "fabric-surface", "method": "GET", "path": "/agent.json" }),
            &[],
        )
        .await;

        assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");
        assert_eq!(upstream.requests(), 1);
        assert!(
            agent_pay
                .received()
                .is_empty(),
            "a public read was sent to Agent Pay"
        );
    }

    #[tokio::test]
    async fn a_request_to_an_unpaid_surface_is_not_sent_to_agent_pay() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("free content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(402, &[], ""));
        let mut free = paid_surface(&target_origin(&upstream));
        free.target.payment_policy = None;

        let result =
            forward_to_stored_surface(&with_agent_pay(&agent_pay), &free, paid_call(serde_json::json!({})), &[]).await;

        assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");
        assert!(
            agent_pay
                .received()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_request_refused_by_source_auth_or_policy_is_never_sent_to_agent_pay() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(200, &[], ""));
        let (middleware, _keys) = caller_key_middleware().await;
        let (deny_all, _dir) = appliance_policies("package agentstream.policy\ndefault allow = false").await;
        let mut keyed_paid = keyed_surface(&target_origin(&upstream));
        keyed_paid
            .target
            .payment_policy = Some(agent_pay_policy());

        let wrong_key = forward_to_stored_surface(
            &ForwardDependencies {
                source_auth: Some(Arc::new(middleware)),
                ..with_agent_pay(&agent_pay)
            },
            &keyed_paid,
            paid_call(serde_json::json!({ "X-API-Key": "not-the-key" })),
            &[],
        )
        .await;
        let denied = forward_to_stored_surface(
            &ForwardDependencies {
                appliance_policies: Arc::new(deny_all),
                ..with_agent_pay(&agent_pay)
            },
            &paid_surface(&target_origin(&upstream)),
            paid_call(serde_json::json!({})),
            &[],
        )
        .await;

        assert_eq!(forward_status(&wrong_key), Some(403), "unexpected result: {wrong_key:?}");
        assert_eq!(forward_status(&denied), Some(403), "unexpected result: {denied:?}");
        assert!(
            agent_pay
                .received()
                .is_empty(),
            "a refused request was sent to Agent Pay"
        );
        assert_eq!(upstream.requests(), 0);
    }

    #[tokio::test]
    async fn the_source_auth_credential_is_not_sent_to_agent_pay() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(200, &[], ""));
        let (middleware, _keys) = caller_key_middleware().await;
        let mut keyed_paid = keyed_surface(&target_origin(&upstream));
        keyed_paid
            .target
            .payment_policy = Some(agent_pay_policy());

        let result = forward_to_stored_surface(
            &ForwardDependencies {
                source_auth: Some(Arc::new(middleware)),
                ..with_agent_pay(&agent_pay)
            },
            &keyed_paid,
            paid_call(serde_json::json!({ "X-API-Key": CALLER_KEY, "PAYMENT-SIGNATURE": "signed" })),
            &[],
        )
        .await;

        assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");
        let sent = &agent_pay.received()[0].headers;
        assert!(
            !sent
                .keys()
                .any(|name| name.eq_ignore_ascii_case("x-api-key")),
            "the caller's key reached Agent Pay: {sent:?}"
        );
        assert_eq!(
            sent.get("PAYMENT-SIGNATURE")
                .map(String::as_str),
            Some("signed")
        );
    }

    fn headers(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn on_a_charged_request_only_agent_pay_supplies_receipt_headers() {
        let target = headers(&[
            ("payment-response", "forged"),
            ("X-Settlement-Tx", "0xforged"),
            ("x-payment-receipt", "forged"),
            ("cache-control", "max-age=60"),
            ("content-type", "application/json"),
        ]);

        assert_eq!(
            with_payment_receipts(target, Some(headers(&[("PAYMENT-RESPONSE", "settled")]))),
            headers(&[
                ("PAYMENT-RESPONSE", "settled"),
                ("cache-control", "max-age=60"),
                ("content-type", "application/json"),
            ])
        );
    }

    #[test]
    fn a_request_that_was_not_charged_keeps_the_targets_headers() {
        let target = headers(&[("X-Settlement-Tx", "0xtarget"), ("content-type", "application/json")]);

        assert_eq!(with_payment_receipts(target.clone(), None), target);
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Every local refusal that can still end the request runs before Agent Pay
    /// is asked, so a refused request is never charged.
    #[tokio::test]
    async fn a_request_refused_before_it_is_sent_is_never_charged() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;
        let origin = target_origin(&upstream);
        let agent_pay = Arc::new(FakeAgentPay::answering(200, &[("PAYMENT-RESPONSE", "settled")], ""));
        let mut target_auth_fails = credentialed_surface(&origin);
        target_auth_fails
            .target
            .payment_policy = Some(agent_pay_policy());
        let mut escaping = paid_call(serde_json::json!({}));
        escaping["path"] = Value::from("/../admin");
        let mut late = paid_call(serde_json::json!({}));
        late["deadline_ms"] = Value::from(now_ms() - 1);

        for (surface, call, expected) in [
            (paid_surface(&format!("{origin}/api")), escaping, 400),
            (paid_surface("http://169.254.169.254"), paid_call(serde_json::json!({})), 502),
            (target_auth_fails, paid_call(serde_json::json!({})), 502),
            (paid_surface(&origin), late, 504),
        ] {
            let result = forward_to_stored_surface(&with_agent_pay(&agent_pay), &surface, call, &[]).await;

            assert_eq!(forward_status(&result), Some(expected), "unexpected result: {result:?}");
            assert_eq!(response_header(&result, "payment-response"), None);
        }
        assert!(
            agent_pay
                .received()
                .is_empty(),
            "a refused request was charged"
        );
        assert_eq!(upstream.requests(), 0);
    }

    #[tokio::test]
    async fn agent_pay_is_given_only_what_is_left_of_the_callers_deadline() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(200, &[], ""));
        let mut call = paid_call(serde_json::json!({}));
        call["deadline_ms"] = Value::from(now_ms() + 5_000);

        let result =
            forward_to_stored_surface(&with_agent_pay(&agent_pay), &paid_surface(&target_origin(&upstream)), call, &[])
                .await;
        let without_deadline = forward_to_stored_surface(
            &with_agent_pay(&agent_pay),
            &paid_surface(&target_origin(&upstream)),
            paid_call(serde_json::json!({})),
            &[],
        )
        .await;

        assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");
        assert_eq!(forward_status(&without_deadline), Some(200), "unexpected result: {without_deadline:?}");
        let relayed = agent_pay.received();
        assert!(
            relayed[0].timeout > std::time::Duration::ZERO && relayed[0].timeout <= std::time::Duration::from_secs(5),
            "Agent Pay was given {:?}",
            relayed[0].timeout
        );
        assert_eq!(relayed[1].timeout, crate::fabric_marketplace::FABRIC_FORWARD_TIMEOUT);
    }

    #[tokio::test]
    async fn a_paid_request_that_fails_at_the_target_still_returns_the_receipt() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::stalling().await;
        let agent_pay = Arc::new(FakeAgentPay::answering(200, &[("PAYMENT-RESPONSE", "settled")], ""));
        let mut call = paid_call(serde_json::json!({}));
        call["deadline_ms"] = Value::from(now_ms() + 1_000);

        let result =
            forward_to_stored_surface(&with_agent_pay(&agent_pay), &paid_surface(&target_origin(&upstream)), call, &[])
                .await;

        assert_eq!(forward_status(&result), Some(504), "unexpected result: {result:?}");
        assert_eq!(response_header(&result, "payment-response"), Some("settled"));
        assert_eq!(agent_pay.received().len(), 1);
    }

    /// The caller names the Variant, so a complete Variant that leaves out the
    /// payment policy must not make a paid surface free.
    #[tokio::test]
    async fn a_complete_variant_without_a_payment_policy_is_still_charged() {
        use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant, TargetOverrides};

        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(402, &[("PAYMENT-REQUIRED", "challenge")], ""));
        let mut surface = paid_surface(&target_origin(&upstream));
        surface.variants = vec![SurfaceVariant {
            id: "id-free".to_string(),
            alias: "free".to_string(),
            name: "free".to_string(),
            description: String::new(),
            enabled: true,
            overrides: SurfaceOverrides {
                complete: true,
                target: Some(TargetOverrides::default()),
                ..Default::default()
            },
        }];
        let mut call = paid_call(serde_json::json!({}));
        call["virtual_channel_alias"] = Value::from("free");

        let result = forward_to_stored_surface(&with_agent_pay(&agent_pay), &surface, call, &[]).await;

        assert_eq!(forward_status(&result), Some(402), "unexpected result: {result:?}");
        assert_eq!(agent_pay.received().len(), 1);
        assert_eq!(upstream.requests(), 0);
    }

    #[tokio::test]
    async fn agent_pay_gets_only_the_payment_headers() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(200, &[], ""));
        let caller_headers = serde_json::json!({
            "PAYMENT-SIGNATURE": "signed",
            "X-PAYMENT": "v1-payment",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Cookie": "sid=target-session",
            "X-Target-Token": "for-the-target",
        });

        for (authorization, relayed) in [("Bearer target-token", false), ("Payment mpp-credential", true)] {
            let mut headers = caller_headers.clone();
            headers["Authorization"] = Value::from(authorization);
            let result = forward_to_stored_surface(
                &with_agent_pay(&agent_pay),
                &paid_surface(&target_origin(&upstream)),
                paid_call(headers),
                &[],
            )
            .await;
            assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");

            let sent = &agent_pay
                .received()
                .last()
                .expect("relayed")
                .headers
                .clone();
            let mut names: Vec<&str> = sent
                .keys()
                .map(String::as_str)
                .collect();
            names.sort_unstable();
            let mut expected = vec!["Accept", "Content-Type", "PAYMENT-SIGNATURE", "X-PAYMENT"];
            if relayed {
                expected.insert(1, "Authorization");
            }
            assert_eq!(names, expected, "{authorization}");
        }
        assert_eq!(upstream.header_values("cookie"), vec!["sid=target-session".to_string(); 2]);
    }

    #[tokio::test]
    async fn agent_pay_never_gets_the_raw_identity_a_surface_strips_from_the_target() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("paid content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(200, &[], ""));
        let mut surface = paid_surface(&target_origin(&upstream));
        surface.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
        surface
            .identity_slots
            .protected = Some(crate::source_auth::ManagedIdentityConfig::PayloadExtraction(
            crate::source_auth::models::PayloadExtractionConfig {
                meta_field: "agentIdentity".to_string(),
                fields: Vec::new(),
                json_schema: None,
                extension_rules: None,
                strip_raw_meta: true,
            },
        ));

        let result = forward_to_stored_surface(
            &with_agent_pay(&agent_pay),
            &surface,
            serde_json::json!({
                "channel_id": "fabric-surface",
                "method": "POST",
                "path": "/mcp",
                "headers": { "Content-Type": "application/json" },
                "body": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": { "name": "lookup" },
                    "_meta": { "agentIdentity": { "did": "did:example:raw" }, "kept": "yes" },
                },
            }),
            &[],
        )
        .await;

        assert_eq!(forward_status(&result), Some(200), "unexpected result: {result:?}");
        let relayed: Value = serde_json::from_slice(&agent_pay.received()[0].body).expect("a JSON body");
        assert_eq!(relayed["_meta"], serde_json::json!({ "kept": "yes" }));
        assert_eq!(relayed["method"], "tools/call");
        assert_eq!(upstream.bodies()[0]["_meta"].get("agentIdentity"), None);
    }

    #[tokio::test]
    async fn only_the_surfaces_own_discovery_document_is_read_free() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("content").await;
        let agent_pay = Arc::new(FakeAgentPay::answering(402, &[("PAYMENT-REQUIRED", "challenge")], ""));

        for (path, charged) in [
            ("/.well-known/agent-card.json", false),
            ("/agent.json?format=json", false),
            ("/files/agent.json", true),
            ("/some/route/agent.json?x=1", true),
        ] {
            let result = forward_to_stored_surface(
                &with_agent_pay(&agent_pay),
                &paid_surface(&target_origin(&upstream)),
                serde_json::json!({ "channel_id": "fabric-surface", "method": "GET", "path": path }),
                &[],
            )
            .await;

            assert_eq!(
                forward_status(&result),
                Some(if charged {
                    402
                } else {
                    200
                }),
                "{path}: {result:?}"
            );
        }
        assert_eq!(agent_pay.received().len(), 2);
        assert_eq!(upstream.requests(), 2);
    }

    #[tokio::test]
    async fn setup_requires_consumed_invitation_and_uses_parent_thread() {
        assert!(matches!(process_connection_setup(&setup_message(false)).await, ProcessingResult::Failed { .. }));
        assert!(matches!(
            process_connection_setup(&setup_message(true)).await,
            ProcessingResult::OOBConnectionSetup { invitation_id, .. }
                if invitation_id == "invitation-1"
        ));
    }

    const VICTIM_DID: &str = "did:example:victim";

    #[test]
    fn envelope_challenge_binds_to_the_envelope_sender_and_receiving_connection_point() {
        let mut message = forward_message("channel-1");
        message.from_did = Some("did:peer:2.sender".to_string());

        assert!(envelope_challenge(&message).is_none(), "no receiving Connection Point, no binding");

        message.receiving_connection_point_did = Some("did:peer:2.receiver".to_string());
        let Some(crate::identity::ExpectedChallenge::Envelope { id, sender, recipient }) = envelope_challenge(&message)
        else {
            panic!("expected an envelope binding");
        };
        assert_eq!(id, message.didcomm_message_id);
        assert_eq!(sender, "did:peer:2.sender");
        assert_eq!(recipient, "did:peer:2.receiver");

        message.from_did = None;
        assert!(envelope_challenge(&message).is_none(), "no sender, no binding");
    }

    async fn extracted_identity(body: serde_json::Value) -> InboundCallerIdentity {
        let surface = crate::config::agent_surface::AgentSurface::default();
        extract_caller_identity_inbound(
            &surface,
            "channel-1",
            "config-1",
            body.to_string().as_bytes(),
            None,
            None,
            None,
        )
        .await
    }

    fn binding(verified: bool) -> crate::surface_context::IdentityBindingContext {
        crate::surface_context::IdentityBindingContext {
            verified,
            agent_did: VICTIM_DID.to_string(),
            gateway_did: String::new(),
            issuer_did: None,
            identity_fields: std::collections::HashMap::new(),
        }
    }

    fn api_key_caller() -> crate::source_auth::AuthenticatedIdentity {
        crate::source_auth::AuthenticatedIdentity::ApiKey {
            key_name: "caller-key".to_string(),
        }
    }

    fn assert_unverified_did_keys_nothing(extracted: InboundCallerIdentity) {
        assert_eq!(extracted.identity.as_deref(), Some(VICTIM_DID), "the DID is still recorded for telemetry");
        let verified = verified_caller_did(extracted.binding.as_ref());
        assert_eq!(verified, None);
        assert_eq!(delegation_user_hash(verified.as_deref(), None), None);
    }

    #[tokio::test]
    async fn a_credential_extension_did_without_a_presentation_does_not_key_the_vault() {
        let ext = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
        let extracted = extracted_identity(serde_json::json!({
            "message": { "extensions": [ext], "metadata": { ext: { "did": VICTIM_DID } } }
        }))
        .await;

        assert_unverified_did_keys_nothing(extracted);
    }

    #[tokio::test]
    async fn a_meta_credential_did_without_a_presentation_does_not_key_the_vault() {
        let ext = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
        let extracted = extracted_identity(serde_json::json!({ "_meta": { ext: { "did": VICTIM_DID } } })).await;

        assert_unverified_did_keys_nothing(extracted);
    }

    #[tokio::test]
    async fn a_raw_identity_extension_did_does_not_key_the_vault() {
        let ext = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;
        let extracted = extracted_identity(serde_json::json!({
            "message": { "extensions": [ext], "metadata": { ext: { "did": VICTIM_DID } } }
        }))
        .await;

        assert_unverified_did_keys_nothing(extracted);
    }

    #[test]
    fn an_unverified_binding_does_not_key_the_vault() {
        assert_eq!(verified_caller_did(Some(&binding(false))), None);
    }

    #[test]
    fn a_verified_binding_keys_the_vault_with_the_holder_did() {
        let verified = verified_caller_did(Some(&binding(true)));

        assert_eq!(delegation_user_hash(verified.as_deref(), None).as_deref(), Some(VICTIM_DID));
    }

    #[test]
    fn a_verified_binding_takes_precedence_over_source_auth() {
        let verified = verified_caller_did(Some(&binding(true)));

        assert_eq!(delegation_user_hash(verified.as_deref(), Some(&api_key_caller())).as_deref(), Some(VICTIM_DID));
    }

    #[test]
    fn an_unverified_caller_falls_back_to_the_source_auth_principal() {
        let verified = verified_caller_did(Some(&binding(false)));

        let key = delegation_user_hash(verified.as_deref(), Some(&api_key_caller()));

        let expected = crate::identity::calculate_identity_hash(&serde_json::json!({ "source_auth": "caller-key" }));
        assert_eq!(key, Some(expected));
    }
}
