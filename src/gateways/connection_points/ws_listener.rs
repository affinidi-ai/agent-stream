//! WebSocket listener for connection points
//!
//! This module manages WebSocket connections to mediators on behalf of gateway DIDs.
//! When a connection point is created, a WebSocket listener is started that will receive
//! incoming DIDComm messages through the mediator.

use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use affinidi_tdk_common::secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::AbortHandle;
use tracing::{debug, error, info, instrument, warn};

use super::filesystem::ConnectionPointStore;
use super::message_processor;
use super::messages::{MessageMetadata, MessageStore, ReceivedMessage};
use super::types::GatewayConnectionPoint;
use super::webhook::WebhookClient;
use crate::comm::didcomm::client::DIDCommClient;
use crate::comm::didcomm::gateway::CacheConfig;
use crate::gateways::filesystem::GatewayStore;
use crate::identity::VCIssuer;
use crate::mediators::utils::{set_acl_to_allow_everything_and_more, set_acl_to_deny_all, set_acl_to_peer};
use crate::messages::MessageType;

/// How often, in consecutive-failure count, to emit a WARN reconnect summary
/// while a connection point is stuck failing. Between summaries, per-attempt
/// detail is logged at DEBUG to keep the logs quiet during long outages.
const RECONNECT_SUMMARY_EVERY: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
enum SenderIdentity {
    Authenticated { did: String, kid: String },
    Signed { did: String, kid: String },
    Anonymous,
}

fn did_from_kid(kid: &str) -> Option<&str> {
    let did = kid
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(kid);
    did.starts_with("did:")
        .then_some(did)
}

fn bind_verified_sender(
    claimed_from: Option<&str>,
    kid: Option<&str>,
) -> Result<(String, String), &'static str> {
    let claimed_from = claimed_from.ok_or("verified message is missing `from`")?;
    let kid = kid.ok_or("verified sender key is missing")?;
    let sender_did = did_from_kid(kid).ok_or("verified sender key is not a DID URL")?;
    if claimed_from != sender_did {
        return Err("claimed `from` does not match verified sender key DID");
    }
    Ok((sender_did.to_string(), kid.to_string()))
}

struct InvitationSetupRateLimiter {
    window_started: Instant,
    attempts: u32,
}

impl InvitationSetupRateLimiter {
    const WINDOW: Duration = Duration::from_secs(60);
    const MAX_ATTEMPTS: u32 = 5;

    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            attempts: 0,
        }
    }

    fn allow(
        &mut self,
        now: Instant,
    ) -> bool {
        if now.duration_since(self.window_started) >= Self::WINDOW {
            self.window_started = now;
            self.attempts = 0;
        }
        if self.attempts >= Self::MAX_ATTEMPTS {
            return false;
        }
        self.attempts += 1;
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MediatorAclIntent {
    UnrestrictedInvitation,
    PeerOnly(String),
    DenyAll,
    Unmanaged,
}

fn mediator_acl_intent(connection_point: &GatewayConnectionPoint) -> MediatorAclIntent {
    use super::types::ConnectionPointType;

    match connection_point.cp_type {
        ConnectionPointType::User if connection_point.use_count == 0 => MediatorAclIntent::UnrestrictedInvitation,
        ConnectionPointType::User => connection_point
            .oob_message
            .get("acceptor_temporary_did")
            .and_then(serde_json::Value::as_str)
            .map(|did| MediatorAclIntent::PeerOnly(did.to_string()))
            .unwrap_or(MediatorAclIntent::DenyAll),
        ConnectionPointType::OobResponder => connection_point
            .oob_message
            .get("acceptor_secure_did")
            .and_then(serde_json::Value::as_str)
            .map(|did| MediatorAclIntent::PeerOnly(did.to_string()))
            .unwrap_or(MediatorAclIntent::DenyAll),
        ConnectionPointType::OobAcceptor => connection_point
            .oob_message
            .get("inviter_secure_did")
            .and_then(serde_json::Value::as_str)
            .map(|did| MediatorAclIntent::PeerOnly(did.to_string()))
            .unwrap_or(MediatorAclIntent::DenyAll),
        ConnectionPointType::System
            if connection_point
                .expires_at
                .is_some()
                || connection_point
                    .oob_message
                    .get("pending_gateway_id")
                    .is_some() =>
        {
            connection_point
                .oob_message
                .get("inviter_temporary_did")
                .and_then(serde_json::Value::as_str)
                .map(|did| MediatorAclIntent::PeerOnly(did.to_string()))
                .unwrap_or(MediatorAclIntent::DenyAll)
        }
        ConnectionPointType::OobInviter | ConnectionPointType::System => MediatorAclIntent::Unmanaged,
    }
}

async fn apply_mediator_acl_intent(
    intent: &MediatorAclIntent,
    atm: &ATM,
    profile: Arc<ATMProfile>,
) -> Result<(), String> {
    match intent {
        MediatorAclIntent::UnrestrictedInvitation => set_acl_to_allow_everything_and_more(atm, profile).await,
        MediatorAclIntent::PeerOnly(peer) => set_acl_to_peer(atm, profile, peer).await,
        MediatorAclIntent::DenyAll => set_acl_to_deny_all(atm, profile).await,
        MediatorAclIntent::Unmanaged => Ok(()),
    }
}

fn expected_peer_did<'a>(
    connection_point: &'a GatewayConnectionPoint,
    gateway_peer_did: Option<&'a str>,
) -> Option<&'a str> {
    let message_peer_did = match connection_point.cp_type {
        super::types::ConnectionPointType::OobResponder => connection_point
            .oob_message
            .get("acceptor_secure_did")
            .and_then(|value| value.as_str()),
        super::types::ConnectionPointType::OobAcceptor => connection_point
            .oob_message
            .get("inviter_secure_did")
            .and_then(|value| value.as_str()),
        super::types::ConnectionPointType::User => return None,
        super::types::ConnectionPointType::OobInviter | super::types::ConnectionPointType::System => None,
    };
    message_peer_did.or(gateway_peer_did)
}

fn authorize_inbound_message(
    connection_point: &GatewayConnectionPoint,
    message_type: &MessageType,
    claimed_from: Option<&str>,
    metadata: &MessageMetadata,
    gateway_peer_did: Option<&str>,
    now: DateTime<Utc>,
) -> Result<SenderIdentity, &'static str> {
    if connection_point
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err("connection point has expired");
    }
    if connection_point.cp_type == super::types::ConnectionPointType::User
        && !matches!(message_type, MessageType::ConnectionSetup)
    {
        return Err("invitation connection points only accept connection setup");
    }
    if matches!(message_type, MessageType::ConnectionSetup)
        && (connection_point.cp_type != super::types::ConnectionPointType::User
            || !connection_point.enabled
            || connection_point
                .expires_at
                .is_some_and(|expires_at| expires_at <= now))
    {
        return Err("connection setup is not valid for this connection point state");
    }

    if metadata.authenticated {
        if metadata.anonymous_sender {
            return Err("authcrypt metadata identifies an anonymous sender");
        }
        let (did, kid) = bind_verified_sender(claimed_from, metadata.from_key.as_deref())?;
        let expected_peer = expected_peer_did(connection_point, gateway_peer_did);
        if connection_point.cp_type != super::types::ConnectionPointType::User && expected_peer != Some(did.as_str()) {
            return Err("verified sender is not the established connection peer");
        }
        return Ok(SenderIdentity::Authenticated { did, kid });
    }

    if metadata.non_repudiation {
        let (did, kid) = bind_verified_sender(claimed_from, metadata.from_key.as_deref())?;
        let expected_peer = expected_peer_did(connection_point, gateway_peer_did);
        if connection_point.cp_type != super::types::ConnectionPointType::User && expected_peer != Some(did.as_str()) {
            return Err("verified sender is not the established connection peer");
        }
        return Ok(SenderIdentity::Signed { did, kid });
    }

    if matches!(message_type, MessageType::ConnectionSetup) && metadata.encrypted && metadata.anonymous_sender {
        Ok(SenderIdentity::Anonymous)
    } else {
        Err("sender identity is not verified")
    }
}

/// Metrics for a connection point WebSocket listener
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionPointMetrics {
    /// Current status of the listener
    pub status: ConnectionStatus,
    /// When the listener was started
    pub started_at: DateTime<Utc>,
    /// Last time a message was received
    pub last_activity: Option<DateTime<Utc>>,
    /// Total number of messages received
    pub message_count: u64,
    /// Total number of errors encountered
    pub error_count: u64,
    /// Current reconnect attempt number (0 if connected)
    pub reconnect_attempts: u64,
    /// Number of dispatches currently running concurrently for this listener
    #[serde(default)]
    pub in_flight_dispatches: u64,
    /// High-watermark of concurrent in-flight dispatches
    #[serde(default)]
    pub max_in_flight_dispatches: u64,
}

/// Status of a WebSocket connection.
///
/// Canonical definition lives in [`crate::comm::connection_health`] so the
/// listener, dashboard, API handlers, and persisted `runtime_status` all share
/// one type. Re-exported here to preserve the existing `ws_listener::ConnectionStatus`
/// path used across the crate.
pub use crate::comm::connection_health::ConnectionStatus;

impl Default for ConnectionPointMetrics {
    fn default() -> Self {
        Self {
            status: ConnectionStatus::Reconnecting,
            started_at: Utc::now(),
            last_activity: None,
            message_count: 0,
            error_count: 0,
            reconnect_attempts: 0,
            in_flight_dispatches: 0,
            max_in_flight_dispatches: 0,
        }
    }
}

/// Information about an active WebSocket listener
#[derive(Clone)]
pub struct ListenerInfo {
    /// Unique identifier for this listener (same as connection point ID)
    pub id: String,
    generation: u64,
    /// Gateway ID this connection point belongs to
    pub gateway_id: String,
    /// Connection point ID
    pub connection_point_id: String,
    /// Gateway DID being monitored
    pub gateway_did: String,
    /// Mediator DID being used
    pub mediator_did: String,
    /// Connection point name
    pub name: String,
    /// Connection point type (user-created, OOB inviter, OOB responder, etc.)
    pub cp_type: super::types::ConnectionPointType,
    /// Metrics for this listener
    pub metrics: Arc<RwLock<ConnectionPointMetrics>>,
    /// The DIDComm client (ATM + profile + TDK state) for this connection.
    /// Refreshed on every reconnect via [`ConnectionPointListenerManager::update_listener_client`].
    pub client: DIDCommClient,
}

impl ListenerInfo {
    /// This listener instance's lifecycle generation; a restarted connection
    /// point's listener gets a new one.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ListenerLease {
    generation: u64,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerLifecycleState {
    Starting,
    Running,
    Stopping,
}

struct ListenerSlot {
    lease: ListenerLease,
    state: ListenerLifecycleState,
    task: Option<tokio::task::JoinHandle<()>>,
}

struct ListenerLifecycle {
    active: bool,
    epoch: u64,
    next_generation: u64,
    slots: HashMap<String, ListenerSlot>,
}

impl ListenerLifecycle {
    fn new() -> Self {
        Self {
            active: true,
            epoch: 1,
            next_generation: 1,
            slots: HashMap::new(),
        }
    }

    fn activate(&mut self) -> u64 {
        if !self.active {
            self.active = true;
            self.epoch = self.epoch.wrapping_add(1);
        }
        self.epoch
    }

    fn deactivate(&mut self) -> Vec<AbortHandle> {
        if self.active {
            self.active = false;
            self.epoch = self.epoch.wrapping_add(1);
        }
        self.slots
            .values_mut()
            .filter_map(|slot| {
                slot.state = ListenerLifecycleState::Stopping;
                slot.task
                    .as_ref()
                    .map(tokio::task::JoinHandle::abort_handle)
            })
            .collect()
    }

    fn reserve(
        &mut self,
        id: &str,
        expected_epoch: Option<u64>,
    ) -> Result<ListenerLease, String> {
        if !self.active {
            return Err("Connection point listeners are currently deactivated".to_string());
        }
        if expected_epoch.is_some_and(|epoch| self.epoch != epoch) {
            return Err("Listener activation generation is no longer current".to_string());
        }
        if self.slots.contains_key(id) {
            return Err(format!("Listener already exists for connection point {id}"));
        }
        let lease = ListenerLease {
            generation: self.next_generation,
            epoch: self.epoch,
        };
        self.next_generation = self
            .next_generation
            .wrapping_add(1);
        self.slots.insert(
            id.to_string(),
            ListenerSlot {
                lease,
                state: ListenerLifecycleState::Starting,
                task: None,
            },
        );
        Ok(lease)
    }

    fn is_current(
        &self,
        id: &str,
        lease: ListenerLease,
    ) -> bool {
        self.active
            && self.epoch == lease.epoch
            && self
                .slots
                .get(id)
                .is_some_and(|slot| slot.lease == lease && slot.state != ListenerLifecycleState::Stopping)
    }

    fn attach_task(
        &mut self,
        id: &str,
        lease: ListenerLease,
        task: tokio::task::JoinHandle<()>,
    ) -> Result<(), tokio::task::JoinHandle<()>> {
        let Some(slot) = self.slots.get_mut(id) else {
            return Err(task);
        };
        if !self.active
            || self.epoch != lease.epoch
            || slot.lease != lease
            || slot.state != ListenerLifecycleState::Starting
        {
            return Err(task);
        }
        slot.task = Some(task);
        Ok(())
    }

    fn mark_running(
        &mut self,
        id: &str,
        lease: ListenerLease,
    ) -> bool {
        if !self.is_current(id, lease) {
            return false;
        }
        if let Some(slot) = self.slots.get_mut(id) {
            slot.state = ListenerLifecycleState::Running;
            true
        } else {
            false
        }
    }

    fn release_start(
        &mut self,
        id: &str,
        lease: ListenerLease,
    ) {
        if self
            .slots
            .get(id)
            .is_some_and(|slot| slot.lease == lease && slot.state == ListenerLifecycleState::Starting)
        {
            self.slots.remove(id);
        }
    }

    fn task_finished(
        &mut self,
        id: &str,
        lease: ListenerLease,
    ) -> bool {
        if self
            .slots
            .get(id)
            .is_some_and(|slot| slot.lease == lease && slot.state != ListenerLifecycleState::Stopping)
        {
            self.slots.remove(id);
            true
        } else {
            false
        }
    }

    fn begin_stop(
        &mut self,
        id: &str,
    ) -> Option<(ListenerLease, Option<tokio::task::JoinHandle<()>>)> {
        let slot = self.slots.get_mut(id)?;
        slot.state = ListenerLifecycleState::Stopping;
        Some((slot.lease, slot.task.take()))
    }

    fn finish_stop(
        &mut self,
        id: &str,
        lease: ListenerLease,
    ) -> bool {
        if self
            .slots
            .get(id)
            .is_some_and(|slot| slot.lease == lease)
        {
            self.slots.remove(id);
            true
        } else {
            false
        }
    }

    fn ids(&self) -> Vec<String> {
        self.slots
            .keys()
            .cloned()
            .collect()
    }
}

#[derive(Clone)]
struct ListenerFence {
    lifecycle: Arc<Mutex<ListenerLifecycle>>,
    id: String,
    lease: ListenerLease,
}

impl ListenerFence {
    fn is_current(&self) -> bool {
        self.lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_current(&self.id, self.lease)
    }

    fn ensure_current(&self) -> Result<(), String> {
        self.is_current()
            .then_some(())
            .ok_or_else(|| "Listener generation is no longer active".to_string())
    }
}

/// Manages WebSocket listeners for connection points
#[derive(Clone)]
pub struct ConnectionPointListenerManager {
    /// Active listeners keyed by connection point ID
    listeners: Arc<RwLock<HashMap<String, ListenerInfo>>>,
    /// Secondary index mapping `gateway_id` → `connection_point_id` for O(1)
    /// reverse lookups in [`Self::get_listener`]. Maintained in lock-step
    /// with `listeners` at every insert / remove site.
    gateway_index: Arc<RwLock<HashMap<String, String>>>,
    /// Identity orchestrator for accessing gateway DID secrets
    #[allow(dead_code)]
    vc_issuer: Arc<VCIssuer>,
    /// Message store for persisting received messages
    message_store: Arc<MessageStore>,
    /// Connection point store for managing connection points
    cp_store: Arc<crate::gateways::FileSystemConnectionPointStore>,
    /// Gateway store for managing gateway connections (optional)
    gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    /// Pending connection store for tracking OOB handshakes (optional)
    pending_connection_store: Option<Arc<crate::gateways::PendingConnectionStore>>,
    /// Mediator store for resolving mediator IDs
    mediator_store: Option<Arc<crate::mediators::FileSystemMediatorStore>>,
    /// Notification store for sending system notifications (optional)
    notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    /// Bootstrap config for storage paths
    bootstrap_config: Option<Arc<crate::config::BootstrapConfig>>,
    /// Network config for DID domain and WebAuthn settings
    network_config: Option<Arc<crate::config::NetworkConfig>>,
    /// Self-reference for starting new listeners from within message handlers
    self_ref: Option<std::sync::Weak<Self>>,
    /// Channel for starting listeners from within async contexts
    listener_start_tx: Option<tokio::sync::mpsc::UnboundedSender<ListenerStartCommand>>,
    /// DID document cache for resilient gateway communication
    did_cache: Arc<crate::gateways::did_cache::DIDCache>,
    lifecycle: Arc<Mutex<ListenerLifecycle>>,
}

/// Command to start a new listener
pub struct ListenerStartCommand {
    pub connection_point: super::types::GatewayConnectionPoint,
    pub mediator_did: String,
    /// Oneshot channel to notify when listener is started (or failed)
    pub completion_tx: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

impl ConnectionPointListenerManager {
    /// Create a new listener manager
    pub async fn new(
        vc_issuer: Arc<VCIssuer>,
        message_store: Arc<MessageStore>,
        cp_store: Arc<crate::gateways::FileSystemConnectionPointStore>,
        did_cache_config: crate::gateways::did_cache::DIDCacheConfig,
    ) -> anyhow::Result<Self> {
        // Create DID cache with provided configuration
        let did_cache = Arc::new(crate::gateways::did_cache::DIDCache::new(did_cache_config).await?);

        Ok(Self {
            listeners: Arc::new(RwLock::new(HashMap::new())),
            gateway_index: Arc::new(RwLock::new(HashMap::new())),
            vc_issuer,
            message_store,
            cp_store,
            gateway_store: None,
            pending_connection_store: None,
            mediator_store: None,
            notification_store: None,
            bootstrap_config: None,
            network_config: None,
            self_ref: None,
            listener_start_tx: None,
            did_cache,
            lifecycle: Arc::new(Mutex::new(ListenerLifecycle::new())),
        })
    }

    /// Set self-reference and create listener start channel
    pub fn with_self_ref_and_channel(
        mut self,
        self_ref: std::sync::Weak<Self>,
    ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<ListenerStartCommand>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.self_ref = Some(self_ref);
        self.listener_start_tx = Some(tx);
        (self, rx)
    }

    /// Request to start a listener asynchronously
    /// Returns a oneshot receiver that will be notified when the listener is started
    pub fn request_start_listener(
        &self,
        connection_point: super::types::GatewayConnectionPoint,
        mediator_did: String,
    ) -> Result<tokio::sync::oneshot::Receiver<Result<(), String>>, String> {
        if !self.is_active() {
            return Err("Connection point listeners are currently deactivated".to_string());
        }

        if let Some(tx) = &self.listener_start_tx {
            let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();

            tx.send(ListenerStartCommand {
                connection_point,
                mediator_did,
                completion_tx: Some(completion_tx),
            })
            .map_err(|e| format!("Failed to send listener start command: {}", e))?;

            Ok(completion_rx)
        } else {
            Err("Listener start channel not initialized".to_string())
        }
    }

    /// Set the gateway store (for OOB connection finalization)
    pub fn with_gateway_store(
        mut self,
        store: Arc<crate::gateways::FileSystemGatewayStore>,
    ) -> Self {
        self.gateway_store = Some(store);
        self
    }

    /// Set the pending connection store (for OOB handshake tracking)
    pub fn with_pending_connection_store(
        mut self,
        store: Arc<crate::gateways::PendingConnectionStore>,
    ) -> Self {
        self.pending_connection_store = Some(store);
        self
    }

    /// Set the mediator store (for mediator lookup during listener startup)
    pub fn with_mediator_store(
        mut self,
        store: Arc<crate::mediators::FileSystemMediatorStore>,
    ) -> Self {
        self.mediator_store = Some(store);
        self
    }

    /// Set the notification store (for system notifications)
    pub fn with_notification_store(
        mut self,
        store: Arc<crate::integrations::FileSystemNotificationStore>,
    ) -> Self {
        self.notification_store = Some(store);
        self
    }

    /// Set the bootstrap config (for storage paths)
    pub fn with_bootstrap_config(
        mut self,
        config: Arc<crate::config::BootstrapConfig>,
    ) -> Self {
        self.bootstrap_config = Some(config);
        self
    }

    /// Set the network config (for DID domain and WebAuthn settings)
    pub fn with_network_config(
        mut self,
        config: Arc<crate::config::NetworkConfig>,
    ) -> Self {
        self.network_config = Some(config);
        self
    }

    pub fn is_active(&self) -> bool {
        self.lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }

    fn is_epoch_active(
        &self,
        epoch: u64,
    ) -> bool {
        let lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lifecycle.active && lifecycle.epoch == epoch
    }

    pub fn activate(&self) -> u64 {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let was_active = lifecycle.active;
        let epoch = lifecycle.activate();
        if !was_active {
            info!("Connection point listeners activated");
        }
        epoch
    }

    pub fn deactivate(&self) {
        let (was_active, abort_handles) = {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let was_active = lifecycle.active;
            (was_active, lifecycle.deactivate())
        };
        for handle in abort_handles {
            handle.abort();
        }
        if was_active {
            info!("Connection point listeners deactivated");
        }
    }

    pub async fn deactivate_and_stop_all_listeners(&self) {
        self.deactivate();
        self.stop_all_listeners()
            .await;
    }

    pub async fn start_all_listeners_for_epoch(
        &self,
        config: Arc<crate::config::BootstrapConfig>,
        epoch: u64,
    ) {
        if !self.is_epoch_active(epoch) {
            return;
        }

        if let Err(e) = self
            .cp_store
            .refresh_from_disk()
            .await
        {
            warn!("Connection point store refresh on activation failed: {e} - starting from cached state");
        }
        if !self.is_epoch_active(epoch) {
            info!("Connection point activation aborted after refresh: activation was superseded");
            return;
        }
        let connection_points = match self.cp_store.list_all().await {
            Ok(connection_points) => connection_points,
            Err(e) => {
                error!("Failed to list connection points for activation startup: {}", e);
                return;
            }
        };

        if connection_points.is_empty() {
            info!("No connection points found to start after activation");
            return;
        }

        let mut started = 0usize;
        let mut failed = 0usize;

        for cp in connection_points {
            if !self.is_epoch_active(epoch) {
                info!("Listener activation interrupted before completion");
                break;
            }
            if !cp.enabled
                || cp
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= Utc::now())
            {
                debug!("Skipping disabled or expired connection point '{}'", cp.id);
                continue;
            }

            let (mediator_did, _) = match self
                .connection_point_mediator(&cp)
                .await
            {
                Ok(mediator) => mediator,
                Err(e) => {
                    warn!("Skipping connection point '{}' (ID: {}), {}", cp.name, cp.id, e);
                    failed += 1;
                    continue;
                }
            };

            match self
                .start_listener_for_epoch(&cp, mediator_did, config.clone(), Some(epoch))
                .await
            {
                Ok(_) => started += 1,
                Err(e) => {
                    warn!("Failed to start listener for connection point '{}' (ID: {}): {}", cp.name, cp.id, e);
                    failed += 1;
                }
            }
        }

        info!("Connection point activation startup complete: {} started, {} failed", started, failed);
    }

    /// The mediator DID a connection point's listener connects to, with the
    /// mediator's stored DID document when it has one. `mediator_id` is either
    /// the mediator's DID or the ID of a stored mediator.
    async fn connection_point_mediator(
        &self,
        cp: &GatewayConnectionPoint,
    ) -> Result<(String, Option<serde_json::Value>), String> {
        use crate::mediators::filesystem::MediatorStore;

        if cp
            .mediator_id
            .starts_with("did:")
        {
            return Ok((cp.mediator_id.clone(), None));
        }
        let store = self
            .mediator_store
            .as_ref()
            .ok_or_else(|| format!("mediator store unavailable for mediator ID '{}'", cp.mediator_id))?;
        let mediator = store
            .get(&cp.mediator_id)
            .await
            .map_err(|e| format!("failed to load mediator '{}': {}", cp.mediator_id, e))?
            .ok_or_else(|| format!("mediator '{}' not found", cp.mediator_id))?;
        Ok((mediator.did, mediator.did_document))
    }

    /// The mediator HTTP(S) endpoint that invitation links and connection
    /// point identities are built from. Only the inviter needs it, so listener
    /// start never depends on fetching the mediator's DID document.
    async fn connection_point_mediator_endpoint(
        &self,
        cp: &GatewayConnectionPoint,
    ) -> Result<String, String> {
        let (mediator_did, mediator_document) = self
            .connection_point_mediator(cp)
            .await?;
        crate::mediators::transport::resolve_mediator_rest_endpoint(&mediator_did, mediator_document)
            .await
            .map_err(|e| format!("failed to resolve mediator endpoint for DID '{}': {}", mediator_did, e))
    }

    /// Start background cache maintenance task
    /// This task periodically evicts expired DID cache entries
    pub fn start_cache_maintenance_task(&self) {
        let did_cache = Arc::clone(&self.did_cache);
        let manager = self.clone();

        crate::observability::spawn_traced_task("did_cache.maintenance", async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                // Evict expired entries
                let evicted = did_cache
                    .evict_expired()
                    .await;
                if evicted > 0 {
                    info!("DID cache maintenance: evicted {} expired entries", evicted);
                }

                // Get cache stats
                let stats = did_cache.stats().await;
                debug!(
                    "DID cache stats: {} total ({} fresh, {} stale, {} expired)",
                    stats.total_entries, stats.fresh_entries, stats.stale_entries, stats.expired_entries
                );

                // Log stale DIDs that should be refreshed
                let stale_dids = did_cache
                    .get_stale_dids()
                    .await;
                if !stale_dids.is_empty() {
                    debug!("DIDs approaching expiration (stale): {}", stale_dids.len());
                    for did in stale_dids.iter().take(5) {
                        debug!("  - {}", did);
                    }
                }

                if manager.is_active() {
                    manager
                        .reconcile_listeners()
                        .await;
                    if let Some(store) = &manager.pending_connection_store {
                        let removed = store.cleanup_expired().await;
                        if removed > 0 {
                            info!("OOB lifecycle maintenance removed {removed} expired pending record(s)");
                        }
                    }
                }
            }
        });

        info!("✓ DID cache maintenance task started (runs every 5 minutes)");
    }

    /// Start a WebSocket listener for a connection point
    pub async fn start_listener(
        &self,
        connection_point: &GatewayConnectionPoint,
        mediator_did: String,
        config: Arc<crate::config::BootstrapConfig>,
    ) -> Result<(), String> {
        self.start_listener_for_epoch(connection_point, mediator_did, config, None)
            .await
    }

    async fn start_listener_for_epoch(
        &self,
        connection_point: &GatewayConnectionPoint,
        mediator_did: String,
        config: Arc<crate::config::BootstrapConfig>,
        expected_epoch: Option<u64>,
    ) -> Result<(), String> {
        let cp_id = connection_point.id.clone();
        let lease = {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            lifecycle.reserve(&cp_id, expected_epoch)?
        };

        info!(
            "Starting WebSocket listener for connection point '{}' (Gateway: {}, Mediator: {})",
            connection_point.name, connection_point.gateway_id, mediator_did
        );

        // Load connection point's unique DID and secrets
        // Each connection point has its own DID to avoid duplicate WebSocket connections
        let connection_point_did = connection_point
            .connection_point_did
            .clone();

        info!("Loading secrets for connection point DID: {}", connection_point_did);

        // Load connection point secrets from storage
        let storage_path_str = config
            .storage_paths
            .connection_points
            .clone();
        let storage_path = std::path::PathBuf::from(storage_path_str);
        let cp_storage_id = connection_point.id.clone();

        let secrets_result =
            tokio::task::spawn_blocking(move || -> Result<Vec<affinidi_secrets_resolver::secrets::Secret>, String> {
                // This needs to be sync because we're calling blocking file operations
                tokio::runtime::Handle::current().block_on(async {
                    super::handlers::load_connection_point_secrets(&cp_storage_id, &storage_path)
                        .await
                        .map_err(|e| format!("Failed to load connection point secrets: {}", e))
                })
            })
            .await
            .map_err(|e| format!("Task join error: {}", e))
            .and_then(std::convert::identity);
        let secrets = match secrets_result {
            Ok(secrets) => secrets,
            Err(error) => {
                self.lifecycle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .release_start(&cp_id, lease);
                return Err(error);
            }
        };

        info!("✓ Loaded {} secret(s) for connection point DID", secrets.len());

        // did:key DIDs are self-describing - no need to build/cache DID document
        // The SDK's DID resolver automatically generates it from the DID string

        // Spawn the WebSocket listener task
        let listeners_clone = Arc::clone(&self.listeners);
        let gateway_index_clone = Arc::clone(&self.gateway_index);
        let message_store_clone = Arc::clone(&self.message_store);
        let cp_clone = connection_point.clone();
        let cp_id_clone = cp_id.clone();
        let cp_name = connection_point.name.clone();
        let gateway_id_clone = connection_point
            .gateway_id
            .clone();
        let connection_point_did_clone = connection_point_did.clone();
        let mediator_did_clone = mediator_did.clone();

        // Create metrics tracker
        let metrics = Arc::new(RwLock::new(ConnectionPointMetrics::default()));
        let metrics_clone = Arc::clone(&metrics);

        // Clone stores for the spawned task
        let gateway_store_clone = self.gateway_store.clone();
        let pending_store_clone = self
            .pending_connection_store
            .clone();
        let notification_store_clone = self
            .notification_store
            .clone();
        let bootstrap_config_clone = self.bootstrap_config.clone();
        let cp_store_clone = Some(Arc::clone(&self.cp_store));
        let manager_weak = self.self_ref.clone();
        let fence = ListenerFence {
            lifecycle: Arc::clone(&self.lifecycle),
            id: cp_id.clone(),
            lease,
        };
        let task_fence = fence.clone();

        // Create a channel to receive the DIDComm client from the spawned task
        let (atm_tx, mut atm_rx) = tokio::sync::mpsc::channel::<DIDCommClient>(1);

        let handle = crate::observability::spawn_traced_task_with_fields(
            "connection_point.listener",
            vec![
                ("cp.name", cp_name.clone()),
                ("cp.id", cp_id_clone.clone()),
                ("cp.did", connection_point_did_clone.clone()),
            ],
            async move {
                if let Err(e) = run_websocket_listener(
                    &cp_clone,
                    &connection_point_did_clone, // Use connection point DID, not gateway DID
                    &mediator_did_clone,
                    secrets,
                    message_store_clone,
                    metrics_clone,
                    atm_tx,
                    gateway_store_clone,
                    pending_store_clone,
                    notification_store_clone,
                    bootstrap_config_clone,
                    cp_store_clone,
                    manager_weak,
                    task_fence.clone(),
                )
                .await
                {
                    error!("WebSocket listener error for connection point '{}': {}", cp_name, e);
                }

                let remove_generation = task_fence
                    .lifecycle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .task_finished(&cp_id_clone, lease);
                if remove_generation {
                    let mut listeners = listeners_clone.write().await;
                    if listeners
                        .get(&cp_id_clone)
                        .is_some_and(|listener| listener.generation == lease.generation)
                    {
                        listeners.remove(&cp_id_clone);
                        let mut idx = gateway_index_clone
                            .write()
                            .await;
                        if idx.get(&gateway_id_clone) == Some(&cp_id_clone) {
                            idx.remove(&gateway_id_clone);
                        }
                    }
                }
                info!("WebSocket listener stopped for connection point '{}'", cp_name);
            },
        );
        let abort_handle = handle.abort_handle();
        let attach_result = {
            self.lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .attach_task(&cp_id, lease, handle)
        };
        if let Err(handle) = attach_result {
            handle.abort();
            let _ = handle.await;
            return Err("Listener generation became stale before task registration".to_string());
        }

        // Wait for ATM and profile to be sent from the spawned task (with timeout)
        // Use a longer timeout to allow WebSocket connections to establish
        // Authentication can take several seconds, so we give it 30 seconds
        // If it times out, we'll still register the listener so it appears in the UI
        // and pings will wait for actual connection rather than failing immediately
        let client = match tokio::time::timeout(std::time::Duration::from_secs(30), atm_rx.recv()).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                return Err("Channel closed before receiving ATM instance".to_string());
            }
            Err(_) => {
                // Timeout - wait for the connection in a non-blocking way
                // The listener task will keep trying to connect in the background
                warn!(
                    "Timeout waiting for initial connection for connection point '{}', will wait for connection in background",
                    cp_id
                );

                // Spawn a task to wait for the ATM and register the listener once connected
                let listeners_clone = Arc::clone(&self.listeners);
                let gateway_index_clone = Arc::clone(&self.gateway_index);
                let cp_id_clone = cp_id.clone();
                let connection_point_clone = connection_point.clone();
                let connection_point_did_clone = connection_point_did.clone();
                let mediator_did_clone = mediator_did.clone();
                let handle_clone = abort_handle.clone();
                let metrics_clone = Arc::clone(&metrics);
                let cp_store_clone = Arc::clone(&self.cp_store);
                let delayed_fence = fence.clone();

                tokio::spawn(async move {
                    if let Some(client) = atm_rx.recv().await {
                        if !delayed_fence.is_current() {
                            handle_clone.abort();
                            return;
                        }
                        // Before registering, verify the connection point still exists
                        // If it was deleted while we were connecting, don't register the listener
                        match cp_store_clone
                            .get(&cp_id_clone)
                            .await
                        {
                            Ok(Some(_)) => {
                                let marked_running = delayed_fence
                                    .lifecycle
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .mark_running(&cp_id_clone, lease);
                                if !marked_running {
                                    handle_clone.abort();
                                    return;
                                }
                                // Connection point still exists, register the listener
                                let listener_info = ListenerInfo {
                                    id: cp_id_clone.clone(),
                                    generation: lease.generation,
                                    gateway_id: connection_point_clone
                                        .gateway_id
                                        .clone(),
                                    connection_point_id: connection_point_clone
                                        .id
                                        .clone(),
                                    gateway_did: connection_point_did_clone,
                                    mediator_did: mediator_did_clone,
                                    name: connection_point_clone
                                        .name
                                        .clone(),
                                    cp_type: connection_point_clone
                                        .cp_type
                                        .clone(),
                                    metrics: metrics_clone,
                                    client,
                                };

                                let mut listeners = listeners_clone.write().await;
                                listeners.insert(cp_id_clone.clone(), listener_info);
                                if !delayed_fence.is_current() {
                                    if listeners
                                        .get(&cp_id_clone)
                                        .is_some_and(|listener| listener.generation == lease.generation)
                                    {
                                        listeners.remove(&cp_id_clone);
                                    }
                                    handle_clone.abort();
                                    return;
                                }
                                {
                                    let mut idx = gateway_index_clone
                                        .write()
                                        .await;
                                    idx.insert(
                                        connection_point_clone
                                            .gateway_id
                                            .clone(),
                                        cp_id_clone.clone(),
                                    );
                                }
                                info!(
                                    "WebSocket listener registered after delayed connection for connection point '{}'",
                                    connection_point_clone.name
                                );
                            }
                            Ok(None) => {
                                warn!(
                                    "Connection point '{}' was deleted while establishing connection, not registering listener",
                                    cp_id_clone
                                );
                                handle_clone.abort();
                                delayed_fence
                                    .lifecycle
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .release_start(&cp_id_clone, lease);
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to verify connection point '{}' exists: {}, not registering listener",
                                    cp_id_clone, e
                                );
                                handle_clone.abort();
                                delayed_fence
                                    .lifecycle
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .release_start(&cp_id_clone, lease);
                            }
                        }
                    }
                });

                // Return OK - listener will be registered when connection succeeds
                info!(
                    "WebSocket listener task started for connection point '{}' (waiting for connection)",
                    connection_point.name
                );
                return Ok(());
            }
        };

        // Store listener info
        let marked_running = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .mark_running(&cp_id, lease);
        if !marked_running {
            abort_handle.abort();
            return Err("Listener generation became stale before registration".to_string());
        }

        let listener_info = ListenerInfo {
            id: cp_id.clone(),
            generation: lease.generation,
            gateway_id: connection_point
                .gateway_id
                .clone(),
            connection_point_id: connection_point.id.clone(),
            gateway_did: connection_point_did.clone(), // Store connection point DID
            mediator_did: mediator_did.clone(),
            name: connection_point.name.clone(),
            cp_type: connection_point
                .cp_type
                .clone(),
            metrics: Arc::clone(&metrics),
            client,
        };

        let mut listeners = self.listeners.write().await;
        listeners.insert(cp_id.clone(), listener_info);
        if !fence.is_current() {
            if listeners
                .get(&cp_id)
                .is_some_and(|listener| listener.generation == lease.generation)
            {
                listeners.remove(&cp_id);
            }
            abort_handle.abort();
            return Err("Listener generation became stale during registration".to_string());
        }
        {
            let mut idx = self
                .gateway_index
                .write()
                .await;
            idx.insert(
                connection_point
                    .gateway_id
                    .clone(),
                cp_id.clone(),
            );
        }

        info!("WebSocket listener started successfully for connection point '{}'", connection_point.name);
        Ok(())
    }

    /// Stop a WebSocket listener for a connection point
    pub async fn stop_listener(
        &self,
        connection_point_id: &str,
    ) -> Result<(), String> {
        let (lease, task) = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .begin_stop(connection_point_id)
            .ok_or_else(|| format!("No listener found for connection point {connection_point_id}"))?;

        if let Some(task) = &task {
            task.abort();
        }

        let listener = self
            .listeners
            .read()
            .await
            .get(connection_point_id)
            .filter(|listener| listener.generation == lease.generation)
            .cloned();
        if let Some(listener) = &listener {
            info!("Stopping WebSocket listener for connection point '{}'", listener.name);
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                listener
                    .client
                    .atm()
                    .graceful_shutdown(),
            )
            .await;
        }

        if let Some(mut task) = task
            && tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }

        let removed = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .finish_stop(connection_point_id, lease);
        if removed {
            let mut listeners = self.listeners.write().await;
            let gateway_id = listeners
                .get(connection_point_id)
                .filter(|listener| listener.generation == lease.generation)
                .map(|listener| listener.gateway_id.clone());
            if gateway_id.is_some() {
                listeners.remove(connection_point_id);
            }
            drop(listeners);
            if let Some(gateway_id) = gateway_id {
                let mut idx = self
                    .gateway_index
                    .write()
                    .await;
                if idx
                    .get(&gateway_id)
                    .is_some_and(|id| id == connection_point_id)
                {
                    idx.remove(&gateway_id);
                }
            }
        }
        Ok(())
    }

    /// Restart a connection point's listener whose mediator session the caller
    /// found unusable (the mediator no longer has its account), so it
    /// re-authenticates and re-applies its ACL. Only listener `generation` is
    /// restarted: a listener another caller already replaced, or one that has
    /// been stopped, is left as it is.
    pub async fn restart_listener_if_current(
        &self,
        connection_point_id: &str,
        generation: u64,
    ) -> Result<(), String> {
        let is_current = self
            .listeners
            .read()
            .await
            .get(connection_point_id)
            .is_some_and(|listener| listener.generation == generation);
        if !is_current {
            return Ok(());
        }

        let connection_point = self
            .cp_store
            .get(connection_point_id)
            .await
            .map_err(|e| format!("Failed to load connection point '{connection_point_id}': {e}"))?
            .ok_or_else(|| format!("Connection point '{connection_point_id}' not found"))?;
        let (mediator_did, _) = self
            .connection_point_mediator(&connection_point)
            .await?;
        let config = self
            .bootstrap_config
            .clone()
            .ok_or_else(|| "Bootstrap config not available".to_string())?;

        self.stop_listener(connection_point_id)
            .await?;
        self.start_listener(&connection_point, mediator_did, config)
            .await
    }

    /// Update the name of a listener (when connection point is renamed)
    pub async fn update_listener_name(
        &self,
        connection_point_id: &str,
        new_name: String,
    ) -> Result<(), String> {
        let mut listeners = self.listeners.write().await;

        if let Some(listener) = listeners.get_mut(connection_point_id) {
            let old_name = listener.name.clone();
            listener.name = new_name.clone();
            info!("Updated listener name from '{}' to '{}'", old_name, new_name);
            Ok(())
        } else {
            Err(format!("No listener found for connection point {}", connection_point_id))
        }
    }

    /// Refresh the stored ATM/profile handles for a listener after a reconnect.
    ///
    /// The supervision loop calls this on every reconnect so outbound sends
    /// (e.g. `get_atm_for_connection_point` / `get_atm_for_mediator`) and any
    /// related services use the live re-authenticated socket rather than the
    /// dead one from before the drop. No-ops if the listener is not registered.
    pub async fn update_listener_client(
        &self,
        connection_point_id: &str,
        client: DIDCommClient,
    ) {
        let mut listeners = self.listeners.write().await;
        if let Some(listener) = listeners.get_mut(connection_point_id) {
            listener.client = client;
            debug!("Refreshed stored DIDComm client for connection point '{}'", listener.name);
        }
    }

    /// Get information about active listeners
    pub async fn get_active_listeners(&self) -> Vec<ListenerInfo> {
        let listeners = self.listeners.read().await;
        listeners
            .values()
            .cloned()
            .collect()
    }

    /// Reconcile active listeners against the connection-point and gateway
    /// stores, stopping (and de-registering) any listener whose connection point
    /// no longer exists, is disabled, or has expired, or whose gateway has been
    /// disabled. Called during hot reload so a protocol/status change never
    /// leaves a stale transit-point serving path. Returns the number stopped.
    ///
    /// This only *removes* stale listeners; (re)starting listeners for newly
    /// added or re-enabled connection points remains owned by the connection
    /// point CRUD handlers and the startup auto-start, which resolve the
    /// mediator DID/URL required to start a listener.
    pub async fn reconcile_listeners(&self) -> usize {
        // Desired connection-point state (source of truth for serving).
        let cps = match self.cp_store.list_all().await {
            Ok(cps) => cps,
            Err(e) => {
                warn!("reconcile_listeners: failed to list connection points ({}); skipping reconciliation", e);
                return 0;
            }
        };
        let now = Utc::now();
        let cp_by_id: HashMap<String, &GatewayConnectionPoint> = cps
            .iter()
            .map(|cp| (cp.id.clone(), cp))
            .collect();

        // Gateways explicitly disabled must not serve; look them up once.
        let disabled_gateways: std::collections::HashSet<String> = match &self.gateway_store {
            Some(store) => match store.list_all().await {
                Ok(gws) => gws
                    .into_iter()
                    .filter(|g| g.status == crate::gateways::types::GatewayStatus::Disabled)
                    .map(|g| g.id)
                    .collect(),
                Err(e) => {
                    warn!(
                        "reconcile_listeners: failed to list gateways ({}); proceeding without gateway-status checks",
                        e
                    );
                    std::collections::HashSet::new()
                }
            },
            None => std::collections::HashSet::new(),
        };

        let cp_state: HashMap<String, (bool, Option<DateTime<Utc>>)> = cp_by_id
            .iter()
            .map(|(id, cp)| (id.clone(), (cp.enabled, cp.expires_at)))
            .collect();
        let running: HashMap<String, ListenerInfo> = self
            .get_active_listeners()
            .await
            .into_iter()
            .map(|listener| {
                (
                    listener
                        .connection_point_id
                        .clone(),
                    listener,
                )
            })
            .collect();
        let tracked: Vec<(String, String)> = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ids()
            .into_iter()
            .map(|id| {
                let gateway_id = cp_by_id
                    .get(&id)
                    .map(|cp| cp.gateway_id.clone())
                    .or_else(|| {
                        running
                            .get(&id)
                            .map(|listener| listener.gateway_id.clone())
                    })
                    .unwrap_or_default();
                (id, gateway_id)
            })
            .collect();

        let mut stopped = 0usize;
        for (cp_id, reason) in listeners_to_stop(&tracked, &cp_state, &disabled_gateways, now) {
            info!("reconcile_listeners: stopping listener for connection point '{}' ({})", cp_id, reason);
            if reason == "connection point has expired"
                && let Some(listener) = running.get(&cp_id)
                && let Err(error) =
                    set_acl_to_deny_all(listener.client.atm().as_ref(), Arc::clone(listener.client.profile())).await
            {
                warn!("reconcile_listeners: failed to revoke expired listener '{}': {}", cp_id, error);
                continue;
            }
            match self
                .stop_listener(&cp_id)
                .await
            {
                Ok(()) => {
                    stopped += 1;
                    if reason == "connection point has expired"
                        && cp_by_id
                            .get(&cp_id)
                            .is_some_and(|cp| cp.cp_type == super::types::ConnectionPointType::System)
                    {
                        if let Err(error) = self
                            .cp_store
                            .delete(&cp_id)
                            .await
                        {
                            warn!(
                                "reconcile_listeners: failed to delete expired temporary connection point '{}': {}",
                                cp_id, error
                            );
                        }
                        if let Some(config) = &self.bootstrap_config {
                            let directory = std::path::Path::new(
                                &config
                                    .storage_paths
                                    .connection_points,
                            )
                            .join(&cp_id);
                            if let Err(error) = tokio::fs::remove_dir_all(&directory).await
                                && error.kind() != std::io::ErrorKind::NotFound
                            {
                                warn!(
                                    "reconcile_listeners: failed to remove expired temporary DID directory '{}': {}",
                                    cp_id, error
                                );
                            }
                        }
                    }
                }
                Err(e) => warn!("reconcile_listeners: failed to stop listener '{}': {}", cp_id, e),
            }
        }
        if stopped > 0 {
            info!("reconcile_listeners: stopped {} stale listener(s)", stopped);
        }
        stopped
    }

    /// Get listener info for a specific gateway or connection point ID
    pub async fn get_listener(
        &self,
        id: &str,
    ) -> Option<ListenerInfo> {
        let listeners = self.listeners.read().await;
        // Try as connection point ID first.
        if let Some(listener) = listeners.get(id) {
            return Some(listener.clone());
        }
        // Otherwise resolve the gateway_id → connection_point_id mapping
        // (O(1) via the secondary index) instead of linear-scanning all
        // listeners.
        let idx = self
            .gateway_index
            .read()
            .await;
        if let Some(cp_id) = idx.get(id)
            && let Some(listener) = listeners.get(cp_id)
        {
            return Some(listener.clone());
        }
        None
    }

    /// Get ATM instance for a specific connection point
    #[allow(dead_code)]
    pub async fn get_atm_for_connection_point(
        &self,
        connection_point_id: &str,
    ) -> Option<(Arc<ATM>, Arc<ATMProfile>)> {
        let listeners = self.listeners.read().await;
        listeners
            .get(connection_point_id)
            .map(|info| (Arc::clone(info.client.atm()), Arc::clone(info.client.profile())))
    }

    /// Get the remote gateway DID for a gateway ID
    pub async fn get_gateway_did(
        &self,
        gateway_id: &str,
    ) -> Option<String> {
        if let Some(ref store) = self.gateway_store {
            store
                .get(gateway_id)
                .await
                .ok()
                .flatten()
                .map(|gw| gw.did)
        } else {
            None
        }
    }

    /// Get ATM instance for a mediator (uses first connection point with that mediator)
    #[allow(dead_code)]
    pub async fn get_atm_for_mediator(
        &self,
        mediator_id: &str,
    ) -> Option<(Arc<ATM>, Arc<ATMProfile>, String)> {
        let listeners = self.listeners.read().await;
        for info in listeners.values() {
            if info.mediator_did == mediator_id {
                return Some((Arc::clone(info.client.atm()), Arc::clone(info.client.profile()), info.id.clone()));
            }
        }
        None
    }

    /// Get the DID cache
    pub fn get_did_cache(&self) -> Arc<crate::gateways::did_cache::DIDCache> {
        Arc::clone(&self.did_cache)
    }

    /// Stop all listeners (for shutdown)
    #[allow(dead_code)]
    pub async fn stop_all_listeners(&self) {
        let ids = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ids();
        for id in ids {
            if let Err(error) = self.stop_listener(&id).await {
                warn!("Failed to stop listener '{id}': {error}");
            }
        }
    }
}

/// Run a WebSocket listener for a connection point
/// This is the main task that maintains the WebSocket connection and processes messages
/// Uses the connection point's unique DID (not the gateway DID) to avoid duplicate connections
#[instrument(name = "connection_point.ws_listener", skip_all, fields(cp.name = %connection_point.name, cp.did = %connection_point_did, mediator = %mediator_did))]
async fn run_websocket_listener<CS: super::ConnectionPointStore + 'static>(
    connection_point: &GatewayConnectionPoint,
    connection_point_did: &str, // Connection point's unique DID
    mediator_did: &str,
    secrets: Vec<Secret>,
    message_store: Arc<MessageStore>,
    metrics: Arc<RwLock<ConnectionPointMetrics>>,
    atm_sender: tokio::sync::mpsc::Sender<DIDCommClient>,
    gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    pending_connection_store: Option<Arc<crate::gateways::PendingConnectionStore>>,
    notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    bootstrap_config: Option<Arc<crate::config::BootstrapConfig>>,
    cp_store: Option<Arc<CS>>,
    manager_weak: Option<std::sync::Weak<ConnectionPointListenerManager>>,
    fence: ListenerFence,
) -> Result<(), String> {
    fence.ensure_current()?;
    info!(
        "Initializing WebSocket listener for '{}' (ConnectionPoint DID: {}, Mediator: {})",
        connection_point.name, connection_point_did, mediator_did
    );

    // Create webhook client (reused across reconnections)
    let webhook_client = WebhookClient::new();

    // Reconnect policy: exponential backoff to a cap, then a fixed cadence.
    let reconnect_policy = bootstrap_config
        .as_ref()
        .map(|c| c.reconnect_policy.to_policy())
        .unwrap_or_default();

    // Runtime health for this connection point, embedded on the CP record.
    // Seeded from the persisted value so a restart/failover continues the
    // existing failure streak rather than resetting it.
    let mut runtime = connection_point
        .runtime_status
        .clone()
        .unwrap_or_default();

    // Tracks whether we have already logged the transition into `failed`, so we
    // WARN once on the way down (and periodically), DEBUG on every other
    // attempt, and INFO once on recovery.
    let mut previously_failed = matches!(runtime.status, ConnectionStatus::Failed);

    // Failover / restart: honor the persisted next-retry time so a promotion or
    // restart resumes the existing backoff schedule instead of hammering the
    // mediator immediately (avoids a thundering herd on promotion).
    if let Some(next_retry_at) = runtime.next_retry_at {
        let now = Utc::now();
        if next_retry_at > now {
            let wait = (next_retry_at - now)
                .to_std()
                .unwrap_or_default()
                .min(std::time::Duration::from_secs(reconnect_policy.max_backoff_seconds));
            debug!(
                cp_id = %connection_point.id,
                "Resuming reconnect schedule for '{}'; waiting {}s before first attempt",
                connection_point.name,
                wait.as_secs()
            );
            tokio::time::sleep(wait).await;
        }
    }

    // Only the very first successful connect hands the freshly-created client to
    // the startup path via `atm_sender` (a one-shot channel consumed by
    // `start_listener`). Every later reconnect refreshes the manager's stored
    // client instead so outbound sends keep using the live socket.
    let mut initial_client_sent = false;

    // Supervision loop: (re)connect -> refresh infra -> re-apply ACL -> pump
    // messages. When the message pump returns because the mediator dropped the
    // socket (restart, or an ACL/storage wipe that severs the connection) we
    // loop back and reconnect, which re-applies this connection point's ACL on
    // the mediator so previously-known connections can route again.
    'supervision: loop {
        fence.ensure_current()?;
        // Connect with policy-driven backoff, recording runtime health on each
        // failed attempt so the connection point surfaces as failed with a
        // reason and a next-retry time.
        let client = loop {
            match create_atm_instance(
                connection_point,
                connection_point_did,
                mediator_did,
                &secrets,
                bootstrap_config.as_ref(),
            )
            .await
            {
                Ok(client) => break client,
                Err(e) => {
                    let now = Utc::now();
                    let code = crate::comm::connection_health::classify_error(&e);
                    runtime.record_failure(now, code, code.message(), e.as_str());
                    runtime.schedule_retry(now, &reconnect_policy);
                    let backoff = runtime
                        .current_backoff_seconds
                        .unwrap_or(reconnect_policy.initial_backoff_seconds);

                    {
                        let mut m = metrics.write().await;
                        m.status = ConnectionStatus::Reconnecting;
                        m.reconnect_attempts = runtime.consecutive_failures;
                        m.error_count = m
                            .error_count
                            .saturating_add(1);
                    }

                    persist_cp_runtime_status(&cp_store, &connection_point.id, &runtime).await;

                    // Log noise control: WARN once on the transition into failed
                    // and then only every RECONNECT_SUMMARY_EVERY attempts; DEBUG
                    // for the per-attempt detail in between.
                    let is_transition = !previously_failed;
                    previously_failed = true;
                    let is_summary = runtime
                        .consecutive_failures
                        .is_multiple_of(RECONNECT_SUMMARY_EVERY);
                    let next_retry_at = runtime
                        .next_retry_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default();

                    if is_transition || is_summary {
                        warn!(
                            gateway_id = %connection_point.gateway_id,
                            cp_id = %connection_point.id,
                            mediator_did = %mediator_did,
                            error_code = ?code,
                            backoff_seconds = backoff,
                            next_retry_at = %next_retry_at,
                            consecutive_failures = runtime.consecutive_failures,
                            authorization_error = is_authorization_error(&e),
                            "Connection point '{}' cannot connect: {} ({})",
                            connection_point.name, code.message(), e
                        );
                    } else {
                        debug!(
                            gateway_id = %connection_point.gateway_id,
                            cp_id = %connection_point.id,
                            mediator_did = %mediator_did,
                            error_code = ?code,
                            backoff_seconds = backoff,
                            "Connection point '{}' retry attempt {} failed: {}",
                            connection_point.name, runtime.consecutive_failures, e
                        );
                    }

                    tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                }
            }
        };

        fence.ensure_current()?;
        let acl_connection_point = match &cp_store {
            Some(store) => store
                .get(&connection_point.id)
                .await
                .map_err(|error| format!("Failed to load listener ACL state: {error}"))?
                .ok_or_else(|| "Connection point was removed before ACL enforcement".to_string())?,
            None => connection_point.clone(),
        };
        let acl_intent = mediator_acl_intent(&acl_connection_point);
        if let Err(error) =
            apply_mediator_acl_intent(&acl_intent, client.atm().as_ref(), Arc::clone(client.profile())).await
        {
            warn!(
                cp_id = %connection_point.id,
                "Mediator ACL enforcement failed closed: {error}"
            );
            let now = Utc::now();
            runtime.record_failure(
                now,
                crate::comm::connection_health::ConnectionErrorCode::AuthenticationFailed,
                "Mediator ACL enforcement failed",
                &error,
            );
            runtime.schedule_retry(now, &reconnect_policy);
            persist_cp_runtime_status(&cp_store, &connection_point.id, &runtime).await;
            client
                .atm()
                .graceful_shutdown()
                .await;
            tokio::time::sleep(Duration::from_secs(
                runtime
                    .current_backoff_seconds
                    .unwrap_or(reconnect_policy.initial_backoff_seconds),
            ))
            .await;
            continue 'supervision;
        }

        fence.ensure_current()?;
        // Hand the client to the startup path on the first connect, or refresh
        // the manager's stored client on reconnects so callers use the live
        // socket rather than the dead one from before the drop.
        if !initial_client_sent {
            let _ = atm_sender
                .send(client.clone())
                .await;
            initial_client_sent = true;
        } else if let Some(manager) = manager_weak
            .as_ref()
            .and_then(|weak| weak.upgrade())
        {
            manager
                .update_listener_client(&connection_point.id, client.clone())
                .await;
        }

        fence.ensure_current()?;

        info!("✓ WebSocket connection established for connection point '{}'", connection_point.name);
        info!("  Connection Point DID: {}", connection_point_did);
        info!("  Mediator: {}", mediator_did);

        // Update metrics: connection successful
        {
            let mut m = metrics.write().await;
            m.status = ConnectionStatus::Connected;
            m.reconnect_attempts = 0;
        }

        // INFO once on recovery (failed -> active), then persist healthy runtime
        // status onto the connection point record.
        if previously_failed {
            info!(
                gateway_id = %connection_point.gateway_id,
                cp_id = %connection_point.id,
                mediator_did = %mediator_did,
                recovered_after_failures = runtime.consecutive_failures,
                "Connection point '{}' reconnected after {} failed attempt(s)",
                connection_point.name, runtime.consecutive_failures
            );
        }
        previously_failed = false;
        runtime.mark_active(Utc::now());
        persist_cp_runtime_status(&cp_store, &connection_point.id, &runtime).await;

        fence.ensure_current()?;
        // Pump messages until the connection drops or errors.
        match process_messages(
            connection_point,
            connection_point_did, // Use connection point DID
            client.atm().as_ref(),
            client.profile(),
            &message_store,
            &webhook_client,
            &metrics,
            &gateway_store,
            &pending_connection_store,
            &notification_store,
            &bootstrap_config,
            &cp_store,
            &manager_weak,
            mediator_did,
        )
        .await
        {
            Ok(()) => {
                info!("Message loop for connection point '{}' ended cleanly; stopping listener", connection_point.name);
                // Close the socket cleanly so it doesn't linger as a zombie.
                client
                    .atm()
                    .graceful_shutdown()
                    .await;
                return Ok(());
            }
            Err(e) => {
                let now = Utc::now();
                let code = crate::comm::connection_health::classify_error(&e);
                runtime.record_failure(now, code, code.message(), e.as_str());
                runtime.schedule_retry(now, &reconnect_policy);
                let backoff = runtime
                    .current_backoff_seconds
                    .unwrap_or(reconnect_policy.initial_backoff_seconds);

                {
                    let mut m = metrics.write().await;
                    m.status = ConnectionStatus::Reconnecting;
                    m.error_count = m
                        .error_count
                        .saturating_add(1);
                }

                persist_cp_runtime_status(&cp_store, &connection_point.id, &runtime).await;

                let is_transition = !previously_failed;
                previously_failed = true;
                if is_authorization_error(&e) {
                    warn!(
                        gateway_id = %connection_point.gateway_id,
                        cp_id = %connection_point.id,
                        error_code = ?code,
                        backoff_seconds = backoff,
                        "Mediator rejected traffic for connection point '{}': {}. It may have lost this DID's ACL; reconnecting and re-applying ACL.",
                        connection_point.name, e
                    );
                } else if is_transition {
                    warn!(
                        gateway_id = %connection_point.gateway_id,
                        cp_id = %connection_point.id,
                        mediator_did = %mediator_did,
                        error_code = ?code,
                        backoff_seconds = backoff,
                        "Connection lost for connection point '{}': {}. Reconnecting in {}s...",
                        connection_point.name, e, backoff
                    );
                } else {
                    debug!(
                        cp_id = %connection_point.id,
                        error_code = ?code,
                        backoff_seconds = backoff,
                        "Connection lost for connection point '{}': {}. Reconnecting.",
                        connection_point.name, e
                    );
                }

                // Gracefully close the old socket BEFORE reconnecting. Dropping
                // the client is not enough: the SDK keeps a background websocket
                // task (with its own auto-reconnect) alive, so a new connection
                // for the same DID makes the mediator terminate the pair in a
                // `w.websocket.duplicate-channel` loop. Shutting down first
                // guarantees only one socket exists for this DID at a time.
                client
                    .atm()
                    .graceful_shutdown()
                    .await;
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
            }
        }
    }
}

/// Sole writer of `runtime_status` on the connection point record.
///
/// Load-modify-saves so concurrent operator edits to other CP fields are
/// preserved. Silently no-ops if the store is absent or the record was deleted
/// mid-flight (the connection point may be gone by the time a failure is
/// recorded).
async fn persist_cp_runtime_status<CS: super::ConnectionPointStore + 'static>(
    cp_store: &Option<Arc<CS>>,
    cp_id: &str,
    runtime: &crate::comm::connection_health::ConnectionRuntimeStatus,
) {
    let Some(store) = cp_store else {
        return;
    };
    match store.get(cp_id).await {
        Ok(Some(mut cp)) => {
            cp.runtime_status = Some(runtime.clone());
            if let Err(e) = store.update(&cp).await {
                debug!(cp_id = %cp_id, "Failed to persist connection point runtime status: {}", e);
            }
        }
        Ok(None) => {
            // Connection point was deleted mid-flight; nothing to persist.
        }
        Err(e) => {
            debug!(cp_id = %cp_id, "Failed to load connection point to persist runtime status: {}", e);
        }
    }
}

/// Best-effort classification of a mediator error string as an authorization /
/// ACL rejection (blocked, forbidden, unauthorized). Used only for clearer
/// operator logging when a mediator has lost this DID's ACL — it never changes
/// control flow.
pub(crate) fn is_authorization_error(error: &str) -> bool {
    let lower = error.to_lowercase();
    lower.contains("forbidden")
        || lower.contains("unauthorized")
        || lower.contains("unauthorised")
        || lower.contains("blocked")
        || lower.contains("not local")
        || lower.contains("401")
        || lower.contains("403")
}

/// Create ATM instance and establish WebSocket connection
/// This should only be called ONCE per connection point to avoid duplicate connections
async fn create_atm_instance(
    connection_point: &GatewayConnectionPoint,
    connection_point_did: &str,
    mediator_did: &str,
    secrets: &[Secret],
    bootstrap_config: Option<&Arc<crate::config::BootstrapConfig>>,
) -> Result<DIDCommClient, String> {
    debug!("Configuring DIDComm client for connection point with mediator: {}", mediator_did);

    // Apply SDK inbound-cache tuning when bootstrap config is available. The
    // upstream defaults (100 msgs / 10MB) are too small under load and cause
    // the WS handler to stop reading the socket once the cache fills, which
    // in turn cascades into mediator backpressure on the sender.
    let cache_config = bootstrap_config.map(|cfg| CacheConfig {
        inbound_cache_count: cfg
            .a2a
            .sdk_inbound_cache_count,
        inbound_cache_bytes: cfg
            .a2a
            .sdk_inbound_cache_bytes,
    });

    info!("Creating DIDComm client with mediator: {}", mediator_did);
    info!("Note: ATM library may log errors during DID resolution but has retry/fallback logic");
    debug!("  ↳ Connection point DID: {}", connection_point_did);
    debug!("  ↳ Connection point name: {}", connection_point.name);

    // Build the client (TDK state + ATM + profile) with the connection point's
    // own DID; then enable the WebSocket (live_stream=true).
    let mut client = DIDCommClient::new_with_cache_config(
        connection_point_did.to_string(),
        secrets.to_vec(),
        Some(mediator_did.to_string()),
        Some(connection_point.name.clone()),
        cache_config.as_ref(),
    )
    .await?;

    info!("Adding profile to ATM with WebSocket enabled...");
    client
        .enable_websocket()
        .await?;

    Ok(client)
}

/// Dispatch a single non-OOB message from a spawned task and respond if needed.
///
/// This is the body of the per-message work for messages that do NOT mutate
/// the listener manager (i.e. everything other than the connection-protocol
/// OOB messages, which must stay on the WS reader task because their handlers
/// can stop/replace this very listener).
async fn dispatch_simple_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    connection_point_did: &str,
    connection_point_id: &str,
    connection_point_name: &str,
    received_msg: ReceivedMessage,
) {
    let dispatch_context =
        crate::messages::DispatchContext::new(&received_msg).with_connection_point(connection_point_id.to_string());

    match crate::messages::dispatch_message(&received_msg, dispatch_context).await {
        message_processor::ProcessingResult::RequiresResponse { response_type, response_body } => {
            info!("Message processing requires response: {} (cp '{}')", response_type, connection_point_name);
            if let Err(e) =
                send_response_message(atm, profile, connection_point_did, &received_msg, &response_type, response_body)
                    .await
            {
                error!("Failed to send response message: {}", e);
            } else {
                info!("✓ Response message sent successfully");
            }
        }
        message_processor::ProcessingResult::ProcessedNoResponse => {
            debug!("Message processed successfully with no response needed");
        }
        message_processor::ProcessingResult::Stored => {
            debug!("Message stored without processing (unknown type)");
        }
        message_processor::ProcessingResult::Failed { reason } => {
            warn!("Message processing failed: {}", reason);
        }
        // Connection-protocol OOB results should never arrive here because
        // the caller classifies on message type and routes them inline.
        // Surface as a warning if it ever does so we don't silently drop.
        other => {
            warn!(
                "Spawned dispatch produced unexpected OOB result on cp '{}': {:?}",
                connection_point_name,
                std::mem::discriminant(&other)
            );
        }
    }
}

/// Send a response message back to the sender
async fn send_response_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    our_did: &str,
    original_message: &ReceivedMessage,
    response_type: &str,
    response_body: serde_json::Value,
) -> Result<(), String> {
    use affinidi_messaging_didcomm::Message as DIDCommMessage;

    // Get the sender's DID from the original message
    let recipient_did = original_message
        .from_did
        .as_ref()
        .ok_or_else(|| "Original message has no 'from' DID".to_string())?;

    // Create the response message
    let response_msg =
        DIDCommMessage::build(uuid::Uuid::new_v4().to_string(), response_type.to_string(), response_body)
            .from(our_did.to_string())
            .to(recipient_did.clone())
            .thid(
                original_message
                    .didcomm_message_id
                    .clone(),
            )
            .finalize();

    debug!("Response message created: {:?}", response_msg);

    // Pack the message encrypted
    let packed_message = atm
        .pack_encrypted(&response_msg, recipient_did, Some(our_did), Some(our_did))
        .await
        .map_err(|e| format!("Failed to pack response message: {:?}", e))?;

    debug!("Response message packed ({} bytes)", packed_message.0.len());

    // Send via ATM send_message
    atm.send_message(
        profile,
        &packed_message.0,
        &response_msg.id,
        false, // Don't wait for response
        false, // Don't auto-delete
    )
    .await
    .map_err(|e| format!("Failed to send response message: {:?}", e))?;

    Ok(())
}

async fn delete_message_after_processing(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    message_sha256_hash: &str,
    connection_point_name: &str,
) {
    if let Err(e) = atm
        .delete_message_background(profile, message_sha256_hash)
        .await
    {
        warn!(
            "Failed to delete processed message '{}' for connection point '{}': {:?}",
            message_sha256_hash, connection_point_name, e
        );
    }
}

/// The surfaces a peer may reach through `connection_point_id`, read from the
/// listener's live stores so an exposure change applies to the next message.
async fn resolve_surface_exposure<CS: super::ConnectionPointStore>(
    cp_store: &Option<Arc<CS>>,
    gateway_store: &Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    connection_point_id: &str,
) -> Result<message_processor::SurfaceExposure, String> {
    let cp_store = cp_store
        .as_ref()
        .ok_or("connection point storage is not available")?;
    let gateway_store = gateway_store
        .as_ref()
        .ok_or("gateway storage is not available")?;
    let connection_point = cp_store
        .get(connection_point_id)
        .await
        .map_err(|e| format!("Failed to load connection point: {e}"))?
        .ok_or_else(|| format!("Connection point {connection_point_id} not found"))?;
    let gateway = gateway_store
        .get(&connection_point.gateway_id)
        .await
        .map_err(|e| format!("Failed to load gateway: {e}"))?
        .ok_or_else(|| format!("Gateway {} not found", connection_point.gateway_id))?;
    Ok(message_processor::SurfaceExposure::new(&gateway, &connection_point))
}

/// Process messages from the WebSocket connection in an infinite loop
async fn process_messages<CS: super::ConnectionPointStore + 'static>(
    connection_point: &GatewayConnectionPoint,
    connection_point_did: &str,
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    message_store: &Arc<MessageStore>,
    webhook_client: &WebhookClient,
    metrics: &Arc<RwLock<ConnectionPointMetrics>>,
    gateway_store: &Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    pending_connection_store: &Option<Arc<crate::gateways::PendingConnectionStore>>,
    _notification_store: &Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    bootstrap_config: &Option<Arc<crate::config::BootstrapConfig>>,
    cp_store: &Option<Arc<CS>>,
    manager_weak: &Option<std::sync::Weak<ConnectionPointListenerManager>>,
    mediator_did: &str,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicU64, Ordering};

    // Pre-compute message-context values that are constant for the lifetime of
    // this listener so they are not re-resolved per inbound message.
    let listener_context: Vec<(&'static str, serde_json::Value)> = match bootstrap_config {
        Some(config) => vec![
            (
                "agent_surface_storage_path",
                serde_json::json!(
                    config
                        .storage_paths
                        .agent_surfaces
                ),
            ),
            (
                "marketplace_models_path",
                serde_json::json!(
                    config
                        .config_files
                        .marketplace_models
                ),
            ),
        ],
        None => Vec::new(),
    };

    // ----------------------------------------------------------------------
    // Concurrent-dispatch infrastructure. Without this the WS reader task
    // blocks on the heaviest dispatch (e.g. a forward-request that proxies
    // an HTTP backend via mTLS) before reading the next inbound message,
    // which combined with the SDK's inbound-cache backpressure produces the
    // cascading slowdown observed under fabric-to-fabric load.
    // ----------------------------------------------------------------------
    let max_inflight = bootstrap_config
        .as_ref()
        .map(|c| c.a2a.max_inflight_dispatches)
        .unwrap_or(256);
    let dispatch_semaphore = Arc::new(tokio::sync::Semaphore::new(max_inflight));
    let mut dispatch_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let in_flight = Arc::new(AtomicU64::new(0));

    // Wrap the ATM in an Arc once so spawned dispatch tasks can cheaply own it.
    let atm_shared: Arc<ATM> = Arc::new(atm.clone());
    let connection_point_did_arc: Arc<str> = Arc::from(connection_point_did);
    let connection_point_arc: Arc<GatewayConnectionPoint> = Arc::new(connection_point.clone());

    // Main message receiving loop
    let auto_deleted_received_messages = false;
    let gateway_peer_did = if connection_point.cp_type == super::types::ConnectionPointType::User {
        None
    } else if let Some(store) = gateway_store {
        store
            .get(&connection_point.gateway_id)
            .await
            .map_err(|error| format!("Failed to load established gateway peer: {error}"))?
            .map(|gateway| gateway.did)
    } else {
        None
    };
    let mut invitation_setup_limiter = InvitationSetupRateLimiter::new(Instant::now());
    loop {
        // Wait for the next message from the WebSocket.
        //
        // auto_delete=false: delete only after processing so messages are not
        // dropped before dispatch completes.
        //
        // TODO: retry mechanism.
        match atm
            .message_pickup()
            .live_stream_next(profile, Some(std::time::Duration::from_secs(300)), auto_deleted_received_messages)
            .await
        {
            Ok(Some((message, metadata))) => {
                debug!("Message metadata: from={:?}, encrypted={}", metadata.sign_from, metadata.encrypted);
                debug!("Message.from: {:?}, Message.to: {:?}", message.from, message.to);
                let message_sha256_hash = metadata.sha256_hash.clone();

                // Extract sender DID from message.from field (not from metadata)
                let from_did = message.from.clone();

                // Extract recipient DIDs from message.to field
                let to_dids = if let Some(to_vec) = &message.to {
                    to_vec.clone()
                } else {
                    vec![connection_point_did.to_string()]
                };

                // Create message metadata
                let msg_metadata = MessageMetadata {
                    encrypted: metadata.encrypted,
                    authenticated: metadata.authenticated,
                    from_key: metadata
                        .encrypted_from_kid
                        .clone()
                        .or_else(|| metadata.sign_from.clone()),
                    non_repudiation: metadata.non_repudiation,
                    anonymous_sender: metadata.anonymous_sender,
                    extra: serde_json::to_value(&metadata).unwrap_or(serde_json::json!({})),
                };

                // Create received message
                let mut received_msg = ReceivedMessage::new(
                    connection_point.id.clone(),
                    connection_point
                        .gateway_id
                        .clone(),
                    message.typ.clone(),
                    message.id.clone(),
                    message.thid.clone(),  // Pass thread ID for correlation
                    message.pthid.clone(), // Bind setup to the OOB invitation
                    from_did,              // Use message.from instead of metadata.from_prior_issuer_kid
                    to_dids,
                    message.body.clone(),
                    msg_metadata,
                );

                // Attach pre-computed per-listener context resolved once at
                // process_messages startup.
                for (key, value) in &listener_context {
                    received_msg
                        .context
                        .insert(key.to_string(), value.clone());
                }
                received_msg.receiving_connection_point_did = Some(connection_point_did.to_string());

                let message_type = MessageType::from_str(&received_msg.message_type);
                let now = Utc::now();
                let sender_identity = match authorize_inbound_message(
                    connection_point,
                    &message_type,
                    received_msg
                        .from_did
                        .as_deref(),
                    &received_msg.metadata,
                    gateway_peer_did.as_deref(),
                    now,
                ) {
                    Ok(identity) => identity,
                    Err(reason) => {
                        warn!(
                            connection_point_id = %connection_point.id,
                            message_type = %received_msg.message_type,
                            reason,
                            "Rejecting DIDComm message with unverified sender"
                        );
                        continue;
                    }
                };

                match &sender_identity {
                    SenderIdentity::Authenticated { did, kid } | SenderIdentity::Signed { did, kid } => {
                        received_msg
                            .context
                            .insert("verified_sender_did".to_string(), serde_json::json!(did));
                        received_msg
                            .context
                            .insert("verified_sender_kid".to_string(), serde_json::json!(kid));
                    }
                    SenderIdentity::Anonymous => {}
                }

                if matches!(message_type, MessageType::GetSurfaces | MessageType::ForwardRequest) {
                    match resolve_surface_exposure(cp_store, gateway_store, &connection_point.id).await {
                        Ok(exposure) => {
                            received_msg.context.insert(
                                message_processor::SURFACE_EXPOSURE_CONTEXT_KEY.to_string(),
                                serde_json::json!(exposure),
                            );
                        }
                        Err(reason) => warn!(
                            connection_point_id = %connection_point.id,
                            reason,
                            "Surface exposure not resolved; the message reaches no surface"
                        ),
                    }
                }

                let mut setup_mediator_url = None;
                if matches!(message_type, MessageType::ConnectionSetup) {
                    if !invitation_setup_limiter.allow(Instant::now()) {
                        warn!(
                            connection_point_id = %connection_point.id,
                            "Throttling OOB connection setup"
                        );
                        continue;
                    }
                    let Some(parent_thread_id) = received_msg
                        .didcomm_pthid
                        .as_deref()
                        .filter(|value| value.len() <= 256)
                    else {
                        warn!(connection_point_id = %connection_point.id, "Rejecting OOB setup without a bounded parent thread");
                        continue;
                    };
                    let Some(capability) = received_msg
                        .message_body
                        .get("secret")
                        .and_then(|value| value.as_str())
                        .filter(|value| !value.is_empty() && value.len() <= 256)
                    else {
                        warn!(connection_point_id = %connection_point.id, "Rejecting OOB setup without a bounded capability");
                        continue;
                    };
                    let Some(store) = cp_store else {
                        error!(connection_point_id = %connection_point.id, "Cannot consume OOB invitation without connection point storage");
                        continue;
                    };
                    let Some(manager) = manager_weak
                        .as_ref()
                        .and_then(std::sync::Weak::upgrade)
                    else {
                        error!(connection_point_id = %connection_point.id, "Cannot answer OOB setup without the listener manager");
                        continue;
                    };
                    // Resolved before the invitation is consumed, so a mediator
                    // that cannot be resolved leaves the invitation redeemable.
                    match manager
                        .connection_point_mediator_endpoint(connection_point)
                        .await
                    {
                        Ok(mediator_url) => setup_mediator_url = Some(mediator_url),
                        Err(reason) => {
                            warn!(
                                connection_point_id = %connection_point.id,
                                reason = %reason,
                                "Leaving OOB connection setup unconsumed"
                            );
                            continue;
                        }
                    }
                    if let Err(reason) = store
                        .consume_invitation(&connection_point.id, parent_thread_id, capability, now)
                        .await
                    {
                        warn!(
                            connection_point_id = %connection_point.id,
                            reason = %reason,
                            "Rejecting invalid or replayed OOB connection setup"
                        );
                        continue;
                    }
                    received_msg
                        .context
                        .insert("invitation_capability_consumed".to_string(), serde_json::json!(true));
                    if let Some(body) = received_msg
                        .message_body
                        .as_object_mut()
                    {
                        body.remove("secret");
                    }
                }

                // Store the message
                match message_store
                    .store(&received_msg)
                    .await
                {
                    Ok(_) => {
                        //info!("✓ Stored message {} for connection point '{}'", received_msg.id, connection_point.name);

                        // Update metrics: increment message count and update last activity
                        {
                            let mut m = metrics.write().await;
                            m.message_count += 1;
                            m.last_activity = Some(Utc::now());
                        }

                        // Dispatch the message. Connection-protocol OOB
                        // messages must run inline on the receiving task
                        // because their handlers stop / replace this very
                        // listener; everything else is spawned onto a
                        // bounded JoinSet so a slow HTTP forward cannot
                        // stall the WS reader and back-pressure the SDK
                        // inbound cache.
                        let must_inline = matches!(
                            received_msg
                                .message_type
                                .as_str(),
                            "https://affinidi.com/atm/client-actions/connection-setup"
                                | "https://affinidi.com/atm/client-actions/connection-accepted"
                                | "https://affinidi.com/atm/client-actions/connection-rejected"
                        );

                        if must_inline {
                            let dispatch_context = crate::messages::DispatchContext::new(&received_msg)
                                .with_connection_point(connection_point.id.clone());
                            let mut temporary_point_cleanup = None;

                            match crate::messages::dispatch_message(&received_msg, dispatch_context).await {
                                message_processor::ProcessingResult::RequiresResponse {
                                    response_type,
                                    response_body,
                                } => {
                                    info!("Message processing requires response: {}", response_type);

                                    // Send response message back through mediator
                                    if let Err(e) = send_response_message(
                                        atm,
                                        profile,
                                        connection_point_did,
                                        &received_msg,
                                        &response_type,
                                        response_body,
                                    )
                                    .await
                                    {
                                        error!("Failed to send response message: {}", e);
                                    } else {
                                        info!("✓ Response message sent successfully");
                                    }
                                }
                                message_processor::ProcessingResult::OOBConnectionAccepted {
                                    inviter_temporary_did,
                                    inviter_secure_did,
                                } => {
                                    info!("🎉 OOB connection-accepted received! Finalizing gateway connection...");

                                    // This is the ACCEPTOR side receiving confirmation from INVITER
                                    // Finalize the gateway connection
                                    if let (Some(gw_store), Some(pend_store), Some(config), Some(cps), Some(mgr_weak)) = (
                                        gateway_store,
                                        pending_connection_store,
                                        bootstrap_config,
                                        cp_store,
                                        manager_weak,
                                    ) {
                                        // Need to convert Weak to Arc for the call
                                        if let Some(mgr) = mgr_weak.upgrade() {
                                            match finalize_oob_connection_as_acceptor(
                                                atm,
                                                profile,
                                                &inviter_temporary_did,
                                                &inviter_secure_did,
                                                gw_store,
                                                pend_store,
                                                cps,
                                                &mgr,
                                                mediator_did,
                                            )
                                            .await
                                            {
                                                Ok((gateway, temp_cp_id)) => {
                                                    info!("✓ Gateway {} created successfully!", gateway.id);
                                                    info!("  Gateway DID: {}", gateway.did);
                                                    temporary_point_cleanup = Some((
                                                        Arc::clone(&mgr),
                                                        Arc::clone(cps),
                                                        config
                                                            .storage_paths
                                                            .connection_points
                                                            .clone(),
                                                        temp_cp_id,
                                                    ));
                                                }
                                                Err(e) => {
                                                    error!("❌ Failed to finalize OOB connection: {}", e);
                                                }
                                            }
                                        } else {
                                            warn!(
                                                "Cannot finalize OOB connection: listener manager no longer available"
                                            );
                                        }
                                    } else {
                                        warn!("Cannot finalize OOB connection: missing required stores");
                                    }
                                }
                                message_processor::ProcessingResult::OOBConnectionSetup {
                                    acceptor_temporary_did,
                                    acceptor_secure_did,
                                    invitation_id,
                                } => {
                                    info!("📥 OOB connection-setup received! Processing as INVITER...");

                                    // This is the INVITER side receiving connection-setup from ACCEPTOR
                                    if let (
                                        Some(gw_store),
                                        Some(pend_store),
                                        Some(config),
                                        Some(cp_st),
                                        Some(mediator_url),
                                    ) = (
                                        gateway_store,
                                        pending_connection_store,
                                        bootstrap_config,
                                        cp_store,
                                        setup_mediator_url.as_deref(),
                                    ) {
                                        match handle_oob_connection_setup_as_inviter(
                                            &acceptor_temporary_did,
                                            &acceptor_secure_did,
                                            &invitation_id,
                                            connection_point_did,
                                            atm,
                                            Arc::clone(profile),
                                            gw_store,
                                            pend_store,
                                            _notification_store,
                                            config,
                                            cp_st,
                                            &connection_point.mediator_id,
                                            manager_weak,
                                            mediator_did,
                                            mediator_url,
                                        )
                                        .await
                                        {
                                            Ok(_) => {
                                                info!("✓ Connection-accepted sent successfully!");

                                                // Trigger integration for successful OOB connection attempt
                                                // This only runs when someone successfully connects with the correct secret
                                                info!(
                                                    "🔔 Triggering integration for successful OOB connection attempt"
                                                );
                                                if let Err(e) = webhook_client
                                                    .trigger_integration(connection_point, &received_msg)
                                                    .await
                                                {
                                                    error!(
                                                        "Notifier/webhook delivery failed for connection point '{}': {}",
                                                        connection_point.name, e
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                error!("❌ Failed to process connection-setup as inviter: {}", e);
                                                // Do NOT trigger integration on failed connection attempts (wrong secret, etc.)
                                            }
                                        }
                                    } else {
                                        warn!("Cannot process OOB connection-setup: missing required stores");
                                    }
                                }
                                message_processor::ProcessingResult::OOBConnectionRejected { reason } => {
                                    error!("❌ OOB connection-rejected received! Reason: {}", reason);

                                    // The peer refused the connection (e.g. it is at its gateway or
                                    // connection-point limit). Fail the local pending gateway and drop
                                    // the pending connection so the aborted attempt neither lingers nor
                                    // holds quota on this side.
                                    use crate::gateways::filesystem::GatewayStore as _;
                                    match received_msg
                                        .from_did
                                        .as_deref()
                                    {
                                        Some(peer_did) => {
                                            if let Some(gw_store) = gateway_store {
                                                match gw_store
                                                    .get_by_did(peer_did)
                                                    .await
                                                {
                                                    Ok(Some(mut gateway)) => {
                                                        gateway.status = crate::gateways::types::GatewayStatus::Failed;
                                                        gateway.description =
                                                            format!("Connection rejected: {}", reason);
                                                        gateway.updated_at = Utc::now();
                                                        if let Err(e) = gw_store
                                                            .update(&gateway)
                                                            .await
                                                        {
                                                            error!("Failed to mark rejected gateway as Failed: {}", e);
                                                        } else {
                                                            info!(
                                                                "✓ Gateway {} marked Failed after rejection",
                                                                gateway.id
                                                            );
                                                        }
                                                    }
                                                    Ok(None) => warn!(
                                                        "No pending gateway found for rejected connection from {}",
                                                        peer_did
                                                    ),
                                                    Err(e) => {
                                                        error!("Failed to look up rejected gateway: {}", e)
                                                    }
                                                }
                                            }
                                            if let Some(pend_store) = pending_connection_store
                                                && let Some(pending_conn) = pend_store
                                                    .get_by_temporary_did(peer_did)
                                                    .await
                                            {
                                                pend_store
                                                    .remove(&pending_conn.id)
                                                    .await;
                                                info!("✓ Removed pending connection after rejection");
                                            }
                                        }
                                        None => warn!("Cannot clean up rejected connection: message has no sender DID"),
                                    }
                                }
                                message_processor::ProcessingResult::ProcessedNoResponse => {
                                    debug!("Message processed successfully with no response needed");
                                }
                                message_processor::ProcessingResult::Stored => {
                                    debug!("Message stored without processing (unknown type)");
                                }
                                message_processor::ProcessingResult::Failed { reason } => {
                                    warn!("Message processing failed: {}", reason);
                                }
                            }

                            delete_message_after_processing(atm, profile, &message_sha256_hash, &connection_point.name)
                                .await;

                            // The temporary listener is this task, and stopping it aborts
                            // the task, so the cleanup runs on its own task after the ack.
                            if let Some((mgr, cps, connection_points_root, temp_cp_id)) = temporary_point_cleanup {
                                tokio::spawn(async move {
                                    remove_temporary_connection_point(
                                        &mgr,
                                        cps.as_ref(),
                                        &connection_points_root,
                                        &temp_cp_id,
                                    )
                                    .await;
                                });
                            }
                        } else {
                            // Spawn the dispatch onto a bounded JoinSet so
                            // heavy proxy work cannot stall the WS reader.
                            let permit = match Arc::clone(&dispatch_semaphore)
                                .acquire_owned()
                                .await
                            {
                                Ok(p) => p,
                                Err(_) => {
                                    error!(
                                        "Dispatch semaphore closed for connection point '{}'",
                                        connection_point.name
                                    );
                                    continue;
                                }
                            };

                            let new_inflight = in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                            {
                                let mut m = metrics.write().await;
                                m.in_flight_dispatches = new_inflight;
                                if new_inflight > m.max_in_flight_dispatches {
                                    m.max_in_flight_dispatches = new_inflight;
                                }
                            }

                            let atm_c = Arc::clone(&atm_shared);
                            let profile_c = profile.clone();
                            let cp_did_c = Arc::clone(&connection_point_did_arc);
                            let cp_id_c = connection_point_arc
                                .id
                                .clone();
                            let cp_name_c = connection_point_arc
                                .name
                                .clone();
                            let message_sha256_hash_c = message_sha256_hash.clone();
                            let metrics_c = Arc::clone(metrics);
                            let in_flight_c = Arc::clone(&in_flight);
                            let received_msg_c = received_msg.clone();

                            dispatch_set.spawn(async move {
                                let _permit = permit; // released on drop
                                let _decrement = scopeguard::guard((in_flight_c, metrics_c), |(c, _m)| {
                                    c.fetch_sub(1, Ordering::Relaxed);
                                });

                                dispatch_simple_message(
                                    &atm_c,
                                    &profile_c,
                                    &cp_did_c,
                                    &cp_id_c,
                                    &cp_name_c,
                                    received_msg_c,
                                )
                                .await;
                                delete_message_after_processing(&atm_c, &profile_c, &message_sha256_hash_c, &cp_name_c)
                                    .await;
                            });

                            // Reap any completed dispatch tasks so the
                            // JoinSet does not grow unboundedly.
                            while dispatch_set
                                .try_join_next()
                                .is_some()
                            {}
                        }

                        // Note: integrations are ONLY triggered on successful OOB connection setup
                        // (see OOBConnectionSetup handler above - around line 905)
                        // This prevents spam from health checks, pings, and other DIDComm messages
                    }
                    Err(e) => {
                        error!("Failed to store message for connection point '{}': {:?}", connection_point.name, e);
                    }
                }

                debug!("Message body: {}", serde_json::to_string_pretty(&message.body).unwrap_or_default());
            }
            Ok(None) => {
                debug!("No message received within timeout for connection point '{}'", connection_point.name);
                // Continue waiting for messages
                continue;
            }
            Err(e) => {
                // Return error to trigger reconnection
                return Err(format!("Error receiving message: {:?}", e));
            }
        }
    }
}

/// Pack and send a `connection-rejected` OOB message to a peer over the given ATM profile.
///
/// Best-effort: pack/send failures are logged, not propagated, so the caller can still
/// abort its own side of the handshake.
async fn send_oob_connection_rejected(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    our_did: &str,
    their_did: &str,
    reason: &str,
) {
    use crate::messages::MessageType;
    use affinidi_messaging_didcomm::Message as DIDCommMessage;
    use serde_json::json;

    info!("📤 Sending connection-rejected message to {} ({})", their_did, reason);

    let rejection_message = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::ConnectionRejected.to_string(),
        json!({ "reason": reason }),
    )
    .from(our_did.to_string())
    .to(their_did.to_string())
    .finalize();

    match atm
        .pack_encrypted(&rejection_message, their_did, Some(our_did), Some(our_did))
        .await
    {
        Ok(packed) => match atm
            .send_message(profile, &packed.0, &rejection_message.id, false, false)
            .await
        {
            Ok(_) => info!("✓ Connection-rejected message sent successfully"),
            Err(e) => error!("❌ Failed to send connection-rejected message: {:?}", e),
        },
        Err(e) => error!("❌ Failed to pack connection-rejected message: {:?}", e),
    }
}

/// Finalize OOB connection as ACCEPTOR after receiving connection-accepted
async fn finalize_oob_connection_as_acceptor<S: GatewayStore, CS: super::ConnectionPointStore>(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    inviter_temporary_did: &str,
    inviter_secure_did: &str,
    gateway_store: &Arc<S>,
    pending_store: &Arc<crate::gateways::PendingConnectionStore>,
    cp_store: &Arc<CS>,
    listener_manager: &Arc<ConnectionPointListenerManager>,
    mediator_did: &str,
) -> Result<(crate::gateways::types::Gateway, String), String> {
    info!("🔧 Finalizing OOB connection as ACCEPTOR");
    info!("  Inviter temporary DID: {}", inviter_temporary_did);
    info!("  Inviter secure DID: {}", inviter_secure_did);

    // Step 1: Retrieve pending connection state
    let pending_conn = pending_store
        .get_by_temporary_did(inviter_temporary_did)
        .await
        .ok_or_else(|| format!("No pending connection found for inviter temporary DID: {}", inviter_temporary_did))?;

    info!("✓ Found pending connection (invitation ID: {})", pending_conn.invitation_id);

    // Step 2: Update pending connection with inviter's secure DID
    let mut updated_conn = pending_conn.clone();
    updated_conn.their_secure_did = Some(inviter_secure_did.to_string());
    updated_conn.state = crate::gateways::ConnectionState::ReadyToFinalize;

    pending_store
        .update(updated_conn)
        .await;
    info!("✓ Updated pending connection state");

    // Step 3: Update existing pending gateway with inviter's SECURE DID and set to Active
    info!("  Looking for existing pending gateway with temporary DID: {}", inviter_temporary_did);

    let mut gateway = gateway_store
        .get_by_did(inviter_temporary_did)
        .await
        .map_err(|e| format!("Failed to get pending gateway: {}", e))?
        .ok_or_else(|| format!("No pending gateway found for temporary DID: {}", inviter_temporary_did))?;

    info!("✓ Found pending gateway: {}", gateway.id);
    info!("  Keeping user-provided name: {}", gateway.name);
    info!("  Keeping user-provided description: {}", gateway.description);

    // Step 4: Create gateway listener endpoint (NOT an OOB connection point!)
    // This is our DID for receiving messages FROM this remote gateway
    // IMPORTANT: Use the SAME DID that we sent in the connection-setup message!
    info!("🎧 Creating gateway listener endpoint...");

    // Extract the UUID from our_secure_did (format: did:web:domain:connection-points:{UUID})
    let cp_id = pending_conn
        .secure_cp_id
        .clone()
        .unwrap_or_else(|| {
            pending_conn
                .our_secure_did
                .split(':')
                .next_back()
                .unwrap_or_default()
                .to_string()
        });

    // Use the existing DID that was already created and sent in connection-setup message
    let cp_did = pending_conn
        .our_secure_did
        .clone();

    info!("   Using existing gateway listener DID: {}", cp_did);
    info!("   Connection point ID: {}", cp_id);

    let mut connection_point = super::types::GatewayConnectionPoint::new(
        gateway.id.clone(),
        mediator_did.to_string(),
        cp_did.clone(),
        format!("Listener for {}", gateway.name),
        "Gateway listener endpoint (acceptor side)".to_string(),
        String::new(),
        String::new(),
        serde_json::json!({
            "inviter_secure_did": inviter_secure_did
        }),
        None,
        super::types::ConnectionPointType::OobAcceptor, // System-created for OOB acceptor side
        String::new(),                                  // No secret for auto-created connection points
    );

    connection_point.id = cp_id.clone();
    connection_point.last_used_at = Some(chrono::Utc::now());

    // Enforce the appliance connection-point limit before persisting.
    if let Err(e) = crate::config::enforce_add("connections.connectionpoints").await {
        error!("❌ Inbound connection-point creation refused — {}", e.message());
        send_oob_connection_rejected(
            atm,
            profile,
            &pending_conn.our_temporary_did,
            inviter_temporary_did,
            &e.message(),
        )
        .await;
        return Err(e.message());
    }

    cp_store
        .create(&connection_point)
        .await
        .map_err(|e| format!("Failed to store gateway listener: {}", e))?;

    info!("   ✓ Gateway listener endpoint {} created", connection_point.id);

    // Record the secure DID only once the limit check and the listener
    // endpoint have passed, so a refusal leaves the pending gateway as it was.
    // The listener started below authenticates the inviter against it. The gateway stays Pending until
    // that listener has started, so nothing is sent through the temporary
    // point while the gateway already looks Active.
    gateway.did = inviter_secure_did.to_string();
    gateway.updated_at = chrono::Utc::now();

    gateway_store
        .update(&gateway)
        .await
        .map_err(|e| format!("Failed to update gateway: {}", e))?;

    info!("✓ Gateway {} updated with secure DID", gateway.id);

    // Step 4.5: Authenticate secure DID with mediator
    info!("🔐 Authenticating secure DID with mediator...");

    // Use the mediator from the pending connection (set during OOB handshake)
    // NOT the default mediator for this gateway!
    let connection_mediator_did = pending_conn
        .mediator_did
        .clone();
    info!("   Using mediator from connection: {}", connection_mediator_did);

    // Start listener for this gateway using the connection's mediator
    // We start the listener AFTER setting ACLs
    info!("🎧 Starting gateway listener...");

    match listener_manager.request_start_listener(connection_point.clone(), connection_mediator_did.clone()) {
        Ok(completion_rx) => {
            info!("   ✓ Gateway listener startup requested");

            // Wait for the listener to actually start (event-driven, no polling)
            info!("   ⏳ Waiting for listener to start...");
            match completion_rx.await {
                Ok(Ok(())) => {
                    info!("   ✓ Listener started successfully");
                }
                Ok(Err(e)) => {
                    warn!("   ⚠️  Listener failed to start: {}", e);
                }
                Err(_) => {
                    warn!("   ⚠️  Listener start notification channel closed");
                }
            }
        }
        Err(e) => {
            warn!("⚠️  Failed to request gateway listener startup: {}", e);
            warn!("  Listener will start on next server restart");
        }
    }

    // Active even if the listener failed to start: Pending is reported as
    // stored, so it would never clear, while the listener's own health
    // reports the failure.
    gateway.status = crate::gateways::types::GatewayStatus::Active;
    gateway.updated_at = chrono::Utc::now();
    gateway_store
        .update(&gateway)
        .await
        .map_err(|e| format!("Failed to activate gateway: {}", e))?;
    info!("✓ Gateway {} is Active", gateway.id);

    // Step 5: Identify the temporary connection point; the caller removes it
    // Format: did:web:domain:connection-points:{UUID}
    let temp_cp_id = pending_conn
        .temporary_cp_id
        .clone()
        .unwrap_or_else(|| {
            pending_conn
                .our_temporary_did
                .split(':')
                .next_back()
                .unwrap_or_default()
                .to_string()
        });

    // Step 5: Don't remove pending connection yet - caller needs mediator info
    // pending_store.remove(&pending_conn.id).await;
    // info!("✓ Removed pending connection state");

    info!("🎉 OOB connection finalized successfully!");
    info!("  Gateway ID: {}", gateway.id);
    info!("  Gateway DID: {}", gateway.did);

    Ok((gateway, temp_cp_id))
}

/// Stop the acceptor's temporary listener and remove its connection point and
/// key directory. Stopping a listener aborts its task, so this must not run on
/// the temporary listener's own task.
async fn remove_temporary_connection_point<CS: super::ConnectionPointStore>(
    listener_manager: &ConnectionPointListenerManager,
    cp_store: &CS,
    connection_points_root: &str,
    temp_cp_id: &str,
) {
    info!("🧹 Cleaning up temporary connection point: {}", temp_cp_id);

    if let Err(e) = listener_manager
        .stop_listener(temp_cp_id)
        .await
    {
        warn!("   Failed to stop temporary listener: {}", e);
    } else {
        info!("   ✓ Stopped temporary listener");
    }

    if let Err(e) = cp_store
        .delete(temp_cp_id)
        .await
    {
        warn!("   Failed to delete temporary connection point: {}", e);
    } else {
        info!("   ✓ Deleted temporary connection point metadata");
    }

    let temp_storage_path = std::path::Path::new(connection_points_root).join(temp_cp_id);
    if temp_storage_path.exists() {
        match std::fs::remove_dir_all(&temp_storage_path) {
            Ok(_) => info!("   ✓ Cleaned up temporary DID storage: {:?}", temp_storage_path),
            Err(e) => {
                warn!("   Failed to cleanup temporary DID storage: {}", e)
            }
        }
    }
}
/// Handle OOB connection-setup as INVITER (receiving connection request from acceptor)
async fn handle_oob_connection_setup_as_inviter<CS: super::ConnectionPointStore + 'static>(
    acceptor_temporary_did: &str,
    acceptor_secure_did: &str,
    invitation_id: &str,
    our_temporary_did: &str,
    atm: &ATM,
    profile: Arc<ATMProfile>,
    gateway_store: &Arc<crate::gateways::FileSystemGatewayStore>,
    _pending_store: &Arc<crate::gateways::PendingConnectionStore>,
    notification_store: &Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    bootstrap_config: &Arc<crate::config::BootstrapConfig>,
    cp_store: &Arc<CS>,
    _mediator_id: &str,
    manager_weak: &Option<std::sync::Weak<ConnectionPointListenerManager>>,
    _mediator_did: &str,
    mediator_url: &str,
) -> Result<(), String> {
    use crate::gateways::filesystem::GatewayStore;
    use crate::gateways::types::{Gateway, GatewayType};

    info!("Processing consumed OOB connection setup as inviter");

    let all_connection_points = cp_store
        .list_all()
        .await
        .map_err(|e| format!("Failed to list connection points: {}", e))?;

    let mut connection_point = all_connection_points
        .iter()
        .find(|cp| cp.connection_point_did == our_temporary_did)
        .cloned()
        .ok_or_else(|| {
            error!("❌ Connection point not found for our DID: {}", our_temporary_did);
            "Connection point not found".to_string()
        })?;
    let expected_invitation_id = connection_point
        .oob_message
        .get("id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or(&connection_point.oob_id);
    if connection_point.use_count != 1 || expected_invitation_id != invitation_id {
        return Err("OOB invitation capability was not atomically consumed".to_string());
    }

    connection_point
        .oob_message
        .as_object_mut()
        .ok_or_else(|| "Invitation metadata is not an object".to_string())?
        .insert("acceptor_temporary_did".to_string(), serde_json::Value::String(acceptor_temporary_did.to_string()));
    cp_store
        .update(&connection_point)
        .await
        .map_err(|error| format!("Failed to persist accepted invitation peer: {error}"))?;
    set_acl_to_peer(atm, Arc::clone(&profile), acceptor_temporary_did)
        .await
        .map_err(|error| format!("Failed to restrict consumed invitation ACL: {error}"))?;

    // Step 1: Check if gateway already exists for this acceptor
    info!("🔍 Checking for existing gateway with acceptor's secure DID...");
    if let Ok(Some(existing_gateway)) = gateway_store
        .get_by_did(acceptor_secure_did)
        .await
    {
        info!("⚠️  Gateway already exists for acceptor DID {}", acceptor_secure_did);
        info!("  Gateway ID: {}", existing_gateway.id);
        info!("  Gateway Status: {:?}", existing_gateway.status);

        // If already awaiting approval or active, don't create duplicate
        if matches!(
            existing_gateway.status,
            crate::gateways::types::GatewayStatus::AwaitingApproval | crate::gateways::types::GatewayStatus::Active
        ) {
            info!("  Gateway already exists - not creating duplicate");
            return Ok(());
        }
    }
    info!("✓ No existing gateway found - proceeding with connection request");
    info!("");

    // Enforce the appliance gateway limit before accepting an inbound connection.
    if let Err(e) = crate::config::enforce_add("connections.gateways").await {
        error!("❌ Inbound gateway connection refused — {}", e.message());
        send_oob_connection_rejected(atm, &profile, our_temporary_did, acceptor_temporary_did, &e.message()).await;
        return Err(e.message());
    }

    // Step 2: Create our secure DID for the permanent connection
    info!("🔑 Creating our secure DID for permanent connection...");

    // Get network_config from manager
    let network_config = manager_weak
        .as_ref()
        .and_then(|w| w.upgrade())
        .and_then(|m| m.network_config.clone())
        .ok_or_else(|| "Network config not available in listener manager".to_string())?;

    let secure_cp_id = uuid::Uuid::new_v4().to_string();
    let (our_secure_did, _secure_secrets, _secure_doc) =
        crate::gateways::connection_points::handlers::generate_connection_point_identity(
            &secure_cp_id,
            &network_config.did.domain,
            std::path::Path::new(
                &bootstrap_config
                    .storage_paths
                    .connection_points,
            ),
            mediator_url,
            &connection_point.did_method,
            #[cfg(feature = "didwebvh")]
            None,
            #[cfg(feature = "didwebvh")]
            None,
        )
        .await
        .map_err(|e| format!("Failed to generate secure DID: {}", e))?;

    info!("✓ Our secure DID created: {}", our_secure_did);

    // Step 3: Create the gateway record with AwaitingApproval status
    // Store the acceptor's information so admin can review and approve
    let gateway_name = format!(
        "Gateway {}",
        &acceptor_secure_did[acceptor_secure_did
            .len()
            .saturating_sub(12)..]
    );
    let mut gateway = Gateway::new_with_creation_type(
        gateway_name,
        format!(
            "Connection request from {}",
            &acceptor_temporary_did[acceptor_temporary_did
                .len()
                .saturating_sub(12)..]
        ),
        acceptor_secure_did.to_string(),
        GatewayType::Remote,
        crate::gateways::types::GatewayCreationType::System,
    );

    // Set status to AwaitingApproval - requires human approval
    gateway.status = crate::gateways::types::GatewayStatus::AwaitingApproval;

    gateway_store
        .create(&gateway)
        .await
        .map_err(|e| format!("Failed to store gateway: {}", e))?;

    info!("✓ Gateway {} created with AwaitingApproval status", gateway.id);
    info!("  Administrator needs to approve this connection request");
    info!("");

    // Step 4: Store the connection context for later approval
    // We need to save the acceptor and inviter DIDs and our secure DID for when admin approves
    info!("💾 Storing connection context for approval...");

    // Create a pending connection record with all the info needed for approval
    use crate::gateways::pending_connections::{PendingConnection, PendingConnectionState};

    let pending_connection = PendingConnection {
        gateway_id: gateway.id.clone(),
        invitation_id: connection_point.id.clone(),
        our_temporary_did: our_temporary_did.to_string(),
        our_secure_did: our_secure_did.clone(),
        their_temporary_did: acceptor_temporary_did.to_string(),
        their_secure_did: Some(acceptor_secure_did.to_string()),
        state: PendingConnectionState::AwaitingApproval,
        created_at: chrono::Utc::now(),
        expires_at: Some(
            chrono::Utc::now()
                + chrono::Duration::hours(
                    bootstrap_config
                        .oob_connection
                        .pending_expiry_hours as i64,
                ),
        ),
    };

    _pending_store
        .store_approval(&pending_connection)
        .await
        .map_err(|e| format!("Failed to store pending connection: {}", e))?;

    info!("✓ Connection context saved - gateway can be approved later");
    info!("");

    // Step 5: Send notification to administrator
    info!("📬 Creating notification for administrators...");

    if let Some(notif_store) = notification_store {
        use crate::integrations::filesystem::NotificationStore;
        use crate::integrations::types::{Notification, NotificationStatus, NotificationType};

        // For now, create a notification for "system" user (all admins)
        // In a real system, you'd want to query all administrator users
        let notification_id = uuid::Uuid::new_v4().to_string();
        let notification = Notification {
            id: notification_id,
            user_id: "system".to_string(), // System-wide notification for admins
            notification_type: NotificationType::System,
            title: "New Gateway Connection Request".to_string(),
            message: format!(
                "A new gateway connection request requires approval.\n\n\
                Gateway: {}\n\
                DID: {}\n\
                Connection Point: {}\n\n\
                Please review and approve or reject this connection in the Gateways section.",
                gateway.name,
                &acceptor_secure_did[..acceptor_secure_did
                    .len()
                    .min(50)],
                connection_point.name
            ),
            metadata: serde_json::json!({
                "gateway_id": gateway.id,
                "gateway_did": acceptor_secure_did,
                "connection_point_id": connection_point.id,
                "connection_point_name": connection_point.name,
                "action_required": "approval"
            }),
            status: NotificationStatus::New,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        match notif_store
            .create(&notification)
            .await
        {
            Ok(_) => {
                info!("✓ System notification created for administrators");
                info!("  Notification ID: {}", notification.id);
                info!("  Gateway: {}", gateway.name);
            }
            Err(e) => {
                error!("❌ Failed to create notification: {}", e);
            }
        }
    } else {
        info!("  (Notification store not configured - skipping notification)");
    }

    info!("");
    info!("✅ Connection request received and stored - awaiting administrator approval");

    Ok(())
}

/// Spawn a temporary listener for OOB acceptor to receive connection-accepted message
/// This listener will automatically cleanup after receiving the message or timing out
#[allow(dead_code)]
pub async fn spawn_oob_acceptor_listener<S: GatewayStore + 'static, CS: super::ConnectionPointStore + 'static>(
    temp_did: String,
    pending_gateway_id: String,
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    gateway_store: Arc<S>,
    pending_store: Arc<crate::gateways::PendingConnectionStore>,
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    cp_store: Arc<CS>,
    listener_manager: Arc<ConnectionPointListenerManager>,
    mediator_did: String,
) {
    crate::observability::spawn_traced_task(&format!("oob_listener.{}", pending_gateway_id), async move {
        info!("🎧 Starting temporary listener for OOB acceptor (pending gateway: {})", pending_gateway_id);
        info!("   Listening on temporary DID: {}", temp_did);
        info!("   Will auto-cleanup after receiving connection-accepted or 5 minute timeout");

        // Set a 5-minute timeout for the entire listener
        let pending_gateway_id_clone = pending_gateway_id.clone();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            listen_for_connection_accepted(
                temp_did,
                pending_gateway_id,
                atm,
                profile,
                gateway_store,
                pending_store,
                bootstrap_config,
                cp_store,
                listener_manager,
                mediator_did,
            ),
        )
        .await;

        match result {
            Ok(Ok(())) => {
                info!("✅ OOB acceptor listener completed successfully");
            }
            Ok(Err(e)) => {
                error!("❌ OOB acceptor listener failed: {}", e);
            }
            Err(_) => {
                warn!("⏱️  OOB acceptor listener timed out after 5 minutes");
                warn!("   Pending gateway {} may remain in Pending state", pending_gateway_id_clone);
            }
        }
    });
}

/// Listen for connection-accepted message on temporary DID
#[allow(dead_code)]
async fn listen_for_connection_accepted<S: GatewayStore, CS: super::ConnectionPointStore>(
    _temp_did: String,
    _pending_gateway_id: String,
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    gateway_store: Arc<S>,
    pending_store: Arc<crate::gateways::PendingConnectionStore>,
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    cp_store: Arc<CS>,
    listener_manager: Arc<ConnectionPointListenerManager>,
    mediator_did: String,
) -> Result<(), String> {
    info!("📥 Polling for messages on temporary DID...");

    // Poll for messages every 2 seconds
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut poll_count = 0;

    loop {
        interval.tick().await;
        poll_count += 1;

        if poll_count % 10 == 0 {
            info!("   Still listening... ({} polls)", poll_count);
        }

        // Fetch messages
        let response = match atm
            .fetch_messages(&profile, &Default::default())
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("   Failed to fetch messages: {:?}", e);
                continue;
            }
        };

        let messages = response.success;

        if messages.is_empty() {
            continue;
        }

        info!("📬 Received {} message(s)", messages.len());

        // Process each message
        for msg_envelope in messages {
            info!("   Processing message ID: {}", msg_envelope.msg_id);

            // Unpack the message
            let msg_str = msg_envelope
                .msg
                .as_ref()
                .ok_or_else(|| "Message content is missing".to_string())?;

            let (message, _metadata): (affinidi_messaging_didcomm::Message, _) = match atm.unpack(msg_str).await {
                Ok(result) => result,
                Err(e) => {
                    error!("   Failed to unpack message: {:?}", e);
                    continue;
                }
            };

            info!("   Message type: {}", message.typ);

            // Check if it's connection-accepted
            if message.typ == MessageType::ConnectionAccepted.to_string() {
                info!("🎉 Received connection-accepted message!");

                // Extract inviter's secure DID from the message body
                let inviter_secure_did = message
                    .body
                    .get("channel_did")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "Missing channel_did in connection-accepted message".to_string())?;

                info!("   Inviter's secure DID: {}", inviter_secure_did);

                // Call finalize function with the temporary DID (since that's what we stored the gateway under)
                let inviter_temp_did = message
                    .from
                    .as_ref()
                    .ok_or_else(|| "Missing 'from' field in connection-accepted message".to_string())?;

                let (gateway, temp_cp_id) = finalize_oob_connection_as_acceptor(
                    &atm,
                    &profile,
                    inviter_temp_did,
                    inviter_secure_did,
                    &gateway_store,
                    &pending_store,
                    &cp_store,
                    &listener_manager,
                    &mediator_did,
                )
                .await
                .map_err(|e| {
                    error!("❌ Failed to finalize OOB connection: {}", e);
                    e
                })?;
                remove_temporary_connection_point(
                    &listener_manager,
                    cp_store.as_ref(),
                    &bootstrap_config
                        .storage_paths
                        .connection_points,
                    &temp_cp_id,
                )
                .await;

                info!("✅ Gateway finalized: {} ({})", gateway.id, gateway.did);

                // Now remove the pending connection (we're done with it)
                if let Some(pending_conn) = pending_store
                    .get_by_temporary_did(inviter_temp_did)
                    .await
                {
                    pending_store
                        .remove(&pending_conn.id)
                        .await;
                    info!("   ✓ Removed pending connection state");
                } else {
                    warn!("   Could not find pending connection to remove (may have been removed already)");
                }

                // Delete the message from mediator
                let delete_req = affinidi_messaging_sdk::messages::DeleteMessageRequest {
                    message_ids: vec![msg_envelope.msg_id.clone()],
                };
                if let Err(e) = atm
                    .delete_messages_direct(&profile, &delete_req)
                    .await
                {
                    warn!("   Failed to delete message from mediator: {:?}", e);
                }

                info!("✅ OOB connection fully established with permanent listener, stopping temporary listener");
                return Ok(());
            } else if message.typ == MessageType::ConnectionRejected.to_string() {
                error!("❌ Received connection-rejected message!");

                // Extract rejection reason
                let reason = message
                    .body
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown reason");

                error!("   Rejection reason: {}", reason);

                // Update the pending gateway to failed status
                let inviter_temp_did = message
                    .from
                    .as_ref()
                    .ok_or_else(|| "Missing 'from' field in connection-rejected message".to_string())?;

                // Find the pending gateway by the inviter's temporary DID
                if let Ok(Some(mut gateway)) = gateway_store
                    .get_by_did(inviter_temp_did)
                    .await
                {
                    info!("   Updating gateway {} to Failed status", gateway.id);
                    gateway.status = crate::gateways::types::GatewayStatus::Failed;
                    gateway.description = format!("Connection rejected: {}", reason);

                    if let Err(e) = gateway_store
                        .update(&gateway)
                        .await
                    {
                        error!("   Failed to update gateway status: {}", e);
                    } else {
                        info!("   ✓ Gateway status updated to Failed");
                    }
                } else {
                    warn!("   Could not find pending gateway to update");
                }

                // Remove the pending connection
                if let Some(pending_conn) = pending_store
                    .get_by_temporary_did(inviter_temp_did)
                    .await
                {
                    pending_store
                        .remove(&pending_conn.id)
                        .await;
                    info!("   ✓ Removed pending connection state");
                }

                // Delete the message from mediator
                let delete_req = affinidi_messaging_sdk::messages::DeleteMessageRequest {
                    message_ids: vec![msg_envelope.msg_id.clone()],
                };
                if let Err(e) = atm
                    .delete_messages_direct(&profile, &delete_req)
                    .await
                {
                    warn!("   Failed to delete message from mediator: {:?}", e);
                }

                error!("❌ OOB connection rejected, stopping temporary listener");
                return Err(format!("Connection rejected: {}", reason));
            } else {
                info!("   Skipping non-connection-accepted message type: {}", message.typ);
            }
        }
    }
}

/// Decide which active listeners must be stopped during reconciliation.
///
/// Pure and side-effect free so the stale-transit-point logic is unit-testable
/// without a live WebSocket harness. `active` is a list of
/// `(connection_point_id, gateway_id)` for currently-running listeners;
/// `cp_state` maps a connection point id to `(enabled, expires_at)`;
/// `disabled_gateways` is the set of gateway ids whose status is `Disabled`.
/// Returns the `(connection_point_id, reason)` pairs to stop.
fn listeners_to_stop(
    active: &[(String, String)],
    cp_state: &HashMap<String, (bool, Option<DateTime<Utc>>)>,
    disabled_gateways: &std::collections::HashSet<String>,
    now: DateTime<Utc>,
) -> Vec<(String, &'static str)> {
    active
        .iter()
        .filter_map(|(cp_id, gateway_id)| {
            let reason: Option<&'static str> = match cp_state.get(cp_id) {
                None => Some("connection point no longer exists"),
                Some((enabled, _)) if !enabled => Some("connection point is disabled"),
                Some((_, Some(exp))) if *exp < now => Some("connection point has expired"),
                Some(_) if disabled_gateways.contains(gateway_id) => Some("gateway is disabled"),
                Some(_) => None,
            };
            reason.map(|r| (cp_id.clone(), r))
        })
        .collect()
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;

    fn state(pairs: &[(&str, bool, Option<DateTime<Utc>>)]) -> HashMap<String, (bool, Option<DateTime<Utc>>)> {
        pairs
            .iter()
            .map(|(id, en, exp)| (id.to_string(), (*en, *exp)))
            .collect()
    }

    fn connection_point(cp_type: super::super::types::ConnectionPointType) -> GatewayConnectionPoint {
        GatewayConnectionPoint::new(
            "gateway-1".to_string(),
            "mediator-1".to_string(),
            "did:example:recipient".to_string(),
            "Test".to_string(),
            String::new(),
            "invitation-1".to_string(),
            String::new(),
            serde_json::json!({
                "id": "invitation-1",
                "acceptor_secure_did": "did:example:alice",
                "inviter_secure_did": "did:example:alice"
            }),
            Some(Utc::now() + chrono::Duration::minutes(5)),
            cp_type,
            "secret".to_string(),
        )
    }

    fn metadata(
        authenticated: bool,
        kid: Option<&str>,
    ) -> MessageMetadata {
        MessageMetadata {
            encrypted: authenticated,
            authenticated,
            from_key: kid.map(str::to_string),
            non_repudiation: false,
            anonymous_sender: !authenticated,
            extra: serde_json::json!({}),
        }
    }

    #[test]
    fn mediator_acl_intent_narrows_consumed_and_established_connections() {
        let mut invitation = connection_point(super::super::types::ConnectionPointType::User);
        assert_eq!(mediator_acl_intent(&invitation), MediatorAclIntent::UnrestrictedInvitation);
        invitation.use_count = 1;
        invitation.oob_message["acceptor_temporary_did"] = serde_json::json!("did:example:acceptor-temp");
        assert_eq!(
            mediator_acl_intent(&invitation),
            MediatorAclIntent::PeerOnly("did:example:acceptor-temp".to_string())
        );

        let established = connection_point(super::super::types::ConnectionPointType::OobResponder);
        assert_eq!(mediator_acl_intent(&established), MediatorAclIntent::PeerOnly("did:example:alice".to_string()));
    }

    #[test]
    fn missing_established_peer_fails_closed() {
        let mut connection_point = connection_point(super::super::types::ConnectionPointType::OobResponder);
        connection_point.oob_message = serde_json::json!({});
        assert_eq!(mediator_acl_intent(&connection_point), MediatorAclIntent::DenyAll);
    }

    #[test]
    fn lifecycle_reserves_once_and_fences_deactivation() {
        let mut lifecycle = ListenerLifecycle::new();
        let epoch = lifecycle.epoch;
        let lease = lifecycle
            .reserve("cp-1", Some(epoch))
            .unwrap();

        assert!(
            lifecycle
                .reserve("cp-1", None)
                .is_err()
        );
        assert!(lifecycle.is_current("cp-1", lease));
        lifecycle.deactivate();
        assert!(!lifecycle.is_current("cp-1", lease));
        assert!(
            lifecycle
                .reserve("cp-2", None)
                .is_err()
        );
        lifecycle.activate();
        assert!(
            lifecycle
                .reserve("cp-2", Some(epoch))
                .is_err()
        );
    }

    #[test]
    fn stale_generation_cannot_remove_or_replace_current_generation() {
        let mut lifecycle = ListenerLifecycle::new();
        let old = lifecycle
            .reserve("cp-1", None)
            .unwrap();
        lifecycle.mark_running("cp-1", old);
        let (stopping, _) = lifecycle
            .begin_stop("cp-1")
            .unwrap();
        assert_eq!(stopping, old);
        assert!(
            lifecycle
                .reserve("cp-1", None)
                .is_err()
        );
        assert!(lifecycle.finish_stop("cp-1", old));

        let current = lifecycle
            .reserve("cp-1", None)
            .unwrap();
        assert_ne!(old.generation, current.generation);
        assert!(!lifecycle.task_finished("cp-1", old));
        assert!(lifecycle.is_current("cp-1", current));
    }

    #[tokio::test]
    async fn deactivation_aborts_starting_task_and_stop_joins_it() {
        let mut lifecycle = ListenerLifecycle::new();
        let lease = lifecycle
            .reserve("cp-1", None)
            .unwrap();
        let task = tokio::spawn(std::future::pending::<()>());
        lifecycle
            .attach_task("cp-1", lease, task)
            .unwrap();

        for handle in lifecycle.deactivate() {
            handle.abort();
        }
        let (_, task) = lifecycle
            .begin_stop("cp-1")
            .unwrap();
        let result = task.unwrap().await;
        assert!(
            result
                .unwrap_err()
                .is_cancelled()
        );
        assert!(lifecycle.finish_stop("cp-1", lease));
    }

    #[test]
    fn expired_connection_point_rejects_authenticated_peer_messages() {
        let mut connection_point = connection_point(super::super::types::ConnectionPointType::OobResponder);
        let now = Utc::now();
        connection_point.expires_at = Some(now);
        let result = authorize_inbound_message(
            &connection_point,
            &MessageType::TrustPing,
            Some("did:example:alice"),
            &metadata(true, Some("did:example:alice#key-1")),
            None,
            now,
        );
        assert_eq!(result.unwrap_err(), "connection point has expired");
    }

    #[test]
    fn unauthenticated_pickup_is_rejected() {
        let result = authorize_inbound_message(
            &connection_point(super::super::types::ConnectionPointType::User),
            &MessageType::MessagePickupDeliveryRequest,
            Some("did:example:mallory"),
            &metadata(false, None),
            None,
            Utc::now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn authenticated_sender_must_match_claimed_from_did() {
        let result = authorize_inbound_message(
            &connection_point(super::super::types::ConnectionPointType::OobResponder),
            &MessageType::ForwardRequest,
            Some("did:example:alice"),
            &metadata(true, Some("did:example:mallory#key-1")),
            None,
            Utc::now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn authenticated_non_peer_is_rejected_on_established_connection_point() {
        let result = authorize_inbound_message(
            &connection_point(super::super::types::ConnectionPointType::OobResponder),
            &MessageType::ForwardRequest,
            Some("did:example:mallory"),
            &metadata(true, Some("did:example:mallory#key-1")),
            None,
            Utc::now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn established_point_uses_gateway_peer_and_fails_closed_without_one() {
        let connection_point = connection_point(super::super::types::ConnectionPointType::OobInviter);
        let without_peer = authorize_inbound_message(
            &connection_point,
            &MessageType::ForwardRequest,
            Some("did:example:alice"),
            &metadata(true, Some("did:example:alice#key-1")),
            None,
            Utc::now(),
        );
        assert!(without_peer.is_err());
        let with_peer = authorize_inbound_message(
            &connection_point,
            &MessageType::ForwardRequest,
            Some("did:example:alice"),
            &metadata(true, Some("did:example:alice#key-1")),
            Some("did:example:alice"),
            Utc::now(),
        );
        assert!(matches!(with_peer, Ok(SenderIdentity::Authenticated { .. })));
    }

    #[test]
    fn anonymous_setup_is_rejected_on_established_connection_point() {
        let result = authorize_inbound_message(
            &connection_point(super::super::types::ConnectionPointType::OobResponder),
            &MessageType::ConnectionSetup,
            Some("did:example:mallory"),
            &metadata(false, None),
            None,
            Utc::now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn verified_sender_and_narrow_anonymous_setup_are_accepted() {
        let authenticated = authorize_inbound_message(
            &connection_point(super::super::types::ConnectionPointType::OobResponder),
            &MessageType::ForwardRequest,
            Some("did:example:alice"),
            &metadata(true, Some("did:example:alice#key-1")),
            None,
            Utc::now(),
        );
        assert!(matches!(authenticated, Ok(SenderIdentity::Authenticated { .. })));

        let mut signed_metadata = metadata(false, Some("did:example:alice#sign-1"));
        signed_metadata.non_repudiation = true;
        signed_metadata.anonymous_sender = false;
        let signed = authorize_inbound_message(
            &connection_point(super::super::types::ConnectionPointType::OobResponder),
            &MessageType::ForwardRequest,
            Some("did:example:alice"),
            &signed_metadata,
            None,
            Utc::now(),
        );
        assert!(matches!(signed, Ok(SenderIdentity::Signed { .. })));

        let mut anonymous_metadata = metadata(false, None);
        anonymous_metadata.encrypted = true;
        let anonymous = authorize_inbound_message(
            &connection_point(super::super::types::ConnectionPointType::User),
            &MessageType::ConnectionSetup,
            Some("did:example:alice"),
            &anonymous_metadata,
            None,
            Utc::now(),
        );
        assert_eq!(anonymous, Ok(SenderIdentity::Anonymous));
    }

    #[test]
    fn invitation_setup_limiter_bounds_attempts_and_recovers() {
        let started = Instant::now();
        let mut limiter = InvitationSetupRateLimiter::new(started);
        for offset in 0..InvitationSetupRateLimiter::MAX_ATTEMPTS {
            assert!(limiter.allow(started + Duration::from_millis(u64::from(offset))));
        }
        assert!(!limiter.allow(started + Duration::from_secs(1)));
        assert!(limiter.allow(started + InvitationSetupRateLimiter::WINDOW));
    }

    #[test]
    fn stops_listener_for_missing_connection_point() {
        let active = vec![("cp-1".to_string(), "gw-1".to_string())];
        let cp_state = state(&[]); // cp-1 no longer exists
        let stop = listeners_to_stop(&active, &cp_state, &Default::default(), Utc::now());
        assert_eq!(stop.len(), 1);
        assert_eq!(stop[0].0, "cp-1");
    }

    #[test]
    fn stops_listener_for_disabled_connection_point() {
        let active = vec![("cp-1".to_string(), "gw-1".to_string())];
        let cp_state = state(&[("cp-1", false, None)]);
        let stop = listeners_to_stop(&active, &cp_state, &Default::default(), Utc::now());
        assert_eq!(stop.len(), 1);
    }

    #[test]
    fn stops_listener_for_disabled_gateway() {
        let active = vec![("cp-1".to_string(), "gw-1".to_string())];
        let cp_state = state(&[("cp-1", true, None)]);
        let mut disabled = std::collections::HashSet::new();
        disabled.insert("gw-1".to_string());
        let stop = listeners_to_stop(&active, &cp_state, &disabled, Utc::now());
        assert_eq!(stop.len(), 1);
        assert_eq!(stop[0].1, "gateway is disabled");
    }

    #[test]
    fn keeps_healthy_enabled_listener() {
        let active = vec![("cp-1".to_string(), "gw-1".to_string())];
        let cp_state = state(&[("cp-1", true, None)]);
        let stop = listeners_to_stop(&active, &cp_state, &Default::default(), Utc::now());
        assert!(stop.is_empty());
    }

    #[test]
    fn stops_expired_connection_point() {
        let active = vec![("cp-1".to_string(), "gw-1".to_string())];
        let past = Utc::now() - chrono::Duration::hours(1);
        let cp_state = state(&[("cp-1", true, Some(past))]);
        let stop = listeners_to_stop(&active, &cp_state, &Default::default(), Utc::now());
        assert_eq!(stop.len(), 1);
        assert_eq!(stop[0].1, "connection point has expired");
    }
}

#[cfg(test)]
mod restart_listener_tests {
    use super::*;
    use crate::gateways::connection_points::types::ConnectionPointType;

    async fn test_manager(root: &std::path::Path) -> (ConnectionPointListenerManager, tempfile::TempDir) {
        let (vc_issuer, issuer_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let manager = ConnectionPointListenerManager::new(
            Arc::new(vc_issuer),
            Arc::new(
                MessageStore::new(root.join("messages"))
                    .await
                    .unwrap(),
            ),
            Arc::new(
                crate::gateways::FileSystemConnectionPointStore::new(root.join("connection_points"))
                    .await
                    .unwrap(),
            ),
            crate::gateways::did_cache::DIDCacheConfig {
                storage_path: root
                    .join("did_cache")
                    .to_string_lossy()
                    .into_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        (manager, issuer_dir)
    }

    async fn register_listener(
        manager: &ConnectionPointListenerManager,
        generation: u64,
    ) {
        let connection_point_did = "did:example:connection-point".to_string();
        let listener = ListenerInfo {
            id: "cp-1".to_string(),
            generation,
            gateway_id: "gw-1".to_string(),
            connection_point_id: "cp-1".to_string(),
            gateway_did: connection_point_did.clone(),
            mediator_did: "did:example:mediator".to_string(),
            name: "Connection Point".to_string(),
            cp_type: ConnectionPointType::OobAcceptor,
            metrics: Arc::new(RwLock::new(ConnectionPointMetrics::default())),
            client: DIDCommClient::new(connection_point_did, Vec::new(), None, None)
                .await
                .unwrap(),
        };
        manager
            .listeners
            .write()
            .await
            .insert("cp-1".to_string(), listener);
    }

    async fn current_generation(manager: &ConnectionPointListenerManager) -> Option<u64> {
        manager
            .get_listener("cp-1")
            .await
            .map(|listener| listener.generation())
    }

    #[tokio::test]
    async fn a_listener_another_caller_already_replaced_is_left_running() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir) = test_manager(root.path()).await;
        register_listener(&manager, 2).await;

        manager
            .restart_listener_if_current("cp-1", 1)
            .await
            .unwrap();

        assert_eq!(current_generation(&manager).await, Some(2));
    }

    #[tokio::test]
    async fn a_stopped_listener_is_not_started_again() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir) = test_manager(root.path()).await;

        manager
            .restart_listener_if_current("cp-1", 1)
            .await
            .unwrap();

        assert_eq!(current_generation(&manager).await, None);
    }

    #[tokio::test]
    async fn the_probed_listener_is_restarted() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir) = test_manager(root.path()).await;
        register_listener(&manager, 1).await;

        let result = manager
            .restart_listener_if_current("cp-1", 1)
            .await;

        assert_eq!(result.err().as_deref(), Some("Connection point 'cp-1' not found"));
    }

    fn point_on_mediator(mediator_id: &str) -> GatewayConnectionPoint {
        GatewayConnectionPoint::new(
            "gw-1".into(),
            mediator_id.into(),
            "did:example:connection-point".into(),
            "Listener".into(),
            String::new(),
            String::new(),
            String::new(),
            serde_json::json!({}),
            None,
            ConnectionPointType::OobAcceptor,
            String::new(),
        )
    }

    fn mediator_document() -> serde_json::Value {
        serde_json::json!({
            "id": "did:web:mediator.example",
            "service": [{
                "id": "did:web:mediator.example#didcomm",
                "type": "DIDCommMessaging",
                "serviceEndpoint": [
                    {"uri": "https://mediator.example/mediator/v1"},
                    {"uri": "wss://mediator.example/mediator/v1/ws"}
                ]
            }, {
                "id": "did:web:mediator.example#auth",
                "type": "Authentication",
                "serviceEndpoint": "https://mediator.example/mediator/v1/authenticate"
            }]
        })
    }

    async fn manager_with_stored_mediator(
        root: &std::path::Path
    ) -> (ConnectionPointListenerManager, tempfile::TempDir, String) {
        use crate::mediators::filesystem::MediatorStore;

        let (manager, issuer_dir) = test_manager(root).await;
        let store = crate::mediators::FileSystemMediatorStore::new(root.join("mediators"))
            .await
            .unwrap();
        let mediator = crate::mediators::types::Mediator::new(
            "Mediator".into(),
            String::new(),
            "did:web:mediator.example".into(),
            Some(mediator_document()),
        );
        store
            .create(&mediator)
            .await
            .unwrap();
        (manager.with_mediator_store(Arc::new(store)), issuer_dir, mediator.id)
    }

    #[tokio::test]
    async fn a_mediator_did_needs_no_lookup() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir) = test_manager(root.path()).await;

        let mediator = manager
            .connection_point_mediator(&point_on_mediator("did:web:mediator.example"))
            .await
            .unwrap();

        assert_eq!(mediator, ("did:web:mediator.example".to_string(), None));
    }

    #[tokio::test]
    async fn a_stored_mediator_comes_with_its_document() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir, mediator_id) = manager_with_stored_mediator(root.path()).await;

        let mediator = manager
            .connection_point_mediator(&point_on_mediator(&mediator_id))
            .await
            .unwrap();

        assert_eq!(mediator, ("did:web:mediator.example".to_string(), Some(mediator_document())));
    }

    #[tokio::test]
    async fn an_unknown_stored_mediator_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir, _) = manager_with_stored_mediator(root.path()).await;

        let result = manager
            .connection_point_mediator(&point_on_mediator("missing"))
            .await;

        assert_eq!(result.err().as_deref(), Some("mediator 'missing' not found"));
    }

    #[tokio::test]
    async fn the_endpoint_comes_from_the_stored_document() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir, mediator_id) = manager_with_stored_mediator(root.path()).await;

        let endpoint = manager
            .connection_point_mediator_endpoint(&point_on_mediator(&mediator_id))
            .await
            .unwrap();

        assert_eq!(endpoint, "https://mediator.example/mediator/v1");
    }

    struct TemporaryPoint {
        manager: Arc<ConnectionPointListenerManager>,
        keys_root: std::path::PathBuf,
        _root: tempfile::TempDir,
        _issuer_dir: tempfile::TempDir,
    }

    async fn temporary_point() -> (TemporaryPoint, ListenerLease) {
        let root = tempfile::tempdir().unwrap();
        let (manager, issuer_dir) = test_manager(root.path()).await;
        let mut connection_point = GatewayConnectionPoint::new(
            "gw-1".into(),
            "mediator-1".into(),
            "did:example:connection-point".into(),
            "Temporary listener".into(),
            String::new(),
            String::new(),
            String::new(),
            serde_json::json!({}),
            None,
            ConnectionPointType::System,
            String::new(),
        );
        connection_point.id = "cp-1".into();
        manager
            .cp_store
            .create(&connection_point)
            .await
            .unwrap();
        let keys_root = root.path().join("keys");
        std::fs::create_dir_all(keys_root.join("cp-1")).unwrap();
        let lease = manager
            .lifecycle
            .lock()
            .unwrap()
            .reserve("cp-1", None)
            .unwrap();
        register_listener(&manager, lease.generation).await;
        let point = TemporaryPoint {
            manager: Arc::new(manager),
            keys_root,
            _root: root,
            _issuer_dir: issuer_dir,
        };
        (point, lease)
    }

    fn attach_listener_task(
        point: &TemporaryPoint,
        lease: ListenerLease,
        task: tokio::task::JoinHandle<()>,
    ) {
        point
            .manager
            .lifecycle
            .lock()
            .unwrap()
            .attach_task("cp-1", lease, task)
            .unwrap();
        point
            .manager
            .lifecycle
            .lock()
            .unwrap()
            .mark_running("cp-1", lease);
    }

    #[tokio::test]
    async fn temporary_point_cleanup_spawned_from_its_listener_task_completes() {
        let (point, lease) = temporary_point().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (cleaned_tx, cleaned_rx) = tokio::sync::oneshot::channel();
        let manager = Arc::clone(&point.manager);
        let keys_root = point
            .keys_root
            .to_string_lossy()
            .into_owned();
        let listener_task = tokio::spawn(async move {
            started_rx.await.unwrap();
            tokio::spawn(async move {
                let cp_store = Arc::clone(&manager.cp_store);
                remove_temporary_connection_point(&manager, cp_store.as_ref(), &keys_root, "cp-1").await;
                let _ = cleaned_tx.send(());
            });
            std::future::pending::<()>().await;
        });
        let listener_abort = listener_task.abort_handle();
        attach_listener_task(&point, lease, listener_task);
        started_tx.send(()).unwrap();

        tokio::time::timeout(Duration::from_secs(10), cleaned_rx)
            .await
            .unwrap()
            .unwrap();

        assert!(
            point
                .manager
                .get_listener("cp-1")
                .await
                .is_none()
        );
        assert!(
            point
                .manager
                .cp_store
                .get("cp-1")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !point
                .keys_root
                .join("cp-1")
                .exists()
        );
        assert!(listener_abort.is_finished());
    }

    #[tokio::test]
    async fn temporary_point_cleanup_inline_on_its_listener_task_is_cut_off() {
        let (point, lease) = temporary_point().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let manager = Arc::clone(&point.manager);
        let keys_root = point
            .keys_root
            .to_string_lossy()
            .into_owned();
        let listener_task = tokio::spawn(async move {
            started_rx.await.unwrap();
            let cp_store = Arc::clone(&manager.cp_store);
            remove_temporary_connection_point(&manager, cp_store.as_ref(), &keys_root, "cp-1").await;
        });
        let listener_abort = listener_task.abort_handle();
        attach_listener_task(&point, lease, listener_task);
        started_tx.send(()).unwrap();

        tokio::time::timeout(Duration::from_secs(10), async {
            while !listener_abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert!(
            point
                .manager
                .get_listener("cp-1")
                .await
                .is_some()
        );
        assert!(
            point
                .manager
                .cp_store
                .get("cp-1")
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[cfg(test)]
mod surface_exposure_tests {
    use super::*;
    use crate::gateways::types::{Gateway, GatewayType};

    struct Stores {
        _dir: tempfile::TempDir,
        cp_store: Option<Arc<crate::gateways::FileSystemConnectionPointStore>>,
        gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
        gateway: Gateway,
        connection_point: GatewayConnectionPoint,
    }

    async fn stores() -> Stores {
        let dir = tempfile::tempdir().expect("storage");
        let mut gateway =
            Gateway::new("peer".to_string(), String::new(), "did:example:peer".to_string(), GatewayType::Remote);
        gateway.id = "gateway-1".to_string();
        gateway.tenant_id = Some("tenant-a".to_string());
        gateway.exposed_channels = vec!["a".to_string(), "b".to_string()];
        let gateway_store = crate::gateways::FileSystemGatewayStore::new(dir.path().join("gateways"), None)
            .await
            .expect("gateway store");
        gateway_store
            .create(&gateway)
            .await
            .expect("save gateway");

        let mut connection_point = GatewayConnectionPoint::new_from_oob_inviter(
            "gateway-1".to_string(),
            "mediator-1".to_string(),
            "did:example:connection-point".to_string(),
            "peer".to_string(),
        );
        connection_point.id = "connection-point-1".to_string();
        connection_point.exposed_channels = vec!["a".to_string()];
        let cp_store = crate::gateways::FileSystemConnectionPointStore::new(
            dir.path()
                .join("connection_points"),
        )
        .await
        .expect("connection point store");
        cp_store
            .create(&connection_point)
            .await
            .expect("save connection point");

        Stores {
            _dir: dir,
            cp_store: Some(Arc::new(cp_store)),
            gateway_store: Some(Arc::new(gateway_store)),
            gateway,
            connection_point,
        }
    }

    #[tokio::test]
    async fn the_exposure_combines_the_connection_point_and_its_gateway() {
        let s = stores().await;

        let exposure = resolve_surface_exposure(&s.cp_store, &s.gateway_store, "connection-point-1")
            .await
            .expect("exposure resolves");

        assert_eq!(exposure, message_processor::SurfaceExposure::new(&s.gateway, &s.connection_point));
    }

    #[tokio::test]
    async fn a_connection_point_change_applies_to_the_next_message() {
        let mut s = stores().await;
        s.connection_point
            .exposed_channels = vec!["b".to_string()];
        s.cp_store
            .as_ref()
            .unwrap()
            .update(&s.connection_point)
            .await
            .expect("update connection point");

        let exposure = resolve_surface_exposure(&s.cp_store, &s.gateway_store, "connection-point-1")
            .await
            .expect("exposure resolves");

        assert_eq!(exposure, message_processor::SurfaceExposure::new(&s.gateway, &s.connection_point));
    }

    #[tokio::test]
    async fn an_exposure_that_cannot_be_resolved_is_an_error() {
        let s = stores().await;

        assert!(
            resolve_surface_exposure(&s.cp_store, &s.gateway_store, "connection-point-unknown")
                .await
                .is_err()
        );
        assert!(
            resolve_surface_exposure::<crate::gateways::FileSystemConnectionPointStore>(
                &None,
                &s.gateway_store,
                "connection-point-1"
            )
            .await
            .is_err()
        );
        assert!(
            resolve_surface_exposure(&s.cp_store, &None, "connection-point-1")
                .await
                .is_err()
        );

        let mut orphaned = s.connection_point.clone();
        orphaned.id = "connection-point-orphaned".to_string();
        orphaned.gateway_id = "gateway-gone".to_string();
        s.cp_store
            .as_ref()
            .unwrap()
            .create(&orphaned)
            .await
            .expect("save orphaned connection point");
        assert!(
            resolve_surface_exposure(&s.cp_store, &s.gateway_store, "connection-point-orphaned")
                .await
                .is_err(),
            "a connection point whose gateway is gone"
        );
    }
}
