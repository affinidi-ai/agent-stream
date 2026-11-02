//! The `DIDCommClient` handle: owns `atm + profile + tdk_state` and exposes all
//! DIDComm operations for a single identity.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use affinidi_messaging_didcomm::Message as DIDCommMessage;
use affinidi_messaging_sdk::{ATM, config::ATMConfig, messages::compat::UnpackMetadata, profiles::ATMProfile};
use affinidi_tdk_common::{TDKSharedState, profiles::TDKProfile, secrets_resolver::secrets::Secret};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use super::mediator::{
    MediatorAuthTestResult, MediatorTrustPingResult, cache_did_document, cache_did_document_in_tdk_state,
    test_authentication, trust_ping,
};

fn decode_oob_invite(
    body: &[u8],
    now: u64,
) -> Result<DIDCommMessage, String> {
    let response: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "OOB invitation endpoint returned invalid JSON".to_string())?;
    let encoded = response
        .get("data")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "OOB invitation response is missing data".to_string())?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "OOB invitation data is not valid base64url".to_string())?;
    let invitation: DIDCommMessage = serde_json::from_slice(&decoded)
        .map_err(|_| "OOB invitation data is not a valid DIDComm message".to_string())?;
    if invitation
        .expires_time
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err("OOB invitation has expired".to_string());
    }
    Ok(invitation)
}

/// Centralized DIDComm client owning the ATM, its profile, and the shared TDK
/// state. All DIDComm operations for a given identity go through one of these,
/// so reconnect / refresh / health-check happen in one place.
#[derive(Clone)]
pub struct DIDCommClient {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    tdk_state: Arc<TDKSharedState>,
}

impl DIDCommClient {
    pub async fn new(
        did: String,
        secrets: Vec<Secret>,
        mediator_did: Option<String>,
        alias: Option<String>,
    ) -> Result<Self, String> {
        Self::build(did, secrets, mediator_did, None, alias, None).await
    }

    pub async fn new_with_mediator_document(
        did: String,
        secrets: Vec<Secret>,
        mediator_did: Option<String>,
        mediator_did_document: Option<serde_json::Value>,
        alias: Option<String>,
    ) -> Result<Self, String> {
        Self::build(did, secrets, mediator_did, mediator_did_document, alias, None).await
    }

    pub async fn new_with_cache_config(
        did: String,
        secrets: Vec<Secret>,
        mediator_did: Option<String>,
        alias: Option<String>,
        cache_config: Option<&super::gateway::CacheConfig>,
    ) -> Result<Self, String> {
        Self::build(did, secrets, mediator_did, None, alias, cache_config).await
    }

    async fn build(
        did: String,
        secrets: Vec<Secret>,
        mediator_did: Option<String>,
        mediator_did_document: Option<serde_json::Value>,
        alias: Option<String>,
        cache_config: Option<&super::gateway::CacheConfig>,
    ) -> Result<Self, String> {
        let tdk_state = Arc::new(
            TDKSharedState::new(
                crate::gateways::did_cache::headless_tdk_config()
                    .map_err(|e| format!("Failed to build TDK config: {:?}", e))?,
            )
            .await
            .map_err(|e| format!("Failed to create TDK shared state: {:?}", e))?,
        );

        let tdk_profile = TDKProfile::new(
            alias
                .as_deref()
                .unwrap_or("didcomm-client"),
            &did,
            None,
            secrets,
        );

        tdk_state
            .add_profile(&tdk_profile)
            .await;

        let config = {
            let mut builder = ATMConfig::builder();
            if let Some(cfg) = cache_config {
                builder = builder
                    .with_fetch_cache_limit_count(cfg.inbound_cache_count)
                    .with_fetch_cache_limit_bytes(cfg.inbound_cache_bytes);
            }
            builder
                .build()
                .map_err(|e| format!("Failed to build ATM config: {}", e))?
        };

        if let Some(mediator_did) = mediator_did.as_deref() {
            let documents = crate::mediators::transport::resolve_and_validate_mediator_documents(
                mediator_did,
                mediator_did_document,
            )
            .await?;
            for (document_did, document) in documents {
                cache_did_document_in_tdk_state(&tdk_state, &document_did, document).await?;
            }
        }

        let atm = ATM::new(config, tdk_state.clone())
            .await
            .map_err(|e| format!("Failed to initialize ATM: {}", e))?;

        let profile = ATMProfile::new(&atm, alias, did, mediator_did)
            .await
            .map_err(|e| format!("Failed to create ATM profile: {:?}", e))?;

        Ok(Self {
            atm: Arc::new(atm),
            profile: Arc::new(profile),
            tdk_state,
        })
    }

    pub async fn cache_did_document(
        &self,
        did: &str,
        did_document: serde_json::Value,
    ) -> Result<(), String> {
        cache_did_document(self, did, did_document).await
    }

    pub async fn test_mediator_authentication(
        &self,
        mediator_did: &str,
        timeout: Duration,
    ) -> Result<MediatorAuthTestResult, String> {
        test_authentication(self, mediator_did, timeout).await
    }

    pub async fn trust_ping_mediator(
        &self,
        mediator_did: &str,
        timeout: Duration,
    ) -> Result<MediatorTrustPingResult, String> {
        trust_ping(self, mediator_did, timeout).await
    }

    pub async fn enable_websocket(&mut self) -> Result<(), String> {
        let profile = self
            .atm
            .profile_add(&self.profile, true)
            .await
            .map_err(|e| format!("Failed to enable WebSocket: {:?}", e))?;
        self.profile = profile;
        Ok(())
    }

    pub async fn register_profile(&mut self) -> Result<(), String> {
        let profile = self
            .atm
            .profile_add(&self.profile, false)
            .await
            .map_err(|e| format!("Failed to register profile: {:?}", e))?;
        self.profile = profile;
        Ok(())
    }

    pub async fn pack_and_send_message(
        &self,
        message: &DIDCommMessage,
        to_did: &str,
        from_did: &str,
    ) -> Result<(), String> {
        let packed = self
            .atm
            .pack_encrypted(message, to_did, Some(from_did), Some(from_did))
            .await
            .map_err(|e| format!("Failed to pack message: {:?}", e))?;

        self.atm
            .send_message(&self.profile, &packed.0, &message.id, false, false)
            .await
            .map_err(|e| format!("Failed to send message: {:?}", e))?;

        Ok(())
    }

    pub async fn live_stream_next(
        &self,
        timeout: Duration,
        auto_delete: bool,
    ) -> Result<Option<(DIDCommMessage, Box<UnpackMetadata>)>, String> {
        self.atm
            .message_pickup()
            .live_stream_next(&self.profile, Some(timeout), auto_delete)
            .await
            .map_err(|e| format!("live_stream_next failed: {:?}", e))
    }

    pub async fn preflight_check(
        &self,
        timeout: Duration,
    ) -> Result<(), String> {
        let result = tokio::time::timeout(
            timeout,
            self.atm
                .message_pickup()
                .send_status_request(&self.profile, true, None),
        )
        .await;

        match result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("Pre-flight status check failed: {:?}", e)),
            Err(_elapsed) => Err(format!("Pre-flight timed out after {:?}", timeout)),
        }
    }

    pub fn atm(&self) -> &Arc<ATM> {
        &self.atm
    }

    pub fn profile(&self) -> &Arc<ATMProfile> {
        &self.profile
    }

    pub fn tdk_state(&self) -> &Arc<TDKSharedState> {
        &self.tdk_state
    }

    pub async fn retrieve_oob_invite(url: &str) -> Result<DIDCommMessage, String> {
        let body = crate::outbound_fetch::fetch_public_bounded(url).await?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| "System clock is before Unix epoch".to_string())?
            .as_secs();
        decode_oob_invite(&body, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(expires_at: u64) -> Vec<u8> {
        let invitation = DIDCommMessage::build(
            "invitation-1".to_string(),
            "https://didcomm.org/out-of-band/2.0/invitation".to_string(),
            serde_json::json!({}),
        )
        .expires_time(expires_at)
        .finalize();
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&invitation).unwrap());
        serde_json::to_vec(&serde_json::json!({"data": encoded})).unwrap()
    }

    #[test]
    fn bounded_oob_response_parser_accepts_valid_and_rejects_expired_or_malformed() {
        assert_eq!(
            decode_oob_invite(&response(101), 100)
                .unwrap()
                .id,
            "invitation-1"
        );
        assert!(decode_oob_invite(&response(100), 100).is_err());
        assert!(decode_oob_invite(br#"{"data":"not-base64"}"#, 100).is_err());
        assert!(decode_oob_invite(br#"{"unexpected":true}"#, 100).is_err());
    }
}
