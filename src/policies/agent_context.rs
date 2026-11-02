//! Build `AgentContext` for OPA evaluation from agent card and trust registry data.
//!
//! This module is responsible for resolving all external data (DID documents, trust registry
//! results) into an `AgentContext` value ready for injection into `PolicyInput.agent`.
//! It belongs in the `policies` module because its sole purpose is building OPA input.
//!
//! `build_agent_context` is intentionally **best-effort**: every step that fails leaves the
//! corresponding field as `None` rather than propagating an error. The Rego policy receives
//! whatever was resolved and decides whether absent fields imply deny.

use tracing::{debug, info, warn};

use crate::config::{AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION, TRUST_REGISTRY_EXTENSION};

use crate::surface_context::AgentContext;

/// Build an `AgentContext` from available agent data and optional trust registry lookups.
///
/// # Arguments
/// * `body_json` — Full message body (source mode) or agent card JSON (target mode).
/// * `agent_card` — Parsed agent card JSON, present only in target mode.
/// * `tr_manager` — Optional reference to the trust registry listener manager used for TR
///   recognition queries.  When `None` the queries are skipped and `trust_verification` stays `None`.
///
/// Returns an `AgentContext` with `trust_verification` set.  Never errors.
pub async fn build_agent_context(
    body_json: Option<&serde_json::Value>,
    agent_card: Option<&serde_json::Value>,
) -> AgentContext {
    let mut ctx = AgentContext {
        trust_verification: None,
        did: None,
        agent_dna: None,
    };

    info!("build_agent_context: body_json={} agent_card={}", body_json.is_some(), agent_card.is_some());

    // Normalize: unwrap JSON-RPC envelope to the A2A message level.
    let msg_body: Option<&serde_json::Value> = body_json.and_then(normalize_message_body);

    // --- DID extraction (needed for Q1: department owns agent) ---
    let mut agent_did: Option<String> = None;
    let mut context_did: Option<String> = None;
    if let Some(card) = agent_card {
        agent_did = extract_did_from_agent_card(card);
        context_did = extract_context_did_from_agent_card(card);

        ctx.agent_dna = card
            .get("agentDNA")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
    }

    if context_did.is_none()
        && let Some(body) = msg_body
    {
        context_did = extract_did_from_message_metadata(body);
    }

    ctx.did = context_did;

    if agent_did.is_none()
        && let Some(body) = msg_body
    {
        agent_did = extract_did_from_message_metadata(body);
    }
    debug!("build_agent_context: agent_did={:?} ctx.did={:?}", agent_did, ctx.did);

    // Trust registry recognition queries removed; trust_verification stays None.
    let _ = agent_did;

    info!("build_agent_context: FINAL ctx={:?}", ctx);
    ctx
}

/// Resolve the A2A message object from an arbitrary JSON body.
///
/// Tries, in order:
/// 1. `params.message`
/// 2. `result.status.message`
/// 3. `result.message`
/// 4. `result` directly (when it looks like a message)
/// 5. `message`
/// 6. The body itself (when it looks like a message)
///
/// Returns `None` when no recognisable message structure is found.
fn normalize_message_body(body: &serde_json::Value) -> Option<&serde_json::Value> {
    // 1. JSON-RPC request envelope: params.message
    if let Some(msg) = body
        .get("params")
        .and_then(|p| p.get("message"))
    {
        debug!("build_agent_context: Using params.message");
        return Some(msg);
    }

    // 2-4. JSON-RPC response envelope: result.*
    if let Some(result) = body.get("result") {
        if let Some(msg) = result
            .get("status")
            .and_then(|s| s.get("message"))
        {
            debug!("build_agent_context: Using result.status.message");
            return Some(msg);
        }
        if let Some(msg) = result.get("message") {
            debug!("build_agent_context: Using result.message");
            return Some(msg);
        }
        if looks_like_message(result) {
            debug!("build_agent_context: Using result directly as message");
            return Some(result);
        }
        debug!("build_agent_context: unrecognized result structure");
        return None;
    }

    // 5. Wrapped in a top-level "message" key
    if let Some(msg) = body.get("message") {
        return Some(msg);
    }

    // 6. Body is the message itself
    if looks_like_message(body) {
        debug!("build_agent_context: Using body as message directly");
        return Some(body);
    }

    let keys: Vec<&String> = body
        .as_object()
        .map(|o| o.keys().collect())
        .unwrap_or_default();
    debug!(keys = ?keys, "build_agent_context: unrecognized message structure");
    None
}

/// Returns `true` when a JSON value has at least one field that indicates it
/// is an A2A message (`metadata`, `extensions`, `kind`, or `parts`).
#[inline]
fn looks_like_message(value: &serde_json::Value) -> bool {
    value
        .get("metadata")
        .is_some()
        || value
            .get("extensions")
            .is_some()
        || value.get("kind").is_some()
        || value.get("parts").is_some()
}

fn extract_context_did_from_agent_card(card: &serde_json::Value) -> Option<String> {
    let extensions = card
        .get("capabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(|e| e.as_array())
        .or_else(|| {
            warn!("Agent card missing capabilities.extensions array");
            None
        })?;

    for ext in extensions {
        if ext
            .get("uri")
            .and_then(|u| u.as_str())
            == Some(AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION)
            && let Some(did) = ext
                .get("did")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    ext.get("params")
                        .and_then(|p| p.get("did"))
                        .and_then(|v| v.as_str())
                })
        {
            return Some(did.to_string());
        }
    }

    extract_did_from_agent_card(card)
}

fn extract_did_from_agent_card(card: &serde_json::Value) -> Option<String> {
    let extensions = card
        .get("capabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(|e| e.as_array())
        .or_else(|| {
            warn!("Agent card missing capabilities.extensions array");
            None
        })?;

    // Extract agent_did from TRUST_REGISTRY_EXTENSION → .params.agent_did
    for ext in extensions {
        if ext
            .get("uri")
            .and_then(|u| u.as_str())
            == Some(TRUST_REGISTRY_EXTENSION)
        {
            if let Some(did) = ext
                .get("params")
                .and_then(|p| p.get("agent_did"))
                .and_then(|v| v.as_str())
            {
                return Some(did.to_string());
            } else {
                warn!("Trust registry extension missing agent_did in params");
            }
        }
    }

    None
}

fn extract_did_from_message_metadata(body: &serde_json::Value) -> Option<String> {
    let metadata = body
        .get("metadata")
        .and_then(|md| md.as_object())
        .or_else(|| {
            warn!("Message metadata missing AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION object");
            None
        })?;

    // Step 1: prefer AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION → .did
    if let Some(did) = metadata
        .get(AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION)
        .and_then(|ext| ext.get("did"))
        .and_then(|v| v.as_str())
    {
        return Some(did.to_string());
    }

    // Step 2: fallback to TRUST_REGISTRY_EXTENSION → .agent_did
    if let Some(ext) = metadata.get(TRUST_REGISTRY_EXTENSION) {
        if let Some(did) = ext
            .get("agent_did")
            .and_then(|v| v.as_str())
        {
            return Some(did.to_string());
        } else {
            warn!("Trust registry extension missing agent_did in params");
        }
    }

    None
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---------------------------------------------------------------
    // normalize_message_body
    // ---------------------------------------------------------------

    #[test]
    fn test_normalize_message_body_params_message() {
        let body = json!({ "jsonrpc": "2.0", "params": { "message": { "kind": "message" } } });
        let msg = normalize_message_body(&body).expect("should find params.message");
        assert_eq!(
            msg.get("kind")
                .and_then(|v| v.as_str()),
            Some("message")
        );
    }

    #[test]
    fn test_normalize_message_body_result_status_message() {
        let body = json!({ "result": { "status": { "message": { "parts": [] } } } });
        let msg = normalize_message_body(&body).expect("should find result.status.message");
        assert!(msg.get("parts").is_some());
    }

    #[test]
    fn test_normalize_message_body_result_message() {
        let body = json!({ "result": { "message": { "metadata": {} } } });
        let msg = normalize_message_body(&body).expect("should find result.message");
        assert!(msg.get("metadata").is_some());
    }

    #[test]
    fn test_normalize_message_body_result_is_message() {
        // result itself looks like a message (has `kind`)
        let body = json!({ "result": { "kind": "message", "parts": [] } });
        let msg = normalize_message_body(&body).expect("should use result directly");
        assert_eq!(
            msg.get("kind")
                .and_then(|v| v.as_str()),
            Some("message")
        );
    }

    #[test]
    fn test_normalize_message_body_result_unrecognized_returns_none() {
        // result exists but has no message-like fields → None (don't fall through to outer body)
        let body = json!({ "result": { "id": "xyz" } });
        assert!(normalize_message_body(&body).is_none());
    }

    #[test]
    fn test_normalize_message_body_top_level_message_key() {
        let body = json!({ "message": { "metadata": { "ext": "value" } } });
        let msg = normalize_message_body(&body).expect("should find top-level message key");
        assert!(msg.get("metadata").is_some());
    }

    #[test]
    fn test_normalize_message_body_body_is_message() {
        let body = json!({ "kind": "message", "parts": [] });
        let msg = normalize_message_body(&body).expect("should use body directly");
        assert_eq!(
            msg.get("kind")
                .and_then(|v| v.as_str()),
            Some("message")
        );
    }

    #[test]
    fn test_normalize_message_body_unrecognized_returns_none() {
        let body = json!({ "foo": "bar", "baz": 42 });
        assert!(normalize_message_body(&body).is_none());
    }

    // params.message takes priority over a top-level kind field
    #[test]
    fn test_normalize_message_body_params_wins_over_direct() {
        let body = json!({
            "kind": "outer",
            "params": { "message": { "kind": "inner" } }
        });
        let msg = normalize_message_body(&body).unwrap();
        assert_eq!(
            msg.get("kind")
                .and_then(|v| v.as_str()),
            Some("inner")
        );
    }

    // ---------------------------------------------------------------
    // extract_did_from_agent_card
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_did_from_agent_card_via_credential_extension() {
        // Credential extension alone is no longer used — only trust registry extension.
        let card = json!({
            "capabilities": {
                "extensions": [{
                    "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                    "verifiable_presentation": {},
                    "did": "did:web:agent.example.com"
                }]
            }
        });
        assert_eq!(extract_did_from_agent_card(&card), None);
    }

    #[test]
    fn test_extract_did_from_agent_card_via_tr_extension_fallback() {
        let card = json!({
            "capabilities": {
                "extensions": [{
                    "uri": TRUST_REGISTRY_EXTENSION,
                    "params": { "agent_did": "did:web:tr-agent.example.com" }
                }]
            }
        });
        assert_eq!(extract_did_from_agent_card(&card), Some("did:web:tr-agent.example.com".to_string()));
    }

    #[test]
    fn test_extract_did_from_agent_card_tr_used_when_both_present() {
        // Only trust registry extension is used for DID extraction.
        let card = json!({
            "capabilities": {
                "extensions": [
                    {
                        "uri": TRUST_REGISTRY_EXTENSION,
                        "params": { "agent_did": "did:web:tr-agent" }
                    },
                    {
                        "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "did": "did:web:credential-agent"
                    }
                ]
            }
        });
        assert_eq!(extract_did_from_agent_card(&card), Some("did:web:tr-agent".to_string()));
    }

    #[test]
    fn test_extract_did_from_agent_card_empty_extensions_returns_none() {
        let card = json!({ "capabilities": { "extensions": [] } });
        assert!(extract_did_from_agent_card(&card).is_none());
    }

    #[test]
    fn test_extract_did_from_agent_card_missing_capabilities_returns_none() {
        let card = json!({ "name": "Agent" });
        assert!(extract_did_from_agent_card(&card).is_none());
    }

    #[test]
    fn test_extract_context_did_from_agent_card_prefers_credential_extension() {
        let card = json!({
            "capabilities": {
                "extensions": [
                    {
                        "uri": TRUST_REGISTRY_EXTENSION,
                        "params": { "agent_did": "did:web:tr-agent" }
                    },
                    {
                        "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "did": "did:web:credential-agent"
                    }
                ]
            }
        });

        assert_eq!(extract_context_did_from_agent_card(&card), Some("did:web:credential-agent".to_string()));
    }

    // ---------------------------------------------------------------
    // extract_did_from_message_metadata
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_did_from_message_metadata_via_credential() {
        let mut metadata = serde_json::Map::new();
        metadata.insert(
            AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION.to_string(),
            json!({ "did": "did:web:sender.example.com" }),
        );
        let body = json!({ "metadata": metadata });
        assert_eq!(extract_did_from_message_metadata(&body), Some("did:web:sender.example.com".to_string()));
    }

    #[test]
    fn test_extract_did_from_message_metadata_via_tr_fallback() {
        let mut metadata = serde_json::Map::new();
        metadata.insert(TRUST_REGISTRY_EXTENSION.to_string(), json!({  "agent_did": "did:web:tr-sender" } ));
        let body = json!({ "metadata": metadata });
        assert_eq!(extract_did_from_message_metadata(&body), Some("did:web:tr-sender".to_string()));
    }

    #[test]
    fn test_extract_did_from_message_metadata_no_metadata_returns_none() {
        let body = json!({ "kind": "message", "parts": [] });
        assert!(extract_did_from_message_metadata(&body).is_none());
    }

    // ---------------------------------------------------------------
    // build_agent_context — integration tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_build_agent_context_no_data() {
        let ctx = build_agent_context(None, None).await;
        assert!(
            ctx.trust_verification
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_build_agent_context_target_mode_no_tr_manager() {
        let card = json!({
            "name": "Payment Agent",
            "url": "https://payments.example.com",
            "capabilities": {
                "extensions": [{
                    "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                    "did": "did:web:payments.example.com"
                }]
            }
        });
        let ctx = build_agent_context(None, Some(&card)).await;
        assert_eq!(ctx.did, Some("did:web:payments.example.com".to_string()));
        assert!(
            ctx.trust_verification
                .is_none(),
            "no tr_manager → trust_verification must stay None"
        );
    }

    #[tokio::test]
    async fn test_didwebvh_fix_build_agent_context_target_mode_from_card() {
        let card = json!({
            "name": "Payment Agent",
            "url": "https://payments.example.com",
            "agentDNA": {
                "uai": "uai:1:scid:gen.beh.op.att",
                "birthEvent": {
                    "scid": "scid",
                    "timestamp": "2026-04-08T00:00:00Z",
                    "initialGenesis": {
                        "codeHash": "code",
                        "modelSpec": { "provider": "OpenAI", "model": "gpt-4.1" },
                        "configHash": "cfg",
                        "genesisHash": "gen",
                        "computedAt": "2026-04-08T00:00:00Z"
                    },
                    "birthEntryHash": "birth"
                },
                "genesis": {
                    "codeHash": "code",
                    "modelSpec": { "provider": "OpenAI", "model": "gpt-4.1" },
                    "configHash": "cfg",
                    "genesisHash": "gen",
                    "computedAt": "2026-04-08T00:00:00Z"
                },
                "behavioral": {
                    "behavioralHash": "beh",
                    "measuredAt": "2026-04-08T00:00:00Z"
                },
                "operational": {
                    "capabilitiesHash": "caps",
                    "operationalHash": "op",
                    "attestedAt": "2026-04-08T00:00:00Z"
                },
                "attestations": {
                    "merkleRoot": "root",
                    "count": 1
                }
            },
            "capabilities": {
                "extensions": [{
                    "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                    "did": "did:web:payments.example.com"
                }]
            }
        });
        let ctx = build_agent_context(None, Some(&card)).await;
        assert_eq!(ctx.did, Some("did:web:payments.example.com".to_string()));
        assert_eq!(
            ctx.agent_dna
                .as_ref()
                .map(|dna| dna.uai.as_str()),
            Some("uai:1:scid:gen.beh.op.att")
        );
    }

    #[tokio::test]
    async fn test_build_agent_context_source_mode_no_tr_manager() {
        let mut inner_metadata = serde_json::Map::new();
        inner_metadata.insert(
            AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION.to_string(),
            json!({ "did": "did:web:source-agent.example.com" }),
        );
        let body = json!({
            "jsonrpc": "2.0",
            "params": {
                "message": {
                    "kind": "message",
                    "metadata": inner_metadata
                }
            }
        });
        let ctx = build_agent_context(Some(&body), None).await;
        assert_eq!(ctx.did, Some("did:web:source-agent.example.com".to_string()));
        assert!(
            ctx.trust_verification
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_build_agent_context_skips_tr_when_no_manager() {
        let card = json!({
            "name": "Agent",
            "capabilities": {
                "extensions": [
                    {
                        "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "did": "did:web:agent"
                    },
                    {
                        "uri": TRUST_REGISTRY_EXTENSION,
                        "params": {
                            "trust_registry_did": "did:web:registry",
                            "provider_did": "did:web:provider",
                            "authority_did": "did:web:authority",
                            "agent_did": "did:web:agent"
                        }
                    }
                ]
            }
        });
        let ctx = build_agent_context(None, Some(&card)).await;
        assert!(
            ctx.trust_verification
                .is_none()
        );
    }
}
