//! Protocol-agnostic extension inspection and utility functions
//!
//! This module contains functions that work across multiple messaging protocols
//! (A2A, MCP, UCP, ACP, etc.) for inspecting extensions, validating messages,
//! and resolving secret references.

use serde_json::Value as JsonValue;
use std::sync::Arc;
use tracing::{debug, info};

/// Recursively resolve $SECRET:secret_name references in a JSON value
/// Returns a new JSON value with secret references resolved to actual secret values
/// Resolve secret references in a JSON value recursively
/// Converts $SECRET:xxx references to actual secret values by looking them up in the secrets store
pub fn resolve_secret_references<'a>(
    value: &'a JsonValue,
    secrets_store: &'a Option<Arc<dyn crate::secrets::SecretsStore>>,
    channel_name: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<JsonValue>> + Send + 'a>> {
    Box::pin(async move {
        match value {
            JsonValue::String(s) => {
                // Check if this is a secret reference
                if s.starts_with("$SECRET:") {
                    // Extract the secret_id
                    let secret_id_ref = s
                        .strip_prefix("$SECRET:")
                        .unwrap();

                    // Get secrets store or error
                    let store = secrets_store
                        .as_ref()
                        .ok_or_else(|| {
                            anyhow::anyhow!("Secret reference {} found but secrets store is not configured", s)
                        })?;

                    // Search for secret by secret_id
                    let secrets = store.list_all().await?;
                    let secret_uuid = secrets
                        .iter()
                        .find(|sec| sec.secret_id == secret_id_ref)
                        .map(|sec| sec.id.clone())
                        .ok_or_else(|| anyhow::anyhow!("Secret with secret_id '{}' not found", secret_id_ref))?;

                    // Get the secret value
                    let secret = store
                        .get(&secret_uuid)
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Secret with secret_id '{}' (UUID: {}) was deleted",
                                secret_id_ref,
                                secret_uuid
                            )
                        })?;

                    debug!(channel = channel_name, secret_id = secret_id_ref, "Resolved secret reference");

                    Ok(JsonValue::String(secret.value))
                } else {
                    Ok(value.clone())
                }
            }
            JsonValue::Array(arr) => {
                let mut resolved_arr = Vec::new();
                for item in arr {
                    resolved_arr.push(resolve_secret_references(item, secrets_store, channel_name).await?);
                }
                Ok(JsonValue::Array(resolved_arr))
            }
            JsonValue::Object(obj) => {
                let mut resolved_obj = serde_json::Map::new();
                for (key, val) in obj {
                    resolved_obj
                        .insert(key.clone(), resolve_secret_references(val, secrets_store, channel_name).await?);
                }
                Ok(JsonValue::Object(resolved_obj))
            }
            _ => Ok(value.clone()),
        }
    })
}

/// Inject custom metadata extension into a JSON-RPC message body.
/// Adds the AFFINIDI_AGENT_METADATA_EXTENSION to the message's extensions array
/// and merges the metadata payload into the message metadata object.
pub async fn inject_custom_metadata_extension(
    body_bytes: &bytes::Bytes,
    custom_metadata: &crate::config::CustomMetadata,
    channel_name: &str,
    secrets_store: &Option<Arc<dyn crate::secrets::SecretsStore>>,
) -> anyhow::Result<bytes::Bytes> {
    let mut body_json: JsonValue =
        serde_json::from_slice(body_bytes).map_err(|e| anyhow::anyhow!("Failed to parse body as JSON: {}", e))?;

    let metadata_payload = custom_metadata
        .payload
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Custom metadata is enabled but no payload configured"))?;

    let resolved_payload =
        crate::protocols::resolve_secret_references(metadata_payload, secrets_store, channel_name).await?;

    let use_params = body_json
        .get("params")
        .and_then(|p| p.get("message"))
        .is_some();

    if !use_params
        && body_json
            .get("result")
            .is_none()
    {
        return Err(anyhow::anyhow!("No message object found in body"));
    }

    let message = if use_params {
        body_json
            .get_mut("params")
            .and_then(|p| p.get_mut("message"))
            .ok_or_else(|| anyhow::anyhow!("No message object found in params"))?
    } else {
        body_json
            .get_mut("result")
            .ok_or_else(|| anyhow::anyhow!("No result object found in body"))?
    };

    if !message
        .as_object()
        .map(|o| o.contains_key("extensions"))
        .unwrap_or(false)
    {
        message
            .as_object_mut()
            .unwrap()
            .insert("extensions".to_string(), JsonValue::Array(vec![]));
    }
    let extensions = message
        .get_mut("extensions")
        .and_then(|e| e.as_array_mut())
        .ok_or_else(|| anyhow::anyhow!("Extensions field is not an array"))?;

    let extension_uri = crate::config::AFFINIDI_AGENT_METADATA_EXTENSION;

    if !extensions
        .iter()
        .any(|e| e.as_str() == Some(extension_uri))
    {
        extensions.push(JsonValue::String(extension_uri.to_string()));
        debug!(channel = channel_name, "Added custom metadata extension URI to extensions array");
    }

    if !message
        .as_object()
        .unwrap()
        .contains_key("metadata")
    {
        message
            .as_object_mut()
            .unwrap()
            .insert("metadata".to_string(), JsonValue::Object(serde_json::Map::new()));
    }

    let metadata = message
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("Metadata field is not an object"))?;

    if let Some(existing) = metadata.get_mut(extension_uri) {
        if let (Some(existing_obj), Some(new_obj)) = (existing.as_object_mut(), resolved_payload.as_object()) {
            for (key, value) in new_obj {
                existing_obj.insert(key.clone(), value.clone());
            }
            debug!(
                channel = channel_name,
                extension = extension_uri,
                "Merged custom metadata payload (GW2 overrides GW1 on collision)"
            );
        } else {
            metadata.insert(extension_uri.to_string(), resolved_payload.clone());
            debug!(
                channel = channel_name,
                extension = extension_uri,
                "Replaced custom metadata payload (not mergeable)"
            );
        }
    } else {
        metadata.insert(extension_uri.to_string(), resolved_payload.clone());
        debug!(channel = channel_name, extension = extension_uri, "Added custom metadata payload to metadata object");
    }

    let modified_json =
        serde_json::to_vec(&body_json).map_err(|e| anyhow::anyhow!("Failed to serialize modified JSON: {}", e))?;

    Ok(bytes::Bytes::from(modified_json))
}

/// The `forward-request` a response presentation answers: its `id` is the
/// challenge and the requester's Connection Point DID the domain.
pub struct AnsweredRequest<'a> {
    pub id: &'a str,
    pub requester_did: &'a str,
}

/// Inject a backend agent VP into a JSON-RPC response message.
/// Replaces the raw identity extension with a credential extension containing the VP.
pub async fn inject_vp_into_response(
    response_bytes: &bytes::Bytes,
    agent_did: &str,
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    workload_binding: Option<serde_json::Value>,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
    answering: AnsweredRequest<'_>,
) -> anyhow::Result<(bytes::Bytes, String)> {
    let vp_jwt = vc_issuer
        .create_agent_identity_presentation_with_binding(
            agent_did,
            identity_fields,
            workload_binding,
            Some(answering.id),
            Some(answering.requester_did),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create identity presentation: {}", e))?;

    info!(channel = channel_name, did = agent_did, "Created identity credential VP for backend agent response");

    let mut response_json: JsonValue = serde_json::from_slice(response_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse response as JSON: {}", e))?;

    let message_obj = if let Some(result) = response_json.get_mut("result") {
        if let Some(history_arr) = result
            .get_mut("history")
            .and_then(|h| h.as_array_mut())
        {
            if let Some(first_msg) = history_arr.first_mut() {
                debug!(channel = channel_name, "VP injection: Using result.history[0]");
                first_msg
            } else {
                return Err(anyhow::anyhow!("History array is empty"));
            }
        } else if result
            .get("metadata")
            .is_some()
            || result
                .get("extensions")
                .is_some()
        {
            debug!(channel = channel_name, "VP injection: Using result directly");
            result
        } else {
            return Err(anyhow::anyhow!("No history array or metadata found in result"));
        }
    } else {
        return Err(anyhow::anyhow!("No result field found in response"));
    };

    if !message_obj
        .as_object()
        .map(|o| o.contains_key("extensions"))
        .unwrap_or(false)
        && let Some(msg_obj) = message_obj.as_object_mut()
    {
        msg_obj.insert("extensions".to_string(), JsonValue::Array(vec![]));
    }

    let extensions = message_obj
        .get_mut("extensions")
        .and_then(|e| e.as_array_mut())
        .ok_or_else(|| anyhow::anyhow!("Extensions field is not an array or doesn't exist"))?;

    let agent_identity_uri = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;
    extensions.retain(|e| e.as_str() != Some(agent_identity_uri));

    let extension_uri = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
    if !extensions
        .iter()
        .any(|e| e.as_str() == Some(extension_uri))
    {
        extensions.push(JsonValue::String(extension_uri.to_string()));
        debug!(channel = channel_name, "Added identity credential extension URI to response extensions array");
    }

    if !message_obj
        .as_object()
        .map(|o| o.contains_key("metadata"))
        .unwrap_or(false)
        && let Some(msg_obj) = message_obj.as_object_mut()
    {
        msg_obj.insert("metadata".to_string(), JsonValue::Object(serde_json::Map::new()));
    }

    let metadata = message_obj
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("Metadata field is not an object"))?;

    metadata.remove(agent_identity_uri);

    metadata.insert(
        extension_uri.to_string(),
        serde_json::json!({
            "verifiablePresentation": vp_jwt,
            "did": agent_did,
        }),
    );

    info!(channel = channel_name, "Injected backend agent identity credential VP into response, removed raw identity");

    let modified_json = serde_json::to_vec(&response_json)
        .map_err(|e| anyhow::anyhow!("Failed to serialize modified response JSON: {}", e))?;

    Ok((bytes::Bytes::from(modified_json), vp_jwt))
}

/// Outcome of [`strip_raw_identity_from_meta`], so the caller can log each case
/// and decide policy (e.g. fail closed on a malformed `_meta`).
#[derive(Debug, Clone, PartialEq)]
pub enum MetaStripOutcome {
    /// `_meta[meta_field]` was present and removed; carries the rewritten body.
    Removed(bytes::Bytes),
    /// Nothing to strip: body is not a JSON object, has no `_meta`, or the field
    /// was already absent. Benign — the raw identity field is not being forwarded.
    Nothing,
    /// `_meta` is present but **not** a JSON object. This is malformed for MCP
    /// (the spec requires `_meta` to be an object), so identity redaction cannot
    /// be reasoned about — the caller should fail closed on a redaction surface.
    MetaNotObject,
    /// The body could not be parsed as JSON, or the redacted body could not be
    /// re-serialized. Redaction cannot be guaranteed, so this is **not** benign:
    /// the caller must fail closed on a redaction surface rather than forward the
    /// original, potentially identity-bearing, body.
    ParseFailed,
    /// The body exceeds [`MAX_REDACTION_BODY_BYTES`], so it is rejected before the
    /// full parse + re-serialize the redaction step would otherwise perform on
    /// every forwarded request. Defense-in-depth against resource exhaustion on the
    /// fabric-forward path, where the transport (DIDComm/websocket) does not apply
    /// the HTTP routers' body limit.
    BodyTooLarge,
}

/// Upper bound on an MCP request body the redaction step will parse. Mirrors the
/// A2A `max_body_size` default (10 MiB); a body larger than this is rejected before
/// `serde_json::from_slice`, bounding per-request CPU/memory on a redaction surface.
/// (Belt-and-braces: the ingress transport also caps message size — this makes the
/// bound explicit and local to the parse. Wire to `A2aConfig::max_body_size` if a
/// per-surface value is ever needed.)
pub const MAX_REDACTION_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Remove a raw identity field from an MCP message's top-level `_meta` object,
/// reporting what happened via [`MetaStripOutcome`].
///
/// Enforces `PayloadExtractionConfig::strip_raw_meta`: once the gateway has
/// extracted the caller identity and injected the verified credential, the raw
/// identity block must not be forwarded to the target alongside it.
///
/// Scope: removes the configured `meta_field` key **and** any other `_meta` key
/// whose value equals that extracted identity — for any value type (object, array,
/// or scalar) — plus, for a scalar (string) identity, any value that is a common
/// reversible encoding of it (base64/base64url/hex). This closes the key-aliasing
/// bypass where a caller copies the raw identity under a second key name, including
/// obvious re-encodings. Unrelated `_meta` keys (progress tokens, trace ids, etc.),
/// whose values differ, are preserved by design.
///
/// This is **best-effort defense-in-depth, not a complete anti-exfiltration
/// guarantee**: the caller controls the request body and can convey data through
/// channels this does not touch (other body fields, unlisted encodings). The
/// authoritative identity a target must trust is the injected verified credential,
/// never a value in `_meta`. It is not a general `_meta` sanitizer.
pub fn strip_raw_identity_from_meta(
    body_bytes: &bytes::Bytes,
    meta_field: &str,
) -> MetaStripOutcome {
    // Defense-in-depth: bound the work before the full parse + re-serialize. On the
    // fabric-forward path the body arrives over DIDComm/websocket, not an axum body,
    // so the routers' `DefaultBodyLimit` does not apply here. Reject oversized bodies
    // (fail closed) rather than parse them on every forwarded request.
    if body_bytes.len() > MAX_REDACTION_BODY_BYTES {
        return MetaStripOutcome::BodyTooLarge;
    }
    let Ok(mut json) = serde_json::from_slice::<JsonValue>(body_bytes) else {
        // Could not parse the body — redaction cannot be verified. Fail closed
        // (do not treat like "no identity present"), mirroring `MetaNotObject`.
        return MetaStripOutcome::ParseFailed;
    };
    let Some(meta_value) = json
        .as_object_mut()
        .and_then(|obj| obj.get_mut("_meta"))
    else {
        return MetaStripOutcome::Nothing; // body not an object, or no `_meta`.
    };
    let Some(meta) = meta_value.as_object_mut() else {
        // `_meta` present but not an object — malformed for MCP. Do not silently
        // pass through on a redaction surface; report so the caller fails closed.
        return MetaStripOutcome::MetaNotObject;
    };
    let Some(identity) = meta.remove(meta_field) else {
        return MetaStripOutcome::Nothing; // field already absent.
    };
    // Close the key-aliasing bypass: drop any remaining `_meta` entry whose value
    // equals the extracted identity, regardless of key name, so a copy smuggled
    // under an alias key cannot reach the target. Swept by value-equality for all
    // identity types (object, array, and scalar). For a scalar (string) identity we
    // additionally drop values that are a common reversible encoding of it
    // (base64/base64url/hex) — best-effort against an obvious re-encoded copy; see
    // the fn doc on why this is defense-in-depth, not a complete guarantee.
    let identity_str = identity
        .as_str()
        .map(str::to_owned);
    meta.retain(|_, v| {
        if *v == identity {
            return false;
        }
        if let (Some(plain), Some(candidate)) = (identity_str.as_deref(), v.as_str())
            && is_reversible_encoding_of(candidate, plain)
        {
            return false;
        }
        true
    });
    match serde_json::to_vec(&json) {
        Ok(v) => MetaStripOutcome::Removed(bytes::Bytes::from(v)),
        // Reserialization of an already-parsed value should not fail — but if it
        // does we cannot produce a verified-redacted body, so fail closed rather
        // than forward the original, potentially identity-bearing, body.
        Err(_) => MetaStripOutcome::ParseFailed,
    }
}

/// True if `candidate` is `plain` re-encoded under a common reversible scheme
/// (base64, base64url, or hex, with or without padding). Best-effort only — there
/// is no complete set of encodings, so this is defense-in-depth, not a guarantee
/// (see [`strip_raw_identity_from_meta`]). Compares decoded bytes to `plain`
/// exactly, so a normal string that merely happens to be valid base64/hex does not
/// match unless it actually decodes to the identity.
fn is_reversible_encoding_of(
    candidate: &str,
    plain: &str,
) -> bool {
    use base64::Engine;
    if candidate.is_empty() || candidate == plain {
        return false;
    }
    let want = plain.as_bytes();
    if let Ok(bytes) = hex::decode(candidate)
        && bytes == want
    {
        return true;
    }
    let cand = candidate.as_bytes();
    for res in [
        base64::engine::general_purpose::STANDARD.decode(cand),
        base64::engine::general_purpose::URL_SAFE.decode(cand),
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(cand),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(cand),
    ] {
        if let Ok(bytes) = res
            && bytes == want
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod strip_raw_meta_tests {
    use super::{MetaStripOutcome, strip_raw_identity_from_meta};

    #[test]
    fn removes_raw_identity_field_from_meta() {
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "method": "tools/call",
                "_meta": { "agentIdentity": { "sub": "raw" }, "keep": 1 }
            }))
            .unwrap(),
        );
        let MetaStripOutcome::Removed(out) = strip_raw_identity_from_meta(&body, "agentIdentity") else {
            panic!("expected Removed");
        };
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(
            json["_meta"]
                .get("agentIdentity")
                .is_none(),
            "raw identity must be stripped"
        );
        assert_eq!(json["_meta"]["keep"], 1, "other _meta keys are preserved");
    }

    #[test]
    fn strips_aliased_duplicate_identity_under_other_key() {
        // Key-aliasing bypass: a caller copies the raw identity block
        // under a second key name. Both copies must be stripped; unrelated keys
        // (e.g. a progress token) must survive.
        let ident = serde_json::json!({ "sub": "raw", "iss": "did:example:123" });
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "method": "tools/call",
                "_meta": {
                    "agentIdentity": ident.clone(),
                    "rawIdentityCopy": ident.clone(),
                    "progressToken": "abc"
                }
            }))
            .unwrap(),
        );
        let MetaStripOutcome::Removed(out) = strip_raw_identity_from_meta(&body, "agentIdentity") else {
            panic!("expected Removed");
        };
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(
            json["_meta"]
                .get("agentIdentity")
                .is_none(),
            "primary identity key must be stripped"
        );
        assert!(
            json["_meta"]
                .get("rawIdentityCopy")
                .is_none(),
            "aliased duplicate of the identity must also be stripped"
        );
        assert_eq!(json["_meta"]["progressToken"], "abc", "unrelated _meta keys must be preserved");
    }

    #[test]
    fn strips_aliased_scalar_duplicate_under_other_key() {
        // The identity is a bare scalar (a DID string)
        // copied under an alias key. The value-equality sweep must strip the
        // scalar copy too — not only object/array identities — while preserving
        // unrelated keys whose values differ.
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "method": "tools/call",
                "_meta": {
                    "agentIdentity": "did:example:123",
                    "rawIdentityCopy": "did:example:123",
                    "progressToken": "abc"
                }
            }))
            .unwrap(),
        );
        let MetaStripOutcome::Removed(out) = strip_raw_identity_from_meta(&body, "agentIdentity") else {
            panic!("expected Removed");
        };
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(
            json["_meta"]
                .get("agentIdentity")
                .is_none(),
            "primary scalar identity must be stripped"
        );
        assert!(
            json["_meta"]
                .get("rawIdentityCopy")
                .is_none(),
            "aliased scalar duplicate of the identity must also be stripped"
        );
        assert_eq!(json["_meta"]["progressToken"], "abc", "unrelated _meta keys must be preserved");
    }

    #[test]
    fn strips_base64_encoded_scalar_duplicate() {
        // A caller re-encodes the scalar identity under an alias key (base64) to
        // dodge the exact-value sweep. Best-effort encoding check must still drop it.
        use base64::Engine;
        let did = "did:example:123";
        let b64 = base64::engine::general_purpose::STANDARD.encode(did);
        let hexed = hex::encode(did);
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "method": "tools/call",
                "_meta": {
                    "agentIdentity": did,
                    "b64Copy": b64,
                    "hexCopy": hexed,
                    "progressToken": "abc"
                }
            }))
            .unwrap(),
        );
        let MetaStripOutcome::Removed(out) = strip_raw_identity_from_meta(&body, "agentIdentity") else {
            panic!("expected Removed");
        };
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(
            json["_meta"]
                .get("agentIdentity")
                .is_none(),
            "primary scalar identity must be stripped"
        );
        assert!(
            json["_meta"]
                .get("b64Copy")
                .is_none(),
            "base64-encoded duplicate must be stripped"
        );
        assert!(
            json["_meta"]
                .get("hexCopy")
                .is_none(),
            "hex-encoded duplicate must be stripped"
        );
        assert_eq!(json["_meta"]["progressToken"], "abc", "unrelated _meta keys must be preserved");
    }

    #[test]
    fn nothing_when_field_absent_or_no_meta() {
        let body = bytes::Bytes::from(serde_json::to_vec(&serde_json::json!({ "_meta": { "other": 1 } })).unwrap());
        assert_eq!(strip_raw_identity_from_meta(&body, "agentIdentity"), MetaStripOutcome::Nothing);

        let no_meta = bytes::Bytes::from(serde_json::to_vec(&serde_json::json!({ "x": 1 })).unwrap());
        assert_eq!(strip_raw_identity_from_meta(&no_meta, "agentIdentity"), MetaStripOutcome::Nothing);
    }

    #[test]
    fn oversized_body_fails_closed() {
        // Defense-in-depth: a body over the parse bound is rejected
        // before serde parses it, rather than parsed+re-serialized on every forward.
        use super::MAX_REDACTION_BODY_BYTES;
        let mut big = Vec::with_capacity(MAX_REDACTION_BODY_BYTES + 64);
        big.extend_from_slice(b"{\"_meta\":{\"agentIdentity\":\"");
        big.resize(MAX_REDACTION_BODY_BYTES + 1, b'a');
        let body = bytes::Bytes::from(big);
        assert!(body.len() > MAX_REDACTION_BODY_BYTES);
        assert_eq!(strip_raw_identity_from_meta(&body, "agentIdentity"), MetaStripOutcome::BodyTooLarge);
    }

    #[test]
    fn parse_failure_fails_closed_not_open() {
        // A body that fails to parse must NOT be treated like
        // "no identity present" (which would forward the original body unredacted).
        // It must report ParseFailed so the caller fails closed on a redaction surface.
        let not_json = bytes::Bytes::from_static(b"not json");
        assert_eq!(strip_raw_identity_from_meta(&not_json, "agentIdentity"), MetaStripOutcome::ParseFailed);
    }

    #[test]
    fn reports_non_object_meta_so_caller_can_fail_closed() {
        // `_meta` as an array — malformed for MCP; must not silently pass through.
        let arr = bytes::Bytes::from(serde_json::to_vec(&serde_json::json!({ "_meta": [1, 2, 3] })).unwrap());
        assert_eq!(strip_raw_identity_from_meta(&arr, "agentIdentity"), MetaStripOutcome::MetaNotObject);

        // `_meta` as a string — same.
        let s = bytes::Bytes::from(serde_json::to_vec(&serde_json::json!({ "_meta": "nope" })).unwrap());
        assert_eq!(strip_raw_identity_from_meta(&s, "agentIdentity"), MetaStripOutcome::MetaNotObject);
    }
}

#[cfg(test)]
mod response_vp_tests {
    use super::{AnsweredRequest, inject_vp_into_response};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn the_response_presentation_answers_the_request_it_was_minted_for() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let identity_fields =
            HashMap::from([("agentIdentity".to_string(), json!({ "softwareInfo": { "name": "backend-agent" } }))]);
        let agent_did = issuer
            .issue_or_get_credential(identity_fields.clone(), None, None)
            .await
            .expect("agent identity")
            .did;
        let response = bytes::Bytes::from(
            json!({ "jsonrpc": "2.0", "id": 1, "result": { "metadata": {}, "extensions": [] } }).to_string(),
        );

        let (body, vp_jwt) = inject_vp_into_response(
            &response,
            &agent_did,
            &identity_fields,
            None,
            &Arc::new(issuer),
            "channel-1",
            AnsweredRequest {
                id: "forward-request-1",
                requester_did: "did:peer:2.requester",
            },
        )
        .await
        .expect("presentation injected");

        let vp: Value = serde_json::from_str(&vp_jwt).expect("JSON presentation");
        assert_eq!(vp["proof"]["challenge"], json!("forward-request-1"));
        assert_eq!(vp["proof"]["domain"], json!("did:peer:2.requester"));
        let body: Value = serde_json::from_slice(&body).expect("JSON response");
        assert_eq!(
            body["result"]["metadata"][crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION]["verifiablePresentation"],
            json!(vp_jwt)
        );
    }
}
