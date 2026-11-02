//! Proof that the caller of an ownership transfer controls the identity.
//!
//! The proof is a compact JWS (`alg` EdDSA, `kid` naming a verification method
//! of the identity's current DID document) whose payload carries a fresh `iat`
//! and `challenge` = `transfer-ownership:<did>:<latest versionId>:<new_controller>`.
//! Binding the latest `versionId` means a proof stops verifying once the log
//! moves on, so it cannot be replayed after the transfer it authorised.

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use super::types::DidDocument;
use super::verifier::resolve_verification_method;

const IAT_FUTURE_SKEW_SECONDS: i64 = 120;
const IAT_MAX_AGE_SECONDS: i64 = 300;

#[derive(Deserialize)]
struct JwsHeader {
    alg: String,
    kid: String,
}

#[derive(Deserialize)]
struct JwsPayload {
    challenge: String,
    iat: i64,
}

pub(crate) fn transfer_challenge(
    did: &str,
    version_id: &str,
    new_controller: &str,
) -> String {
    format!("transfer-ownership:{did}:{version_id}:{new_controller}")
}

/// Verify `authorization` against the identity's current DID document for this
/// exact transfer. `now` is unix seconds.
pub(crate) fn verify_transfer_authorization(
    did: &str,
    document: &DidDocument,
    version_id: &str,
    new_controller: &str,
    authorization: &str,
    now: i64,
) -> Result<()> {
    let segments: Vec<&str> = authorization
        .split('.')
        .collect();
    let [header_b64, payload_b64, signature_b64] = segments[..] else {
        bail!("authorization is not a compact JWS");
    };

    let header: JwsHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64)?)?;
    if header.alg != "EdDSA" {
        bail!("unsupported JWS alg {}", header.alg);
    }
    let own_method_prefix = format!("{did}#");
    if !header
        .kid
        .starts_with(&own_method_prefix)
    {
        bail!("kid {} is not a verification method of {did}", header.kid);
    }

    let public_key = resolve_verification_method(&header.kid, document)?;
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature_b64)?)?;
    VerifyingKey::from_bytes(&public_key)?
        .verify_strict(format!("{header_b64}.{payload_b64}").as_bytes(), &signature)
        .map_err(|_| anyhow!("signature does not verify"))?;

    let payload: JwsPayload = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64)?)?;
    if payload.challenge != transfer_challenge(did, version_id, new_controller) {
        bail!("challenge does not match this transfer");
    }
    if payload.iat > now + IAT_FUTURE_SKEW_SECONDS || payload.iat < now - IAT_MAX_AGE_SECONDS {
        bail!("iat outside the accepted window");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const DID: &str = "did:webvh:zScid:example.com:agents:a";
    const VERSION_ID: &str = "1-zHash";
    const NEW_CONTROLLER: &str = "did:key:z6MkNewController";
    const NOW: i64 = 1_800_000_000;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub(crate) fn sign_jws(
        key: &SigningKey,
        header: serde_json::Value,
        payload: serde_json::Value,
    ) -> String {
        let signing_input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(payload.to_string().as_bytes()));
        let signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64(&signature.to_bytes()))
    }

    fn document_for(key: &SigningKey) -> DidDocument {
        serde_json::from_value(serde_json::json!({
            "id": DID,
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{
                "id": format!("{DID}#key-1"),
                "type": "JsonWebKey2020",
                "controller": DID,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": b64(key.verifying_key().as_bytes())}
            }],
            "authentication": [format!("{DID}#key-1")]
        }))
        .unwrap()
    }

    fn proof(
        key: &SigningKey,
        kid: &str,
        challenge: &str,
        iat: i64,
    ) -> String {
        sign_jws(
            key,
            serde_json::json!({"alg": "EdDSA", "kid": kid}),
            serde_json::json!({"challenge": challenge, "iat": iat}),
        )
    }

    fn verify(
        document: &DidDocument,
        authorization: &str,
    ) -> Result<()> {
        verify_transfer_authorization(DID, document, VERSION_ID, NEW_CONTROLLER, authorization, NOW)
    }

    fn setup() -> (SigningKey, DidDocument, String, String) {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let document = document_for(&key);
        let kid = format!("{DID}#key-1");
        let challenge = transfer_challenge(DID, VERSION_ID, NEW_CONTROLLER);
        (key, document, kid, challenge)
    }

    #[test]
    fn accepts_fresh_proof_signed_by_current_key() {
        let (key, document, kid, challenge) = setup();
        verify(&document, &proof(&key, &kid, &challenge, NOW)).expect("valid proof must verify");
    }

    #[test]
    fn rejects_arbitrary_string() {
        let (_, document, _, _) = setup();
        assert!(verify(&document, "anything").is_err());
        assert!(verify(&document, "a.b.c").is_err());
    }

    #[test]
    fn rejects_proof_signed_by_another_key() {
        let (_, document, kid, challenge) = setup();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(verify(&document, &proof(&other, &kid, &challenge, NOW)).is_err());
    }

    #[test]
    fn rejects_kid_outside_the_identity_document() {
        let (key, document, _, challenge) = setup();
        let mb = multibase::encode(multibase::Base::Base58Btc, key.verifying_key().as_bytes());
        let did_key_kid = format!("did:key:{mb}#{mb}");
        assert!(verify(&document, &proof(&key, &did_key_kid, &challenge, NOW)).is_err());
    }

    #[test]
    fn rejects_proof_bound_to_another_transfer() {
        let (key, document, kid, _) = setup();
        let other_controller = transfer_challenge(DID, VERSION_ID, "did:key:z6MkSomeoneElse");
        let other_version = transfer_challenge(DID, "2-zLater", NEW_CONTROLLER);
        assert!(verify(&document, &proof(&key, &kid, &other_controller, NOW)).is_err());
        assert!(verify(&document, &proof(&key, &kid, &other_version, NOW)).is_err());
    }

    #[test]
    fn rejects_stale_or_future_iat() {
        let (key, document, kid, challenge) = setup();
        assert!(verify(&document, &proof(&key, &kid, &challenge, NOW - IAT_MAX_AGE_SECONDS - 1)).is_err());
        assert!(verify(&document, &proof(&key, &kid, &challenge, NOW + IAT_FUTURE_SKEW_SECONDS + 1)).is_err());
    }

    #[test]
    fn rejects_non_eddsa_alg() {
        let (key, document, kid, challenge) = setup();
        let jws = sign_jws(
            &key,
            serde_json::json!({"alg": "none", "kid": kid}),
            serde_json::json!({"challenge": challenge, "iat": NOW}),
        );
        assert!(verify(&document, &jws).is_err());
    }
}
