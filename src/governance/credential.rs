//! Wraps a [`GovernanceRecord`] in a W3C Verifiable Credential (VC Data Model
//! v2) and signs it with the appliance's Ed25519 key via the existing
//! [`VcSigner`] using the `eddsa-jcs-2022` Data Integrity suite, producing an
//! independently verifiable attestation.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::identity::ssi::vc_issuer::VcSigner;

use super::record::GovernanceRecord;

/// The credential `type` for a governance record VC.
pub const GOVERNANCE_CREDENTIAL_TYPE: &str = "AIGovernanceRecordCredential";

/// Inline `@vocab` namespace for governance-record terms. The custom credential
/// `type` and every `credentialSubject` field expand under this IRI for
/// consumers that process the VC as JSON-LD. It is an RDF namespace identifier
/// only — never dereferenced.
pub(super) const GOVERNANCE_VOCAB: &str = "https://schema.affinidi.com/governance#";

/// Build the **unsigned** W3C VC (v2) envelope around a finalized governance
/// record. The record becomes the `credentialSubject`; `issuer` is the
/// appliance DID; `validFrom` is the record timestamp. The returned value is
/// ready to hand to [`VcSigner::sign`].
pub fn build_record_credential(
    record: &GovernanceRecord,
    issuer_did: &str,
) -> Result<Value> {
    let subject = serde_json::to_value(record).context("serialize governance record subject")?;
    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            { "@vocab": GOVERNANCE_VOCAB }
        ],
        "type": ["VerifiableCredential", GOVERNANCE_CREDENTIAL_TYPE],
        "issuer": issuer_did,
        "validFrom": record.timestamp,
        "credentialSubject": subject,
    }))
}

/// Signs governance records into Verifiable Credentials using the appliance's
/// DID and Ed25519 signer. Holds the issuer DID (from
/// `VCIssuer::get_issuer_did()`) and the reusable [`VcSigner`] (from
/// `VCIssuer::get_vc_signer()`).
#[derive(Clone)]
pub struct GovernanceSigner {
    issuer_did: String,
    signer: Arc<dyn VcSigner>,
}

impl GovernanceSigner {
    /// Construct from an issuer DID and a VC signer.
    pub fn new(
        issuer_did: String,
        signer: Arc<dyn VcSigner>,
    ) -> Self {
        Self { issuer_did, signer }
    }

    /// The appliance DID that issues (and can verify) records.
    pub fn issuer_did(&self) -> &str {
        &self.issuer_did
    }

    /// Wrap a finalized record in a VC and sign it with `eddsa-jcs-2022`,
    /// returning the signed VC JSON. The proof verifies with an Ed25519 library
    /// and the issuer's DID document alone (no JSON-LD canonicalisation).
    pub async fn sign_record(
        &self,
        record: &GovernanceRecord,
    ) -> Result<Value> {
        let credential = build_record_credential(record, &self.issuer_did)?;
        self.signer
            .sign_jcs(credential)
            .await
            .context("sign governance record credential")
    }

    /// Wrap a retention anchor in a VC and sign it the way records are signed.
    pub async fn sign_anchor(
        &self,
        anchor: &super::anchor::ChainAnchor,
    ) -> Result<Value> {
        let credential = super::anchor::build_anchor_credential(anchor, &self.issuer_did)?;
        self.signer
            .sign_jcs(credential)
            .await
            .context("sign governance chain anchor")
    }

    /// The appliance key records are signed with now.
    pub async fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        self.signer
            .verifying_key()
            .await
    }

    /// Check a credential's `eddsa-jcs-2022` proof against the appliance key.
    pub async fn verify(
        &self,
        signed: &Value,
    ) -> Result<()> {
        self.signer
            .verify_jcs(signed)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::record::{GENESIS_HASH, GovernanceRecord, RecordMetrics};
    use crate::identity::ssi::vc_issuer::verify_eddsa_jcs_2022;
    use async_trait::async_trait;

    /// A stub signer that echoes the credential with a fake proof, so the
    /// envelope shape and signer plumbing can be tested without real crypto.
    struct StubSigner;

    #[async_trait]
    impl VcSigner for StubSigner {
        async fn sign(
            &self,
            mut payload: Value,
        ) -> anyhow::Result<Value> {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "proof".to_string(),
                    json!({ "type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022" }),
                );
            }
            Ok(payload)
        }
    }

    fn record() -> GovernanceRecord {
        let mut r = GovernanceRecord {
            record_id: "rec-1".to_string(),
            trace_id: None,
            surface_id: "surf-1".to_string(),
            surface_name: None,
            caller_identity_hash: None,
            caller_identity_kind: None,
            principal_key: None,
            attribution: Default::default(),
            timestamp: "2026-08-12T00:00:00Z".to_string(),
            prev_record_hash: GENESIS_HASH.to_string(),
            stages: vec![],
            prompt: Some("hi".to_string()),
            completion: Some("hello".to_string()),
            attachments: Vec::new(),
            metrics: RecordMetrics::default(),
            content_hash: None,
        };
        r.finalize();
        r
    }

    #[test]
    fn builds_v2_credential_envelope() {
        let vc = build_record_credential(&record(), "did:webvh:example.com:gw").unwrap();
        assert_eq!(vc["issuer"], "did:webvh:example.com:gw");
        assert_eq!(vc["type"][0], "VerifiableCredential");
        assert_eq!(vc["type"][1], GOVERNANCE_CREDENTIAL_TYPE);
        assert_eq!(vc["validFrom"], "2026-08-12T00:00:00Z");
        assert_eq!(vc["credentialSubject"]["record_id"], "rec-1");
        assert!(vc["credentialSubject"]["content_hash"].is_string());
    }

    #[tokio::test]
    async fn signs_record_into_vc_with_proof() {
        let signer = GovernanceSigner::new("did:webvh:example.com:gw".to_string(), Arc::new(StubSigner));
        let signed = signer
            .sign_record(&record())
            .await
            .unwrap();
        assert_eq!(signed["issuer"], "did:webvh:example.com:gw");
        assert!(signed["proof"].is_object());
        assert_eq!(signed["credentialSubject"]["surface_id"], "surf-1");
    }

    #[tokio::test]
    async fn real_signer_signs_governance_record() {
        use crate::identity::VCIssuerConfig;
        use crate::identity::ssi::vc_issuer::LocalVcSigner;
        use tokio::sync::RwLock;

        let signing_key = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "B7hiAU-eeRjFFNXtswXSQhmzwmYfBuZF9f1c3wODZJI",
            "d": "prjVZyovt_E5tC-MCfjcpCNXTw7bEAbrbsgma7VJT64"
        }))
        .unwrap();
        let issuer_did = "did:web:did.example.com:agent-stream".to_string();
        let config = Arc::new(RwLock::new(VCIssuerConfig {
            storage_path: "".into(),
            proxy_did: issuer_did.clone(),
            signing_key,
        }));
        let signer = GovernanceSigner::new(issuer_did, Arc::new(LocalVcSigner::new(config)));
        let signed = signer
            .sign_record(&record())
            .await
            .expect("real signer must sign a governance record");
        assert!(signed["proof"].is_object());
        assert_eq!(signed["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert_eq!(signed["proof"]["verificationMethod"], "did:web:did.example.com:agent-stream#key-2");

        let key = ed25519_dalek::SigningKey::from_bytes(&{
            use base64::Engine;
            let d = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode("prjVZyovt_E5tC-MCfjcpCNXTw7bEAbrbsgma7VJT64")
                .unwrap();
            <[u8; 32]>::try_from(d).unwrap()
        });
        let vk = key.verifying_key();
        verify_eddsa_jcs_2022(&signed, &vk).expect("proof must verify without JSON-LD");

        let mut tampered = signed.clone();
        tampered["credentialSubject"]["prompt"] = json!("tampered");
        assert!(verify_eddsa_jcs_2022(&tampered, &vk).is_err());

        let other = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        assert!(verify_eddsa_jcs_2022(&signed, &other).is_err());
    }

    #[tokio::test]
    async fn the_appliance_signer_signs_and_checks_a_retention_anchor() {
        use crate::identity::VCIssuerConfig;
        use crate::identity::ssi::vc_issuer::LocalVcSigner;
        use tokio::sync::RwLock;

        let config = |d: &str, x: &str| {
            Arc::new(RwLock::new(VCIssuerConfig {
                storage_path: "".into(),
                proxy_did: "did:web:did.example.com:agent-stream".to_string(),
                signing_key: serde_json::from_value(json!({ "kty": "OKP", "crv": "Ed25519", "x": x, "d": d })).unwrap(),
            }))
        };
        let appliance = GovernanceSigner::new(
            "did:web:did.example.com:agent-stream".to_string(),
            Arc::new(LocalVcSigner::new(config(
                "prjVZyovt_E5tC-MCfjcpCNXTw7bEAbrbsgma7VJT64",
                "B7hiAU-eeRjFFNXtswXSQhmzwmYfBuZF9f1c3wODZJI",
            ))),
        );
        let anchor = crate::governance::anchor::ChainAnchor {
            surface_id: "surf-1".to_string(),
            seq: 12,
            content_hash: "sha256:ab".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            pruned_at: "2026-10-04T00:00:00Z".to_string(),
            retention_days: 30,
            prev_anchor: None,
        };
        let signed = appliance
            .sign_anchor(&anchor)
            .await
            .unwrap();
        assert_eq!(signed["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert_eq!(signed["issuer"], "did:web:did.example.com:agent-stream");
        appliance
            .verify(&signed)
            .await
            .expect("the appliance key checks its own anchor");

        let mut tampered = signed.clone();
        tampered["credentialSubject"]["seq"] = json!(11);
        assert!(
            appliance
                .verify(&tampered)
                .await
                .is_err()
        );

        let other_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut unsigned = signed.clone();
        unsigned
            .as_object_mut()
            .unwrap()
            .remove("proof");
        let forged = crate::identity::ssi::vc_issuer::sign_eddsa_jcs_2022(
            unsigned,
            &other_key,
            "did:web:did.example.com:agent-stream#key-2",
        )
        .unwrap();
        assert!(
            appliance
                .verify(&forged)
                .await
                .is_err(),
            "a proof by another key is refused"
        );

        let stub = GovernanceSigner::new("did:webvh:example.com:gw".to_string(), Arc::new(StubSigner));
        assert!(
            stub.verify(&signed)
                .await
                .is_err(),
            "a signer with no key to check against refuses rather than passes"
        );
    }
}
