//! The retention anchor: what a surface's chain starts from once retention has
//! pruned its oldest records.
//!
//! Pruning removes a prefix of the chain, so the first kept record's
//! `prev_record_hash` names a record that is gone. The anchor states the
//! sequence number and content hash of that last pruned record (and the anchor
//! the log continued from before the prune, if any), wrapped in a W3C
//! VC and signed with the appliance key exactly like a record
//! (`eddsa-jcs-2022`), so verification starts from it instead of from genesis
//! and a forged or altered anchor fails its proof.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::credential::GOVERNANCE_VOCAB;

/// The credential `type` of a retention anchor.
pub const ANCHOR_CREDENTIAL_TYPE: &str = "AIGovernanceChainAnchorCredential";

/// The attested chain position the kept records continue from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainAnchor {
    pub surface_id: String,
    /// Sequence number of the last pruned record (the first kept record is
    /// `seq + 1`).
    pub seq: u64,
    /// That record's `content_hash`, which the first kept record's
    /// `prev_record_hash` must equal.
    pub content_hash: String,
    /// That record's timestamp.
    pub timestamp: String,
    /// When the records were pruned (RFC 3339).
    pub pruned_at: String,
    /// The retention window in force when they were pruned.
    pub retention_days: u32,
    /// The anchor the log continued from before this prune (absent when it
    /// continued from genesis). A prune interrupted after this anchor was
    /// installed leaves a log that still continues from that one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_anchor: Option<AnchorLink>,
}

/// A chain position an anchor attests: a record's `seq` and `content_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorLink {
    pub seq: u64,
    pub content_hash: String,
}

/// The **unsigned** VC envelope around `anchor`, issued by `issuer_did`.
pub fn build_anchor_credential(
    anchor: &ChainAnchor,
    issuer_did: &str,
) -> Result<Value> {
    let subject = serde_json::to_value(anchor).context("serialize governance chain anchor")?;
    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            { "@vocab": GOVERNANCE_VOCAB }
        ],
        "type": ["VerifiableCredential", ANCHOR_CREDENTIAL_TYPE],
        "issuer": issuer_did,
        "validFrom": anchor.pruned_at,
        "credentialSubject": subject,
    }))
}

/// The anchor a signed anchor credential states. Checks its type, not its
/// proof (the signer does that).
pub fn anchor_of(credential: &Value) -> Result<ChainAnchor> {
    let typed = credential["type"]
        .as_array()
        .is_some_and(|types| {
            types
                .iter()
                .any(|t| t == ANCHOR_CREDENTIAL_TYPE)
        });
    if !typed {
        return Err(anyhow!("not a governance chain anchor credential"));
    }
    serde_json::from_value(credential["credentialSubject"].clone()).context("parse governance chain anchor")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> ChainAnchor {
        ChainAnchor {
            surface_id: "surf".to_string(),
            seq: 41,
            content_hash: "sha256:ab".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            pruned_at: "2026-10-04T00:00:00Z".to_string(),
            retention_days: 30,
            prev_anchor: None,
        }
    }

    #[test]
    fn the_anchor_round_trips_through_its_credential() {
        let vc = build_anchor_credential(&anchor(), "did:web:example.com").unwrap();
        assert_eq!(vc["type"][1], ANCHOR_CREDENTIAL_TYPE);
        assert_eq!(vc["issuer"], "did:web:example.com");
        assert_eq!(vc["validFrom"], "2026-10-04T00:00:00Z");
        assert_eq!(vc["credentialSubject"]["seq"], 41);
        assert!(
            vc["credentialSubject"]
                .get("prev_anchor")
                .is_none(),
            "a first prune names no earlier anchor"
        );
        assert_eq!(anchor_of(&vc).unwrap(), anchor());

        let second = ChainAnchor {
            seq: 90,
            prev_anchor: Some(AnchorLink {
                seq: 41,
                content_hash: "sha256:ab".to_string(),
            }),
            ..anchor()
        };
        let vc = build_anchor_credential(&second, "did:web:example.com").unwrap();
        assert_eq!(vc["credentialSubject"]["prev_anchor"], json!({ "seq": 41, "content_hash": "sha256:ab" }));
        assert_eq!(anchor_of(&vc).unwrap(), second);
    }

    #[test]
    fn a_record_credential_is_not_an_anchor() {
        let mut vc = build_anchor_credential(&anchor(), "did:web:example.com").unwrap();
        vc["type"] = json!(["VerifiableCredential", "AIGovernanceRecordCredential"]);
        assert!(anchor_of(&vc).is_err());
        let mut missing = build_anchor_credential(&anchor(), "did:web:example.com").unwrap();
        missing["credentialSubject"]
            .as_object_mut()
            .unwrap()
            .remove("content_hash");
        assert!(anchor_of(&missing).is_err());
    }
}
