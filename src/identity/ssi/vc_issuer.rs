use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Ok, Result};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use ssi::claims::vc;
use ssi::crypto::ed25519::VerifyingKey;
use ssi::dids::DIDKey;
use ssi::jwk::JWK;
use ssi::prelude::{AnyMethod, AnySuite, CryptographicSuite, ProofOptions, SingleSecretSigner};
use ssi::verification_methods::LocalSigner as SsiLocalSigner;
use ssi::verification_methods::{Multikey, ReferenceOrOwned};
use ssi_json_ld::IriBuf;
use tokio::sync::RwLock;

use crate::identity::VCIssuerConfig;
use crate::identity::ssi::context::{CTX_AGENT_IDENTITY_V1_URL, create_signature_environment};
use crate::identity::ssi::jcs;
use crate::identity::status_list::StatusListRegistry;

pub const VC_LIFETIME_DAYS: i64 = 365;
pub const DEFAULT_SIGNING_KEY_ID: &str = "key-2";

pub struct AgentIdentity<'a> {
    pub identity_fields: Cow<'a, HashMap<String, serde_json::Value>>,
    pub did: Cow<'a, str>,
    /// Pre-built workload binding JSON for the credential subject.
    /// When present, replaces the flat `identityFields` with structured `workloadBinding`.
    pub workload_binding: Option<serde_json::Value>,
}

pub enum IssueVcPayload<'a> {
    AgentIdentity(AgentIdentity<'a>),
}

#[async_trait]
pub trait VcSigner: Send + Sync {
    async fn sign(
        &self,
        payload: Value,
    ) -> Result<Value>;

    /// Sign with the `eddsa-jcs-2022` Data Integrity suite, which a verifier
    /// can check with an Ed25519 library and the DID document alone (no
    /// JSON-LD processing). Signers without a JCS implementation fall back to
    /// their native suite.
    async fn sign_jcs(
        &self,
        payload: Value,
    ) -> Result<Value> {
        self.sign(payload).await
    }

    /// The Ed25519 public key this signer signs with now. Signers that hold no
    /// key a proof can be checked against answer an error.
    async fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        Err(anyhow::anyhow!("this signer cannot check a proof"))
    }

    /// Check an `eddsa-jcs-2022` proof made with this signer's key.
    async fn verify_jcs(
        &self,
        signed: &Value,
    ) -> Result<()> {
        verify_eddsa_jcs_2022(signed, &self.verifying_key().await?)
    }
}

#[async_trait]
pub trait VcIssuer: Send + Sync {
    async fn issue<'a>(
        &self,
        payload: IssueVcPayload<'a>,
    ) -> Result<Value>;
}

pub struct LocalVcIssuer {
    config: Arc<RwLock<VCIssuerConfig>>,
    signer: Arc<dyn VcSigner>,
    status_list: Option<Arc<StatusListRegistry>>,
}

impl LocalVcIssuer {
    pub fn new(
        config: Arc<RwLock<VCIssuerConfig>>,
        signer: Arc<dyn VcSigner>,
    ) -> Self {
        Self {
            config,
            signer,
            status_list: None,
        }
    }

    /// Give every issued credential a revocation entry in `status_list`.
    pub fn with_status_list(
        mut self,
        status_list: Arc<StatusListRegistry>,
    ) -> Self {
        self.status_list = Some(status_list);
        self
    }
}

pub struct LocalVcSigner {
    config: Arc<RwLock<VCIssuerConfig>>,
}

impl LocalVcSigner {
    pub fn new(config: Arc<RwLock<VCIssuerConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl VcSigner for LocalVcSigner {
    async fn sign(
        &self,
        payload: Value,
    ) -> Result<Value> {
        self.sign_w3c_ldv2(payload.clone())
            .await
    }

    async fn sign_jcs(
        &self,
        payload: Value,
    ) -> Result<Value> {
        let (signing_key, issuer_did) = {
            let config = self.config.read().await;
            (config.signing_key.clone(), config.proxy_did.clone())
        };
        let verification_method = format!("{}#{}", issuer_did, DEFAULT_SIGNING_KEY_ID);
        sign_eddsa_jcs_2022(payload, &ed25519_signing_key(&signing_key)?, &verification_method)
    }

    async fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        let signing_key = self
            .config
            .read()
            .await
            .signing_key
            .clone();
        Ok(ed25519_signing_key(&signing_key)?.verifying_key())
    }
}

/// The Ed25519 key behind the issuer's private JWK.
fn ed25519_signing_key(jwk: &JWK) -> Result<ed25519_dalek::SigningKey> {
    let d_str = serde_json::to_value(jwk)?
        .get("d")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .context("Missing private key component 'd'")?;
    let secret: [u8; 32] = URL_SAFE_NO_PAD
        .decode(d_str)
        .context("Failed to decode private key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&secret))
}

/// The `eddsa-jcs-2022` hash input: SHA-256 of the JCS proof configuration
/// (the proof minus `proofValue`, plus the document's `@context`) followed by
/// SHA-256 of the JCS unsecured document.
fn jcs_hash_data(
    unsecured: &Value,
    proof_options: &Value,
) -> Result<Vec<u8>> {
    let mut config = proof_options.clone();
    if let (Some(obj), Some(ctx)) = (config.as_object_mut(), unsecured.get("@context")) {
        obj.insert("@context".to_string(), ctx.clone());
    }
    let config_jcs = jcs::canonicalize(&config);
    let doc_jcs = jcs::canonicalize(unsecured);
    Ok([Sha256::digest(config_jcs.as_bytes()).as_slice(), Sha256::digest(doc_jcs.as_bytes()).as_slice()].concat())
}

/// Attach an `eddsa-jcs-2022` Data Integrity proof (multibase base58btc
/// `proofValue`) to `document`.
pub fn sign_eddsa_jcs_2022(
    mut document: Value,
    signing_key: &ed25519_dalek::SigningKey,
    verification_method: &str,
) -> Result<Value> {
    let obj = document
        .as_object_mut()
        .context("document must be a JSON object")?;
    obj.remove("proof");
    let mut proof = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
    });
    let hash_data = jcs_hash_data(&document, &proof)?;
    let sig = signing_key.sign(&hash_data);
    proof["proofValue"] = Value::String(multibase::encode(multibase::Base::Base58Btc, sig.to_bytes()));
    document["proof"] = proof;
    Ok(document)
}

/// Verify an `eddsa-jcs-2022` proof on `signed` against `verifying_key`.
pub fn verify_eddsa_jcs_2022(
    signed: &Value,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    let mut unsecured = signed.clone();
    let mut proof = unsecured
        .as_object_mut()
        .and_then(|o| o.remove("proof"))
        .context("missing proof")?;
    anyhow::ensure!(proof["cryptosuite"] == "eddsa-jcs-2022", "unsupported cryptosuite");
    let proof_value = proof
        .as_object_mut()
        .and_then(|o| o.remove("proofValue"))
        .and_then(|v| v.as_str().map(str::to_owned))
        .context("missing proofValue")?;
    let (_base, sig_bytes) = multibase::decode(&proof_value).context("decode proofValue")?;
    let sig = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signature length"))?,
    );
    let hash_data = jcs_hash_data(&unsecured, &proof)?;
    verifying_key
        .verify_strict(&hash_data, &sig)
        .context("signature mismatch")
}

/// Verify an `eddsa-rdfc-2022` proof (the suite [`VcSigner::sign`] produces)
/// on the credential `signed` against `verifying_key`, whatever key id its
/// `verificationMethod` names.
pub async fn verify_eddsa_rdfc_2022(
    signed: &Value,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    use ssi::claims::VerificationParameters;
    use ssi::claims::data_integrity::AnyDataIntegrity;
    use ssi::claims::vc::v2::syntax::JsonCredential;

    anyhow::ensure!(signed["proof"]["cryptosuite"] == "eddsa-rdfc-2022", "unsupported cryptosuite");
    let method = &signed["proof"]["verificationMethod"];
    let method = method
        .as_str()
        .or_else(|| method["id"].as_str())
        .context("missing verificationMethod")?;
    let controller = method
        .split_once('#')
        .map_or(method, |(did, _)| did);
    let key = VerifyingKey::from_bytes(verifying_key.as_bytes()).map_err(|e| anyhow::anyhow!("invalid key: {e}"))?;
    let iri: IriBuf = method
        .to_string()
        .try_into()
        .map_err(|_| anyhow::anyhow!("verificationMethod is not an IRI"))?;
    let resolver: HashMap<IriBuf, AnyMethod> = HashMap::from([(
        iri.clone(),
        AnyMethod::Multikey(Multikey::from_public_key(
            iri,
            controller
                .to_string()
                .try_into()
                .map_err(|_| anyhow::anyhow!("issuer is not a URI"))?,
            &key,
        )),
    )]);
    let credential: AnyDataIntegrity<JsonCredential> =
        serde_json::from_value(signed.clone()).context("parse Data Integrity credential")?;
    let env = create_signature_environment(None).await?;
    let params = VerificationParameters::from_resolver(resolver).with_json_ld_loader(env.json_ld_loader);
    credential
        .verify(&params)
        .await
        .map_err(|e| anyhow::anyhow!("check proof: {e}"))?
        .map_err(|e| anyhow::anyhow!("signature mismatch: {e}"))
}

impl LocalVcSigner {
    async fn sign_w3c_ldv2(
        &self,
        credential: Value,
    ) -> Result<Value> {
        // Read config at signing time for current values
        let config = self.config.read().await;
        let signing_key = config.signing_key.clone();
        let issuer_did = config.proxy_did.clone();
        drop(config);

        // Parse as SSI v2 credential
        let vc: vc::v2::SpecializedJsonCredential =
            serde_json::from_value(credential).context("Failed to parse as v2 credential")?;

        // Generate DIDKey from the JWK
        let did_key = DIDKey::generate(&signing_key).context("Failed to generate DID key")?;

        let verification_method_str = format!("{}#{}", issuer_did, DEFAULT_SIGNING_KEY_ID);

        // Setup verification method and resolver
        let mut resolver_map: HashMap<IriBuf, AnyMethod> = HashMap::new();

        // Extract Ed25519 public key from JWK
        let public_key_multicodec = signing_key
            .to_public()
            .to_multicodec()
            .context("Failed to convert public key to multicodec")?;
        let public_key_bytes = public_key_multicodec.as_bytes();

        // Create Ed25519 verifying key (skip first 2 bytes of multicodec prefix)
        let verifying_key = VerifyingKey::from_bytes(
            &public_key_bytes[2..]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid public key length"))?,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create verifying key: {}", e))?;

        // Create verification method
        let verification_method_key = Multikey::from_public_key(
            did_key.into_iri(),
            issuer_did
                .clone()
                .try_into()?,
            &verifying_key,
        );

        let verification_method_unwrapped = AnyMethod::Multikey(verification_method_key.clone());

        let verification_method: ReferenceOrOwned<AnyMethod> = ReferenceOrOwned::Reference(
            verification_method_str
                .clone()
                .try_into()?,
        );

        resolver_map.insert(
            verification_method_str
                .clone()
                .try_into()?,
            verification_method_unwrapped,
        );

        // Create signer
        let signer: SsiLocalSigner<SingleSecretSigner<JWK>> = SingleSecretSigner::new(signing_key).into_local();

        // Setup proof options
        let options = ProofOptions::from_method_and_options(verification_method, Default::default());

        let env = create_signature_environment(None).await?;

        let suite = AnySuite::EdDsaRdfc2022;

        // Sign the credential
        let signed_vc = suite
            .sign_with(env, vc, &resolver_map, signer, options, Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;

        // Convert back to JSON Value
        let signed_json = serde_json::to_value(&signed_vc).context("Failed to serialize signed credential")?;

        Ok(signed_json)
    }
}

#[async_trait]
impl VcIssuer for LocalVcIssuer {
    async fn issue<'a>(
        &self,
        payload: IssueVcPayload<'a>,
    ) -> Result<Value> {
        let IssueVcPayload::AgentIdentity(air) = payload;

        // Read issuer DID from config at issuance time
        let config = self.config.read().await;
        let proxy_did = config.proxy_did.clone();
        drop(config);

        // Build credential subject — use workloadBinding if provided, else legacy identityFields
        let credential_subject = if let Some(ref wb) = air.workload_binding {
            json!({
                "id": air.did.as_ref(),
                "workloadBinding": wb,
            })
        } else {
            let identity_json =
                serde_json::to_value(&*air.identity_fields).context("Failed to serialize identity fields")?;
            json!({
                "id": air.did.as_ref(),
                "identityFields": identity_json,
            })
        };

        // Create unsigned VC v2 payload
        let now = chrono::Utc::now();
        let mut credential = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                CTX_AGENT_IDENTITY_V1_URL.to_string()
            ],
            "type": ["VerifiableCredential", "AgentIdentityCredential"],
            "issuer": proxy_did,
            "validFrom": now.to_rfc3339(),
            "validUntil": (now + chrono::Duration::days(VC_LIFETIME_DAYS)).to_rfc3339(),
            "credentialSubject": credential_subject,
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        });
        if let Some(status_list) = &self.status_list {
            credential["credentialStatus"] = status_list
                .entry_for(air.did.as_ref())
                .await?;
        }

        // Sign using SSI library

        self.signer
            .sign(credential)
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::identity::VCIssuerConfig;

    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_config() -> VCIssuerConfig {
        let signing_key: JWK = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "B7hiAU-eeRjFFNXtswXSQhmzwmYfBuZF9f1c3wODZJI",
            "d": "prjVZyovt_E5tC-MCfjcpCNXTw7bEAbrbsgma7VJT64"
        }))
        .expect("Failed to parse test private key JWK");
        VCIssuerConfig {
            storage_path: "".into(),
            proxy_did: "did:web:did.example.com:agent-stream".to_string(),
            signing_key,
        }
    }

    fn create_test_agent_identity_record() -> AgentIdentity<'static> {
        let mut identity_fields = HashMap::new();
        identity_fields.insert(
            "agentIdentity".to_string(),
            json!({
                "llmInfo": {
                    "model": "gpt-4",
                    "provider": "openai"
                },
                "softwareInfo": {
                    "name": "test-agent",
                    "version": "1.0.0"
                },
                "region": "us-east-1"
            }),
        );

        AgentIdentity {
            did: Cow::Borrowed("did:web:example.com:agent:123"),
            identity_fields: Cow::Owned(identity_fields),
            workload_binding: None,
        }
    }

    #[tokio::test]
    async fn test_issue_happy_path() {
        // Arrange
        let config = create_test_config();
        let config = Arc::new(RwLock::new(config));

        let signer = Arc::new(LocalVcSigner::new(config.clone())) as Arc<dyn VcSigner>;
        let vc_issuer = LocalVcIssuer::new(config.clone(), signer);

        let agent_record = create_test_agent_identity_record();
        let agent_did = agent_record.did.clone();
        let payload = IssueVcPayload::AgentIdentity(agent_record);

        // Act
        let result = vc_issuer.issue(payload).await;

        // Assert
        assert!(result.is_ok(), "Expected successful VC issuance");

        let vc = result.unwrap();

        // Verify VC structure
        assert_eq!(vc["type"], json!(["VerifiableCredential", "AgentIdentityCredential"]));
        assert_eq!(vc["issuer"], json!("did:web:did.example.com:agent-stream"));

        // Verify credential subject
        let credential_subject = &vc["credentialSubject"];
        assert_eq!(credential_subject["id"], json!(agent_did));
        assert!(credential_subject["identityFields"].is_object());

        // Verify dates are present
        assert!(vc["validFrom"].is_string());
        assert!(vc["validUntil"].is_string());

        // Verify credential ID
        assert!(
            vc["id"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:")
        );

        // Verify proof was added by the real signer
        assert!(vc["proof"].is_object());
        let proof = &vc["proof"];
        assert_eq!(proof["type"], json!("DataIntegrityProof"));
        assert_eq!(proof["cryptosuite"], json!("eddsa-rdfc-2022"));
        assert!(proof["created"].is_string());
        // verificationMethod can be either a string or an object
        assert!(!proof["verificationMethod"].is_null());
        assert_eq!(proof["proofPurpose"], json!("assertionMethod"));
        assert!(proof["proofValue"].is_string());

        // Verify context
        let context = vc["@context"]
            .as_array()
            .unwrap();
        assert!(context.contains(&json!("https://www.w3.org/ns/credentials/v2")));
    }

    #[tokio::test]
    async fn an_issued_credential_carries_its_agents_revocation_entry() {
        let config = Arc::new(RwLock::new(create_test_config()));
        let signer = Arc::new(LocalVcSigner::new(config.clone())) as Arc<dyn VcSigner>;
        let dir = tempfile::tempdir().unwrap();
        let status_list = Arc::new(
            StatusListRegistry::load(
                dir.path(),
                "did.example.com",
                "did:web:did.example.com:agent-stream".to_string(),
                signer.clone(),
            )
            .await
            .unwrap(),
        );
        let vc_issuer = LocalVcIssuer::new(config, signer).with_status_list(status_list.clone());

        let first = vc_issuer
            .issue(IssueVcPayload::AgentIdentity(create_test_agent_identity_record()))
            .await
            .unwrap();
        let second = vc_issuer
            .issue(IssueVcPayload::AgentIdentity(create_test_agent_identity_record()))
            .await
            .unwrap();

        let entry = &first["credentialStatus"];
        assert_eq!(entry["type"], "BitstringStatusListEntry");
        assert_eq!(entry["statusPurpose"], "revocation");
        assert_eq!(entry["statusListCredential"], status_list.url());
        assert_eq!(second["credentialStatus"], *entry, "every credential of an agent shares its index");
        assert_eq!(first["proof"]["cryptosuite"], "eddsa-rdfc-2022", "the entry is covered by the proof");
    }

    #[tokio::test]
    async fn a_credential_issued_without_a_status_list_has_no_status_entry() {
        let config = Arc::new(RwLock::new(create_test_config()));
        let signer = Arc::new(LocalVcSigner::new(config.clone())) as Arc<dyn VcSigner>;

        let vc = LocalVcIssuer::new(config, signer)
            .issue(IssueVcPayload::AgentIdentity(create_test_agent_identity_record()))
            .await
            .unwrap();

        assert!(
            vc.get("credentialStatus")
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_rdfc_proof_checks_against_its_key_and_no_other() {
        let config = Arc::new(RwLock::new(create_test_config()));
        let signer = LocalVcSigner::new(config);
        let signed = signer
            .sign(json!({
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    { "@vocab": "https://schema.affinidi.com/governance#" }
                ],
                "type": ["VerifiableCredential", "AIGovernanceRecordCredential"],
                "issuer": "did:web:did.example.com:agent-stream",
                "validFrom": "2026-08-12T00:00:00Z",
                "credentialSubject": { "record_id": "rec-1", "content_hash": "sha256:ab", "prompt": "hi" },
            }))
            .await
            .unwrap();
        assert_eq!(signed["proof"]["cryptosuite"], "eddsa-rdfc-2022");
        let key = signer
            .verifying_key()
            .await
            .unwrap();
        verify_eddsa_rdfc_2022(&signed, &key)
            .await
            .expect("the signing key checks its own proof");

        let mut tampered = signed.clone();
        tampered["credentialSubject"]["prompt"] = json!("bye");
        assert!(
            verify_eddsa_rdfc_2022(&tampered, &key)
                .await
                .is_err()
        );
        let other = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        assert!(
            verify_eddsa_rdfc_2022(&signed, &other)
                .await
                .is_err()
        );
        assert!(
            verify_eddsa_rdfc_2022(&verified_jcs_document(), &key)
                .await
                .is_err(),
            "a proof of another suite is not checked as rdfc"
        );
    }

    fn verified_jcs_document() -> Value {
        sign_eddsa_jcs_2022(
            json!({ "credentialSubject": { "a": 1 } }),
            &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
            "did:web:example.com#key-2",
        )
        .unwrap()
    }
}
