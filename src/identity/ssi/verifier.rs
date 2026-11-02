use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use anyhow::{Context as AnyhowContext, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use did_peer::resolve_did_peer;
use serde_json::Value;
use ssi::claims::VerificationParameters;
use ssi::claims::data_integrity::AnyDataIntegrity;
use ssi::claims::vc::MEDIA_TYPE_VC;
use ssi::claims::vc::v2::syntax::{JsonCredential, JsonPresentation};
use ssi::dids::document::{self, representation::MediaType};
use ssi::dids::resolution::{self, Options};
use ssi::dids::{AnyDidMethod, DID, DIDResolver, VerificationMethodDIDResolver};
use ssi::json_ld::ContextLoader;
use ssi::status::FromBytes;
use ssi::status::bitstring_status_list::{
    BITSTRING_STATUS_LIST_ENTRY_TYPE, BitstringStatusListCredential, BitstringStatusListEntry, StatusPurpose,
};
use ssi::verification_methods::AnyMethod;

use super::context::create_signature_environment;

const STATUS_LIST_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_STATUS_LIST_BYTES: usize = 512 * 1024;

type Params = VerificationParameters<VerificationMethodDIDResolver<CompositeResolver, AnyMethod>, ContextLoader>;

#[allow(dead_code)]
pub struct VcVerificationResult {
    pub issuer_did: String,
    pub subject_did: String,
    pub identity_fields: HashMap<String, Value>,
}

pub struct VpVerificationResult {
    pub holder_did: String,
    pub credentials: Vec<VcVerificationResult>,
}

#[async_trait]
pub trait Verifier: Send + Sync {
    /// Verify `presentation` and every credential it embeds. A credential is
    /// accepted only when its issuer is in `trusted_issuers`.
    async fn verify_vp(
        &self,
        presentation: &Value,
        trusted_issuers: &HashSet<String>,
    ) -> Result<VpVerificationResult>;
}

/// Where a credential's `BitstringStatusListCredential` is read from.
#[async_trait]
pub trait StatusListSource: Send + Sync {
    async fn fetch(
        &self,
        url: &str,
    ) -> Result<Vec<u8>>;
}

/// Fetches a status list over HTTPS from a public host only, without
/// redirects, within [`STATUS_LIST_FETCH_TIMEOUT`] and [`MAX_STATUS_LIST_BYTES`].
pub struct HttpStatusListSource;

#[async_trait]
impl StatusListSource for HttpStatusListSource {
    async fn fetch(
        &self,
        url: &str,
    ) -> Result<Vec<u8>> {
        let url = crate::url_validation::validate_webhook_url(url).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(url.scheme() == "https", "status list URL must use https");
        let mut response = crate::http_client::with_strict_validating_resolver(STATUS_LIST_FETCH_TIMEOUT)?
            .get(url)
            .send()
            .await?
            .error_for_status()?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                body.len() + chunk.len() <= MAX_STATUS_LIST_BYTES,
                "status list exceeds {MAX_STATUS_LIST_BYTES} bytes"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

pub struct LocalVerifier {
    did_cache: Arc<DIDCacheClient>,
    status_lists: Arc<dyn StatusListSource>,
}

impl LocalVerifier {
    pub fn with_status_lists(
        did_cache: Arc<DIDCacheClient>,
        status_lists: Arc<dyn StatusListSource>,
    ) -> Self {
        Self { did_cache, status_lists }
    }
}

pub struct CompositeResolver {
    ssi_resolver: AnyDidMethod,
    did_cache: Arc<DIDCacheClient>,
}

impl CompositeResolver {
    pub fn new(did_cache: Arc<DIDCacheClient>) -> Self {
        Self {
            ssi_resolver: AnyDidMethod::default(),
            did_cache,
        }
    }

    async fn resolve_peer_did(
        &self,
        did_str: &str,
    ) -> Result<Vec<u8>, resolution::Error> {
        let doc_json = resolve_did_peer(did_str)
            .await
            .map_err(|e| resolution::Error::Internal(format!("Failed to resolve did:peer: {:?}", e)))?;

        let mut doc: serde_json::Value = serde_json::from_str(&doc_json)
            .map_err(|e| resolution::Error::Internal(format!("Failed to parse did:peer document: {}", e)))?;
        // ssi lib expects did/v1
        doc["@context"] = serde_json::json!(["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]);

        serde_json::to_vec(&doc).map_err(|e| resolution::Error::Internal(e.to_string()))
    }
}

impl DIDResolver for CompositeResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        let method = did.method_name();

        match method {
            "peer" => {
                let doc_bytes = self
                    .resolve_peer_did(did.as_str())
                    .await?;
                Ok(resolution::Output::new(
                    doc_bytes,
                    document::Metadata::default(),
                    resolution::Metadata::from_content_type(Some(MediaType::JsonLd.to_string())),
                ))
            }
            "key" | "jwk" | "pkh" | "ethr" | "ion" | "tz" => {
                self.ssi_resolver
                    .resolve_representation(did, options)
                    .await
            }
            _ => {
                let resolve_result = self
                    .did_cache
                    .resolve(did.as_str())
                    .await
                    .map_err(|e| resolution::Error::Internal(e.to_string()))?;

                let doc_bytes =
                    serde_json::to_vec(&resolve_result.doc).map_err(|e| resolution::Error::Internal(e.to_string()))?;

                Ok(resolution::Output::new(
                    doc_bytes,
                    document::Metadata::default(),
                    resolution::Metadata::from_content_type(Some(MediaType::JsonLd.to_string())),
                ))
            }
        }
    }
}

fn verify_vc_lifetime(vc: &Value) -> Result<()> {
    let now = Utc::now();

    if let Some(valid_from) = vc
        .get("validFrom")
        .and_then(|v| v.as_str())
    {
        let valid_from_dt: DateTime<Utc> = valid_from
            .parse()
            .context("Invalid validFrom date format")?;
        if now < valid_from_dt {
            anyhow::bail!("VC is not yet valid (validFrom: {})", valid_from);
        }
    }

    if let Some(valid_until) = vc
        .get("validUntil")
        .and_then(|v| v.as_str())
    {
        let valid_until_dt: DateTime<Utc> = valid_until
            .parse()
            .context("Invalid validUntil date format")?;
        if now > valid_until_dt {
            anyhow::bail!("VC has expired (validUntil: {})", valid_until);
        }
    }

    if let Some(expiration_date) = vc
        .get("expirationDate")
        .and_then(|v| v.as_str())
    {
        let expiration_dt: DateTime<Utc> = expiration_date
            .parse()
            .context("Invalid expirationDate format")?;
        if now > expiration_dt {
            anyhow::bail!("VC has expired (expirationDate: {})", expiration_date);
        }
    }

    if let Some(issuance_date) = vc
        .get("issuanceDate")
        .and_then(|v| v.as_str())
    {
        let issuance_dt: DateTime<Utc> = issuance_date
            .parse()
            .context("Invalid issuanceDate format")?;
        if now < issuance_dt {
            anyhow::bail!("VC is not yet valid (issuanceDate: {})", issuance_date);
        }
    }

    Ok(())
}

/// Fail unless a library verification outcome is a pass.
fn ensure_verified<I: Display, E: Display>(outcome: Result<Result<(), I>, E>) -> Result<()> {
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(invalid)) => anyhow::bail!("invalid proof: {invalid}"),
        Err(error) => anyhow::bail!("proof could not be checked: {error}"),
    }
}

/// One JSON value or each element of a JSON array.
fn one_or_many(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    }
}

/// Require every proof on `document` to name, by reference, a verification
/// method of `controller_did`. An embedded verification method object is
/// refused: it carries its own key instead of one resolved from the DID.
fn ensure_proofs_controlled_by(
    document: &Value,
    controller_did: &str,
) -> Result<()> {
    let proofs = document
        .get("proof")
        .map(one_or_many)
        .unwrap_or_default();
    anyhow::ensure!(!proofs.is_empty(), "missing proof");
    for proof in proofs {
        let method = proof
            .get("verificationMethod")
            .and_then(Value::as_str)
            .context("proof verificationMethod must be a DID URL")?;
        let did = method
            .split_once('#')
            .map_or(method, |(did, _)| did);
        anyhow::ensure!(
            did == controller_did,
            "proof verificationMethod {method:?} is not controlled by {controller_did:?}"
        );
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PresentationBinding {
    pub challenge: Option<String>,
    pub domains: Vec<String>,
    pub expires: DateTime<Utc>,
    /// The proof's signature, which tells one presentation from another.
    pub proof_value: String,
}

/// Checks no signature: act on the result only once [`Verifier::verify_vp`] passes.
pub fn presentation_binding(
    presentation: &Value,
    now: DateTime<Utc>,
) -> Result<PresentationBinding> {
    let proof = presentation
        .get("proof")
        .filter(|proof| proof.is_object())
        .context("presentation must carry exactly one proof")?;
    let expires: DateTime<Utc> = proof
        .get("expires")
        .and_then(Value::as_str)
        .context("presentation proof has no expires")?
        .parse()
        .context("Invalid presentation proof expires")?;
    anyhow::ensure!(expires > now, "presentation proof expired {}s ago, at {expires}", (now - expires).num_seconds());
    let challenge = proof
        .get("challenge")
        .and_then(Value::as_str)
        .map(String::from);
    let domains = proof
        .get("domain")
        .map(one_or_many)
        .unwrap_or_default()
        .into_iter()
        .filter_map(Value::as_str)
        .map(String::from)
        .collect();
    let proof_value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .context("presentation proof has no proofValue")?
        .to_string();
    Ok(PresentationBinding {
        challenge,
        domains,
        expires,
        proof_value,
    })
}

fn status_list_issuer(list: &BitstringStatusListCredential) -> Option<&str> {
    let issuer = list
        .other_properties
        .get("issuer")?;
    issuer.as_str().or_else(|| {
        issuer
            .get("id")
            .and_then(Value::as_str)
    })
}

fn verify_vc_fields(
    vc: &Value,
    holder_did: &str,
) -> Result<VcVerificationResult> {
    verify_vc_lifetime(vc)?;

    let subject_did = vc
        .get("credentialSubject")
        .and_then(|cs| cs.get("id"))
        .and_then(|id| id.as_str())
        .ok_or_else(|| anyhow::anyhow!("VC missing credentialSubject.id"))?
        .to_string();

    if subject_did != holder_did {
        anyhow::bail!("VP holder ({:?}) does not match VC subject ({:?})", holder_did, subject_did);
    }

    let issuer_did = vc
        .get("issuer")
        .and_then(|i| i.as_str())
        .ok_or_else(|| anyhow::anyhow!("VC missing issuer field"))?
        .to_string();

    let identity_fields = vc
        .get("credentialSubject")
        .and_then(|cs| cs.get("identityFields"))
        .and_then(|fields| fields.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<HashMap<String, Value>>()
        })
        .unwrap_or_default();

    Ok(VcVerificationResult {
        issuer_did,
        subject_did,
        identity_fields,
    })
}

impl LocalVerifier {
    async fn verification_parameters(&self) -> Result<Params> {
        let resolver = CompositeResolver::new(self.did_cache.clone());
        let vm_resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(resolver);
        let env = create_signature_environment(None).await?;
        Ok(VerificationParameters::from_resolver(vm_resolver).with_json_ld_loader(env.json_ld_loader))
    }

    /// Check one embedded credential: its claims, that its issuer is trusted,
    /// its own proof, that the proof key belongs to the issuer, and its status.
    /// The issuer is checked before any proof so an untrusted issuer's DID is
    /// never resolved.
    async fn verify_credential(
        &self,
        vc_json: &Value,
        vc: &AnyDataIntegrity<JsonCredential>,
        holder_did: &str,
        trusted_issuers: &HashSet<String>,
        params: &Params,
    ) -> Result<VcVerificationResult> {
        let result = verify_vc_fields(vc_json, holder_did)?;
        anyhow::ensure!(
            trusted_issuers.contains(&result.issuer_did),
            "VC issuer {:?} is not a trusted issuer",
            result.issuer_did
        );
        ensure_verified(vc.verify(params).await).context("VC proof verification failed")?;
        ensure_proofs_controlled_by(vc_json, &result.issuer_did).context("VC proof")?;
        self.check_revocation_status(vc_json, &result.issuer_did, params)
            .await?;
        Ok(result)
    }

    /// Reject a credential whose `BitstringStatusListEntry` marks it revoked or
    /// suspended. The status list must be signed by the credential's issuer.
    /// Any other status type, or a status list that cannot be read or
    /// verified, fails the credential.
    async fn check_revocation_status(
        &self,
        vc: &Value,
        issuer_did: &str,
        params: &Params,
    ) -> Result<()> {
        let Some(status) = vc.get("credentialStatus") else {
            return Ok(());
        };
        for entry in one_or_many(status) {
            let status_type = entry
                .get("type")
                .and_then(Value::as_str);
            anyhow::ensure!(
                status_type == Some(BITSTRING_STATUS_LIST_ENTRY_TYPE),
                "unsupported credentialStatus type {status_type:?}"
            );
            let entry: BitstringStatusListEntry =
                serde_json::from_value(entry.clone()).context("invalid BitstringStatusListEntry")?;
            if entry.status_purpose == StatusPurpose::Message {
                continue;
            }

            let url = entry
                .status_list_credential
                .as_str();
            let bytes = self
                .status_lists
                .fetch(url)
                .await
                .with_context(|| format!("failed to fetch status list {url}"))?;
            let list = BitstringStatusListCredential::from_bytes(&bytes, MEDIA_TYPE_VC, params)
                .await
                .context("status list credential failed verification")?;
            anyhow::ensure!(
                status_list_issuer(&list) == Some(issuer_did),
                "status list is not issued by the credential issuer"
            );
            let list_json: Value = serde_json::from_slice(&bytes).context("status list is not JSON")?;
            ensure_proofs_controlled_by(&list_json, issuer_did).context("status list proof")?;
            anyhow::ensure!(
                list.credential_subject
                    .status_purpose
                    == entry.status_purpose,
                "status list purpose does not match the credential status entry"
            );

            let value = list
                .decode_status_list()
                .context("invalid status list encoding")?
                .get(entry.status_size, entry.status_list_index)
                .context("statusListIndex is outside the status list")?;
            anyhow::ensure!(
                value == 0,
                "VC is {}",
                match entry.status_purpose {
                    StatusPurpose::Suspension => "suspended",
                    _ => "revoked",
                }
            );
        }
        Ok(())
    }
}

#[async_trait]
impl Verifier for LocalVerifier {
    async fn verify_vp(
        &self,
        presentation: &Value,
        trusted_issuers: &HashSet<String>,
    ) -> Result<VpVerificationResult> {
        let holder_did = presentation
            .get("holder")
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow::anyhow!("VP missing holder field"))?
            .to_string();

        let vc_field = presentation
            .get("verifiableCredential")
            .ok_or_else(|| anyhow::anyhow!("VP missing verifiableCredential field"))?;

        let vcs: Vec<&Value> = if let Some(arr) = vc_field.as_array() {
            if arr.is_empty() {
                anyhow::bail!("VP has no credentials");
            }
            arr.iter().collect()
        } else if vc_field.is_object() {
            vec![vc_field]
        } else {
            anyhow::bail!("VP verifiableCredential must be an object or array");
        };

        let params = self
            .verification_parameters()
            .await?;

        let vp: AnyDataIntegrity<JsonPresentation<AnyDataIntegrity<JsonCredential>>> =
            serde_json::from_value(presentation.clone())
                .context("Failed to parse VP as Data Integrity presentation")?;

        ensure_proofs_controlled_by(presentation, &holder_did).context("VP proof binding failed")?;
        presentation_binding(presentation, Utc::now()).context("VP proof lifetime check failed")?;
        ensure_verified(vp.verify(&params).await).context("VP proof verification failed")?;

        let typed_vcs = &vp.verifiable_credentials;
        anyhow::ensure!(typed_vcs.len() == vcs.len(), "VP credentials could not be parsed consistently");

        let mut credentials = Vec::with_capacity(vcs.len());
        for (i, (vc_json, vc)) in vcs
            .iter()
            .zip(typed_vcs)
            .enumerate()
        {
            let vc_result = self
                .verify_credential(vc_json, vc, &holder_did, trusted_issuers, &params)
                .await
                .with_context(|| format!("VC[{}] validation failed", i))?;
            credentials.push(vc_result);
        }

        Ok(VpVerificationResult { holder_did, credentials })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ssi::vp_issuer::VP_LIFETIME_MINUTES;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use chrono::TimeDelta;
    use serde_json::json;
    use ssi::crypto::ed25519::VerifyingKey;
    use ssi::dids::DIDKey;
    use ssi::jwk::JWK;
    use ssi::prelude::{AnySuite, CryptographicSuite, ProofOptions, SingleSecretSigner};
    use ssi::status::bitstring_status_list::{SizedBitString, StatusSize};
    use ssi::verification_methods::{LocalSigner, Multikey, ReferenceOrOwned};
    use ssi_json_ld::IriBuf;

    const STATUS_LIST_URL: &str = "https://status.example/lists/1";
    const STATUS_INDEX: usize = 5;

    struct Party {
        jwk: JWK,
        did: String,
        method: String,
    }

    impl Party {
        fn new() -> Self {
            let jwk = JWK::generate_ed25519().unwrap();
            let did = DIDKey::generate(&jwk)
                .unwrap()
                .to_string();
            let fragment = did
                .strip_prefix("did:key:")
                .unwrap()
                .to_string();
            let method = format!("{did}#{fragment}");
            Self { jwk, did, method }
        }

        fn resolver(&self) -> HashMap<IriBuf, AnyMethod> {
            let multicodec = self
                .jwk
                .to_public()
                .to_multicodec()
                .unwrap();
            let key = VerifyingKey::from_bytes(
                &multicodec.as_bytes()[2..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
            let iri: IriBuf = self
                .method
                .clone()
                .try_into()
                .unwrap();
            let controller = self
                .did
                .clone()
                .try_into()
                .unwrap();
            HashMap::from([(iri.clone(), AnyMethod::Multikey(Multikey::from_public_key(iri, controller, &key)))])
        }

        fn options(&self) -> ProofOptions<AnyMethod, ssi::claims::data_integrity::AnyInputSuiteOptions> {
            ProofOptions::from_method_and_options(
                ReferenceOrOwned::Reference(
                    self.method
                        .clone()
                        .try_into()
                        .unwrap(),
                ),
                Default::default(),
            )
        }

        fn signer(&self) -> LocalSigner<SingleSecretSigner<JWK>> {
            SingleSecretSigner::new(self.jwk.clone()).into_local()
        }

        async fn sign_credential(
            &self,
            credential: Value,
        ) -> Value {
            let claims: JsonCredential = serde_json::from_value(credential).unwrap();
            let env = create_signature_environment(None)
                .await
                .unwrap();
            let signed = AnySuite::EdDsaRdfc2022
                .sign_with(env, claims, &self.resolver(), self.signer(), self.options(), Default::default())
                .await
                .unwrap();
            serde_json::to_value(&signed).unwrap()
        }

        async fn sign_presentation(
            &self,
            holder_did: &str,
            credential: Value,
        ) -> Value {
            self.sign_presentation_expiring(
                holder_did,
                credential,
                Utc::now() + TimeDelta::minutes(VP_LIFETIME_MINUTES),
            )
            .await
        }

        async fn sign_presentation_expiring(
            &self,
            holder_did: &str,
            credential: Value,
            expires: DateTime<Utc>,
        ) -> Value {
            let claims: JsonPresentation = serde_json::from_value(json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "id": "urn:uuid:7f1d3a52-50d6-4a39-9b53-33a6b8f1b2a1",
                "holder": holder_did,
                "verifiableCredential": credential,
            }))
            .unwrap();
            let env = create_signature_environment(None)
                .await
                .unwrap();
            let mut options = self.options();
            options.expires = Some(
                expires
                    .to_rfc3339()
                    .parse()
                    .unwrap(),
            );
            let signed = AnySuite::EdDsaRdfc2022
                .sign_with(env, claims, &self.resolver(), self.signer(), options, Default::default())
                .await
                .unwrap();
            serde_json::to_value(&signed).unwrap()
        }
    }

    #[async_trait]
    impl crate::identity::ssi::vc_issuer::VcSigner for Party {
        async fn sign(
            &self,
            payload: Value,
        ) -> Result<Value> {
            Ok(self
                .sign_credential(payload)
                .await)
        }
    }

    fn agent_credential(
        issuer_did: &str,
        subject_did: &str,
    ) -> Value {
        let now = Utc::now();
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2", super::super::context::CTX_AGENT_IDENTITY_V1_URL],
            "id": "urn:uuid:3c3b8d0e-4d55-4bf4-9b0f-9f8a1d1c6e21",
            "type": ["VerifiableCredential", "AgentIdentityCredential"],
            "issuer": issuer_did,
            "validFrom": (now - chrono::Duration::hours(1)).to_rfc3339(),
            "validUntil": (now + chrono::Duration::days(1)).to_rfc3339(),
            "credentialSubject": {
                "id": subject_did,
                "identityFields": { "role": "agent" }
            }
        })
    }

    /// A did:peer whose `#key-1` and `#key-2` are both the returned key. `LocalVpSigner` signs as
    /// `#key-2`, so a VP it signs for this DID resolves to a real key, like an agent's did:webvh does.
    fn new_did_peer() -> (ssi::jwk::JWK, String) {
        use did_peer::{DIDPeer, DIDPeerCreateKeys, DIDPeerKeys};

        let key = ssi::jwk::JWK::generate_ed25519().unwrap();
        let verification_key = DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(&key).unwrap()),
        };
        let (did, _) = DIDPeer::create_peer_did(&vec![verification_key.clone(), verification_key], None).unwrap();
        (key, did)
    }

    /// An unsigned presentation by `holder_did` of an agent credential issued to it.
    fn unsigned_test_vp(holder_did: &str) -> serde_json::Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": agent_credential("did:example:issuer", holder_did),
        })
    }

    /// Signs [`unsigned_test_vp`] for `holder_did` with `signer_key`, naming a verification method of
    /// `signer_did`.
    async fn sign_test_vp(
        holder_did: &str,
        signer_key: &ssi::jwk::JWK,
        signer_did: &str,
    ) -> serde_json::Value {
        use crate::identity::ssi::vp_issuer::{LocalVpSigner, VpSigner};

        LocalVpSigner::new()
            .sign(
                unsigned_test_vp(holder_did),
                signer_key,
                signer_did,
                None,
                None,
                crate::identity::ssi::vp_issuer::VP_LIFETIME,
            )
            .await
            .expect("VP signing should succeed")
    }

    /// Signs [`unsigned_test_vp`] for `holder_did` with `signer_key`, embedding a verification method whose
    /// `id` is the holder's signing key but whose key material is `signer_key`.
    async fn sign_test_vp_with_embedded_method(
        holder_did: &str,
        signer_key: &ssi::jwk::JWK,
    ) -> serde_json::Value {
        use crate::identity::ssi::vp_issuer::DEFAULT_SIGNING_KEY_ID;
        use ssi::crypto::ed25519::VerifyingKey;
        use ssi::prelude::{AnyMethod, CryptographicSuite, ProofOptions, SingleSecretSigner};
        use ssi::verification_methods::{Multikey, ReferenceOrOwned};

        let public_key = signer_key
            .to_public()
            .to_multicodec()
            .unwrap();
        let verifying_key = VerifyingKey::from_bytes(
            &public_key.as_bytes()[2..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let method = Multikey::from_public_key(
            format!("{holder_did}#{DEFAULT_SIGNING_KEY_ID}")
                .try_into()
                .unwrap(),
            holder_did
                .to_string()
                .try_into()
                .unwrap(),
            &verifying_key,
        );
        let mut options = ProofOptions::from_method_and_options(
            ReferenceOrOwned::Owned(AnyMethod::Multikey(method)),
            Default::default(),
        );
        // The credentials context does not define the embedded `Multikey` type.
        options.context = Some(
            serde_json::from_value(json!([
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/multikey/v1"
            ]))
            .unwrap(),
        );
        let presentation: super::JsonPresentation = serde_json::from_value(unsigned_test_vp(holder_did)).unwrap();
        let env = super::create_signature_environment(None)
            .await
            .unwrap();
        let signed = AnySuite::EdDsaRdfc2022
            .sign_with(
                env,
                presentation,
                &std::collections::HashMap::<ssi_json_ld::IriBuf, AnyMethod>::new(),
                SingleSecretSigner::new(signer_key.clone()).into_local(),
                options,
                Default::default(),
            )
            .await
            .expect("VP signing should succeed");
        serde_json::to_value(signed).unwrap()
    }

    async fn verify_vp_error(vp: &serde_json::Value) -> String {
        error_chain(verify(vp, &HashSet::new(), None).await)
    }

    fn with_status(mut credential: Value) -> Value {
        credential["credentialStatus"] = json!({
            "id": format!("{STATUS_LIST_URL}#{STATUS_INDEX}"),
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": STATUS_INDEX.to_string(),
            "statusListCredential": STATUS_LIST_URL,
        });
        credential
    }

    async fn status_list(
        signer: &Party,
        issuer_did: &str,
        revoked: bool,
    ) -> Vec<u8> {
        let mut bits = SizedBitString::new_zeroed(StatusSize::default(), 16 * 1024 * 8);
        if revoked {
            bits.set(STATUS_INDEX, 1)
                .unwrap();
        }
        let list = signer
            .sign_credential(json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": STATUS_LIST_URL,
                "type": ["VerifiableCredential", "BitstringStatusListCredential"],
                "issuer": issuer_did,
                "credentialSubject": {
                    "id": format!("{STATUS_LIST_URL}#list"),
                    "type": "BitstringStatusList",
                    "statusPurpose": "revocation",
                    "encodedList": bits.encode(),
                }
            }))
            .await;
        serde_json::to_vec(&list).unwrap()
    }

    struct StaticStatusLists(HashMap<String, Vec<u8>>);

    #[async_trait]
    impl StatusListSource for StaticStatusLists {
        async fn fetch(
            &self,
            url: &str,
        ) -> Result<Vec<u8>> {
            self.0
                .get(url)
                .cloned()
                .context("no such status list")
        }
    }

    async fn verifier(status_list: Option<Vec<u8>>) -> LocalVerifier {
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let lists = status_list
            .map(|bytes| HashMap::from([(STATUS_LIST_URL.to_string(), bytes)]))
            .unwrap_or_default();
        LocalVerifier::with_status_lists(Arc::new(client), Arc::new(StaticStatusLists(lists)))
    }

    fn trusting(issuer: &Party) -> HashSet<String> {
        HashSet::from([issuer.did.clone()])
    }

    async fn verify(
        vp: &Value,
        trusted: &HashSet<String>,
        status_list: Option<Vec<u8>>,
    ) -> Result<VpVerificationResult> {
        verifier(status_list)
            .await
            .verify_vp(vp, trusted)
            .await
    }

    fn error_chain(result: Result<VpVerificationResult>) -> String {
        match result {
            Ok(_) => panic!("verification must fail"),
            Err(error) => format!("{error:#}"),
        }
    }

    #[tokio::test]
    async fn vp_signed_by_the_holder_key_is_controlled_by_the_holder() {
        let (holder_key, holder_did) = new_did_peer();
        let vp = sign_test_vp(&holder_did, &holder_key, &holder_did).await;

        ensure_proofs_controlled_by(&vp, &holder_did).expect("holder-signed VP must be bound to the holder");
    }

    #[tokio::test]
    async fn vp_signed_by_a_key_of_another_did_is_rejected() {
        let (_, victim_did) = new_did_peer();
        let (attacker_key, attacker_did) = new_did_peer();
        let vp = sign_test_vp(&victim_did, &attacker_key, &attacker_did).await;

        let error = ensure_proofs_controlled_by(&vp, &victim_did)
            .expect_err("a proof by another DID must be rejected")
            .to_string();

        assert_eq!(
            error,
            format!("proof verificationMethod \"{attacker_did}#key-2\" is not controlled by \"{victim_did}\"")
        );
    }

    #[tokio::test]
    async fn a_credential_from_a_trusted_issuer_verifies() {
        let (issuer, holder) = (Party::new(), Party::new());
        let vc = issuer
            .sign_credential(agent_credential(&issuer.did, &holder.did))
            .await;
        let vp = holder
            .sign_presentation(&holder.did, vc)
            .await;

        let result = verify(&vp, &trusting(&issuer), None)
            .await
            .expect("a genuine VP must verify");

        assert_eq!(result.holder_did, holder.did);
        assert_eq!(result.credentials[0].issuer_did, issuer.did);
        assert_eq!(result.credentials[0].identity_fields["role"], json!("agent"));
        let binding = presentation_binding(&vp, Utc::now()).expect("binding");
        assert!(binding.expires <= Utc::now() + TimeDelta::minutes(VP_LIFETIME_MINUTES));
        assert_eq!(json!(binding.proof_value), vp["proof"]["proofValue"]);
    }

    #[tokio::test]
    async fn an_expired_presentation_is_rejected() {
        let (issuer, holder) = (Party::new(), Party::new());
        let vc = issuer
            .sign_credential(agent_credential(&issuer.did, &holder.did))
            .await;
        let vp = holder
            .sign_presentation_expiring(&holder.did, vc, Utc::now() - TimeDelta::seconds(1))
            .await;

        let error = error_chain(verify(&vp, &trusting(&issuer), None).await);

        assert!(error.contains("presentation proof expired"), "got: {error}");
    }

    #[tokio::test]
    async fn a_long_lived_presentation_verifies_until_it_expires() {
        let (issuer, holder) = (Party::new(), Party::new());
        let vc = issuer
            .sign_credential(agent_credential(&issuer.did, &holder.did))
            .await;
        let expires = Utc::now() + TimeDelta::days(365);
        let vp = holder
            .sign_presentation_expiring(&holder.did, vc, expires)
            .await;

        let result = verify(&vp, &trusting(&issuer), None)
            .await
            .expect("a presentation is valid until it expires, however far ahead");

        assert_eq!(result.holder_did, holder.did);
    }

    #[test]
    fn presentation_binding_requires_an_expires() {
        let vp = json!({ "proof": { "challenge": "c-1" } });

        let error = presentation_binding(&vp, Utc::now())
            .err()
            .map(|e| e.to_string());

        assert_eq!(error.as_deref(), Some("presentation proof has no expires"));
    }

    #[test]
    fn presentation_binding_requires_a_single_proof() {
        let expires = (Utc::now() + TimeDelta::minutes(1)).to_rfc3339();
        let vp = json!({ "proof": [{ "expires": expires }, { "expires": expires }] });

        let error = presentation_binding(&vp, Utc::now())
            .err()
            .map(|e| e.to_string());

        assert_eq!(error.as_deref(), Some("presentation must carry exactly one proof"));
    }

    #[test]
    fn presentation_binding_reads_the_challenge_and_every_domain() {
        let now = Utc::now();
        let expires = now + TimeDelta::minutes(VP_LIFETIME_MINUTES);
        let vp = json!({ "proof": {
            "expires": expires.to_rfc3339(),
            "challenge": "c-1",
            "domain": ["did:web:a.example", "did:web:b.example"],
            "proofValue": "z-signature",
        } });

        let binding = match presentation_binding(&vp, now) {
            Ok(binding) => binding,
            Err(e) => panic!("binding must be read: {e:#}"),
        };

        assert_eq!(binding.challenge.as_deref(), Some("c-1"));
        assert_eq!(binding.domains, vec!["did:web:a.example", "did:web:b.example"]);
        assert_eq!(binding.expires, expires);
        assert_eq!(binding.proof_value, "z-signature");
    }

    #[test]
    fn presentation_binding_states_how_long_ago_a_proof_expired() {
        let now = Utc::now();
        let expired = json!({ "proof": { "expires": (now - TimeDelta::seconds(90)).to_rfc3339(), "proofValue": "z" } });

        let error = presentation_binding(&expired, now)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();

        assert!(error.starts_with("presentation proof expired 90s ago"), "got: {error}");
    }

    #[tokio::test]
    async fn a_credential_from_an_issuer_not_on_the_allow_list_is_rejected() {
        let (trusted, forger, holder) = (Party::new(), Party::new(), Party::new());
        let vc = forger
            .sign_credential(agent_credential(&forger.did, &holder.did))
            .await;
        let vp = holder
            .sign_presentation(&holder.did, vc)
            .await;

        let error = error_chain(verify(&vp, &trusting(&trusted), None).await);

        assert!(error.contains("is not a trusted issuer"), "got: {error}");
    }

    #[tokio::test]
    async fn a_credential_naming_a_trusted_issuer_but_signed_by_another_key_is_rejected() {
        let (trusted, forger, holder) = (Party::new(), Party::new(), Party::new());
        let vc = forger
            .sign_credential(agent_credential(&trusted.did, &holder.did))
            .await;
        let vp = holder
            .sign_presentation(&holder.did, vc)
            .await;

        let error = error_chain(verify(&vp, &trusting(&trusted), None).await);

        assert!(error.contains("is not controlled by"), "got: {error}");
    }

    #[tokio::test]
    async fn a_credential_altered_after_signing_is_rejected() {
        let (issuer, holder) = (Party::new(), Party::new());
        let mut vc = issuer
            .sign_credential(agent_credential(&issuer.did, &holder.did))
            .await;
        vc["credentialSubject"]["identityFields"]["role"] = json!("administrator");
        let vp = holder
            .sign_presentation(&holder.did, vc)
            .await;

        let error = error_chain(verify(&vp, &trusting(&issuer), None).await);

        assert!(error.contains("VC proof verification failed"), "got: {error}");
    }

    #[tokio::test]
    async fn a_credential_without_a_proof_is_rejected() {
        let (issuer, holder) = (Party::new(), Party::new());
        let vp = holder
            .sign_presentation(&holder.did, agent_credential(&issuer.did, &holder.did))
            .await;

        let error = error_chain(verify(&vp, &trusting(&issuer), None).await);

        assert!(error.contains("VC proof verification failed"), "got: {error}");
    }

    #[tokio::test]
    async fn a_presentation_signed_by_a_key_other_than_the_holder_is_rejected() {
        let (issuer, holder, impostor) = (Party::new(), Party::new(), Party::new());
        let vc = issuer
            .sign_credential(agent_credential(&issuer.did, &holder.did))
            .await;
        let vp = impostor
            .sign_presentation(&holder.did, vc)
            .await;

        let error = error_chain(verify(&vp, &trusting(&issuer), None).await);

        assert!(error.contains("VP proof binding failed"), "got: {error}");
    }

    #[tokio::test]
    async fn a_credential_whose_status_bit_is_clear_verifies() {
        let (issuer, holder) = (Party::new(), Party::new());
        let vc = issuer
            .sign_credential(with_status(agent_credential(&issuer.did, &holder.did)))
            .await;
        let vp = holder
            .sign_presentation(&holder.did, vc)
            .await;
        let list = status_list(&issuer, &issuer.did, false).await;

        verify(&vp, &trusting(&issuer), Some(list))
            .await
            .expect("an unrevoked credential must verify");
    }

    #[tokio::test]
    async fn a_revoked_credential_is_rejected() {
        let (issuer, holder) = (Party::new(), Party::new());
        let vc = issuer
            .sign_credential(with_status(agent_credential(&issuer.did, &holder.did)))
            .await;
        let vp = holder
            .sign_presentation(&holder.did, vc)
            .await;
        let list = status_list(&issuer, &issuer.did, true).await;

        let error = error_chain(verify(&vp, &trusting(&issuer), Some(list)).await);

        assert!(error.contains("VC is revoked"), "got: {error}");
    }

    #[tokio::test]
    async fn a_status_list_signed_by_someone_other_than_the_issuer_is_rejected() {
        let (issuer, holder, other) = (Party::new(), Party::new(), Party::new());
        let vc = issuer
            .sign_credential(with_status(agent_credential(&issuer.did, &holder.did)))
            .await;
        let vp = holder
            .sign_presentation(&holder.did, vc)
            .await;
        let list = status_list(&other, &other.did, false).await;

        let error = error_chain(verify(&vp, &trusting(&issuer), Some(list)).await);

        assert!(error.contains("status list is not issued by the credential issuer"), "got: {error}");
    }

    #[tokio::test]
    async fn an_unreachable_status_list_fails_closed() {
        let (issuer, holder) = (Party::new(), Party::new());
        let vc = issuer
            .sign_credential(with_status(agent_credential(&issuer.did, &holder.did)))
            .await;
        let vp = holder
            .sign_presentation(&holder.did, vc)
            .await;

        let error = error_chain(verify(&vp, &trusting(&issuer), None).await);

        assert!(error.contains("failed to fetch status list"), "got: {error}");
    }

    #[tokio::test]
    async fn an_unsupported_status_type_fails_closed() {
        let (issuer, holder) = (Party::new(), Party::new());
        let mut credential = agent_credential(&issuer.did, &holder.did);
        credential["credentialStatus"] = json!({
            "id": format!("{STATUS_LIST_URL}#{STATUS_INDEX}"),
            "type": "https://w3id.org/vc/status-list#StatusList2021Entry",
        });
        let vc = issuer
            .sign_credential(credential)
            .await;
        let vp = holder
            .sign_presentation(&holder.did, vc)
            .await;

        let error = error_chain(verify(&vp, &trusting(&issuer), None).await);

        assert!(error.contains("unsupported credentialStatus type"), "got: {error}");
    }

    #[tokio::test]
    async fn an_own_credential_is_rejected_once_its_agent_is_revoked() {
        use crate::identity::status_list::{RegistryStatusListSource, StatusListRegistry};
        let (issuer, holder) = (Arc::new(Party::new()), Party::new());
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(
            StatusListRegistry::load(dir.path(), "appliance.example", issuer.did.clone(), issuer.clone())
                .await
                .unwrap(),
        );
        let mut credential = agent_credential(&issuer.did, &holder.did);
        credential["credentialStatus"] = registry
            .entry_for(&holder.did)
            .await
            .unwrap();
        let vp = holder
            .sign_presentation(
                &holder.did,
                issuer
                    .sign_credential(credential)
                    .await,
            )
            .await;
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let verifier = LocalVerifier::with_status_lists(
            Arc::new(client),
            Arc::new(RegistryStatusListSource::new(registry.clone())),
        );

        verifier
            .verify_vp(&vp, &trusting(&issuer))
            .await
            .expect("an own credential verifies against the local list before revocation");
        registry
            .revoke(&holder.did)
            .await
            .unwrap();
        let error = error_chain(
            verifier
                .verify_vp(&vp, &trusting(&issuer))
                .await,
        );

        assert!(error.contains("VC is revoked"), "got: {error}");
    }

    #[test]
    fn a_proof_with_an_embedded_verification_method_is_refused() {
        let document = json!({
            "proof": { "verificationMethod": { "id": "did:key:z6Mk#z6Mk", "controller": "did:key:z6Mk" } }
        });

        let error = ensure_proofs_controlled_by(&document, "did:key:z6Mk").unwrap_err();

        assert!(
            error
                .to_string()
                .contains("must be a DID URL"),
            "got: {error}"
        );
    }

    #[tokio::test]
    async fn every_proof_in_a_proof_set_must_be_controlled_by_the_holder() {
        let (holder_key, holder_did) = new_did_peer();
        let (attacker_key, attacker_did) = new_did_peer();
        let mut vp = sign_test_vp(&holder_did, &holder_key, &holder_did).await;
        let attacker_proof = sign_test_vp(&holder_did, &attacker_key, &attacker_did).await["proof"].clone();
        vp["proof"] = json!([vp["proof"].clone(), attacker_proof]);

        let error = ensure_proofs_controlled_by(&vp, &holder_did)
            .expect_err("a proof set with a foreign proof must be rejected")
            .to_string();

        assert!(error.contains("is not controlled by"), "got: {error}");
    }

    #[test]
    fn no_proof_is_rejected() {
        let error = ensure_proofs_controlled_by(&json!({}), "did:example:holder")
            .expect_err("a VP without proof must be rejected")
            .to_string();

        assert_eq!(error, "missing proof");
    }

    #[tokio::test]
    async fn vp_claiming_a_victim_holder_but_signed_by_an_attacker_key_fails_verification() {
        let (_, victim_did) = new_did_peer();
        let (attacker_key, attacker_did) = new_did_peer();
        let forged_vp = sign_test_vp(&victim_did, &attacker_key, &attacker_did).await;

        let error = verify_vp_error(&forged_vp).await;

        assert!(error.starts_with("VP proof binding failed"), "got: {error}");
        assert!(error.contains("is not controlled by"), "got: {error}");
    }

    /// An embedded method's `id` can name the holder's key while it carries other key
    /// material, so it is refused before its key is used.
    #[tokio::test]
    async fn embedded_verification_method_naming_the_holder_but_carrying_an_attacker_key_fails_verification() {
        let (_, victim_did) = new_did_peer();
        let (attacker_key, _) = new_did_peer();
        let forged_vp = sign_test_vp_with_embedded_method(&victim_did, &attacker_key).await;
        assert!(forged_vp["proof"]["verificationMethod"].is_object(), "method must be embedded");

        let error = verify_vp_error(&forged_vp).await;

        assert!(error.starts_with("VP proof binding failed"), "got: {error}");
        assert!(error.contains("must be a DID URL"), "got: {error}");
    }

    #[tokio::test]
    async fn status_lists_are_fetched_only_over_https_from_public_hosts() {
        for url in ["http://status.example/lists/1", "https://127.0.0.1/lists/1", "https://10.0.0.5/lists/1"] {
            assert!(
                HttpStatusListSource
                    .fetch(url)
                    .await
                    .is_err(),
                "{url} must be refused"
            );
        }
    }

    async fn did_web_resolution_error(
        host_policy: affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy
    ) -> String {
        use super::*;
        use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;

        let client = DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_host_policy(host_policy)
                .build(),
        )
        .await
        .expect("Failed to create DID cache client");
        let resolver = CompositeResolver::new(Arc::new(client));
        match resolver
            .resolve_representation(DID::new("did:web:localhost%3A1").unwrap(), Options::default())
            .await
        {
            Ok(_) => panic!("resolving an unreachable did:web must fail"),
            Err(error) => error.to_string(),
        }
    }

    #[tokio::test]
    async fn did_web_on_a_private_host_is_refused_under_the_default_policy() {
        let error =
            did_web_resolution_error(affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy::PublicOnly).await;
        assert!(error.contains("SSRF-prone host"), "expected a blocked-host refusal, got: {error}");
    }

    #[tokio::test]
    async fn did_web_on_a_private_host_is_fetched_when_private_hosts_are_allowed() {
        let error =
            did_web_resolution_error(affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy::AllowPrivate)
                .await;
        assert!(!error.contains("SSRF-prone host"), "AllowPrivate must not refuse localhost, got: {error}");
    }
}
