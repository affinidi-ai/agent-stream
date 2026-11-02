//! Verifiable Credential issuer for agent identities
//!
//! This module handles issuing VCs for agent identities using the Affinidi TDK

#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssi::jwk::JWK;
use std::borrow::Cow;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::identity::ssi::vc_issuer::{
    AgentIdentity, IssueVcPayload, LocalVcIssuer, LocalVcSigner, VC_LIFETIME_DAYS, VcIssuer,
};
use crate::identity::ssi::verifier::{LocalVerifier, PresentationBinding, Verifier, presentation_binding};
use crate::identity::ssi::vp_issuer::{
    Credentials, LocalVpIssuer, LocalVpSigner, VP_LIFETIME, VP_LIFETIME_MINUTES, VpIssuer, VpIssuerPayload,
};
use crate::identity::status_list::{RegistryStatusListSource, Revocation, StatusListRegistry};

use super::{IdentityStore, VpChallengeStore};

fn extract_domain_from_proxy_did(proxy_did: &str) -> String {
    if let Some(without_prefix) = proxy_did.strip_prefix("did:webvh:") {
        let parts: Vec<&str> = without_prefix
            .split(':')
            .collect();
        if parts.is_empty() {
            return proxy_did.replace("%3A", ":");
        }

        let has_scid = parts.len() >= 2 && !parts[0].contains('.') && !parts[0].contains('%');
        let domain_idx = if has_scid { 1 } else { 0 };
        return parts
            .get(domain_idx)
            .copied()
            .unwrap_or(proxy_did)
            .replace("%3A", ":");
    }

    proxy_did
        .strip_prefix("did:web:")
        .unwrap_or(proxy_did)
        .split(':')
        .next()
        .unwrap_or(proxy_did)
        .replace("%3A", ":")
}

/// Agent Identity Credential Subject Schema
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentityCredentialSubject {
    /// The DID of the agent
    pub id: String,

    /// LLM information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_info: Option<serde_json::Value>,

    /// Software information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_info: Option<serde_json::Value>,

    /// Provisioning information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning_info: Option<serde_json::Value>,

    /// Region
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// VC Issuer configuration
#[derive(Debug, Clone)]
pub struct VCIssuerConfig {
    /// The proxy's DID (did:web)
    pub proxy_did: String,

    /// The proxy's signing key
    pub signing_key: JWK,

    /// Storage path for keys and DIDs
    pub storage_path: PathBuf,
}

/// Saved issuer configuration
#[derive(Debug, Serialize, Deserialize)]
struct SavedIssuerConfig {
    proxy_did: String,
    signing_key: serde_json::Value,
}

#[derive(Debug, Clone, Copy)]
pub enum ExpectedChallenge<'a> {
    /// Issued for `surface_id`, or the IDE Surface a request came through, to
    /// `principal` if it was issued to one; the `domain` is this appliance's DID.
    Issued { surface_id: &'a str, front_door_id: Option<&'a str>, principal: Option<&'a str> },
    /// The `forward-request` envelope id from `sender`; the `domain` is `recipient`,
    /// the Connection Point the envelope was addressed to.
    Envelope { id: &'a str, sender: &'a str, recipient: &'a str },
}

impl<'a> ExpectedChallenge<'a> {
    fn issuing_surfaces(&self) -> Vec<&'a str> {
        match *self {
            Self::Issued { surface_id, front_door_id, .. } => std::iter::once(surface_id)
                .chain(front_door_id)
                .collect(),
            Self::Envelope { .. } => Vec::new(),
        }
    }
}

const ISSUED_CHALLENGE_REFUSED: &str = "VP challenge was not issued by this surface, was already used, or has expired";

/// The lifetime of the presentations this appliance sends, plus clock skew.
const MAX_LIVE_PRESENTATION_LIFETIME: chrono::TimeDelta = chrono::TimeDelta::minutes(VP_LIFETIME_MINUTES + 1);

#[derive(Serialize, Debug)]
pub struct IssuedVpChallenge {
    pub challenge: String,
    /// The presentation proof's `domain`: this appliance's DID.
    pub domain: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Response containing agent DID and credential
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentIdentityResponse {
    /// The agent's DID
    pub did: String,

    /// The verifiable credential (JWT format)
    pub credential: String,

    /// Whether this is a newly created DID
    pub is_new: bool,

    /// When the identity was created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// VC Issuer for agent identities
pub struct VCIssuer {
    config: Arc<RwLock<VCIssuerConfig>>,
    identity_store: Arc<dyn IdentityStore>,
    vp_challenge_store: Arc<VpChallengeStore>,
    did_cache: Arc<RwLock<Option<Arc<crate::gateways::did_cache::DIDCache>>>>,
    vc_issuer: Arc<dyn VcIssuer>,
    vp_issuer: Arc<dyn VpIssuer>,
    verifier: Arc<dyn Verifier>,
    /// Issuers whose credentials a presented VP may carry: this appliance's
    /// own DID plus any configured with [`Self::with_trusted_issuers`].
    trusted_issuers: HashSet<String>,
    status_list: Arc<StatusListRegistry>,
}

impl VCIssuer {
    pub async fn new(
        storage_path: impl AsRef<std::path::Path>,
        proxy_domain: impl AsRef<str>,
        identity_store: Arc<dyn IdentityStore>,
        vp_challenge_store: Arc<VpChallengeStore>,
        vc_issuer: Option<Arc<dyn VcIssuer>>,
        vp_issuer: Option<Arc<dyn VpIssuer>>,
    ) -> Result<Self> {
        let storage_path = storage_path
            .as_ref()
            .to_path_buf();
        let proxy_domain = proxy_domain
            .as_ref()
            .to_string();

        // Ensure storage directory exists
        tokio::fs::create_dir_all(&storage_path).await?;

        // Load or generate proxy DID and keys
        let config = Self::load_or_create_config(storage_path.clone(), proxy_domain.clone()).await?;
        let proxy_did = config.proxy_did.clone();
        let config = Arc::new(RwLock::new(config));
        let signer: Arc<dyn crate::identity::ssi::vc_issuer::VcSigner> =
            Arc::new(LocalVcSigner::new(Arc::clone(&config)));
        let status_list = Arc::new(
            StatusListRegistry::load(&storage_path, &proxy_domain, proxy_did.clone(), Arc::clone(&signer)).await?,
        );
        let vc_issuer = if let Some(provided_vc_issuer) = vc_issuer {
            provided_vc_issuer
        } else {
            Arc::new(LocalVcIssuer::new(Arc::clone(&config), signer).with_status_list(Arc::clone(&status_list)))
        };

        let vp_issuer = if let Some(provided_vp_issuer) = vp_issuer {
            provided_vp_issuer
        } else {
            Arc::new(LocalVpIssuer::new(Arc::new(LocalVpSigner::new())))
        };

        let resolver_client = crate::gateways::did_cache::shared_resolver().clone();
        let verifier: Arc<dyn Verifier> = Arc::new(LocalVerifier::with_status_lists(
            resolver_client,
            Arc::new(RegistryStatusListSource::new(Arc::clone(&status_list))),
        ));
        let trusted_issuers = HashSet::from([proxy_did]);

        Ok(Self {
            config,
            identity_store,
            vp_challenge_store,
            did_cache: Arc::new(RwLock::new(None)),
            vc_issuer,
            vp_issuer,
            verifier,
            trusted_issuers,
            status_list,
        })
    }

    /// Also trust credentials issued by `issuers` (other appliances' DIDs).
    pub fn with_trusted_issuers(
        mut self,
        issuers: impl IntoIterator<Item = String>,
    ) -> Self {
        self.trusted_issuers
            .extend(issuers);
        self
    }

    /// Set the DID cache for this issuer (for caching DID resolution during VP verification)
    pub async fn set_did_cache(
        &self,
        did_cache: Arc<crate::gateways::did_cache::DIDCache>,
    ) {
        let mut cache = self.did_cache.write().await;
        *cache = Some(did_cache);
        info!("DID cache initialized");
    }

    /// The revocation status list for the credentials this appliance issues.
    pub fn status_list(&self) -> &StatusListRegistry {
        &self.status_list
    }

    /// Revoke every credential issued to the local agent identity `agent_did`.
    /// Answers `None` when this appliance holds no local identity with that DID.
    pub async fn revoke_agent(
        &self,
        agent_did: &str,
    ) -> Result<Option<Revocation>> {
        match self
            .identity_store
            .find_by_did(agent_did)
            .await?
        {
            Some(record) if record.is_local => Ok(Some(
                self.status_list
                    .revoke(agent_did)
                    .await?,
            )),
            _ => Ok(None),
        }
    }

    /// Get a reference to the identity store
    pub fn get_identity_store(&self) -> Arc<dyn IdentityStore> {
        Arc::clone(&self.identity_store)
    }

    /// Get a VC signer that can sign arbitrary VC payloads with the gateway's Ed25519 key
    pub fn get_vc_signer(&self) -> Arc<dyn crate::identity::ssi::vc_issuer::VcSigner> {
        Arc::new(LocalVcSigner::new(Arc::clone(&self.config)))
    }

    /// Get the storage path used by the VC issuer (contains `did.json`, `did.jsonl`, keys)
    pub async fn get_storage_path(&self) -> std::path::PathBuf {
        self.config
            .read()
            .await
            .storage_path
            .clone()
    }

    /// Get the issuer DID
    pub async fn get_issuer_did(&self) -> Result<String> {
        let config = self.config.read().await;
        Ok(config.proxy_did.clone())
    }

    /// Get the signing keys as Secrets for DID authentication
    /// Returns Ed25519 (authentication), X25519 (keyAgreement), and P-256 (keyAgreement)
    /// This is used for self gateway OOB invitation creation
    pub async fn get_signing_secrets(&self) -> Result<Vec<affinidi_secrets_resolver::secrets::Secret>> {
        let config = self.config.read().await;

        // Ed25519 secret for authentication/signing
        let ed25519_key_id = format!("{}#key-1", config.proxy_did);
        let ed25519_secret: affinidi_secrets_resolver::secrets::Secret = serde_json::from_value(serde_json::json!({
            "id": ed25519_key_id,
            "type": "JsonWebKey2020",
            "privateKeyJwk": config.signing_key
        }))?;

        let mut secrets = vec![ed25519_secret];

        // X25519 secret for keyAgreement (DIDComm encryption)
        let x25519_key_path = config
            .storage_path
            .join("x25519_key.json");
        if let Some(content) = crate::encryption::secret_file::read_secret_file(&x25519_key_path).await? {
            let x25519_secret = serde_json::from_str(&content)?;
            secrets.push(x25519_secret);
        }

        // P-256 secret for keyAgreement (compatible with Affinidi mediator)
        let p256_key_path = config
            .storage_path
            .join("p256_key.json");
        if let Some(content) = crate::encryption::secret_file::read_secret_file(&p256_key_path).await? {
            let p256_secret = serde_json::from_str(&content)?;
            secrets.push(p256_secret);
        }

        Ok(secrets)
    }

    /// Get the signing key as a Secret for DID authentication (deprecated, use get_signing_secrets)
    /// This is used for self gateway OOB invitation creation
    pub async fn get_signing_secret(&self) -> Result<affinidi_secrets_resolver::secrets::Secret> {
        let secrets = self
            .get_signing_secrets()
            .await?;
        Ok(secrets
            .into_iter()
            .next()
            .unwrap())
    }

    /// Get the DID document for the proxy/gateway
    /// This is used to cache the DID document in the resolver
    pub async fn get_did_document(&self) -> Result<serde_json::Value> {
        let config = self.config.read().await;
        let did_doc_path = config
            .storage_path
            .join("did.json");

        if did_doc_path.exists() {
            let content = tokio::fs::read_to_string(&did_doc_path).await?;
            Ok(serde_json::from_str(&content)?)
        } else {
            use crate::identity::ssi::did_utils::jwk_to_multibase_ed25519;

            let domain = extract_domain_from_proxy_did(&config.proxy_did);

            let public_key_multibase = jwk_to_multibase_ed25519(&config.signing_key)?;

            let x25519_key_path = config
                .storage_path
                .join("x25519_key.json");
            let p256_key_path = config
                .storage_path
                .join("p256_key.json");

            let (x25519_key_id, x25519_public_jwk) =
                if let Some(content) = crate::encryption::secret_file::read_secret_file(&x25519_key_path).await? {
                    let secret: affinidi_secrets_resolver::secrets::Secret = serde_json::from_str(&content)?;
                    let key_id = secret.id.clone();
                    let public_jwk =
                        if let affinidi_secrets_resolver::secrets::SecretMaterial::JWK(jwk) = &secret.secret_material {
                            let mut public_jwk = serde_json::to_value(jwk)?;
                            if let Some(obj) = public_jwk.as_object_mut() {
                                obj.remove("d");
                            }
                            public_jwk
                        } else {
                            return Err(anyhow::anyhow!("X25519 secret is not a JWK"));
                        };
                    (key_id, public_jwk)
                } else {
                    let key_id = format!("{}#key-x25519-1", config.proxy_did);
                    (key_id, serde_json::json!({}))
                };

            let (p256_key_id, p256_public_jwk) =
                if let Some(content) = crate::encryption::secret_file::read_secret_file(&p256_key_path).await? {
                    let secret: affinidi_secrets_resolver::secrets::Secret = serde_json::from_str(&content)?;
                    let key_id = secret.id.clone();
                    let public_jwk =
                        if let affinidi_secrets_resolver::secrets::SecretMaterial::JWK(jwk) = &secret.secret_material {
                            let mut public_jwk = serde_json::to_value(jwk)?;
                            if let Some(obj) = public_jwk.as_object_mut() {
                                obj.remove("d");
                            }
                            public_jwk
                        } else {
                            return Err(anyhow::anyhow!("P-256 secret is not a JWK"));
                        };
                    (key_id, public_jwk)
                } else {
                    let key_id = format!("{}#key-p256-1", config.proxy_did);
                    (key_id, serde_json::json!({}))
                };

            // Include both JsonWebKey2020 (#key-1) and Multikey (#key-2) formats
            // VP signatures use EdDsaRdfc2022 cryptosuite which expects Multikey format
            Ok(serde_json::json!({
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1",
                    "https://w3id.org/security/multikey/v1"
                ],
                "id": config.proxy_did,
                "verificationMethod": [
                    {
                        "id": format!("{}#key-1", config.proxy_did),
                        "type": "JsonWebKey2020",
                        "controller": config.proxy_did,
                        "publicKeyJwk": config.signing_key.to_public()
                    },
                    {
                        "id": format!("{}#key-2", config.proxy_did),
                        "type": "Multikey",
                        "controller": config.proxy_did,
                        "publicKeyMultibase": public_key_multibase
                    },
                    {
                        "id": &x25519_key_id,
                        "type": "JsonWebKey2020",
                        "controller": config.proxy_did,
                        "publicKeyJwk": x25519_public_jwk
                    },
                    {
                        "id": &p256_key_id,
                        "type": "JsonWebKey2020",
                        "controller": config.proxy_did,
                        "publicKeyJwk": p256_public_jwk
                    }
                ],
                "authentication": [format!("{}#key-1", config.proxy_did)],
                "assertionMethod": [
                    format!("{}#key-1", config.proxy_did),
                    format!("{}#key-2", config.proxy_did)
                ],
                "keyAgreement": [&x25519_key_id, &p256_key_id],
                "service": [{
                    "id": format!("{}#didcomm", config.proxy_did),
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{
                        "uri": format!("https://{}/didcomm", domain),
                        "accept": ["didcomm/v2"],
                        "routingKeys": []
                    }]
                }]
            }))
        }
    }

    /// Migrate the gateway `proxy_did` from `did:web:` to `did:webvh:` on first boot after upgrade.
    ///
    /// Delegates to `create_webvh_did` (the same spec-compliant helper used by
    /// channels and trust-registries) and persists the birth log to
    /// `{storage_path}/did.jsonl`.  Returns the new canonical `did:webvh` DID.
    ///
    /// This function is **idempotent**: if `did.jsonl` already exists it reads the
    /// SCID from the first line and returns the corresponding DID without touching
    /// any file.
    ///
    #[cfg(feature = "didwebvh")]
    async fn migrate_proxy_did_to_webvh(
        storage_path: &std::path::Path,
        proxy_did: &str,
        signing_key: &JWK,
    ) -> Result<String> {
        use crate::identity::didwebvh::create::create_webvh_did;
        use crate::identity::didwebvh::types::LogEntry;

        let jsonl_path = storage_path.join("did.jsonl");
        let domain_encoded = proxy_did
            .strip_prefix("did:web:")
            .unwrap_or(proxy_did);

        // Idempotent: already migrated — read SCID from existing log.
        // Only reuse if the SCID is non-empty (guard against the old bug where scid was "").
        if jsonl_path.exists() {
            let content = tokio::fs::read_to_string(&jsonl_path).await?;
            if let Some(first_line) = content.lines().next() {
                let entry: LogEntry = serde_json::from_str(first_line)?;
                let scid = entry.parameters.scid.clone();
                if !scid.is_empty() {
                    return Ok(format!("did:webvh:{}:{}", scid, domain_encoded));
                }
                info!("Gateway did.jsonl has empty SCID (old format), regenerating");
            }
        }

        // Read existing did.json as raw JSON (not via DidDocument/url::Url which
        // would percent-encode placeholders and break SCID substitution).
        let did_json_path = storage_path.join("did.json");
        let did_json_content = tokio::fs::read_to_string(&did_json_path)
            .await
            .context("did.json not found; ensure the gateway has started at least once before upgrading")?;

        // Replace old did:web: prefix with {SCID} placeholder at the raw JSON string level,
        // preserving all fields (including @context which DidDocument/url::Url may mangle).
        let placeholder_did = format!("did:webvh:{{SCID}}:{}", domain_encoded);
        let placeholder_json = did_json_content.replace(proxy_did, &placeholder_did);
        let did_doc_value: serde_json::Value =
            serde_json::from_str(&placeholder_json).context("Failed to parse did.json for webvh migration")?;

        // Extract the Ed25519 private key as a JSON value for the didwebvh_rs helper.
        let private_jwk = serde_json::to_value(signing_key)?;

        // Derive the base URL from the domain-encoded portion of the did:web
        let domain = domain_encoded.replace("%3A", ":");
        let base_url = format!("https://{}/", domain);

        let result = create_webvh_did(&private_jwk, did_doc_value, &base_url).await?;

        // Persist birth log
        tokio::fs::write(&jsonl_path, format!("{}\n", result.log_entry_json)).await?;

        // Update did.json to serve as the parallel did:web document
        let state_json = serde_json::to_string(&result.signed_entry.state)?;
        let state_value: serde_json::Value = serde_json::from_str(&state_json)?;
        let parallel_doc =
            crate::identity::didwebvh::generate_parallel_did_web(&state_value, &result.final_did, &result.scid);
        tokio::fs::write(&did_json_path, serde_json::to_string_pretty(&parallel_doc)?).await?;

        info!("Gateway proxy_did migrated: {} → {}", proxy_did, result.final_did);
        Ok(result.final_did)
    }

    #[cfg(feature = "didwebvh")]
    async fn update_didcomm_key_ids(
        storage_path: &std::path::Path,
        old_did: &str,
        new_did: &str,
    ) {
        for filename in &["x25519_key.json", "p256_key.json"] {
            let path = storage_path.join(filename);
            if let Ok(Some(content)) = crate::encryption::secret_file::read_secret_file(&path).await {
                let updated = content.replace(old_did, new_did);
                if updated != content
                    && let Err(e) = crate::encryption::secret_file::write_secret_file(&path, &updated).await
                {
                    warn!("Failed to update key ID in {}: {}", filename, e);
                }
            }
        }
    }

    /// Load existing config or create new one
    async fn load_or_create_config(
        storage_path: PathBuf,
        proxy_domain: String,
    ) -> Result<VCIssuerConfig> {
        let config_path = storage_path.join("issuer_config.json");

        let existing_config = crate::encryption::secret_file::read_secret_file(&config_path).await?;
        let (key, proxy_did, is_new_config) = if let Some(content) = existing_config {
            // Load existing config
            let saved: SavedIssuerConfig = serde_json::from_str(&content)?;

            (serde_json::from_value(saved.signing_key)?, saved.proxy_did, false)
        } else {
            // Generate new key pair
            let key = JWK::generate_ed25519().context("Failed to generate Ed25519 key")?;

            // Create did:web DID
            let proxy_did = format!("did:web:{}", proxy_domain.replace(":", "%3A"));

            (key, proxy_did, true)
        };

        // Save config if it's new
        if is_new_config {
            let saved = SavedIssuerConfig {
                proxy_did: proxy_did.clone(),
                signing_key: serde_json::to_value(&key)?,
            };

            let content = serde_json::to_string_pretty(&saved)?;
            crate::encryption::secret_file::write_secret_file(&config_path, &content).await?;
        }

        // Generate or load X25519 and P-256 keys for DIDComm keyAgreement
        let x25519_key_path = storage_path.join("x25519_key.json");
        let existing_x25519 = crate::encryption::secret_file::read_secret_file(&x25519_key_path).await?;
        let x25519_existed = existing_x25519.is_some();
        let x25519_secret = if let Some(content) = existing_x25519 {
            // Load existing X25519 key
            serde_json::from_str(&content)?
        } else {
            // Generate new X25519 key using Affinidi SDK
            let x25519_key_id = format!("{}#key-x25519-1", proxy_did);
            let secret = affinidi_secrets_resolver::secrets::Secret::generate_x25519(Some(&x25519_key_id), None)?;

            // Save to file
            let x25519_json = serde_json::to_string_pretty(&secret)?;
            crate::encryption::secret_file::write_secret_file(&x25519_key_path, &x25519_json).await?;

            secret
        };

        let p256_key_path = storage_path.join("p256_key.json");
        let existing_p256 = crate::encryption::secret_file::read_secret_file(&p256_key_path).await?;
        let p256_existed = existing_p256.is_some();
        let p256_secret = if let Some(content) = existing_p256 {
            // Load existing P-256 key
            serde_json::from_str(&content)?
        } else {
            // Generate new P-256 key using Affinidi SDK
            let p256_key_id = format!("{}#key-p256-1", proxy_did);
            let secret = affinidi_secrets_resolver::secrets::Secret::generate_p256(Some(&p256_key_id), None)?;

            // Save to file
            let p256_json = serde_json::to_string_pretty(&secret)?;
            crate::encryption::secret_file::write_secret_file(&p256_key_path, &p256_json).await?;

            secret
        };

        // Extract public keys from the secrets for the DID document
        let x25519_key_id = x25519_secret.id.clone();
        let x25519_public_jwk =
            if let affinidi_secrets_resolver::secrets::SecretMaterial::JWK(jwk) = &x25519_secret.secret_material {
                // Create public-only version (without 'd' parameter)
                let mut public_jwk = serde_json::to_value(jwk)?;
                if let Some(obj) = public_jwk.as_object_mut() {
                    obj.remove("d");
                }
                public_jwk
            } else {
                return Err(anyhow::anyhow!("X25519 secret is not a JWK"));
            };

        let p256_key_id = p256_secret.id.clone();
        let p256_public_jwk =
            if let affinidi_secrets_resolver::secrets::SecretMaterial::JWK(jwk) = &p256_secret.secret_material {
                // Create public-only version (without 'd' parameter)
                let mut public_jwk = serde_json::to_value(jwk)?;
                if let Some(obj) = public_jwk.as_object_mut() {
                    obj.remove("d");
                }
                public_jwk
            } else {
                return Err(anyhow::anyhow!("P-256 secret is not a JWK"));
            };

        // Generate or update the DID document
        let did_doc_path = storage_path.join("did.json");

        // Only regenerate DID document if it doesn't exist or if we created new keys
        let should_update_did_doc = !did_doc_path.exists() || is_new_config || !x25519_existed || !p256_existed;

        if should_update_did_doc {
            use crate::identity::ssi::did_utils::jwk_to_multibase_ed25519;

            let domain = extract_domain_from_proxy_did(&proxy_did);

            let public_key_multibase = jwk_to_multibase_ed25519(&key)?;

            let did_doc = json!({
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1",
                    "https://w3id.org/security/multikey/v1"
                ],
                "id": proxy_did,
                "verificationMethod": [
                    {
                        "id": format!("{}#key-1", proxy_did),
                        "type": "JsonWebKey2020",
                        "controller": proxy_did,
                        "publicKeyJwk": key.to_public()
                    },
                    {
                        "id": format!("{}#key-2", proxy_did),
                        "type": "Multikey",
                        "controller": proxy_did,
                        "publicKeyMultibase": public_key_multibase
                    },
                    {
                        "id": &x25519_key_id,
                        "type": "JsonWebKey2020",
                        "controller": proxy_did,
                        "publicKeyJwk": x25519_public_jwk
                    },
                    {
                        "id": &p256_key_id,
                        "type": "JsonWebKey2020",
                        "controller": proxy_did,
                        "publicKeyJwk": p256_public_jwk
                    }
                ],
                "authentication": [format!("{}#key-1", proxy_did)],
                "assertionMethod": [format!("{}#key-1", proxy_did), format!("{}#key-2", proxy_did)],
                "keyAgreement": [&x25519_key_id, &p256_key_id],
                "service": [{
                    "id": format!("{}#didcomm", proxy_did),
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{
                        "uri": format!("https://{}/didcomm", domain),
                        "accept": ["didcomm/v2"],
                        "routingKeys": []
                    }]
                }]
            });

            tokio::fs::write(&did_doc_path, serde_json::to_string_pretty(&did_doc)?).await?;
        }

        // Create or migrate proxy_did to did:webvh.
        // Runs on first boot (new config) and on subsequent boots if still did:web: (legacy upgrade path).
        #[cfg(feature = "didwebvh")]
        let proxy_did = if proxy_did.starts_with("did:web:") {
            match Self::migrate_proxy_did_to_webvh(&storage_path, &proxy_did, &key).await {
                Ok(new_did) => {
                    // Persist the new DID back to issuer_config.json
                    let saved = SavedIssuerConfig {
                        proxy_did: new_did.clone(),
                        signing_key: serde_json::to_value(&key)?,
                    };
                    let content = serde_json::to_string_pretty(&saved)?;
                    crate::encryption::secret_file::write_secret_file(&config_path, &content).await?;

                    // Update DIDComm key IDs from old did:web to new did:webvh
                    Self::update_didcomm_key_ids(&storage_path, &proxy_did, &new_did).await;

                    new_did
                }
                Err(e) => {
                    warn!("Gateway DID webvh migration skipped: {}", e);
                    proxy_did
                }
            }
        } else {
            proxy_did
        };

        Ok(VCIssuerConfig {
            proxy_did,
            signing_key: key,
            storage_path,
        })
    }

    /// Issue a VC for an agent identity, or return existing DID if already issued
    ///
    /// If identity_hash is provided, it will be used directly (preferred).
    /// Otherwise, the hash will be computed from the identity_fields.
    pub async fn issue_or_get_credential(
        &self,
        identity_fields: std::collections::HashMap<String, serde_json::Value>,
        identity_hash: Option<String>,
        channel_config_id: Option<String>,
    ) -> Result<AgentIdentityResponse> {
        info!(
            "issue_or_get_credential called: channel_config_id={:?}, identity_hash={:?}, field_count={}",
            channel_config_id,
            identity_hash,
            identity_fields.len()
        );
        // Use provided hash or calculate from the identity fields
        let identity_hash = identity_hash
            .unwrap_or_else(|| crate::identity::identity_hash::compute_canonical_identity_hash(&identity_fields));

        // Check if we already have a DID for this identity
        if let Some(record) = self
            .identity_store
            .find_by_hash(&identity_hash)
            .await?
        {
            info!(
                "[TR-TRACE] Identity ALREADY EXISTS for hash={}, did={} — skipping TR registration (only runs on first creation)",
                identity_hash, record.did
            );
            // Update usage tracking with the current channel
            self.identity_store
                .update_usage(&identity_hash, channel_config_id.clone())
                .await?;
            // Return existing DID and generate a fresh VC
            let vc = self
                .create_credential(&record.did, &identity_fields)
                .await?;

            return Ok(AgentIdentityResponse {
                did: record.did,
                credential: vc.to_string(),
                is_new: false,
                created_at: record.created_at,
            });
        }

        // Generate new did:webvh DID for this agent
        let (agent_did, mut record) = crate::vault_identity::handlers::generate_did_webvh_identity(
            self,
            "surface",
            Some(format!(
                "Surface: {}",
                channel_config_id
                    .as_deref()
                    .unwrap_or("unknown")
            )),
        )
        .await?;

        // Create VC
        let vc = self
            .create_credential(&agent_did, &identity_fields)
            .await?;

        // Update the record with the actual identity_hash and fields before storing
        record.identity_hash = identity_hash.clone();
        record.identity_fields = identity_fields;
        record.channel_config_id = channel_config_id.clone();
        let created_at = record.created_at;
        let channel_config_id_for_usage = channel_config_id;

        // Store the record once with the correct identity_hash
        self.identity_store
            .create(record)
            .await?;

        // Treat the very call that triggered creation as the first usage,
        // so the dashboard shows usage_count=1 / last_used_at instead of
        // an unused record. Without this, the first request silently
        // creates the identity but it appears as "Unused" until a second
        // call exercises the existing-record branch above.
        if let Err(e) = self
            .identity_store
            .update_usage(&identity_hash, channel_config_id_for_usage)
            .await
        {
            warn!(
                agent_did = %agent_did,
                identity_hash = %identity_hash,
                error = %e,
                "Failed to record initial usage for newly created identity (non-fatal)"
            );
        }

        Ok(AgentIdentityResponse {
            did: agent_did,
            credential: vc.to_string(),
            is_new: true,
            created_at,
        })
    }

    /// Create a verifiable credential for an agent identity
    async fn create_credential(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<String> {
        let config = self.config.read().await;

        // Convert identity fields to JSON for credential
        let identity_json = serde_json::to_value(identity_fields).context("Failed to serialize identity fields")?;

        // Create credential subject with identity fields
        // The public key can be resolved from the channel's DID document at /channel/{id}/did.json
        let credential_subject = serde_json::json!({
            "id": agent_did,
            "identityFields": identity_json,
        });

        // Create JWT payload
        let now = chrono::Utc::now().timestamp();
        let payload = json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://affinidi.io/contexts/agent-identity/v1"
            ],
            "type": ["VerifiableCredential", "AgentIdentityCredential"],
            "issuer": config.proxy_did,
            "issuanceDate": chrono::Utc::now().to_rfc3339(),
            "credentialSubject": credential_subject,
            "iat": now,
            "exp": now + (365 * 24 * 60 * 60), // 1 year
            "jti": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        });

        // Sign as JWT
        let jwt = self.sign_jwt(&payload, &config.signing_key)?;

        Ok(jwt)
    }

    /// Sign a payload as JWT
    fn sign_jwt(
        &self,
        payload: &serde_json::Value,
        key: &JWK,
    ) -> Result<String> {
        use base64::Engine;

        // Create JWT header
        let header = json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": key.key_id.as_ref().unwrap_or(&"key-1".to_string())
        });

        // Encode header and payload
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?.as_bytes());
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign using the JWK
        let signature = self.sign_with_jwk(signing_input.as_bytes(), key)?;
        let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    /// Sign data with JWK (Ed25519)
    fn sign_with_jwk(
        &self,
        data: &[u8],
        key: &JWK,
    ) -> Result<Vec<u8>> {
        use base64::Engine;

        use ed25519_dalek::{Signer, SigningKey};

        // Serialize JWK to JSON to extract the d parameter
        let key_json = serde_json::to_value(key)?;
        let d_str = key_json
            .get("d")
            .and_then(|v| v.as_str())
            .context("Missing private key component 'd'")?;

        // Decode the private key
        let secret_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(d_str)
            .context("Failed to decode private key")?;

        let signing_key = SigningKey::from_bytes(
            &secret_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
        );

        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    pub async fn get_agent_key_by_did(
        &self,
        did: &str,
    ) -> Result<JWK> {
        let record = self
            .identity_store
            .find_by_did(did)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Agent DID not found: {}", did))?;

        let key_json = record
            .private_key
            .ok_or_else(|| anyhow::anyhow!("No private key found for agent: {}", did))?;

        let key: JWK = serde_json::from_value(key_json).context("Failed to deserialize agent private key")?;

        Ok(key)
    }

    pub async fn get_agent_key_by_hash(
        &self,
        identity_hash: &str,
    ) -> Result<JWK> {
        let record = self
            .identity_store
            .find_by_hash(identity_hash)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Agent identity hash not found: {}", identity_hash))?;

        let key_json = record
            .private_key
            .ok_or_else(|| anyhow::anyhow!("No private key found for identity: {}", identity_hash))?;

        let key: JWK = serde_json::from_value(key_json).context("Failed to deserialize agent private key")?;

        Ok(key)
    }

    /// Sign data with an agent's private key (by DID)
    pub async fn sign_with_agent_key(
        &self,
        did: &str,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self
            .get_agent_key_by_did(did)
            .await?;
        self.sign_with_jwk(data, &key)
    }

    /// Sign a JWT payload with an agent's private key
    pub async fn sign_jwt_with_agent_key(
        &self,
        did: &str,
        payload: &serde_json::Value,
    ) -> Result<String> {
        let key = self
            .get_agent_key_by_did(did)
            .await?;
        let jwt = self.sign_jwt(payload, &key)?;
        info!(did = did, "✍️ Signed JWT with agent key");
        Ok(jwt)
    }

    /// Sign a JWT payload with the gateway's private key
    pub async fn sign_jwt_with_gateway_key(
        &self,
        payload: &serde_json::Value,
    ) -> Result<String> {
        let config = self.config.read().await;
        let gateway_did = config.proxy_did.clone();
        let jwt = self.sign_jwt(payload, &config.signing_key)?;
        drop(config);
        info!(did = %gateway_did, "✍️ Signed JWT with gateway key");
        Ok(jwt)
    }

    /// Create a Verifiable Presentation containing a Verifiable Credential for an agent
    /// This is used when GW1 forwards identity to GW2 with proof of identity
    pub async fn create_agent_identity_presentation(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
        challenge: Option<&str>,
        domain: Option<&str>,
    ) -> Result<String> {
        self.create_agent_identity_presentation_with_binding(agent_did, identity_fields, None, challenge, domain)
            .await
    }

    /// Create a VP with optional workload binding attestation.
    /// When `workload_binding` is provided, the VC uses structured `workloadBinding`
    /// instead of flat `identityFields`.
    pub async fn create_agent_identity_presentation_with_binding(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
        workload_binding: Option<serde_json::Value>,
        challenge: Option<&str>,
        domain: Option<&str>,
    ) -> Result<String> {
        self.mint_presentation(agent_did, identity_fields, workload_binding, challenge, domain, VP_LIFETIME)
            .await
    }

    /// Kept as evidence, so it lasts as long as its credential; its challenge (the
    /// token id) keeps any verifier that issues challenges from accepting it live.
    pub async fn create_consent_audit_presentation(
        &self,
        agent_did: &str,
        workload_binding: serde_json::Value,
        token_id: &str,
    ) -> Result<String> {
        let appliance_did = self.get_issuer_did().await?;
        self.mint_presentation(
            agent_did,
            &std::collections::HashMap::new(),
            Some(workload_binding),
            Some(token_id),
            Some(&appliance_did),
            chrono::TimeDelta::days(VC_LIFETIME_DAYS),
        )
        .await
    }

    async fn mint_presentation(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
        workload_binding: Option<serde_json::Value>,
        challenge: Option<&str>,
        domain: Option<&str>,
        lifetime: chrono::TimeDelta,
    ) -> Result<String> {
        let agent_key = self
            .get_agent_key_by_did(agent_did)
            .await?;

        let agent_identity = AgentIdentity {
            did: Cow::Borrowed(agent_did),
            identity_fields: Cow::Borrowed(identity_fields),
            workload_binding,
        };
        let vc = self
            .vc_issuer
            .issue(IssueVcPayload::AgentIdentity(agent_identity))
            .await?;

        let presentation_creds = Credentials {
            holder_key: Cow::Owned(agent_key),
            holder_did: Cow::Borrowed(agent_did),
            verifiable_credentials: Cow::Owned(vec![vc]),
            challenge: challenge.map(Cow::Borrowed),
            domain: domain.map(Cow::Borrowed),
            lifetime,
        };

        let vp = self
            .vp_issuer
            .issue(VpIssuerPayload::Credentials(presentation_creds))
            .await?;

        info!(agent_did = agent_did, "Created VP for agent identity presentation");

        Ok(vp.to_string())
    }

    /// Uses the challenge up before verification, so concurrent copies are refused
    /// without a signature check, and a presentation that fails has used it too.
    async fn accept_vp_challenge(
        &self,
        binding: &PresentationBinding,
        expected: ExpectedChallenge<'_>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        anyhow::ensure!(
            binding.expires <= now + MAX_LIVE_PRESENTATION_LIFETIME,
            "presentation proof expires {}s ahead, at {}, more than the {}s allowed; the presenting host's clock may \
             be ahead of this one",
            (binding.expires - now).num_seconds(),
            binding.expires,
            MAX_LIVE_PRESENTATION_LIFETIME.num_seconds()
        );
        let challenge = binding
            .challenge
            .as_deref()
            .context("VP challenge is required but not presented")?;
        match expected {
            ExpectedChallenge::Issued { principal, .. } => {
                let appliance_did = self.get_issuer_did().await?;
                anyhow::ensure!(
                    binding
                        .domains
                        .contains(&appliance_did),
                    "VP domain does not name this appliance"
                );
                anyhow::ensure!(
                    self.vp_challenge_store
                        .redeem(challenge, &expected.issuing_surfaces(), principal, now),
                    ISSUED_CHALLENGE_REFUSED
                );
                Ok(())
            }
            ExpectedChallenge::Envelope { id, sender, recipient } => {
                anyhow::ensure!(
                    binding
                        .domains
                        .iter()
                        .any(|domain| domain == recipient),
                    "VP domain does not name the Connection Point the envelope was sent to"
                );
                anyhow::ensure!(challenge == id, "VP challenge does not match the envelope that carried it");
                self.vp_challenge_store
                    .claim(sender, id, &binding.proof_value, binding.expires, now)
            }
        }
    }

    /// Verify a VP carrying the `expected` challenge and return the holder DID,
    /// the first credential's issuer DID (for "known issuer" policy checks),
    /// and its identity fields.
    pub async fn verify_presentation_with_issuer(
        &self,
        vp_input: &str,
        expected: ExpectedChallenge<'_>,
    ) -> Result<(String, Option<String>, std::collections::HashMap<String, serde_json::Value>)> {
        let vp: serde_json::Value = serde_json::from_str(vp_input).context("Failed to parse VP as JSON")?;
        let binding = presentation_binding(&vp, chrono::Utc::now()).context("VP proof lifetime check failed")?;
        self.accept_vp_challenge(&binding, expected, chrono::Utc::now())
            .await?;
        let result = self
            .verifier
            .verify_vp(&vp, &self.trusted_issuers)
            .await
            .context("VP verification failed")?;
        let first = result.credentials.first();
        let issuer_did = first.map(|vc| vc.issuer_did.clone());
        let identity_fields = first
            .map(|vc| vc.identity_fields.clone())
            .unwrap_or_default();
        Ok((result.holder_did, issuer_did, identity_fields))
    }

    pub async fn create_vp_challenge(
        &self,
        surface_id: &str,
        caller: &crate::identity::ChallengeCaller,
    ) -> Result<IssuedVpChallenge> {
        let domain = self.get_issuer_did().await?;
        let (challenge, expires_at) = self
            .vp_challenge_store
            .issue(surface_id, caller, chrono::Utc::now())?;
        Ok(IssuedVpChallenge { challenge, domain, expires_at })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_helpers::MockIdentityStore;
    use crate::identity::{IdentityStore, VpChallengeStore};
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn extract_domain_from_proxy_did_supports_didwebvh() {
        assert_eq!(extract_domain_from_proxy_did("did:web:localhost%3A8080"), "localhost:8080");
        assert_eq!(extract_domain_from_proxy_did("did:webvh:z6MkScid123:localhost%3A8080"), "localhost:8080");
    }

    #[tokio::test]
    #[ignore] // FIXME: failing test
    async fn test_create_agent_identity_presentation() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let orchestrator =
            VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
                .await
                .unwrap();

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
                }
            }),
        );

        let response = orchestrator
            .issue_or_get_credential(identity_fields.clone(), None, None)
            .await
            .unwrap();

        let agent_did = response.did;

        let vp_json_str = orchestrator
            .create_agent_identity_presentation(&agent_did, &identity_fields, None, None)
            .await
            .unwrap();

        assert!(!vp_json_str.is_empty(), "VP should not be empty");

        let vp: serde_json::Value = serde_json::from_str(&vp_json_str).unwrap();

        assert!(vp.get("proof").is_some(), "VP should have a proof");
        assert_eq!(vp["type"], json!(["VerifiablePresentation"]));

        let holder = vp["holder"].as_str().unwrap();
        assert!(holder.starts_with("did:peer:"), "Holder should be a did:peer");

        let vc = &vp["verifiableCredential"];
        assert!(vc.is_object() || vc.is_array(), "VP should contain verifiableCredential");
    }

    #[tokio::test]
    async fn only_a_local_agent_identity_can_be_revoked() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());
        let issuer =
            VCIssuer::new(temp_dir.path(), "example.com", identity_store.clone(), vp_challenge_store, None, None)
                .await
                .unwrap();
        let identity_fields = HashMap::from([("role".to_string(), json!("agent"))]);
        let agent_did = issuer
            .issue_or_get_credential(identity_fields.clone(), None, None)
            .await
            .unwrap()
            .did;
        identity_store
            .store_external_did("did:example:peer-agent", HashMap::new(), None, true)
            .await
            .unwrap();

        let vp: serde_json::Value = serde_json::from_str(
            &issuer
                .create_agent_identity_presentation(&agent_did, &identity_fields, None, None)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            vp["verifiableCredential"]["credentialStatus"]["statusListCredential"],
            "https://example.com/credentials/status/revocation"
        );

        assert_eq!(
            issuer
                .revoke_agent(&agent_did)
                .await
                .unwrap(),
            Some(Revocation::Revoked)
        );
        assert_eq!(
            issuer
                .revoke_agent(&agent_did)
                .await
                .unwrap(),
            Some(Revocation::AlreadyRevoked)
        );
        assert!(
            issuer
                .status_list()
                .is_revoked(&agent_did)
                .await
        );
        assert_eq!(
            issuer
                .revoke_agent("did:example:peer-agent")
                .await
                .unwrap(),
            None,
            "an external DID"
        );
        assert_eq!(
            issuer
                .revoke_agent("did:example:unknown")
                .await
                .unwrap(),
            None
        );
        assert!(
            !issuer
                .status_list()
                .is_revoked("did:example:peer-agent")
                .await
        );
    }

    // === Baseline did:webvh Tests ===
    /// The proxy DID is created as did:webvh on the first boot and is
    /// stable on all subsequent boots.
    #[tokio::test]
    async fn proxy_did_persists_across_restarts() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        // Boot 1 — new config, creates did:webvh directly
        let issuer1 = VCIssuer::new(
            temp_dir.path(),
            "example.com",
            Arc::clone(&identity_store),
            Arc::clone(&vp_challenge_store),
            None,
            None,
        )
        .await
        .unwrap();
        let did1 = issuer1
            .get_issuer_did()
            .await
            .unwrap();
        assert!(did1.starts_with("did:webvh:"), "Boot 1 must create did:webvh, got: {}", did1);

        // Boot 2 — DID is stable
        let issuer2 = VCIssuer::new(
            temp_dir.path(),
            "example.com",
            Arc::clone(&identity_store),
            Arc::clone(&vp_challenge_store),
            None,
            None,
        )
        .await
        .unwrap();
        let did2 = issuer2
            .get_issuer_did()
            .await
            .unwrap();
        assert_eq!(did1, did2, "Boot 2 DID must be identical to boot 1 (stable)");

        // Boot 3 — DID is still stable
        let issuer3 = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();
        let did3 = issuer3
            .get_issuer_did()
            .await
            .unwrap();
        assert_eq!(did1, did3, "Proxy DID must be identical on third boot (stable)");
    }

    /// The proxy DID must use the did:webvh method on first boot.
    #[tokio::test]
    async fn proxy_did_format_is_did_webvh() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let did = issuer
            .get_issuer_did()
            .await
            .unwrap();
        assert!(did.starts_with("did:webvh:"), "Proxy DID must use the did:webvh method, got: {}", did);
    }

    /// Three key types (Ed25519, X25519, P-256) must be generated.
    #[tokio::test]
    async fn generates_three_key_types_ed25519_x25519_p256() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let secrets = issuer
            .get_signing_secrets()
            .await
            .unwrap();
        assert_eq!(secrets.len(), 3, "Must generate exactly 3 key types (Ed25519 + X25519 + P-256)");
    }

    #[tokio::test]
    async fn trusts_its_own_did_and_configured_issuers_only() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap()
            .with_trusted_issuers(["did:web:peer.example".to_string()]);
        let own_did = issuer
            .get_issuer_did()
            .await
            .unwrap();

        assert_eq!(issuer.trusted_issuers, HashSet::from([own_did, "did:web:peer.example".to_string()]));
    }

    /// Secret IDs must follow the expected naming convention.
    #[tokio::test]
    async fn key_ids_follow_hash_key_n_convention() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let secrets = issuer
            .get_signing_secrets()
            .await
            .unwrap();
        assert_eq!(secrets.len(), 3, "Expected 3 secrets");

        // Ed25519 key has #key-1 fragment
        assert!(
            secrets[0]
                .id
                .contains("#key-1"),
            "Ed25519 secret ID must contain '#key-1', got: {}",
            secrets[0].id
        );
        // X25519 key has #key-x25519-1 fragment
        assert!(
            secrets[1]
                .id
                .contains("#key-x25519-1"),
            "X25519 secret ID must contain '#key-x25519-1', got: {}",
            secrets[1].id
        );
        // P-256 key has #key-p256-1 fragment
        assert!(
            secrets[2]
                .id
                .contains("#key-p256-1"),
            "P-256 secret ID must contain '#key-p256-1', got: {}",
            secrets[2].id
        );
    }

    /// Ed25519 signing key must be identical after reload.
    #[tokio::test]
    async fn signing_key_unchanged_after_reload() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store1 = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp1 = Arc::new(VpChallengeStore::default());
        let store2 = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp2 = Arc::new(VpChallengeStore::default());

        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", store1, vp1, None, None)
            .await
            .unwrap();
        let secrets1 = issuer1
            .get_signing_secrets()
            .await
            .unwrap();
        let _ed25519_id_1 = secrets1[0].id.clone();
        // Serialize so we can compare after reload
        let material1 = serde_json::to_string(&secrets1[0].secret_material).unwrap();

        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store2, vp2, None, None)
            .await
            .unwrap();
        let secrets2 = issuer2
            .get_signing_secrets()
            .await
            .unwrap();
        let ed25519_id_2 = secrets2[0].id.clone();
        let material2 = serde_json::to_string(&secrets2[0].secret_material).unwrap();

        // The DID (and thus the key reference ID) changes on the 2nd boot migration.
        // Only the cryptographic material must be preserved.
        assert_eq!(material1, material2, "Ed25519 key material must be identical after migration");
        // Verify the ID now references the webvh DID
        assert!(
            ed25519_id_2.starts_with("did:webvh:"),
            "After migration, Ed25519 key ID must reference the webvh DID, got: {}",
            ed25519_id_2
        );
    }

    /// The DID document must contain all required sections.
    #[tokio::test]
    async fn did_document_has_required_sections() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let doc = issuer
            .get_did_document()
            .await
            .unwrap();

        assert!(
            doc.get("verificationMethod")
                .is_some(),
            "DID document missing 'verificationMethod'"
        );
        assert!(
            doc.get("authentication")
                .is_some(),
            "DID document missing 'authentication'"
        );
        assert!(
            doc.get("assertionMethod")
                .is_some(),
            "DID document missing 'assertionMethod'"
        );
        assert!(
            doc.get("keyAgreement")
                .is_some(),
            "DID document missing 'keyAgreement'"
        );
        assert!(doc.get("id").is_some(), "DID document missing 'id'");
    }

    /// Governance proofs name `#key-2`, so a new appliance's DID document lists it
    /// for assertions; authentication stays on `#key-1`.
    #[tokio::test]
    async fn new_did_document_lists_key_2_for_assertions_only() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());
        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let doc = issuer
            .get_did_document()
            .await
            .unwrap();
        let did = doc["id"].as_str().unwrap();
        assert_eq!(doc["assertionMethod"], json!([format!("{did}#key-1"), format!("{did}#key-2")]));
        assert_eq!(doc["authentication"], json!([format!("{did}#key-1")]));
    }

    /// The issued VC's issuer field must match the proxy_did.
    #[tokio::test]
    async fn issued_vc_issuer_matches_proxy_did() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let proxy_did = issuer
            .get_issuer_did()
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"llmInfo": {"model": "gpt-4", "provider": "openai"}}));

        let response = issuer
            .issue_or_get_credential(fields, None, None)
            .await
            .unwrap();

        // Decode the JWT payload (second segment between dots)
        use base64::Engine;
        let parts: Vec<&str> = response
            .credential
            .split('.')
            .collect();
        assert!(parts.len() >= 2, "JWT must have at least 2 segments");
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let vc_issuer = payload["issuer"]
            .as_str()
            .unwrap_or("");
        assert_eq!(vc_issuer, proxy_did, "VC issuer must match proxy DID");
    }

    // === Per-Agent Credential DID Tests ===
    /// Same metadata → same DID (second call retrieves from store).
    #[tokio::test]
    async fn agent_did_deterministic_from_metadata() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "gpt-4", "provider": "openai"}));

        let r1 = issuer
            .issue_or_get_credential(fields.clone(), None, None)
            .await
            .unwrap();
        let r2 = issuer
            .issue_or_get_credential(fields.clone(), None, None)
            .await
            .unwrap();

        assert_eq!(r1.did, r2.did, "Same metadata must yield same DID on repeated calls");
    }

    /// Agent DID format must be did:webvh:<SCID>:<domain>:surface:<UUID>.
    #[tokio::test]
    async fn agent_did_format_includes_surface_segment() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "claude-3"}));

        let response = issuer
            .issue_or_get_credential(fields, None, None)
            .await
            .unwrap();

        // Format: did:webvh:<SCID>:<domain>:surface:<UUID>
        let parts: Vec<&str> = response
            .did
            .split(':')
            .collect();
        assert!(parts.len() >= 6, "Agent DID must have at least 6 colon-delimited parts, got: {}", response.did);
        assert_eq!(parts[0], "did");
        assert_eq!(parts[1], "webvh");
        // The "surface" segment is second-to-last
        let surface_idx = parts.len() - 2;
        assert_eq!(parts[surface_idx], "surface", "Agent DID must contain 'surface' segment, got: {}", response.did);
    }

    /// Different metadata → different DIDs.
    #[tokio::test]
    async fn different_metadata_different_dids() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields_a = HashMap::new();
        fields_a.insert("agentIdentity".to_string(), json!({"model": "gpt-4"}));

        let mut fields_b = HashMap::new();
        fields_b.insert("agentIdentity".to_string(), json!({"model": "claude-3"}));

        let r_a = issuer
            .issue_or_get_credential(fields_a, None, None)
            .await
            .unwrap();
        let r_b = issuer
            .issue_or_get_credential(fields_b, None, None)
            .await
            .unwrap();

        assert_ne!(r_a.did, r_b.did, "Different metadata must yield different DIDs");
    }

    /// First issuance for new metadata must set is_new = true.
    #[tokio::test]
    async fn first_issuance_returns_is_new_true() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "new-agent"}));

        let response = issuer
            .issue_or_get_credential(fields, None, None)
            .await
            .unwrap();
        assert!(response.is_new, "First issuance must return is_new = true");
    }

    /// Second issuance for the same metadata must set is_new = false.
    #[tokio::test]
    async fn second_issuance_returns_is_new_false() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "reused-agent"}));

        let _first = issuer
            .issue_or_get_credential(fields.clone(), None, None)
            .await
            .unwrap();
        let second = issuer
            .issue_or_get_credential(fields, None, None)
            .await
            .unwrap();

        assert!(!second.is_new, "Second issuance for same metadata must return is_new = false");
    }

    // === Key Material Preservation Tests ===
    /// Ed25519 key must be unchanged after migration to did:webvh.
    #[tokio::test]
    async fn key_material_unchanged_after_migration_to_didwebvh() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(VpChallengeStore::default());

        // Boot 1 — new config, did:web
        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let secrets_before = issuer1
            .get_signing_secrets()
            .await
            .unwrap();
        let ed25519_before = serde_json::to_string(&secrets_before[0].secret_material).unwrap();

        // Boot 2 — migration fires, switches to did:webvh
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();
        let secrets_after = issuer2
            .get_signing_secrets()
            .await
            .unwrap();
        let ed25519_after = serde_json::to_string(&secrets_after[0].secret_material).unwrap();

        assert_eq!(ed25519_before, ed25519_after, "Ed25519 key must be unchanged after migration");

        let did = issuer2
            .get_issuer_did()
            .await
            .unwrap();
        assert!(did.starts_with("did:webvh:"), "Post-migration DID must use did:webvh method, got: {}", did);
    }

    /// X25519 key must be unchanged after migration.
    #[tokio::test]
    async fn x25519_key_unchanged_after_migration() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(VpChallengeStore::default());

        // Boot 1 — new config
        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let secrets_before = issuer1
            .get_signing_secrets()
            .await
            .unwrap();
        let x25519_before = serde_json::to_string(&secrets_before[1].secret_material).unwrap();

        // Boot 2 — migration fires
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();
        let secrets_after = issuer2
            .get_signing_secrets()
            .await
            .unwrap();
        let x25519_after = serde_json::to_string(&secrets_after[1].secret_material).unwrap();

        assert_eq!(x25519_before, x25519_after, "X25519 key must be unchanged after migration");
    }

    /// P-256 key must be unchanged after migration.
    #[tokio::test]
    async fn p256_key_unchanged_after_migration() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(VpChallengeStore::default());

        // Boot 1 — new config
        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let secrets_before = issuer1
            .get_signing_secrets()
            .await
            .unwrap();
        let p256_before = serde_json::to_string(&secrets_before[2].secret_material).unwrap();

        // Boot 2 — migration fires
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();
        let secrets_after = issuer2
            .get_signing_secrets()
            .await
            .unwrap();
        let p256_after = serde_json::to_string(&secrets_after[2].secret_material).unwrap();

        assert_eq!(p256_before, p256_after, "P-256 key must be unchanged after migration");
    }

    // === VC Issuer Migration Tests ===
    /// After migration, issued VCs must use did:webvh as issuer.
    #[tokio::test]
    async fn post_migration_vcs_use_didwebvh_issuer() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(VpChallengeStore::default());

        // Boot 1 — new config
        VCIssuer::new(
            temp_dir.path(),
            "example.com",
            Arc::clone(&identity_store),
            Arc::clone(&vp_challenge_store),
            None,
            None,
        )
        .await
        .unwrap();

        // Boot 2 — migration fires, proxy_did is now did:webvh
        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "post-migration-agent"}));
        let response = issuer
            .issue_or_get_credential(fields, None, None)
            .await
            .unwrap();

        use base64::Engine;
        let parts: Vec<&str> = response
            .credential
            .split('.')
            .collect();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let vc_issuer = payload["issuer"]
            .as_str()
            .unwrap_or("");
        assert!(vc_issuer.starts_with("did:webvh:"), "Post-migration VC issuer must use did:webvh, got: {}", vc_issuer);
    }

    /// VCIssuerConfig.proxy_did must hold the did:webvh string after migration.
    #[tokio::test]
    async fn vc_issuer_config_stores_didwebvh_string() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(VpChallengeStore::default());

        // Boot 1 — new config
        VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();

        // Boot 2 — migration fires
        let issuer = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();
        let did = issuer
            .get_issuer_did()
            .await
            .unwrap();
        assert!(
            did.starts_with("did:webvh:"),
            "VCIssuerConfig.proxy_did must be did:webvh after migration, got: {}",
            did
        );
    }

    // === Helpers shared by 8.5 / 8.6 / 11.4 ===

    /// Extract the Ed25519 `VerifyingKey` from the first `JsonWebKey2020` OKP entry in a DID document.
    fn extract_ed25519_verifying_key(did_doc: &serde_json::Value) -> ed25519_dalek::VerifyingKey {
        use base64::Engine;
        let vms = did_doc["verificationMethod"]
            .as_array()
            .expect("no verificationMethod array");
        for vm in vms {
            if let Some(jwk) = vm.get("publicKeyJwk")
                && jwk
                    .get("kty")
                    .and_then(|v| v.as_str())
                    == Some("OKP")
            {
                let x = jwk["x"]
                    .as_str()
                    .expect("OKP key missing 'x'");
                let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .expect("bad base64 in x");
                let arr: [u8; 32] = x_bytes
                    .try_into()
                    .expect("wrong key length");
                return ed25519_dalek::VerifyingKey::from_bytes(&arr).expect("invalid Ed25519 key");
            }
        }
        panic!("No Ed25519 OKP JWK found in DID document");
    }

    /// Verify the signature portion of a compact JWS (JWT) using an Ed25519 key.
    fn verify_jwt_ed25519(
        jwt: &str,
        key: &ed25519_dalek::VerifyingKey,
    ) -> bool {
        use base64::Engine;
        use ed25519_dalek::Verifier;
        let parts: Vec<&str> = jwt.splitn(3, '.').collect();
        if parts.len() != 3 {
            return false;
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2]) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        key.verify(signing_input.as_bytes(), &signature)
            .is_ok()
    }

    /// A JWT signed with the gateway's did:web key before migration still verifies
    /// after migration, because `did.json` continues to serve the identical public key.
    #[tokio::test]
    async fn old_vc_signature_still_verifies_after_migration() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(VpChallengeStore::default());

        // Boot 1 — new config, proxy_did = did:web:example.com
        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();

        // Sign a JWT payload with the gateway key (did:web era)
        let old_jwt = issuer1
            .sign_jwt_with_gateway_key(&json!({"test": "before-migration"}))
            .await
            .unwrap();

        // Boot 2 — migration fires, proxy_did becomes did:webvh
        drop(issuer1);
        let _issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();

        // did.json after migration still has the same Ed25519 public key
        let did_json_content = tokio::fs::read_to_string(
            temp_dir
                .path()
                .join("did.json"),
        )
        .await
        .unwrap();
        let did_json: serde_json::Value = serde_json::from_str(&did_json_content).unwrap();
        let verifying_key = extract_ed25519_verifying_key(&did_json);

        assert!(
            verify_jwt_ed25519(&old_jwt, &verifying_key),
            "Old JWT signed before migration must still verify with did.json public key after migration"
        );
    }

    /// A JWT signed with the gateway's did:webvh key after migration verifies
    /// using the public key from the did:webvh log (did.jsonl).
    #[tokio::test]
    async fn new_vc_verifies_via_didwebvh_resolver() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(VpChallengeStore::default());

        // Boot 1 then Boot 2 (migration fires)
        VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();

        // Issue a new JWT post-migration (issuer is now did:webvh)
        let new_jwt = issuer2
            .sign_jwt_with_gateway_key(&json!({"test": "after-migration"}))
            .await
            .unwrap();

        let did = issuer2
            .get_issuer_did()
            .await
            .unwrap();
        assert!(did.starts_with("did:webvh:"), "issuer must be did:webvh after migration, got: {}", did);

        // Get the public key from the latest did:webvh log entry state (simulates did:webvh resolver)
        let jsonl_content = tokio::fs::read_to_string(
            temp_dir
                .path()
                .join("did.jsonl"),
        )
        .await
        .unwrap();
        let latest_line = jsonl_content
            .lines()
            .last()
            .expect("did.jsonl must have at least one entry");
        let entry_json: serde_json::Value = serde_json::from_str(latest_line).unwrap();
        let state_doc = &entry_json["state"];
        let verifying_key = extract_ed25519_verifying_key(state_doc);

        assert!(
            verify_jwt_ed25519(&new_jwt, &verifying_key),
            "New JWT with did:webvh issuer must verify with public key from did.jsonl log state"
        );
    }

    /// A JWT with a did:webvh issuer can be verified by an external verifier that only
    /// knows about did:web — it reads the parallel `did.json` to obtain the public key.
    #[tokio::test]
    async fn vc_with_didwebvh_issuer_resolves_via_did_json_fallback() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(VpChallengeStore::default());

        // Boot 1 then Boot 2 (migration fires)
        VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();

        // Issue a JWT post-migration (issuer is did:webvh)
        let jwt = issuer2
            .sign_jwt_with_gateway_key(&json!({"test": "didweb-fallback"}))
            .await
            .unwrap();

        // Simulate external verifier: resolve did.json at the equivalent did:web URL (no did:webvh support)
        let did_json_content = tokio::fs::read_to_string(
            temp_dir
                .path()
                .join("did.json"),
        )
        .await
        .unwrap();
        let did_json: serde_json::Value = serde_json::from_str(&did_json_content).unwrap();

        // did.json must have alsoKnownAs pointing to the did:webvh DID
        let did = issuer2
            .get_issuer_did()
            .await
            .unwrap();
        let also_known_as = did_json["alsoKnownAs"]
            .as_array()
            .expect("did.json must have alsoKnownAs");
        assert!(
            also_known_as
                .iter()
                .any(|v| v.as_str() == Some(&did)),
            "did.json alsoKnownAs must reference the did:webvh DID for cross-resolution"
        );

        // The public key from did.json must verify the JWT signed by the post-migration gateway
        let verifying_key = extract_ed25519_verifying_key(&did_json);
        assert!(
            verify_jwt_ed25519(&jwt, &verifying_key),
            "JWT with did:webvh issuer must verify with public key from the parallel did.json fallback"
        );
    }

    const SURFACE: &str = "surface-a";

    fn caller() -> crate::identity::ChallengeCaller {
        crate::identity::ChallengeCaller::Address(std::net::IpAddr::from([192, 0, 2, 1]))
    }
    const PEER: &str = "did:peer:2.peer-connection-point";
    const OUR_CONNECTION_POINT: &str = "did:peer:2.our-connection-point";

    fn bound(
        challenge: Option<&str>,
        domain: &str,
        proof_value: &str,
    ) -> PresentationBinding {
        PresentationBinding {
            challenge: challenge.map(String::from),
            domains: vec![domain.to_string()],
            expires: chrono::Utc::now() + chrono::TimeDelta::minutes(5),
            proof_value: proof_value.to_string(),
        }
    }

    fn issued_on(surface_id: &str) -> ExpectedChallenge<'_> {
        ExpectedChallenge::Issued {
            surface_id,
            front_door_id: None,
            principal: None,
        }
    }

    fn envelope(id: &str) -> ExpectedChallenge<'_> {
        ExpectedChallenge::Envelope {
            id,
            sender: PEER,
            recipient: OUR_CONNECTION_POINT,
        }
    }

    async fn accept(
        issuer: &VCIssuer,
        binding: &PresentationBinding,
        expected: ExpectedChallenge<'_>,
    ) -> Result<()> {
        issuer
            .accept_vp_challenge(binding, expected, chrono::Utc::now())
            .await
    }

    fn rejection(result: Result<()>) -> String {
        match result {
            Ok(()) => panic!("the presentation must be rejected"),
            Err(e) => e.to_string(),
        }
    }

    async fn appliance_did(issuer: &VCIssuer) -> String {
        issuer
            .get_issuer_did()
            .await
            .expect("did")
    }

    #[tokio::test]
    async fn test_create_vp_challenge_names_this_appliance_and_expires_after_the_ttl() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let before = chrono::Utc::now();

        let issued = issuer
            .create_vp_challenge(SURFACE, &caller())
            .await
            .expect("challenge");

        assert_eq!(issued.domain, appliance_did(&issuer).await);
        assert!(issued.expires_at >= before + crate::identity::VP_CHALLENGE_TTL);
        assert!(issued.expires_at <= chrono::Utc::now() + crate::identity::VP_CHALLENGE_TTL);
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_rejects_a_presentation_without_one() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let domain = appliance_did(&issuer).await;

        for expected in [issued_on(SURFACE), envelope("msg-1")] {
            let error = rejection(accept(&issuer, &bound(None, &domain, "vp-1"), expected).await);
            assert_eq!(error, "VP challenge is required but not presented", "{expected:?}");
        }
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_redeems_an_issued_challenge_once() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issued = issuer
            .create_vp_challenge(SURFACE, &caller())
            .await
            .expect("challenge");
        let presentation = bound(Some(&issued.challenge), &issued.domain, "vp-1");

        accept(&issuer, &presentation, issued_on(SURFACE))
            .await
            .expect("a fresh issued challenge is accepted");
        let replay = rejection(accept(&issuer, &presentation, issued_on(SURFACE)).await);

        assert_eq!(replay, ISSUED_CHALLENGE_REFUSED);
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_rejects_a_challenge_issued_by_another_surface() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issued = issuer
            .create_vp_challenge(SURFACE, &caller())
            .await
            .expect("challenge");
        let presentation = bound(Some(&issued.challenge), &issued.domain, "vp-1");

        let error = rejection(accept(&issuer, &presentation, issued_on("surface-b")).await);

        assert_eq!(error, ISSUED_CHALLENGE_REFUSED);
        accept(&issuer, &presentation, issued_on(SURFACE))
            .await
            .expect("the issuing surface can still redeem it");
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_redeems_a_front_door_challenge_on_a_dispatched_member() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issued = issuer
            .create_vp_challenge("ide-surface", &caller())
            .await
            .expect("challenge");
        let presentation = bound(Some(&issued.challenge), &issued.domain, "vp-1");
        let dispatched = ExpectedChallenge::Issued {
            surface_id: "member-surface",
            front_door_id: Some("ide-surface"),
            principal: None,
        };

        accept(&issuer, &presentation, dispatched)
            .await
            .expect("a challenge from the IDE front door is redeemed by the member it dispatches to");
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_rejects_a_challenge_not_issued_here() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let domain = appliance_did(&issuer).await;

        let error = rejection(accept(&issuer, &bound(Some("made-up"), &domain, "vp-1"), issued_on(SURFACE)).await);

        assert_eq!(error, ISSUED_CHALLENGE_REFUSED);
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_rejects_an_expired_challenge() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let domain = appliance_did(&issuer).await;
        let (challenge, _) = issuer
            .vp_challenge_store
            .issue(SURFACE, &caller(), chrono::Utc::now() - crate::identity::VP_CHALLENGE_TTL)
            .expect("issue");

        let error = rejection(accept(&issuer, &bound(Some(&challenge), &domain, "vp-1"), issued_on(SURFACE)).await);

        assert_eq!(error, ISSUED_CHALLENGE_REFUSED);
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_rejects_another_domain_without_using_the_challenge() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issued = issuer
            .create_vp_challenge(SURFACE, &caller())
            .await
            .expect("challenge");

        let error = rejection(
            accept(&issuer, &bound(Some(&issued.challenge), "did:web:other.example", "vp-1"), issued_on(SURFACE)).await,
        );

        assert_eq!(error, "VP domain does not name this appliance");
        accept(&issuer, &bound(Some(&issued.challenge), &issued.domain, "vp-1"), issued_on(SURFACE))
            .await
            .expect("the challenge is still redeemable by a presentation for this appliance");
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_binds_a_fabric_presentation_to_its_envelope_and_recipient() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;

        let other_envelope =
            rejection(accept(&issuer, &bound(Some("msg-1"), OUR_CONNECTION_POINT, "vp-1"), envelope("msg-2")).await);
        assert_eq!(other_envelope, "VP challenge does not match the envelope that carried it");

        let appliance_domain = rejection(
            accept(&issuer, &bound(Some("msg-1"), &appliance_did(&issuer).await, "vp-1"), envelope("msg-1")).await,
        );
        assert_eq!(appliance_domain, "VP domain does not name the Connection Point the envelope was sent to");

        accept(&issuer, &bound(Some("msg-1"), OUR_CONNECTION_POINT, "vp-1"), envelope("msg-1"))
            .await
            .expect("a presentation bound to its envelope and recipient is accepted");
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_keeps_identity_on_redelivery_but_refuses_reuse() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let presentation = bound(Some("msg-1"), OUR_CONNECTION_POINT, "vp-1");
        accept(&issuer, &presentation, envelope("msg-1"))
            .await
            .expect("first delivery");

        accept(&issuer, &presentation, envelope("msg-1"))
            .await
            .expect("the same presentation, redelivered in the same envelope, is accepted again");
        let reuse =
            rejection(accept(&issuer, &bound(Some("msg-1"), OUR_CONNECTION_POINT, "vp-2"), envelope("msg-1")).await);

        assert_eq!(reuse, "VP challenge was already used");
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_keys_envelope_ids_by_sender() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        accept(&issuer, &bound(Some("msg-1"), OUR_CONNECTION_POINT, "vp-1"), envelope("msg-1"))
            .await
            .expect("first sender");
        let other_sender = ExpectedChallenge::Envelope {
            id: "msg-1",
            sender: "did:peer:2.other-peer",
            recipient: OUR_CONNECTION_POINT,
        };

        accept(&issuer, &bound(Some("msg-1"), OUR_CONNECTION_POINT, "vp-2"), other_sender)
            .await
            .expect("another sender's envelope id does not collide");
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_does_not_redeem_an_envelope_id_as_an_issued_challenge() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        accept(&issuer, &bound(Some("msg-1"), OUR_CONNECTION_POINT, "vp-1"), envelope("msg-1"))
            .await
            .expect("fabric presentation");

        let error = rejection(
            accept(&issuer, &bound(Some("msg-1"), &appliance_did(&issuer).await, "vp-1"), issued_on(PEER)).await,
        );

        assert_eq!(error, ISSUED_CHALLENGE_REFUSED);
    }

    #[tokio::test]
    async fn test_verify_presentation_refuses_an_unusable_challenge_before_verifying() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let unsigned = json!({
            "holder": "did:example:holder",
            "verifiableCredential": [],
            "proof": {
                "expires": (chrono::Utc::now() + chrono::TimeDelta::minutes(5)).to_rfc3339(),
                "challenge": "made-up",
                "domain": appliance_did(&issuer).await,
                "proofValue": "z-not-a-signature",
            }
        });

        let error = issuer
            .verify_presentation_with_issuer(&unsigned.to_string(), issued_on(SURFACE))
            .await
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();

        assert_eq!(error, ISSUED_CHALLENGE_REFUSED, "refused on its challenge, before any signature check");
    }

    #[tokio::test]
    async fn test_verify_presentation_uses_the_challenge_even_when_verification_fails() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issued = issuer
            .create_vp_challenge(SURFACE, &caller())
            .await
            .expect("challenge");
        let unsigned = json!({
            "holder": "did:example:holder",
            "verifiableCredential": [],
            "proof": {
                "expires": (chrono::Utc::now() + chrono::TimeDelta::minutes(5)).to_rfc3339(),
                "challenge": issued.challenge,
                "domain": issued.domain,
                "proofValue": "z-not-a-signature",
            }
        });

        let first = issuer
            .verify_presentation_with_issuer(&unsigned.to_string(), issued_on(SURFACE))
            .await
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        let again = issuer
            .verify_presentation_with_issuer(&unsigned.to_string(), issued_on(SURFACE))
            .await
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();

        assert!(first.starts_with("VP verification failed"), "got: {first}");
        assert_eq!(again, ISSUED_CHALLENGE_REFUSED, "a second copy is refused without verifying it");
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_binds_a_principal_challenge_to_that_principal() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issued = issuer
            .create_vp_challenge(SURFACE, &crate::identity::ChallengeCaller::Principal("agent-a".to_string()))
            .await
            .expect("challenge");
        let presentation = bound(Some(&issued.challenge), &issued.domain, "vp-1");
        let presented_by = |principal| ExpectedChallenge::Issued {
            surface_id: SURFACE,
            front_door_id: None,
            principal,
        };

        assert_eq!(rejection(accept(&issuer, &presentation, presented_by(None)).await), ISSUED_CHALLENGE_REFUSED);
        assert_eq!(
            rejection(accept(&issuer, &presentation, presented_by(Some("agent-b"))).await),
            ISSUED_CHALLENGE_REFUSED
        );
        accept(&issuer, &presentation, presented_by(Some("agent-a")))
            .await
            .expect("the principal it was issued to redeems it");
    }

    #[tokio::test]
    async fn test_consent_audit_presentation_is_long_lived_and_bound_to_its_token() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let mut identity_fields = HashMap::new();
        identity_fields.insert("agentIdentity".to_string(), json!({ "softwareInfo": { "name": "test-agent" } }));
        let agent_did = issuer
            .issue_or_get_credential(identity_fields, None, None)
            .await
            .expect("agent identity")
            .did;

        let minted = issuer
            .create_consent_audit_presentation(&agent_did, json!({ "agentIdentity": { "id": agent_did } }), "token-1")
            .await
            .expect("audit presentation");

        let vp: serde_json::Value = serde_json::from_str(&minted).expect("JSON presentation");
        assert_eq!(vp["proof"]["challenge"], json!("token-1"));
        assert_eq!(vp["proof"]["domain"], json!(appliance_did(&issuer).await));
        let expires: chrono::DateTime<chrono::Utc> = vp["proof"]["expires"]
            .as_str()
            .expect("proof expires")
            .parse()
            .expect("RFC 3339 expires");
        let lifetime = chrono::TimeDelta::days(VC_LIFETIME_DAYS);
        assert!(
            expires > chrono::Utc::now() + lifetime - chrono::TimeDelta::minutes(1)
                && expires <= chrono::Utc::now() + lifetime,
            "an audit presentation lasts as long as its credential, got {expires}"
        );

        let live = issuer
            .verify_presentation_with_issuer(&minted, issued_on(SURFACE))
            .await
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(live.contains("more than the 360s allowed"), "not accepted as a live presentation, got: {live}");
    }

    #[tokio::test]
    async fn test_accept_vp_challenge_refuses_a_presentation_valid_for_longer_than_a_live_one() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issued = issuer
            .create_vp_challenge(SURFACE, &caller())
            .await
            .expect("challenge");
        let mut presentation = bound(Some(&issued.challenge), &issued.domain, "vp-1");
        presentation.expires = chrono::Utc::now() + chrono::TimeDelta::minutes(10);

        let error = rejection(accept(&issuer, &presentation, issued_on(SURFACE)).await);

        assert!(error.contains("more than the 360s allowed"), "got: {error}");
        assert!(error.contains("clock may be ahead"), "got: {error}");
        presentation.expires = chrono::Utc::now() + chrono::TimeDelta::minutes(5);
        accept(&issuer, &presentation, issued_on(SURFACE))
            .await
            .expect("the refusal did not use the challenge up");
    }
}
