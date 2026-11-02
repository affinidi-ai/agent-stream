#![allow(dead_code)]
//! Encryption at rest module for securing sensitive data
//!
//! This module provides AES-256-GCM encryption for data stored on disk.
//! It implements envelope encryption where:
//! - A Master Encryption Key (MEK) is loaded from environment/config
//! - Data Encryption Keys (DEKs) are generated per tenant/store
//! - DEKs are encrypted with the MEK and cached in memory
//! - Actual data is encrypted with DEKs
//!
//! Key features:
//! - AES-256-GCM authenticated encryption
//! - Envelope encryption with cached DEKs
//! - Field-level and file-level encryption support
//! - Backward compatibility with unencrypted data
//! - Key rotation support

pub(crate) mod aes_gcm;
mod data_key;
mod envelope;
pub mod init;
mod key_management;
mod kms_envelope;
pub mod preflight;
pub mod secret_file;
pub mod serde_encrypted;

#[allow(unused_imports)]
pub use data_key::DataKey;
pub use envelope::{EncryptedData, EnvelopeEncryption};
pub use key_management::{KeyManager, KeySource};

use self::key_management::KmsDataKeys;
use self::kms_envelope::{KMS_ENVELOPE_VERSION, KmsEnvelope};
use anyhow::{Result, anyhow};
use std::sync::Arc;

/// Field-encryption backend selected by `key_source`.
///
/// `LocalMek` writes/reads `version = 1` envelopes with a process-held MEK
/// (environment / file sources). `Kms` writes/reads `version = 2` per-value KMS
/// envelopes (`aws_kms`). Decrypt dispatches on the stored version byte and fails
/// closed on a cross-backend mismatch.
#[derive(Clone)]
enum FieldCipher {
    LocalMek(Arc<EnvelopeEncryption>),
    Kms(Arc<KmsEnvelope>),
}

impl std::fmt::Debug for FieldCipher {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            FieldCipher::LocalMek(_) => f.write_str("FieldCipher::LocalMek"),
            FieldCipher::Kms(_) => f.write_str("FieldCipher::Kms"),
        }
    }
}

impl FieldCipher {
    fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<EncryptedData> {
        match self {
            FieldCipher::LocalMek(envelope) => envelope.encrypt(plaintext),
            FieldCipher::Kms(kms) => kms.encrypt(plaintext),
        }
    }

    fn decrypt(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<Vec<u8>> {
        match self {
            FieldCipher::LocalMek(envelope) => {
                if encrypted.version == KMS_ENVELOPE_VERSION {
                    return Err(anyhow!(
                        "cannot decrypt a version-{KMS_ENVELOPE_VERSION} (AWS KMS) value: key_source is a \
                         local MEK (environment/file). Set key_source = \"aws_kms\" to read it."
                    ));
                }
                envelope.decrypt(encrypted)
            }
            FieldCipher::Kms(kms) => {
                if encrypted.version != KMS_ENVELOPE_VERSION {
                    return Err(anyhow!(
                        "cannot decrypt a version-{} (local MEK) value: key_source is aws_kms. Restore the \
                         original environment/file key_source to read it.",
                        encrypted.version
                    ));
                }
                kms.decrypt(encrypted)
            }
        }
    }
}

/// Main encryption service that combines all encryption functionality
#[derive(Clone, Debug)]
pub struct EncryptionService {
    cipher: FieldCipher,
    enabled: bool,
}

impl EncryptionService {
    /// Create a new encryption service
    pub fn new(key_source: KeySource) -> Result<Self> {
        let key_manager = KeyManager::new(key_source)?;
        let envelope = EnvelopeEncryption::new(key_manager);

        Ok(Self {
            cipher: FieldCipher::LocalMek(Arc::new(envelope)),
            enabled: true,
        })
    }

    /// Create a disabled encryption service (pass-through mode)
    pub fn disabled() -> Self {
        // For disabled mode, we still need a minimal key manager
        // Use a dummy key that won't actually be used
        let key_manager =
            KeyManager::new(KeySource::Environment { var_name: "DUMMY".to_string() }).unwrap_or_else(|_| {
                // Fallback to a fixed key for disabled mode
                KeyManager::from_raw_key(&[0u8; 32]).unwrap()
            });
        let envelope = EnvelopeEncryption::new(key_manager);

        Self {
            cipher: FieldCipher::LocalMek(Arc::new(envelope)),
            enabled: false,
        }
    }

    /// Build a KMS-backed field-encryption service (`key_source = aws_kms`).
    ///
    /// Every value is protected with a per-value KMS envelope. Used by
    /// `init_encryption_service` for the real AWS client and by tests with a mock
    /// `KmsDataKeys`.
    pub(crate) fn with_kms(
        client: Arc<dyn KmsDataKeys>,
        key_id: String,
        max_concurrent_ops: usize,
    ) -> Self {
        let kms = KmsEnvelope::new(client, key_id, max_concurrent_ops);
        Self {
            cipher: FieldCipher::Kms(Arc::new(kms)),
            enabled: true,
        }
    }

    /// Check if encryption is enabled
    #[allow(unused)]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Encrypt a string value (for field-level encryption)
    pub fn encrypt_field(
        &self,
        value: &str,
    ) -> Result<String> {
        if !self.enabled {
            return Ok(value.to_string());
        }

        let encrypted = self
            .cipher
            .encrypt(value.as_bytes())?;
        Ok(encrypted.to_string())
    }

    /// Decrypt a string value (for field-level encryption)
    pub fn decrypt_field(
        &self,
        encrypted: &str,
    ) -> Result<String> {
        if !self.enabled {
            return Ok(encrypted.to_string());
        }

        // Check if actually encrypted
        if !encrypted.starts_with("ENC[") {
            // Backward compatibility: return as-is if not encrypted
            return Ok(encrypted.to_string());
        }

        let encrypted_data: EncryptedData = encrypted.parse()?;
        let decrypted = self
            .cipher
            .decrypt(&encrypted_data)?;
        Ok(String::from_utf8(decrypted)?)
    }

    /// Encrypt bytes (for file-level encryption)
    #[allow(unused)]
    pub fn encrypt_bytes(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.enabled {
            return Ok(data.to_vec());
        }

        let encrypted = self.cipher.encrypt(data)?;
        Ok(encrypted.to_bytes())
    }

    /// Decrypt bytes (for file-level encryption)
    #[allow(unused)]
    pub fn decrypt_bytes(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.enabled {
            return Ok(data.to_vec());
        }

        let encrypted_data = EncryptedData::from_bytes(data)?;
        self.cipher
            .decrypt(&encrypted_data)
    }

    /// Encrypt a string (convenience method)
    pub fn encrypt_string(
        &self,
        plaintext: String,
    ) -> Result<String> {
        self.encrypt_field(&plaintext)
    }

    /// Decrypt a string (convenience method)
    pub fn decrypt_string(
        &self,
        ciphertext: String,
    ) -> Result<String> {
        self.decrypt_field(&ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_service_disabled() {
        let service = EncryptionService::disabled();
        assert!(!service.is_enabled());

        let plaintext = "hello world";
        let encrypted = service
            .encrypt_field(plaintext)
            .unwrap();
        assert_eq!(encrypted, plaintext);

        let decrypted = service
            .decrypt_field(&encrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_service_enabled() {
        // Use a fixed key for testing
        let key_manager = KeyManager::from_raw_key(&[42u8; 32]).unwrap();
        let envelope = EnvelopeEncryption::new(key_manager);
        let service = EncryptionService {
            cipher: FieldCipher::LocalMek(Arc::new(envelope)),
            enabled: true,
        };

        assert!(service.is_enabled());

        let plaintext = "secret data";
        let encrypted = service
            .encrypt_field(plaintext)
            .unwrap();
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.starts_with("ENC["));

        let decrypted = service
            .decrypt_field(&encrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_backward_compatibility() {
        let key_manager = KeyManager::from_raw_key(&[42u8; 32]).unwrap();
        let envelope = EnvelopeEncryption::new(key_manager);
        let service = EncryptionService {
            cipher: FieldCipher::LocalMek(Arc::new(envelope)),
            enabled: true,
        };

        // Should handle unencrypted data gracefully
        let plaintext = "not encrypted yet";
        let decrypted = service
            .decrypt_field(plaintext)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    use super::key_management::{GeneratedDataKey, KmsDataKeys as TestKmsDataKeys};

    struct IdentityKms;

    #[async_trait::async_trait]
    impl TestKmsDataKeys for IdentityKms {
        async fn generate_data_key(
            &self,
            _key_id: &str,
        ) -> Result<GeneratedDataKey> {
            // Distinct-enough key material for the test; identity-wrapped.
            let plaintext = vec![0x5Au8; 32];
            Ok(GeneratedDataKey {
                ciphertext_blob: plaintext.clone(),
                plaintext: zeroize::Zeroizing::new(plaintext),
            })
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            ciphertext_blob: Vec<u8>,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            Ok(zeroize::Zeroizing::new(ciphertext_blob))
        }
    }

    fn local_mek_service() -> EncryptionService {
        EncryptionService::new(KeySource::Raw { key: [7u8; 32] }).unwrap()
    }

    fn kms_service() -> EncryptionService {
        EncryptionService::with_kms(Arc::new(IdentityKms), "test-cmk".to_string(), 4)
    }

    #[test]
    fn kms_backend_round_trips_field() {
        let service = kms_service();
        let plaintext = "kms-protected-secret";
        let encrypted = service
            .encrypt_field(plaintext)
            .unwrap();
        assert!(encrypted.starts_with(&format!("ENC[{KMS_ENVELOPE_VERSION}:")));
        let decrypted = service
            .decrypt_field(&encrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn local_mek_backend_rejects_kms_value() {
        // A value written under aws_kms (version 2) must fail closed under local MEK.
        let kms_value = kms_service()
            .encrypt_field("written-under-kms")
            .unwrap();
        let err = local_mek_service()
            .decrypt_field(&kms_value)
            .expect_err("local MEK must fail closed on a KMS envelope");
        assert!(
            err.to_string()
                .contains("aws_kms"),
            "error must name the required aws_kms backend, got: {err}"
        );
    }

    #[test]
    fn kms_backend_rejects_local_mek_value() {
        // A value written under local MEK (version 1) must fail closed under aws_kms.
        let local_value = local_mek_service()
            .encrypt_field("written-under-local")
            .unwrap();
        let err = kms_service()
            .decrypt_field(&local_value)
            .expect_err("aws_kms must fail closed on a local-MEK envelope");
        assert!(
            err.to_string()
                .contains("local MEK"),
            "error must name the local-MEK origin, got: {err}"
        );
    }
}
