//! Encryption-aware whole-file read/write for standalone secret files.
//!
//! DID private-key material (connection points, did:webvh identities) and VC
//! issuer keys are persisted as individual JSON files *outside* the generic
//! `StorageBackend` layer. These helpers give those files the same whole-file
//! encryption-at-rest the generic layer provides:
//!
//! - When encryption at rest is active, the `{path}.enc` ciphertext blob is
//!   authoritative and any plaintext sibling is removed, so key material never
//!   lingers in plaintext.
//! - When it is disabled, the plaintext file is authoritative and any stale
//!   `.enc` sibling is removed.
//! - Reads transparently decrypt the `.enc` sibling, and — when encryption is
//!   active — converge on-disk state by migrating a plaintext-only file to
//!   `.enc` and dropping the plaintext, mirroring the generic storage layer.
//!
//! Only private-key files should be routed through these helpers. Public
//! artefacts that must stay resolvable as plaintext (e.g. a `did.json` served
//! over HTTP) must continue to use plain filesystem writes.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::{error, warn};

use crate::encryption::EncryptionService;
use crate::storage::filesystem::global_encryption_service;

/// Path of the whole-file-encrypted sibling for a plaintext secret file.
pub fn secret_enc_path(path: &Path) -> PathBuf {
    let mut os = path
        .as_os_str()
        .to_os_string();
    os.push(".enc");
    PathBuf::from(os)
}

/// Best-effort removal of a plaintext secret file once its `.enc` sibling is
/// authoritative. A failure is logged at `error`, not propagated: the record is
/// already durably encrypted, but a lingering plaintext file is a key-material
/// exposure operators must be able to alert on.
///
/// The deletion is guarded by the encrypt-then-delete invariant: the plaintext
/// is removed only when its ciphertext sibling actually exists on disk. If the
/// `.enc` is missing the plaintext is the only readable copy of the key
/// material, so the removal is refused rather than destroying it.
async fn remove_plaintext_sibling(path: &Path) {
    if !path.exists() {
        return;
    }
    let enc_path = secret_enc_path(path);
    if !enc_path.exists() {
        error!(
            "Refusing to delete plaintext secret file {}: its encrypted sibling {} is missing, so this \
             is the only readable copy of the key material",
            path.display(),
            enc_path.display()
        );
        return;
    }
    if let Err(e) = tokio::fs::remove_file(path).await {
        error!(
            "Failed to delete plaintext secret file {} after encryption; key material may remain on disk: {}",
            path.display(),
            e
        );
    }
}

/// Write a secret file, encrypting the whole file when encryption at rest is
/// enabled. See [`write_secret_file_with`] for the core logic.
pub async fn write_secret_file(
    path: &Path,
    contents: &str,
) -> Result<()> {
    write_secret_file_with(global_encryption_service().as_ref(), path, contents).await
}

/// Read a secret file, transparently decrypting the whole-file `.enc` sibling
/// when encryption at rest is enabled. See [`read_secret_file_with`].
pub async fn read_secret_file(path: &Path) -> Result<Option<String>> {
    read_secret_file_with(global_encryption_service().as_ref(), path).await
}

/// Write a secret file. When `encryption` is `Some`, the content is written as a
/// whole-file `.enc` blob and any plaintext sibling is removed, so key material
/// never lingers in plaintext. Otherwise it is written as plaintext and any
/// stale `.enc` sibling is removed.
async fn write_secret_file_with(
    encryption: Option<&EncryptionService>,
    path: &Path,
    contents: &str,
) -> Result<()> {
    let enc_path = secret_enc_path(path);
    match encryption {
        Some(service) => {
            let ciphertext = service
                .encrypt_string(contents.to_string())
                .context("Failed to encrypt secret file")?;
            tokio::fs::write(&enc_path, ciphertext)
                .await
                .with_context(|| format!("Failed to write encrypted secret file {}", enc_path.display()))?;
            remove_plaintext_sibling(path).await;
        }
        None => {
            tokio::fs::write(path, contents)
                .await
                .with_context(|| format!("Failed to write secret file {}", path.display()))?;
            if enc_path.exists()
                && let Err(e) = tokio::fs::remove_file(&enc_path).await
            {
                warn!("Failed to remove stale encrypted secret file {}: {}", enc_path.display(), e);
            }
        }
    }
    Ok(())
}

/// Read a secret file, transparently decrypting the whole-file `.enc` sibling
/// when `encryption` is `Some`. Returns `None` when neither the encrypted nor
/// the plaintext form exists.
///
/// When encryption is active this also converges the on-disk state: a plaintext
/// file sitting beside an authoritative `.enc` is removed (ciphertext wins), and
/// a plaintext-only file is migrated to `.enc` and its plaintext deleted — so
/// enabling encryption removes lingering plaintext on the next read.
///
/// When encryption is disabled but an encrypted-only `.enc` sibling exists (no
/// readable plaintext), this fails loudly instead of reporting the secret as
/// missing. Reporting `None` would let callers (VC issuer / DID stores) treat
/// the key as absent and regenerate it, persisting fresh plaintext key material
/// beside the unreadable ciphertext.
async fn read_secret_file_with(
    encryption: Option<&EncryptionService>,
    path: &Path,
) -> Result<Option<String>> {
    let enc_path = secret_enc_path(path);
    match encryption {
        Some(service) => {
            if enc_path.exists() {
                let ciphertext = tokio::fs::read_to_string(&enc_path)
                    .await
                    .with_context(|| format!("Failed to read encrypted secret file {}", enc_path.display()))?;
                let plaintext = service
                    .decrypt_string(ciphertext)
                    .with_context(|| format!("Failed to decrypt secret file {}", enc_path.display()))?;
                remove_plaintext_sibling(path).await;
                Ok(Some(plaintext))
            } else if path.exists() {
                let content = tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format!("Failed to read secret file {}", path.display()))?;
                write_secret_file_with(encryption, path, &content).await?;
                Ok(Some(content))
            } else {
                Ok(None)
            }
        }
        None => {
            if path.exists() {
                let content = tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format!("Failed to read secret file {}", path.display()))?;
                Ok(Some(content))
            } else if enc_path.exists() {
                anyhow::bail!(
                    "Secret file {} exists only as an encrypted sibling ({}) but encryption at rest \
                     is disabled; refusing to treat it as missing. Re-enable encryption or migrate \
                     this file to plaintext.",
                    path.display(),
                    enc_path.display()
                );
            } else {
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{EncryptionService, KeySource};

    fn enabled_local_service() -> EncryptionService {
        EncryptionService::new(KeySource::Raw { key: [7u8; 32] }).unwrap()
    }

    #[tokio::test]
    async fn round_trips_plaintext_when_encryption_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");

        write_secret_file_with(None, &path, "{\"secret\":\"material\"}")
            .await
            .unwrap();

        assert!(path.exists());
        assert!(!secret_enc_path(&path).exists());
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, "{\"secret\":\"material\"}");

        let read = read_secret_file_with(None, &path)
            .await
            .unwrap();
        assert_eq!(read.as_deref(), Some("{\"secret\":\"material\"}"));
    }

    #[tokio::test]
    async fn write_encrypts_and_removes_plaintext_when_enabled() {
        let service = enabled_local_service();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");

        write_secret_file_with(Some(&service), &path, "{\"secret\":\"material\"}")
            .await
            .unwrap();

        let enc_path = secret_enc_path(&path);
        assert!(enc_path.exists(), "encrypted sibling must exist");
        assert!(!path.exists(), "plaintext must be removed");

        let on_disk = std::fs::read_to_string(&enc_path).unwrap();
        assert!(on_disk.starts_with("ENC["), "on-disk value must be an envelope, got: {on_disk}");
        assert!(!on_disk.contains("material"), "plaintext secret must not appear on disk");

        let read = read_secret_file_with(Some(&service), &path)
            .await
            .unwrap();
        assert_eq!(read.as_deref(), Some("{\"secret\":\"material\"}"));
    }

    #[tokio::test]
    async fn read_migrates_plaintext_only_to_encrypted_when_enabled() {
        let service = enabled_local_service();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");

        std::fs::write(&path, "{\"secret\":\"legacy\"}").unwrap();

        let read = read_secret_file_with(Some(&service), &path)
            .await
            .unwrap();
        assert_eq!(read.as_deref(), Some("{\"secret\":\"legacy\"}"));

        assert!(secret_enc_path(&path).exists(), "should have migrated to .enc");
        assert!(!path.exists(), "plaintext should be gone after migration");
    }

    #[tokio::test]
    async fn read_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("missing.json");
        let read = read_secret_file_with(None, &path)
            .await
            .unwrap();
        assert!(read.is_none());
    }

    #[tokio::test]
    async fn read_errors_on_encrypted_only_when_encryption_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");
        std::fs::write(secret_enc_path(&path), "ENC[whatever]").unwrap();

        let err = read_secret_file_with(None, &path)
            .await
            .expect_err("must fail when only an encrypted sibling exists and encryption is disabled");
        let msg = err.to_string();
        assert!(msg.contains("encryption at rest"), "error must explain the encryption-disabled cause, got: {msg}");
        assert!(secret_enc_path(&path).exists(), "encrypted sibling must not be deleted");
    }

    #[tokio::test]
    async fn remove_plaintext_sibling_keeps_plaintext_when_enc_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key_0.json");
        std::fs::write(&path, "{\"secret\":\"only-copy\"}").unwrap();

        remove_plaintext_sibling(&path).await;
        assert!(path.exists(), "plaintext must be kept when its .enc sibling is missing");

        std::fs::write(secret_enc_path(&path), b"ENC[whatever]").unwrap();
        remove_plaintext_sibling(&path).await;
        assert!(!path.exists(), "plaintext must be removed once its .enc sibling exists");
    }
}
