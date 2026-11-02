//! Content-addressed store for binary attachments referenced by governance records.
//!
//! A caller can attach binary media to a chat request — audio (`input_audio`
//! parts), documents (`file` parts: PDF, DOCX, …), and inline images
//! (`image_url` data URLs). Governance records must stay small and must never
//! embed the raw bytes, so each attachment is persisted **once**, keyed by the
//! SHA-256 of its plaintext, and the record carries only a [`MediaRef`] (kind,
//! media type, filename, hash, size). The bytes can be retrieved later by hash
//! and re-verified against the record — the record holds the hash, the store
//! holds the file.
//!
//! Blobs are sharded by the first two hex chars of the hash and (when an
//! encryption service is configured) encrypted at rest with the same key as the
//! governance log. The on-disk name stays the plaintext hash, so
//! content-addressing and later hash comparison are unaffected by encryption. A
//! sidecar `{hash}.json` records the attachment metadata so the store is
//! self-describing.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use crate::encryption::EncryptionService;

use super::record::digest_bytes;

/// Coarse classification of a binary attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentKind {
    Audio,
    Document,
    Image,
}

impl AttachmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AttachmentKind::Audio => "audio",
            AttachmentKind::Document => "document",
            AttachmentKind::Image => "image",
        }
    }
}

/// A reference to a stored binary attachment, embedded in a governance record in
/// place of the raw bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaRef {
    /// Coarse kind: `audio`, `document`, or `image`.
    pub kind: String,
    /// Declared media (MIME) type, e.g. `audio/wav`, `application/pdf`.
    pub media_type: String,
    /// Original filename when the caller supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// `sha256:{hex}` of the plaintext bytes — links the record to the blob.
    pub sha256: String,
    /// Decoded byte length.
    pub bytes: u64,
    /// Whether the bytes were persisted to the multimedia store (`false` when the
    /// store is unavailable or a write failed — the hash is still recorded).
    pub stored: bool,
}

/// A decoded binary attachment lifted from a request body, before storage.
pub struct RawAttachment {
    pub kind: AttachmentKind,
    pub media_type: String,
    pub filename: Option<String>,
    pub data: Vec<u8>,
}

impl RawAttachment {
    /// The `sha256:{hex}` content hash of the plaintext bytes.
    fn hash(&self) -> String {
        digest_bytes(&self.data)
    }

    /// A hash-only reference (no persistence), for when the store is unavailable.
    fn unstored_ref(&self) -> MediaRef {
        MediaRef {
            kind: self.kind.as_str().to_string(),
            media_type: self.media_type.clone(),
            filename: self.filename.clone(),
            sha256: self.hash(),
            bytes: self.data.len() as u64,
            stored: false,
        }
    }
}

// ── Extraction ──────────────────────────────────────────────────────────────

/// Decode a `data:` URL or bare base64 payload into `(declared_mime, bytes)`.
fn decode_data_payload(s: &str) -> Option<(Option<String>, Vec<u8>)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    if let Some(rest) = s.strip_prefix("data:") {
        let (meta, payload) = rest.split_once(',')?;
        let mime = meta
            .split(';')
            .next()
            .filter(|m| !m.is_empty())
            .map(|m| m.to_ascii_lowercase());
        let bytes = if meta.contains(";base64") {
            BASE64
                .decode(payload.trim().as_bytes())
                .ok()?
        } else {
            payload.as_bytes().to_vec()
        };
        Some((mime, bytes))
    } else {
        BASE64
            .decode(s.trim().as_bytes())
            .ok()
            .map(|b| (None, b))
    }
}

/// The MIME for an audio part, derived from the declared `format` (`wav` →
/// `audio/wav`, `mp3` → `audio/mpeg`).
fn audio_media_type(format: Option<&str>) -> String {
    match format
        .map(|f| f.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("mp3") | Some("mpeg") => "audio/mpeg".to_string(),
        Some("") | None => "audio/octet-stream".to_string(),
        Some(other) => format!("audio/{other}"),
    }
}

/// Extract every decodable binary attachment from an OpenAI-canonical chat body:
/// audio (`input_audio`), documents (`file` with inline `file_data`), and inline
/// images (`image_url` data URLs). Reference-only parts (`file_id`, remote image
/// URLs) carry no bytes and are skipped.
pub fn extract_binary_attachments(body: &Value) -> Vec<RawAttachment> {
    let mut out = Vec::new();
    let Some(messages) = body
        .get("messages")
        .and_then(|m| m.as_array())
    else {
        return out;
    };
    for message in messages {
        let Some(parts) = message
            .get("content")
            .and_then(|c| c.as_array())
        else {
            continue;
        };
        for part in parts {
            match part
                .get("type")
                .and_then(|t| t.as_str())
            {
                Some("input_audio") => {
                    let Some(audio) = part.get("input_audio") else {
                        continue;
                    };
                    let Some(data) = audio
                        .get("data")
                        .and_then(|d| d.as_str())
                    else {
                        continue;
                    };
                    if let Some((_, bytes)) = decode_data_payload(data) {
                        let media_type = audio_media_type(
                            audio
                                .get("format")
                                .and_then(|f| f.as_str()),
                        );
                        out.push(RawAttachment {
                            kind: AttachmentKind::Audio,
                            media_type,
                            filename: None,
                            data: bytes,
                        });
                    }
                }
                Some("file") => {
                    let Some(file) = part.get("file") else {
                        continue;
                    };
                    let Some(file_data) = file
                        .get("file_data")
                        .and_then(|d| d.as_str())
                    else {
                        continue;
                    };
                    let filename = file
                        .get("filename")
                        .and_then(|n| n.as_str())
                        .map(str::to_string);
                    if let Some((mime, bytes)) = decode_data_payload(file_data) {
                        let media_type = mime.unwrap_or_else(|| "application/octet-stream".to_string());
                        out.push(RawAttachment {
                            kind: AttachmentKind::Document,
                            media_type,
                            filename,
                            data: bytes,
                        });
                    }
                }
                Some("image_url") => {
                    let Some(url) = part
                        .get("image_url")
                        .and_then(|i| i.get("url"))
                        .and_then(|u| u.as_str())
                    else {
                        continue;
                    };
                    if !url.starts_with("data:") {
                        continue;
                    }
                    if let Some((mime, bytes)) = decode_data_payload(url) {
                        let media_type = mime.unwrap_or_else(|| "image/octet-stream".to_string());
                        out.push(RawAttachment {
                            kind: AttachmentKind::Image,
                            media_type,
                            filename: None,
                            data: bytes,
                        });
                    }
                }
                _ => {}
            }
        }
    }
    out
}

// ── Store ───────────────────────────────────────────────────────────────────

static MULTIMEDIA_STORE: OnceLock<Arc<MultimediaStore>> = OnceLock::new();

/// Install the process-wide multimedia store. Idempotent — a second call is a
/// no-op (with a warning).
pub fn init_store(store: MultimediaStore) {
    if MULTIMEDIA_STORE
        .set(Arc::new(store))
        .is_err()
    {
        warn!("multimedia store already initialized");
    }
}

/// The process-wide multimedia store, if installed.
pub fn global_multimedia_store() -> Option<Arc<MultimediaStore>> {
    MULTIMEDIA_STORE
        .get()
        .cloned()
}

/// Extract every binary attachment from `body`, persist each to the multimedia
/// store, and return the hash-only [`MediaRef`]s for the governance record. When
/// the store is not installed the bytes are hashed but not written (`stored:
/// false`). Returns an empty vec when the body carries no binary attachments.
pub async fn extract_and_store(body: &Value) -> Vec<MediaRef> {
    let attachments = extract_binary_attachments(body);
    if attachments.is_empty() {
        return Vec::new();
    }
    let store = global_multimedia_store();
    let mut refs = Vec::with_capacity(attachments.len());
    for att in &attachments {
        match &store {
            Some(s) => refs.push(s.put(att).await),
            None => refs.push(att.unstored_ref()),
        }
    }
    refs
}

/// Hash-only references for every binary attachment in `body`, without writing
/// any bytes. Used for digests-only governance (body capture off): the record
/// still links the attachment by hash, but the raw bytes are not retained.
pub fn extract_refs(body: &Value) -> Vec<MediaRef> {
    extract_binary_attachments(body)
        .iter()
        .map(RawAttachment::unstored_ref)
        .collect()
}

/// Sidecar metadata written alongside each blob so the store is self-describing.
#[derive(Debug, Serialize, Deserialize)]
struct BlobMetadata {
    kind: String,
    media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    sha256: String,
    bytes: u64,
    stored_at: String,
}

/// Content-addressed blob store for governance attachments. Cheap to clone.
#[derive(Clone)]
pub struct MultimediaStore {
    root: PathBuf,
    encryption: Option<EncryptionService>,
}

impl MultimediaStore {
    /// Create a store rooted at `root` (e.g. `_storage/multimedia_store`),
    /// optionally encrypting blob bytes at rest with `encryption`.
    pub fn new(
        root: impl Into<PathBuf>,
        encryption: Option<EncryptionService>,
    ) -> Self {
        Self { root: root.into(), encryption }
    }

    /// The hex part of a `sha256:{hex}` hash.
    fn hex_of(hash: &str) -> &str {
        hash.strip_prefix("sha256:")
            .unwrap_or(hash)
    }

    /// Directory + blob + sidecar paths for a hash, sharded by the first two hex
    /// chars so a single directory never holds every blob.
    fn blob_paths(
        &self,
        hash: &str,
    ) -> (PathBuf, PathBuf, PathBuf) {
        let hex = Self::hex_of(hash);
        let shard = hex.get(0..2).unwrap_or("00");
        let dir = self.root.join(shard);
        let blob = dir.join(hex);
        let sidecar = dir.join(format!("{hex}.json"));
        (dir, blob, sidecar)
    }

    /// Persist one attachment (dedup by hash) and return its reference. A blob
    /// already on disk is not rewritten. A write failure is logged and reported
    /// as `stored: false` so the record still carries the hash.
    pub async fn put(
        &self,
        att: &RawAttachment,
    ) -> MediaRef {
        let hash = att.hash();
        let bytes_len = att.data.len() as u64;
        let (dir, blob, sidecar) = self.blob_paths(&hash);

        let stored = match self
            .write_blob(&dir, &blob, &sidecar, att, &hash, bytes_len)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                warn!(error = %e, hash = %hash, "failed to persist multimedia attachment");
                false
            }
        };

        MediaRef {
            kind: att.kind.as_str().to_string(),
            media_type: att.media_type.clone(),
            filename: att.filename.clone(),
            sha256: hash,
            bytes: bytes_len,
            stored,
        }
    }

    async fn write_blob(
        &self,
        dir: &Path,
        blob: &Path,
        sidecar: &Path,
        att: &RawAttachment,
        hash: &str,
        bytes_len: u64,
    ) -> anyhow::Result<()> {
        if tokio::fs::try_exists(blob)
            .await
            .unwrap_or(false)
        {
            return Ok(()); // content-addressed: identical bytes already stored
        }
        tokio::fs::create_dir_all(dir).await?;
        let payload = match &self.encryption {
            Some(enc) => enc.encrypt_bytes(&att.data)?,
            None => att.data.clone(),
        };
        tokio::fs::write(blob, &payload).await?;

        let meta = BlobMetadata {
            kind: att.kind.as_str().to_string(),
            media_type: att.media_type.clone(),
            filename: att.filename.clone(),
            sha256: hash.to_string(),
            bytes: bytes_len,
            stored_at: chrono::Utc::now().to_rfc3339(),
        };
        if let Ok(json) = serde_json::to_vec_pretty(&meta) {
            let _ = tokio::fs::write(sidecar, json).await;
        }
        Ok(())
    }

    /// Read a stored blob's plaintext bytes by `sha256:{hex}` hash, if present.
    pub async fn get(
        &self,
        sha256: &str,
    ) -> Option<Vec<u8>> {
        let (_, blob, _) = self.blob_paths(sha256);
        let raw = tokio::fs::read(&blob)
            .await
            .ok()?;
        match &self.encryption {
            Some(enc) => enc.decrypt_bytes(&raw).ok(),
            None => Some(raw),
        }
    }

    /// Re-hash a stored blob and confirm it matches its content-address — the
    /// integrity check that lets a governance record be verified against the
    /// stored bytes.
    pub async fn verify(
        &self,
        sha256: &str,
    ) -> bool {
        match self.get(sha256).await {
            Some(bytes) => digest_bytes(&bytes) == sha256,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body_with(parts: Value) -> Value {
        json!({ "model": "m", "messages": [ { "role": "user", "content": parts } ] })
    }

    #[test]
    fn extracts_audio_document_and_image() {
        let body = body_with(json!([
            { "type": "text", "text": "hi" },
            { "type": "input_audio", "input_audio": { "data": "QUJDRA==", "format": "wav" } },
            { "type": "file", "file": { "filename": "a.pdf", "file_data": "data:application/pdf;base64,QUJDRA==" } },
            { "type": "image_url", "image_url": { "url": "data:image/png;base64,QUJDRA==" } },
            { "type": "image_url", "image_url": { "url": "https://example.com/x.png" } }
        ]));
        let atts = extract_binary_attachments(&body);
        assert_eq!(atts.len(), 3);
        assert_eq!(atts[0].kind, AttachmentKind::Audio);
        assert_eq!(atts[0].media_type, "audio/wav");
        assert_eq!(atts[1].kind, AttachmentKind::Document);
        assert_eq!(atts[1].media_type, "application/pdf");
        assert_eq!(atts[1].filename.as_deref(), Some("a.pdf"));
        assert_eq!(atts[2].kind, AttachmentKind::Image);
    }

    #[test]
    fn reference_only_parts_are_skipped() {
        let body = body_with(json!([
            { "type": "file", "file": { "file_id": "file-123" } },
            { "type": "text", "text": "hi" }
        ]));
        assert!(extract_binary_attachments(&body).is_empty());
    }

    #[test]
    fn mp3_maps_to_audio_mpeg() {
        assert_eq!(audio_media_type(Some("mp3")), "audio/mpeg");
        assert_eq!(audio_media_type(Some("wav")), "audio/wav");
        assert_eq!(audio_media_type(None), "audio/octet-stream");
    }

    #[tokio::test]
    async fn put_get_verify_roundtrip_and_dedup() {
        let tmp = std::env::temp_dir().join(format!("mm-store-{}", uuid::Uuid::new_v4()));
        let store = MultimediaStore::new(&tmp, None);
        let att = RawAttachment {
            kind: AttachmentKind::Audio,
            media_type: "audio/wav".to_string(),
            filename: None,
            data: b"hello audio bytes".to_vec(),
        };
        let r1 = store.put(&att).await;
        assert!(r1.stored);
        assert_eq!(r1.bytes, att.data.len() as u64);
        assert!(
            r1.sha256
                .starts_with("sha256:")
        );

        let got = store
            .get(&r1.sha256)
            .await
            .expect("blob present");
        assert_eq!(got, att.data);
        assert!(store.verify(&r1.sha256).await);

        // Storing identical bytes again is a dedup no-op with the same hash.
        let r2 = store.put(&att).await;
        assert_eq!(r1.sha256, r2.sha256);

        assert!(
            !store
                .verify("sha256:deadbeef")
                .await
        );
        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }

    #[tokio::test]
    async fn extract_and_store_without_global_is_hash_only() {
        let body = body_with(json!([
            { "type": "input_audio", "input_audio": { "data": "QUJDRA==", "format": "mp3" } }
        ]));
        let refs = extract_and_store(&body).await;
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].kind, "audio");
        assert!(
            refs[0]
                .sha256
                .starts_with("sha256:")
        );
        // No global store installed in the unit test → hash only.
        assert!(!refs[0].stored);
    }
}
