//! Storage export with PII redaction and public-key encryption.
//!
//! Walks the `_storage` directory tree without following links, excludes
//! sensitive directories (keys, secrets, credentials, delegated tokens, people,
//! messages, media), redacts credentials, PII and user content in JSON and JSON
//! Lines files, leaves out every other file, builds a ZIP archive in memory,
//! then encrypts it with the recipient's Ed25519 public key.

pub mod crypto;
pub mod redact;

use anyhow::{Context, Result};
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use zip::write::{FileOptions, SimpleFileOptions, ZipWriter};

/// Run the full export: walk storage → redact → zip → encrypt → write.
///
/// `storage_root` is the path to the `_storage` directory.
/// `output_path` is where the encrypted ATGX file will be written.
pub fn export_storage(
    storage_root: &Path,
    output_path: &Path,
) -> Result<()> {
    if !storage_root.is_dir() {
        anyhow::bail!("Storage directory does not exist: {}", storage_root.display());
    }

    // Read recipient public key
    let pubkey = crypto::read_ed25519_pubkey_interactive().context("Failed to read Ed25519 public key")?;

    eprintln!();
    eprintln!("Building redacted export from: {}", storage_root.display());

    // Build ZIP in memory
    let mut stats = ExportStats::default();
    let zip_bytes = build_redacted_zip(storage_root, &mut stats)?;

    eprintln!(
        "  {} files included, {} files excluded, {} directories skipped",
        stats.included, stats.excluded_files, stats.excluded_dirs
    );
    eprintln!("  Uncompressed ZIP size: {} bytes", zip_bytes.len());

    // Encrypt
    eprintln!("Encrypting with recipient public key...");
    let encrypted = crypto::encrypt_for_recipient(&zip_bytes, &pubkey).context("Encryption failed")?;

    // Write output
    fs::write(output_path, &encrypted)
        .with_context(|| format!("Failed to write export to {}", output_path.display()))?;

    eprintln!("✓ Encrypted export written to: {} ({} bytes)", output_path.display(), encrypted.len());

    Ok(())
}

/// Decrypt an ATGX export file back to a ZIP archive.
///
/// `input_path` is the encrypted ATGX file.
/// `output_path` is where the decrypted ZIP will be written.
pub fn decrypt_export(
    input_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let encrypted = fs::read(input_path).with_context(|| format!("Failed to read {}", input_path.display()))?;

    // Read recipient private key
    let privkey = crypto::read_ed25519_privkey_interactive().context("Failed to read Ed25519 private key")?;

    eprintln!();
    eprintln!("Decrypting export...");

    let zip_bytes = crypto::decrypt_with_privkey(&encrypted, &privkey).context("Decryption failed")?;

    fs::write(output_path, &zip_bytes).with_context(|| format!("Failed to write {}", output_path.display()))?;

    eprintln!("✓ Decrypted ZIP written to: {} ({} bytes)", output_path.display(), zip_bytes.len());

    Ok(())
}

/// Build a redacted, encrypted export from the storage directory.
///
/// Called by the API handler — accepts the public key PEM as a string
/// and returns the encrypted ATGX bytes directly.
pub fn build_encrypted_export(
    storage_root: &Path,
    pubkey_pem: &str,
) -> Result<Vec<u8>> {
    if !storage_root.is_dir() {
        anyhow::bail!("Storage directory does not exist: {}", storage_root.display());
    }

    let pubkey = crypto::parse_ed25519_pubkey_pem(pubkey_pem).context("Invalid Ed25519 public key PEM")?;

    let mut stats = ExportStats::default();
    let zip_bytes = build_redacted_zip(storage_root, &mut stats)?;

    tracing::info!(
        "Storage export: {} files included, {} excluded, {} dirs skipped, ZIP {} bytes",
        stats.included,
        stats.excluded_files,
        stats.excluded_dirs,
        zip_bytes.len()
    );

    let encrypted = crypto::encrypt_for_recipient(&zip_bytes, &pubkey).context("Encryption failed")?;

    Ok(encrypted)
}

#[derive(Default)]
struct ExportStats {
    included: u64,
    excluded_files: u64,
    excluded_dirs: u64,
}

/// Build a ZIP archive in memory from the storage directory, applying redaction.
fn build_redacted_zip(
    storage_root: &Path,
    stats: &mut ExportStats,
) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let cursor = Cursor::new(buf);
    let mut zip = ZipWriter::new(cursor);

    let options: SimpleFileOptions = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    walk_and_add(storage_root, storage_root, &mut zip, options, stats)?;

    let cursor = zip
        .finish()
        .context("Failed to finalize ZIP archive")?;
    Ok(cursor.into_inner())
}

/// Recursively walk a directory, adding redacted files to the ZIP.
fn walk_and_add(
    base: &Path,
    dir: &Path,
    zip: &mut ZipWriter<Cursor<Vec<u8>>>,
    options: SimpleFileOptions,
    stats: &mut ExportStats,
) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("Failed to read directory: {}", dir.display()))?;

    let mut entries: Vec<_> = entries
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(base)
            .unwrap_or(&path);
        let relative_str = relative
            .to_string_lossy()
            .replace('\\', "/");

        // A link is never followed: it could reach outside the storage tree or loop.
        let Ok(file_type) = entry.file_type() else {
            stats.excluded_files += 1;
            continue;
        };
        if file_type.is_symlink() {
            stats.excluded_files += 1;
            continue;
        }

        if file_type.is_dir() {
            let dir_name = path
                .file_name()
                .map(|n| {
                    n.to_string_lossy()
                        .to_string()
                })
                .unwrap_or_default();

            if redact::is_excluded_dir(&dir_name) {
                stats.excluded_dirs += 1;
                continue;
            }

            walk_and_add(base, &path, zip, options, stats)?;
        } else if file_type.is_file() {
            // Check if any ancestor directory is excluded
            if is_under_excluded_dir(relative) {
                stats.excluded_files += 1;
                continue;
            }

            let content = match fs::read(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("  warning: skipping unreadable file {}: {}", relative_str, e);
                    stats.excluded_files += 1;
                    continue;
                }
            };

            let Some(redacted) = redact_file_content(&path, &content) else {
                stats.excluded_files += 1;
                continue;
            };

            zip.start_file(&relative_str, options)
                .with_context(|| format!("Failed to add {} to ZIP", relative_str))?;
            zip.write_all(&redacted)
                .with_context(|| format!("Failed to write {} to ZIP", relative_str))?;

            stats.included += 1;
        }
    }

    Ok(())
}

/// Check if a relative path has any excluded directory as an ancestor.
fn is_under_excluded_dir(relative: &Path) -> bool {
    relative
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .any(|component| {
            matches!(component, std::path::Component::Normal(name) if redact::is_excluded_dir(&name.to_string_lossy()))
        })
}

/// Marker written in place of a JSON Lines record that does not parse.
const UNPARSEABLE_LINE: &str = "[REDACTED-UNPARSEABLE]";

/// Redact a file by its extension, or `None` to leave it out of the export.
/// Only structured records the redactor understands are exported: JSON and
/// JSON Lines. A JSON file that does not parse and every other file (logs and
/// other free text, binaries, media, ciphertext) are left out.
fn redact_file_content(
    path: &Path,
    content: &[u8],
) -> Option<Vec<u8>> {
    let ext = path
        .extension()
        .map(|e| {
            e.to_string_lossy()
                .to_lowercase()
        })
        .unwrap_or_default();
    let text = std::str::from_utf8(content).ok()?;

    if ext == "json" {
        let mut value = serde_json::from_str::<serde_json::Value>(text).ok()?;
        redact::redact_json(&mut value);
        serde_json::to_string_pretty(&value)
            .ok()
            .map(String::into_bytes)
    } else if ext == "jsonl" {
        let lines: Vec<String> = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| match serde_json::from_str::<serde_json::Value>(line) {
                Ok(mut value) => {
                    redact::redact_json(&mut value);
                    serde_json::to_string(&value).unwrap_or_else(|_| UNPARSEABLE_LINE.to_string())
                }
                Err(_) => UNPARSEABLE_LINE.to_string(),
            })
            .collect();
        Some(format!("{}\n", lines.join("\n")).into_bytes())
    } else {
        None
    }
}

/// Resolve the storage root from bootstrap config, applying base_folder if set.
pub fn resolve_storage_root(
    storage_path: &str,
    base_folder: &str,
) -> PathBuf {
    let path = if base_folder.is_empty() {
        PathBuf::from(storage_path)
    } else {
        PathBuf::from(base_folder).join(storage_path)
    };

    // Walk up to find the _storage root (storage_path is e.g. "_storage/channels",
    // we want "_storage")
    let mut current = path.as_path();
    while let Some(parent) = current.parent() {
        if let Some(name) = current.file_name()
            && name == "_storage"
        {
            return current.to_path_buf();
        }
        current = parent;
    }

    // Fallback: use the configured path's parent if we can't find _storage
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_storage() -> TempDir {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("_storage");

        // Create included directories with files
        let channels = root.join("channels");
        fs::create_dir_all(&channels).unwrap();
        fs::write(
            channels.join("ch1.json"),
            r#"{"name":"test-channel","did":"did:peer:2.abc123","listen_address":"0.0.0.0:8443"}"#,
        )
        .unwrap();

        let metrics = root.join("metrics");
        fs::create_dir_all(&metrics).unwrap();
        fs::write(metrics.join("metrics.json"), r#"{"agent_identity":"agent-1","source":"192.168.1.1"}"#).unwrap();

        let logs = root.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("app.log"), "2025-01-01 Connection from 10.0.0.1 user admin@test.com did:peer:2.xyz\n")
            .unwrap();

        let gateways = root.join("gateways");
        fs::create_dir_all(&gateways).unwrap();
        fs::write(
            gateways.join("gw1.json"),
            r#"{"name":"gw1","did":"did:web:example.com","exposed_channels":["ch1"]}"#,
        )
        .unwrap();

        // Create excluded directories with files
        let secrets = root.join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("smtp.txt"), "super-secret-password").unwrap();

        let identities = root.join("identities");
        fs::create_dir_all(&identities).unwrap();
        fs::write(identities.join("id1.json"), r#"{"did":"did:key:z6Mk1","private_key":{"d":"base64secret"}}"#)
            .unwrap();

        let avatars = root.join("avatars");
        fs::create_dir_all(&avatars).unwrap();
        fs::write(avatars.join("user1.png"), [0x89, 0x50, 0x4E, 0x47]).unwrap();

        let sessions = root.join("sessions");
        fs::create_dir_all(&sessions).unwrap();
        fs::write(sessions.join("s1.json"), r#"{"token":"secret-token","username":"alice"}"#).unwrap();

        dir
    }

    #[test]
    fn test_build_redacted_zip_excludes_sensitive_dirs() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");

        let mut stats = ExportStats::default();
        let zip_bytes = build_redacted_zip(&storage_root, &mut stats).unwrap();

        assert!(stats.excluded_dirs >= 4, "should exclude secrets, identities, avatars, sessions");
        assert_eq!(stats.included, 3, "should include channels, metrics, gateways");

        // Verify ZIP contents
        let cursor = Cursor::new(zip_bytes);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();

        let names: Vec<String> = (0..archive.len())
            .map(|i| {
                archive
                    .by_index(i)
                    .unwrap()
                    .name()
                    .unwrap()
                    .to_string()
            })
            .collect();

        assert!(
            names
                .iter()
                .any(|n| n.contains("channels/"))
        );
        assert!(
            names
                .iter()
                .any(|n| n.contains("gateways/"))
        );
        assert!(
            !names
                .iter()
                .any(|n| n.contains("secrets/"))
        );
        assert!(
            !names
                .iter()
                .any(|n| n.contains("identities/"))
        );
        assert!(
            !names
                .iter()
                .any(|n| n.contains("avatars/"))
        );
        assert!(
            !names
                .iter()
                .any(|n| n.contains("sessions/"))
        );
    }

    #[test]
    fn test_build_redacted_zip_redacts_json() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");

        let mut stats = ExportStats::default();
        let zip_bytes = build_redacted_zip(&storage_root, &mut stats).unwrap();

        let cursor = Cursor::new(zip_bytes);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        let mut binding = archive.clone();

        // Check channel JSON — DID should be redacted
        let mut ch_file = archive
            .by_name("channels/ch1.json")
            .unwrap();
        let mut content = String::new();
        std::io::Read::read_to_string(&mut ch_file, &mut content).unwrap();
        let val: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(
            val["did"]
                .as_str()
                .unwrap()
                .starts_with("did:redacted:")
        );
        assert_eq!(val["name"], "test-channel");

        // Check gateway JSON — DID should be redacted
        let mut gw_file = binding
            .by_name("gateways/gw1.json")
            .unwrap();
        let mut gw_content = String::new();
        std::io::Read::read_to_string(&mut gw_file, &mut gw_content).unwrap();
        let gw_val: serde_json::Value = serde_json::from_str(&gw_content).unwrap();
        assert!(
            gw_val["did"]
                .as_str()
                .unwrap()
                .starts_with("did:redacted:")
        );
    }

    #[test]
    fn test_build_redacted_zip_leaves_out_logs() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");

        let mut stats = ExportStats::default();
        let zip_bytes = build_redacted_zip(&storage_root, &mut stats).unwrap();

        let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        assert!(
            archive
                .by_name("logs/app.log")
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_never_followed() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("config.json"), r#"{"name":"outside-the-store"}"#).unwrap();
        std::os::unix::fs::symlink(&outside, storage_root.join("linked")).unwrap();
        std::os::unix::fs::symlink(&storage_root, storage_root.join("channels/loop")).unwrap();

        let mut stats = ExportStats::default();
        let zip_bytes = build_redacted_zip(&storage_root, &mut stats).unwrap();

        let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        assert!(
            archive
                .by_name("linked/config.json")
                .is_err()
        );
        assert_eq!(stats.included, 3);
    }

    #[test]
    fn test_is_under_excluded_dir() {
        assert!(is_under_excluded_dir(Path::new("secrets/smtp.txt")));
        assert!(is_under_excluded_dir(Path::new("identities/id1.json")));
        assert!(is_under_excluded_dir(Path::new("avatars/photo.png")));
        assert!(!is_under_excluded_dir(Path::new("channels/ch1.json")));
        assert!(!is_under_excluded_dir(Path::new("metrics/metrics.json")));
        assert!(is_under_excluded_dir(Path::new("surfaces/messages/m1.json")));
        assert!(!is_under_excluded_dir(Path::new("connection_points/cp1/did.json")));
        assert!(!is_under_excluded_dir(Path::new("settings/sessions.json")));
    }

    #[test]
    fn test_resolve_storage_root() {
        let path = resolve_storage_root("_storage/channels", "");
        assert_eq!(path, PathBuf::from("_storage"));

        let path = resolve_storage_root("_storage/channels", "/app");
        assert_eq!(path, PathBuf::from("/app/_storage"));
    }

    #[test]
    fn test_redact_file_content_json() {
        let content = br#"{"did":"did:peer:2.abc","name":"test"}"#;
        let result = redact_file_content(Path::new("test.json"), content).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("did:redacted:"));
        assert!(text.contains("test"));
    }

    #[test]
    fn a_file_the_redactor_cannot_read_is_left_out() {
        let png = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A];
        for (name, content) in [
            ("image.dat", png.as_slice()),
            ("photo.png", png.as_slice()),
            ("key_0.json.enc", b"ENCRYPTED".as_slice()),
            ("tls.pem", b"-----BEGIN PRIVATE KEY-----".as_slice()),
            ("broken.json", br#"{"refresh_token": "rt-live""#.as_slice()),
            ("notes.txt", png.as_slice()),
            ("app.log", b"prompt: my card is 4111 from 10.0.0.1".as_slice()),
            ("openai_key.txt", b"sk-live-abc".as_slice()),
            ("config.toml", b"api_key = \"sk-live\"".as_slice()),
        ] {
            assert!(redact_file_content(Path::new(name), content).is_none(), "{name}");
        }
    }

    #[test]
    fn json_lines_with_crlf_and_any_extension_case_are_redacted() {
        let content = "{\"vp_jwt\":\"eyJ.live\",\"event\":\"x\"}\r\n{\"prompt\":\"hi\"}\r\n";
        let text =
            String::from_utf8(redact_file_content(Path::new("AUDIT.JSONL"), content.as_bytes()).unwrap()).unwrap();
        assert!(!text.contains("eyJ.live"), "{text}");
        assert!(!text.contains("UNPARSEABLE"), "{text}");
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn json_lines_are_redacted_line_by_line() {
        let content = concat!(
            r#"{"record_id":"r1","prompt":"my card is 4111","completion":"noted","surface_id":"s1"}"#,
            "\n\n",
            r#"{"refresh_token":"rt-live","event":"token_refreshed"}"#,
            "\nnot json with secret-value\n"
        );
        let result = redact_file_content(Path::new("records.jsonl"), content.as_bytes()).unwrap();
        let text = String::from_utf8(result).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines.len(), 3);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["prompt"], "[REDACTED-CONTENT]");
        assert_eq!(first["completion"], "[REDACTED-CONTENT]");
        assert_eq!(first["surface_id"], "s1");
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["refresh_token"], "[REDACTED-SECRET]");
        assert_eq!(lines[2], UNPARSEABLE_LINE);
        for leaked in ["4111", "noted", "rt-live", "secret-value"] {
            assert!(!text.contains(leaked), "{leaked} leaked");
        }
    }

    #[test]
    fn credential_stores_and_key_files_never_reach_the_export() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("_storage");
        let write = |relative: &str, content: &str| {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        };
        write("delegation_vault/u1/p1.json", r#"{"refresh_token":"rt-live","access_token":"at-live"}"#);
        write("access_tokens/t1.json", r#"{"token_hash":"th-live"}"#);
        write("api_keys/k1.json", r#"{"secret_hash":"sh-live"}"#);
        write("multimedia_store/m1/image.png", "binary-media");
        write(
            "connection_points/cp1/key_0.json",
            r#"{"id":"did:web:x#key-1","privateKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"pub","d":"jwk-d-live"}}"#,
        );
        write(
            "connection_points/cp1/key_1.json",
            r#"{"id":"did:web:x#key-2","secret_material":{"kty":"OKP","crv":"X25519","x":"pub","d":"jwk-d-two"}}"#,
        );
        write(
            "mediators/m1.json",
            r#"{"name":"mediator","our_secrets":[{"id":"k","privateKeyJwk":{"kty":"OKP","d":"mediator-d-live"}}]}"#,
        );
        write("connection_points/cp1.json", r#"{"name":"cp","secret":"oob-secret-live"}"#);
        write("connection_points/cp1/did.json", r#"{"jwk":{"kty":"OKP","x":"pub","d":"neutral-key-d-live"}}"#);
        write(
            "surfaces/s1.json",
            r#"{"name":"chat","expert_witnesses":[{"headers":{"X-API-Key":"ew-key-live","x-goog-api-key":"goog-live"}}]}"#,
        );
        write(
            "messages/cp1/m1.json",
            r#"{"message_body":{"headers":{"X-API-Key":"caller-key-live"},"text":"passport X1234567"}}"#,
        );
        write("members/m1.json", r#"{"name":"John Smith","identifiers":[{"value":"john@corp.com"}]}"#);
        write("passkeys.backup-2026/u1.json", r#"{"credential":"passkey-backup-live"}"#);
        write("audit/delegation-audit.jsonl", "{\"vp_jwt\":\"eyJ.vp-live\",\"caller_principal\":\"alice\"}\n");
        write("surfaces/tags.json", r#"{"to_dids":["did:peer:2.Ezlive"],"notify":["ops@corp.com"]}"#);

        let mut stats = ExportStats::default();
        let zip_bytes = build_redacted_zip(&root, &mut stats).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        let mut exported = String::new();
        let mut names = Vec::new();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            names.push(
                file.name()
                    .unwrap()
                    .to_string(),
            );
            std::io::Read::read_to_string(&mut file, &mut exported).unwrap();
        }

        for leaked in [
            "rt-live",
            "at-live",
            "th-live",
            "sh-live",
            "binary-media",
            "jwk-d-live",
            "jwk-d-two",
            "mediator-d-live",
            "oob-secret-live",
            "neutral-key-d-live",
            "ew-key-live",
            "goog-live",
            "caller-key-live",
            "X1234567",
            "John Smith",
            "john@corp.com",
            "passkey-backup-live",
            "eyJ.vp-live",
            "alice",
            "did:peer:2.Ezlive",
            "ops@corp.com",
        ] {
            assert!(!exported.contains(leaked), "{leaked} leaked into the export");
        }
        for excluded in [
            "delegation_vault/",
            "access_tokens/",
            "api_keys/",
            "multimedia_store/",
            "messages/",
            "members/",
            "passkeys.backup-2026/",
        ] {
            assert!(
                !names
                    .iter()
                    .any(|name| name.starts_with(excluded)),
                "{excluded} exported"
            );
        }
        assert!(names.contains(&"mediators/m1.json".to_string()));
        assert!(names.contains(&"connection_points/cp1/did.json".to_string()));
        assert!(exported.contains("\"name\": \"mediator\""));
    }
}
