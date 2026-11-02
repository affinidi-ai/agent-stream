//! Backup and restore logic for the `_storage` directory.
//!
//! - `build_full_zip` creates an in-memory ZIP of the entire storage tree.
//! - `check_and_restore_backup` runs at startup: if `backup.asbak` (or the
//!   legacy `backup.tgwbak`) exists in
//!   the dedicated `backup_restore` directory, it archives the old storage, extracts
//!   the backup, and signals the caller to restart.
//! - `extract_zip_to_dir` inflates a ZIP file into a target directory.
//! - Backup files are encrypted with AES-256-GCM (see `encryption` module).
//!   The resulting `.asbak` file is NOT a ZIP — it is an encrypted binary blob.

pub mod audit;
pub mod encryption;
pub mod handlers;
pub mod manifest;
pub mod normalize;
pub mod reencrypt;

pub use handlers::{backup_storage, restore_storage};

use tracing::warn;

/// Directories to skip when building a backup ZIP (ephemeral / regenerated data).
const BACKUP_SKIP_DIRS: &[&str] = &["logs", "system_metrics"];

/// File name of a backup download and of a restore staged for the next start.
pub(crate) const BACKUP_FILE_NAME: &str = "backup.asbak";

/// File name used before the rename to `BACKUP_FILE_NAME`; a staged file with
/// this name is still restored at startup.
const LEGACY_BACKUP_FILE_NAME: &str = "backup.tgwbak";

/// Subdirectory name for pre-restore snapshots of `_storage`.
const LOCAL_BACKUPS_DIR: &str = "local_backups";

#[derive(Clone, Copy)]
struct ArchiveLimits {
    max_entries: usize,
    max_entry_uncompressed_bytes: u64,
    max_total_uncompressed_bytes: u64,
    max_compression_ratio: u64,
    max_manifest_bytes: u64,
}

pub(super) const MAX_ENCRYPTED_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

const ARCHIVE_LIMITS: ArchiveLimits = ArchiveLimits {
    max_entries: 100_000,
    max_entry_uncompressed_bytes: 128 * 1024 * 1024,
    max_total_uncompressed_bytes: 512 * 1024 * 1024,
    max_compression_ratio: 200,
    max_manifest_bytes: manifest::MAX_MANIFEST_BYTES,
};

/// Build a full (no redaction) ZIP of the `_storage` directory, copying every
/// file byte-for-byte. Used for the pre-restore snapshot, which must round-trip
/// this node's on-disk state exactly.
pub fn build_full_zip(storage_root: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    build_zip(storage_root, false, None)
}

/// Build a portable ZIP of the `_storage` directory. Whole-file `.json.enc` blobs
/// are decrypted to plaintext and renamed `id.json` so the archive does not depend
/// on this node's field-encryption key (KEK) — under `aws_kms` that key is a
/// CMK-bound per-value envelope, so a verbatim copy would be unreadable on a node
/// with a different or rotated CMK. Any residual field-level `ENC[...]` value in a
/// `.json` file is also flattened. The whole archive is BEK-encrypted afterwards by
/// the caller. A `.json.enc` that cannot be decrypted (no/wrong key) is kept verbatim
/// with a warning — the export never aborts and never drops data. Non-`.json`/`.enc`
/// files are copied byte-for-byte, so with encryption disabled this is identical to
/// [`build_full_zip`].
pub fn build_portable_zip(
    storage_root: &std::path::Path,
    source_domain: &str,
) -> anyhow::Result<Vec<u8>> {
    let service = normalize::backup_decryption_service();
    if service.is_none() {
        warn!(
            "Portable backup: no decryption key is available — any encrypted files are exported \
             verbatim and will be unreadable after restore. Check the encryption key source."
        );
    }
    let zip_bytes = build_zip(storage_root, true, service.as_ref())?;
    manifest::add_backup_manifest(&zip_bytes, source_domain, false)
}

fn build_zip(
    storage_root: &std::path::Path,
    normalize: bool,
    decrypt_service: Option<&crate::encryption::EncryptionService>,
) -> anyhow::Result<Vec<u8>> {
    use std::io::{Cursor, Write};
    use zip::write::{FileOptions, SimpleFileOptions, ZipWriter};

    if !storage_root.is_dir() {
        anyhow::bail!("Storage directory does not exist: {}", storage_root.display());
    }

    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);
    let options: SimpleFileOptions = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    fn walk(
        base: &std::path::Path,
        dir: &std::path::Path,
        zip: &mut ZipWriter<Cursor<Vec<u8>>>,
        options: SimpleFileOptions,
        normalize: bool,
        decrypt_service: Option<&crate::encryption::EncryptionService>,
    ) -> anyhow::Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
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

            if path.is_dir() {
                // Skip ephemeral directories (logs, system_metrics) that can
                // grow to hundreds of MB and are regenerated at runtime.
                let dir_name = path
                    .file_name()
                    .map(|n| {
                        n.to_string_lossy()
                            .to_string()
                    })
                    .unwrap_or_default();
                if BACKUP_SKIP_DIRS.contains(&dir_name.as_str()) {
                    warn!("Backup: skipping ephemeral directory {}", relative_str);
                    continue;
                }
                walk(base, &path, zip, options, normalize, decrypt_service)?;
            } else if path.is_file() {
                let content = match std::fs::read(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Skipping unreadable file {}: {}", relative_str, e);
                        continue;
                    }
                };
                if normalize {
                    // An encrypted sibling is authoritative: when it can be decrypted,
                    // skip the raw plaintext `.json` so the archive carries one plaintext
                    // entry rather than a duplicate.
                    if decrypt_service.is_some() && relative_str.ends_with(".json") {
                        let mut enc_sibling = path.clone().into_os_string();
                        enc_sibling.push(".enc");
                        if std::path::Path::new(&enc_sibling).exists() {
                            continue;
                        }
                    }
                    let (entry_name, out) = normalize::backup_entry_for_file(&relative_str, &content, decrypt_service)?;
                    zip.start_file(&entry_name, options)?;
                    zip.write_all(&out)?;
                } else {
                    zip.start_file(&relative_str, options)?;
                    zip.write_all(&content)?;
                }
            }
        }
        Ok(())
    }

    walk(storage_root, storage_root, &mut zip, options, normalize, decrypt_service)?;

    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

fn record_startup_restore_audit(
    key_source: Option<&str>,
    source_domain: Option<&str>,
    target_domain: Option<&str>,
    outcome: &str,
    failure_category: Option<&str>,
    archive_size_bytes: Option<usize>,
) {
    audit::record_startup_storage_audit(audit::StorageAuditEvent {
        operation: audit::StorageOperation::Restore,
        actor_id: "system",
        actor_type: "system",
        restore_path: Some("startup"),
        key_source,
        source_domain,
        target_domain,
        outcome,
        failure_category,
        archive_size_bytes,
    });
}

/// Check for `backup.asbak` (or the legacy `backup.tgwbak`) at startup and
/// perform the restore procedure if found.
///
/// If the staged backup is encrypted (has TGWENC magic trailer), it is decrypted in
/// place before extraction. A valid explicit `backup_encryption_key` is required;
/// optional legacy fallback is read only through `legacy_backup_encryption_keys`.
/// Missing or malformed required key material aborts with current `_storage` untouched.
///
/// Returns `true` if a restore was performed (caller should exit).
pub fn check_and_restore_backup(
    storage_root: &std::path::Path,
    backup_restore_dir: &std::path::Path,
    backup_encryption_key: Option<&str>,
    legacy_backup_encryption_keys: Option<&str>,
    target_domain: &str,
) -> bool {
    if let Err(e) = std::fs::create_dir_all(backup_restore_dir) {
        eprintln!("ERROR: Failed to create backups directory {}: {}", backup_restore_dir.display(), e);
        return false;
    }

    let Some(backup_zip_path) = [BACKUP_FILE_NAME, LEGACY_BACKUP_FILE_NAME]
        .iter()
        .map(|name| backup_restore_dir.join(name))
        .find(|path| path.exists())
    else {
        return false;
    };

    let target_domain = match manifest::canonicalize_domain(target_domain) {
        Ok(domain) => domain,
        Err(e) => {
            record_startup_restore_audit(None, None, None, "failure", Some("target_domain_invalid"), None);
            eprintln!("ERROR: Current did.domain is invalid for backup restore: {e}");
            return false;
        }
    };
    record_startup_restore_audit(None, None, Some(&target_domain), "attempt", None, None);

    println!("Staged backup detected at {}. Starting restore procedure...", backup_zip_path.display());
    println!("Note: backup does not include directories: {:?}. These will not be restored.", BACKUP_SKIP_DIRS);

    let current_key = match encryption::resolve_backup_key_checked(backup_encryption_key) {
        Ok(key) => key,
        Err(e) => {
            record_startup_restore_audit(None, None, Some(&target_domain), "failure", Some("key_unavailable"), None);
            eprintln!("ERROR: Cannot restore backup: {e}");
            return false;
        }
    };
    let legacy_keys = match encryption::resolve_legacy_backup_keys(legacy_backup_encryption_keys) {
        Ok(keys) => keys,
        Err(e) => {
            record_startup_restore_audit(
                None,
                None,
                Some(&target_domain),
                "failure",
                Some("legacy_key_configuration_invalid"),
                None,
            );
            eprintln!("ERROR: Legacy backup key configuration is invalid: {e}");
            return false;
        }
    };
    let data = {
        use std::io::Read;

        let file = match std::fs::File::open(&backup_zip_path) {
            Ok(file) => file,
            Err(e) => {
                record_startup_restore_audit(None, None, Some(&target_domain), "failure", Some("read_failed"), None);
                eprintln!("ERROR: Failed to open {}: {e}", backup_zip_path.display());
                return false;
            }
        };
        let mut data = Vec::new();
        if let Err(e) = file
            .take(MAX_ENCRYPTED_ARCHIVE_BYTES as u64 + 1)
            .read_to_end(&mut data)
        {
            record_startup_restore_audit(None, None, Some(&target_domain), "failure", Some("read_failed"), None);
            eprintln!("ERROR: Failed to read {}: {e}", backup_zip_path.display());
            return false;
        }
        if data.len() > MAX_ENCRYPTED_ARCHIVE_BYTES {
            record_startup_restore_audit(
                None,
                None,
                Some(&target_domain),
                "failure",
                Some("archive_too_large"),
                Some(data.len()),
            );
            eprintln!("ERROR: Encrypted backup exceeds the 64 MiB archive limit");
            return false;
        }
        data
    };
    if !encryption::is_encrypted_backup(&data) {
        record_startup_restore_audit(
            None,
            None,
            Some(&target_domain),
            "failure",
            Some("encryption_required"),
            Some(data.len()),
        );
        eprintln!("ERROR: Startup restore requires an encrypted backup");
        return false;
    }

    let decrypted = match encryption::decrypt_backup_with_keys(&current_key, &legacy_keys, &data) {
        Ok(decrypted) => decrypted,
        Err(e) => {
            record_startup_restore_audit(
                None,
                None,
                Some(&target_domain),
                "failure",
                Some("authentication_failed"),
                Some(data.len()),
            );
            eprintln!("ERROR: Backup authentication failed: {e}");
            return false;
        }
    };
    let key_source = match decrypted.key_source {
        encryption::BackupKeySource::Current => "current",
        encryption::BackupKeySource::Legacy => "legacy",
    };
    let zip_data = decrypted.bytes;
    if let Err(e) = validate_zip_entries(&zip_data) {
        record_startup_restore_audit(
            Some(key_source),
            None,
            Some(&target_domain),
            "failure",
            Some("zip_invalid"),
            Some(zip_data.len()),
        );
        eprintln!("ERROR: Backup ZIP validation failed: {e}");
        return false;
    }
    let parsed_manifest = match manifest::read_optional_backup_manifest(&zip_data) {
        Ok(manifest) => manifest,
        Err(e) => {
            record_startup_restore_audit(
                Some(key_source),
                None,
                Some(&target_domain),
                "failure",
                Some("manifest_invalid"),
                Some(zip_data.len()),
            );
            eprintln!("ERROR: Backup manifest validation failed: {e}");
            return false;
        }
    };
    let parsed_source_domain = parsed_manifest
        .as_ref()
        .and_then(|manifest| manifest::canonicalize_domain(&manifest.source_domain).ok());
    let backup_manifest = match parsed_manifest {
        Some(manifest) => match manifest::validate_parsed_backup_manifest(manifest, &target_domain) {
            Ok(manifest) => Some(manifest),
            Err(e) => {
                record_startup_restore_audit(
                    Some(key_source),
                    parsed_source_domain.as_deref(),
                    Some(&target_domain),
                    "failure",
                    Some("manifest_invalid"),
                    Some(zip_data.len()),
                );
                eprintln!("ERROR: Backup manifest validation failed: {e}");
                return false;
            }
        },
        None if decrypted.key_source == encryption::BackupKeySource::Legacy => None,
        None => {
            record_startup_restore_audit(
                Some(key_source),
                None,
                Some(&target_domain),
                "failure",
                Some("manifest_missing"),
                Some(zip_data.len()),
            );
            eprintln!("ERROR: Backup manifest is required");
            return false;
        }
    };
    let restore_source_domain = backup_manifest
        .as_ref()
        .map(|manifest| {
            manifest
                .source_domain
                .as_str()
        });
    let record_failure = |failure_category| {
        record_startup_restore_audit(
            Some(key_source),
            restore_source_domain,
            Some(&target_domain),
            "failure",
            Some(failure_category),
            Some(zip_data.len()),
        );
    };

    let staging_path = backup_restore_dir.join(".restore-staging");
    if staging_path.exists()
        && let Err(e) = std::fs::remove_dir_all(&staging_path)
    {
        record_failure("staging_cleanup_failed");
        eprintln!("ERROR: Failed to clean stale restore staging directory: {e}");
        return false;
    }
    if let Err(e) = std::fs::create_dir_all(&staging_path) {
        record_failure("staging_directory_failed");
        eprintln!("ERROR: Failed to create restore staging directory: {e}");
        return false;
    }
    if let Err(e) = extract_zip_bytes_to_dir(&zip_data, &staging_path) {
        let _ = std::fs::remove_dir_all(&staging_path);
        record_failure("staging_extraction_failed");
        eprintln!("ERROR: Failed to validate and stage backup contents: {e}");
        return false;
    }

    let local_backups = backup_restore_dir.join(LOCAL_BACKUPS_DIR);
    if let Err(e) = std::fs::create_dir_all(&local_backups) {
        let _ = std::fs::remove_dir_all(&staging_path);
        record_failure("snapshot_directory_failed");
        eprintln!("ERROR: Failed to create local_backups directory: {e}");
        return false;
    }

    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let archive_path = local_backups.join(format!("storage-before-restore-{ts}.zip"));
    let had_existing_storage = storage_root.is_dir();
    if had_existing_storage {
        println!("Backing up current _storage to {}", archive_path.display());
        match build_full_zip(storage_root) {
            Ok(zip_bytes) => {
                if let Err(e) = std::fs::write(&archive_path, &zip_bytes) {
                    let _ = std::fs::remove_dir_all(&staging_path);
                    record_failure("snapshot_write_failed");
                    eprintln!("ERROR: Failed to write pre-restore backup: {e}");
                    return false;
                }
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&staging_path);
                record_failure("snapshot_build_failed");
                eprintln!("ERROR: Failed to build pre-restore backup zip: {e}");
                return false;
            }
        }
    } else if let Err(e) = std::fs::create_dir_all(storage_root) {
        let _ = std::fs::remove_dir_all(&staging_path);
        record_failure("storage_directory_failed");
        eprintln!("ERROR: Failed to create storage directory: {e}");
        return false;
    }

    if let Err(failure) = install_staged_restore(&staging_path, storage_root, had_existing_storage, &archive_path) {
        let _ = std::fs::remove_dir_all(&staging_path);
        record_failure(
            if failure
                .rollback_error
                .is_none()
            {
                "storage_install_failed_rolled_back"
            } else {
                "storage_install_and_rollback_failed"
            },
        );
        eprintln!("ERROR: Failed to install staged backup: {}", failure.install_error);
        if let Some(rollback_error) = failure.rollback_error {
            eprintln!("ERROR: Failed to restore the pre-restore snapshot: {rollback_error}");
        }
        return false;
    }
    let _ = std::fs::remove_dir_all(&staging_path);
    if archive_path.exists()
        && let Err(e) = std::fs::remove_file(&archive_path)
    {
        eprintln!("WARNING: Failed to remove pre-restore snapshot: {e}");
    }

    // Remove every staged backup, including a leftover under the other name,
    // so the next restart proceeds normally
    for path in [BACKUP_FILE_NAME, LEGACY_BACKUP_FILE_NAME]
        .iter()
        .map(|name| backup_restore_dir.join(name))
        .filter(|path| path.exists())
    {
        if let Err(e) = std::fs::remove_file(&path) {
            eprintln!("WARNING: Failed to remove {}: {}", path.display(), e);
            eprintln!("Remove it manually to prevent re-restore on next restart.");
        }
    }

    // 6. Records land as plaintext; mark so the next boot re-encrypts them under
    //    this node's current key as the storage layer loads each store.
    reencrypt::mark_reencrypt_pending(backup_restore_dir);

    record_startup_restore_audit(
        Some(key_source),
        backup_manifest
            .as_ref()
            .map(|manifest| {
                manifest
                    .source_domain
                    .as_str()
            }),
        Some(&target_domain),
        "success",
        if backup_manifest.is_none() {
            Some("legacy_import")
        } else {
            None
        },
        Some(zip_data.len()),
    );
    println!("Restore complete. Exiting for final restart...");
    true
}

#[derive(Debug)]
struct RestoreInstallationFailure {
    install_error: anyhow::Error,
    rollback_error: Option<anyhow::Error>,
}

fn install_staged_restore(
    staging_path: &std::path::Path,
    storage_root: &std::path::Path,
    had_existing_storage: bool,
    archive_path: &std::path::Path,
) -> Result<(), RestoreInstallationFailure> {
    install_staged_restore_with(storage_root, had_existing_storage, archive_path, || {
        clear_directory_contents(storage_root).and_then(|_| move_directory_contents(staging_path, storage_root))
    })
}

fn install_staged_restore_with(
    storage_root: &std::path::Path,
    had_existing_storage: bool,
    archive_path: &std::path::Path,
    install: impl FnOnce() -> anyhow::Result<()>,
) -> Result<(), RestoreInstallationFailure> {
    if let Err(install_error) = install() {
        let rollback_error = clear_directory_contents(storage_root)
            .and_then(|_| {
                if had_existing_storage {
                    let snapshot = std::fs::read(archive_path)?;
                    extract_zip_bytes_to_dir(&snapshot, storage_root)?;
                }
                Ok(())
            })
            .err();
        return Err(RestoreInstallationFailure { install_error, rollback_error });
    }
    Ok(())
}

/// Remove all files and subdirectories inside `dir` without removing `dir` itself.
/// This is necessary when `dir` is a Docker volume mount point — removing the mount
/// point itself will fail with "Permission denied".
fn clear_directory_contents(dir: &std::path::Path) -> anyhow::Result<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
        count += 1;
    }
    Ok(count)
}

fn move_directory_contents(
    source: &std::path::Path,
    target: &std::path::Path,
) -> anyhow::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(source)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        move_directory_entry(&entry.path(), &target.join(entry.file_name()))?;
    }
    Ok(())
}

fn move_directory_entry(
    source: &std::path::Path,
    target: &std::path::Path,
) -> anyhow::Result<()> {
    match std::fs::rename(source, target) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() != std::io::ErrorKind::CrossesDevices => return Err(error.into()),
        Err(_) => {}
    }

    if source.is_dir() {
        std::fs::create_dir(target)?;
        let mut entries: Vec<_> = std::fs::read_dir(source)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            move_directory_entry(&entry.path(), &target.join(entry.file_name()))?;
        }
        std::fs::remove_dir(source)?;
    } else if source.is_file() {
        std::fs::copy(source, target)?;
        std::fs::File::open(target)?.sync_all()?;
        std::fs::remove_file(source)?;
    } else {
        anyhow::bail!("restore staging contains an unsupported filesystem entry");
    }
    Ok(())
}

/// Validate a ZIP entry name is safe for extraction into `target_dir`.
///
/// Returns the sanitized relative path on success. Rejects:
/// - Absolute paths (starting with `/` or a Windows prefix)
/// - Paths containing `..` components
///
/// This check is independent of the zip crate's own normalization so that
/// safety does not depend on reader implementation details.
fn validated_entry_path(entry_name: &str) -> anyhow::Result<std::path::PathBuf> {
    use std::path::{Component, Path, PathBuf};

    let path = Path::new(entry_name);
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("ZIP contains unsafe path (absolute): {}", entry_name);
            }
            Component::ParentDir => {
                anyhow::bail!("ZIP contains unsafe path ('..' traversal): {}", entry_name);
            }
            Component::Normal(component) => normalized.push(component),
            Component::CurDir => {}
        }
    }
    if normalized
        .as_os_str()
        .is_empty()
    {
        anyhow::bail!("ZIP contains an empty entry path");
    }

    Ok(normalized)
}

pub(super) fn validate_zip_entries(zip_bytes: &[u8]) -> anyhow::Result<()> {
    validate_zip_entries_with_limits(zip_bytes, ARCHIVE_LIMITS)
}

fn validate_zip_entries_with_limits(
    zip_bytes: &[u8],
    limits: ArchiveLimits,
) -> anyhow::Result<()> {
    use std::collections::HashSet;
    use std::io::{Read, sink};

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))?;
    if archive.len() > limits.max_entries {
        anyhow::bail!("ZIP contains too many entries");
    }

    let mut seen_paths = HashSet::new();
    let mut file_paths = HashSet::new();
    let mut paths_with_children = HashSet::new();
    let mut total_uncompressed_bytes = 0u64;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name()?.into_owned();
        let path = validated_entry_path(&name)?;
        if !seen_paths.insert(path.clone()) {
            anyhow::bail!("ZIP contains duplicate entry path: {}", name);
        }
        if path
            .ancestors()
            .skip(1)
            .any(|ancestor| {
                !ancestor
                    .as_os_str()
                    .is_empty()
                    && file_paths.contains(ancestor)
            })
            || (!entry.is_dir() && paths_with_children.contains(&path))
        {
            anyhow::bail!("ZIP contains a file/directory path collision: {}", name);
        }
        for ancestor in path.ancestors().skip(1) {
            if !ancestor
                .as_os_str()
                .is_empty()
            {
                paths_with_children.insert(ancestor.to_path_buf());
            }
        }
        if !entry.is_dir() {
            file_paths.insert(path);
        }

        let uncompressed_bytes = entry.size();
        let compressed_bytes = entry.compressed_size();
        if uncompressed_bytes > limits.max_entry_uncompressed_bytes {
            anyhow::bail!("ZIP entry exceeds the uncompressed size limit: {}", name);
        }
        if name == manifest::MANIFEST_PATH && (entry.is_dir() || uncompressed_bytes > limits.max_manifest_bytes) {
            anyhow::bail!("backup manifest exceeds the size limit");
        }
        total_uncompressed_bytes = total_uncompressed_bytes
            .checked_add(uncompressed_bytes)
            .ok_or_else(|| anyhow::anyhow!("ZIP total uncompressed size overflow"))?;
        if total_uncompressed_bytes > limits.max_total_uncompressed_bytes {
            anyhow::bail!("ZIP exceeds the total uncompressed size limit");
        }
        if uncompressed_bytes > 0
            && (compressed_bytes == 0
                || uncompressed_bytes > compressed_bytes.saturating_mul(limits.max_compression_ratio))
        {
            anyhow::bail!("ZIP entry exceeds the compression ratio limit: {}", name);
        }

        if !entry.is_dir() {
            let expected_bytes = uncompressed_bytes;
            let actual_bytes = std::io::copy(
                &mut entry
                    .by_ref()
                    .take(limits.max_entry_uncompressed_bytes + 1),
                &mut sink(),
            )?;
            if actual_bytes != expected_bytes || actual_bytes > limits.max_entry_uncompressed_bytes {
                anyhow::bail!("ZIP entry size does not match its metadata: {}", name);
            }
        }
    }
    Ok(())
}

/// Extract a ZIP file into a target directory, preserving relative paths.
#[cfg(test)]
pub fn extract_zip_to_dir(
    zip_path: &std::path::Path,
    target_dir: &std::path::Path,
) -> anyhow::Result<usize> {
    let zip_bytes = std::fs::read(zip_path)?;
    extract_zip_bytes_to_dir(&zip_bytes, target_dir)
}

fn extract_zip_bytes_to_dir(
    zip_bytes: &[u8],
    target_dir: &std::path::Path,
) -> anyhow::Result<usize> {
    use std::io::Read;

    validate_zip_entries(zip_bytes)?;

    if !target_dir.is_dir() {
        anyhow::bail!("Target directory does not exist: {}", target_dir.display());
    }
    let canonical_target = target_dir.canonicalize()?;

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))?;
    let mut count = 0;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name()?.into_owned();
        if name == manifest::MANIFEST_PATH {
            continue;
        }

        // Primary guard: validate the raw entry name for absolute paths and
        // '..' traversal, independent of the zip crate's normalization.
        let rel_path = validated_entry_path(&name)?;

        let out_path = canonical_target.join(&rel_path);

        // Defense in depth: verify the resolved path is inside target_dir.
        if let Ok(canonical_out) = out_path.canonicalize() {
            if !canonical_out.starts_with(&canonical_target) {
                anyhow::bail!("ZIP entry resolves outside target directory: {}", name);
            }
        } else if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
            let canonical_parent = parent.canonicalize()?;
            if !canonical_parent.starts_with(&canonical_target) {
                anyhow::bail!("ZIP entry resolves outside target directory: {}", name);
            }
        }

        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut output = std::fs::File::create(&out_path)?;
            let written = std::io::copy(
                &mut entry
                    .by_ref()
                    .take(ARCHIVE_LIMITS.max_entry_uncompressed_bytes + 1),
                &mut output,
            )?;
            if written != entry.size() || written > ARCHIVE_LIMITS.max_entry_uncompressed_bytes {
                anyhow::bail!("ZIP entry size does not match its metadata: {}", name);
            }
            output.sync_all()?;
            count += 1;
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Create a temp dir with a `_storage` subtree containing known files.
    fn create_test_storage() -> TempDir {
        let dir = TempDir::new().unwrap();
        let storage = dir.path().join("_storage");

        let channels = storage.join("channels");
        fs::create_dir_all(&channels).unwrap();
        fs::write(channels.join("ch1.json"), r#"{"name":"test"}"#).unwrap();

        let nested = channels.join("sub");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("deep.txt"), "deep-content").unwrap();

        let metrics = storage.join("metrics");
        fs::create_dir_all(&metrics).unwrap();
        fs::write(metrics.join("m.json"), r#"{"v":1}"#).unwrap();

        dir
    }

    // ── backup tests ─────────────────────────────────────────────────────

    #[test]
    fn backup_creates_valid_zip() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");

        let zip_bytes = build_full_zip(&storage_root).expect("build_full_zip should succeed");

        // Must be a non-empty byte vector starting with ZIP magic bytes (PK)
        assert!(zip_bytes.len() > 4, "zip must not be empty");
        assert_eq!(&zip_bytes[0..2], &[0x50, 0x4B], "must start with PK magic");

        // Re-open the zip and verify expected entries exist
        let cursor = std::io::Cursor::new(&zip_bytes);
        let archive = zip::ZipArchive::new(cursor).expect("must be a valid zip archive");

        let names: Vec<String> = (0..archive.len())
            .map(|i| {
                archive
                    .name_for_index(i)
                    .unwrap()
                    .unwrap()
                    .to_string()
            })
            .collect();

        assert!(names.contains(&"channels/ch1.json".to_string()), "missing channels/ch1.json: {names:?}");
        assert!(names.contains(&"channels/sub/deep.txt".to_string()), "missing channels/sub/deep.txt: {names:?}");
        assert!(names.contains(&"metrics/m.json".to_string()), "missing metrics/m.json: {names:?}");
    }

    #[test]
    fn portable_zip_flattens_encrypted_files_to_plaintext() {
        use crate::encryption::{EncryptionService, KeySource};

        let dir = TempDir::new().unwrap();
        let storage = dir.path().join("_storage");
        let service = EncryptionService::new(KeySource::Raw { key: [5u8; 32] }).unwrap();

        // A whole-file `.json.enc` blob (envelope of the file bytes).
        let identity = storage.join("identity");
        fs::create_dir_all(&identity).unwrap();
        let identity_plain = r#"{"did":"did:key:z6Mk","private_key":"abc"}"#;
        let envelope = service
            .encrypt_string(identity_plain.to_string())
            .unwrap();
        fs::write(identity.join("x.json.enc"), envelope.as_bytes()).unwrap();

        // A `.json` file with a residual field-level `ENC[...]` value.
        let secrets = storage.join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        let field = service
            .encrypt_field("top-secret")
            .unwrap();
        fs::write(secrets.join("s.json"), format!(r#"{{"secret":"{field}"}}"#)).unwrap();

        let zip_bytes = build_zip(&storage, true, Some(&service)).expect("portable zip should build");

        let cursor = std::io::Cursor::new(&zip_bytes);
        let mut archive = zip::ZipArchive::new(cursor).expect("valid zip");
        let names: Vec<String> = (0..archive.len())
            .map(|i| {
                archive
                    .name_for_index(i)
                    .unwrap()
                    .unwrap()
                    .to_string()
            })
            .collect();

        // The `.json.enc` blob is renamed to `.json`; no encrypted entry remains.
        assert!(names.contains(&"identity/x.json".to_string()), "expected renamed plaintext entry: {names:?}");
        assert!(
            !names
                .iter()
                .any(|n| n.ends_with(".enc")),
            "no .enc entry may remain: {names:?}"
        );

        // Whole-file blob content is the decrypted plaintext.
        let mut identity_out = String::new();
        {
            use std::io::Read;
            archive
                .by_name("identity/x.json")
                .unwrap()
                .read_to_string(&mut identity_out)
                .unwrap();
        }
        assert_eq!(identity_out, identity_plain);

        // Field-level `ENC[...]` value is flattened to plaintext.
        let mut secret_out = String::new();
        {
            use std::io::Read;
            archive
                .by_name("secrets/s.json")
                .unwrap()
                .read_to_string(&mut secret_out)
                .unwrap();
        }
        let parsed: serde_json::Value = serde_json::from_str(&secret_out).unwrap();
        assert_eq!(parsed["secret"], serde_json::Value::String("top-secret".to_string()));
    }

    #[test]
    fn portable_zip_contains_agent_stream_domain_manifest() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");

        let zip_bytes = build_portable_zip(&storage_root, "Agent.Example.com.").unwrap();
        let manifest = manifest::validate_backup_manifest(&zip_bytes, "agent.example.com").unwrap();

        assert_eq!(manifest.product, "agent-stream");
        assert_eq!(manifest.source_domain, "agent.example.com");
    }

    #[test]
    fn portable_zip_rejects_storage_collision_with_reserved_manifest() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let reserved = storage_root.join(manifest::MANIFEST_PATH);
        fs::create_dir_all(reserved.parent().unwrap()).unwrap();
        fs::write(reserved, b"untrusted").unwrap();

        assert!(build_portable_zip(&storage_root, "agent.example.com").is_err());
    }

    // ── restore tests ────────────────────────────────────────────────────

    fn stage_current_v2_backup(
        storage_root: &std::path::Path,
        backup_restore_dir: &std::path::Path,
    ) -> String {
        let key = [0x31; 32];
        let zip_bytes =
            manifest::add_backup_manifest(&build_full_zip(storage_root).unwrap(), "agent.example.com", false).unwrap();
        let encrypted = encryption::encrypt_backup(&key, &zip_bytes).unwrap();
        fs::write(backup_restore_dir.join("backup.asbak"), encrypted).unwrap();
        "31".repeat(32)
    }

    #[test]
    fn startup_rejects_plaintext_backup_without_mutating_storage() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let original = fs::read(storage_root.join("channels/ch1.json")).unwrap();
        let zip_bytes = build_full_zip(&storage_root).unwrap();
        fs::write(backup_restore_dir.join("backup.asbak"), zip_bytes).unwrap();

        let restored = check_and_restore_backup(
            &storage_root,
            &backup_restore_dir,
            Some(&"31".repeat(32)),
            None,
            "agent.example.com",
        );

        assert!(!restored);
        assert_eq!(fs::read(storage_root.join("channels/ch1.json")).unwrap(), original);
    }

    #[test]
    fn startup_rejects_plaintext_even_with_valid_manifest() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let original = fs::read(storage_root.join("channels/ch1.json")).unwrap();
        let zip_bytes =
            manifest::add_backup_manifest(&build_full_zip(&storage_root).unwrap(), "agent.example.com", false).unwrap();
        fs::write(backup_restore_dir.join("backup.asbak"), zip_bytes).unwrap();

        let restored = check_and_restore_backup(
            &storage_root,
            &backup_restore_dir,
            Some(&"31".repeat(32)),
            None,
            "agent.example.com",
        );

        assert!(!restored);
        assert_eq!(fs::read(storage_root.join("channels/ch1.json")).unwrap(), original);
    }

    #[test]
    fn startup_rejects_cross_domain_backup_without_mutating_storage() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let original = fs::read(storage_root.join("channels/ch1.json")).unwrap();
        let key = [0x31; 32];
        let zip_bytes =
            manifest::add_backup_manifest(&build_full_zip(&storage_root).unwrap(), "source.example.com", false)
                .unwrap();
        let encrypted = encryption::encrypt_backup(&key, &zip_bytes).unwrap();
        fs::write(backup_restore_dir.join("backup.asbak"), encrypted).unwrap();

        let restored = check_and_restore_backup(
            &storage_root,
            &backup_restore_dir,
            Some(&"31".repeat(32)),
            None,
            "target.example.com",
        );

        assert!(!restored);
        assert_eq!(fs::read(storage_root.join("channels/ch1.json")).unwrap(), original);
    }

    #[test]
    fn startup_rejects_unsafe_zip_path_without_mutating_storage() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let original = fs::read(storage_root.join("channels/ch1.json")).unwrap();
        let zip_bytes =
            manifest::add_backup_manifest(&make_zip_with_entry("../outside.json", b"{}"), "agent.example.com", false)
                .unwrap();
        let encrypted = encryption::encrypt_backup(&[0x31; 32], &zip_bytes).unwrap();
        fs::write(backup_restore_dir.join("backup.asbak"), encrypted).unwrap();

        let restored = check_and_restore_backup(
            &storage_root,
            &backup_restore_dir,
            Some(&"31".repeat(32)),
            None,
            "agent.example.com",
        );

        assert!(!restored);
        assert_eq!(fs::read(storage_root.join("channels/ch1.json")).unwrap(), original);
        assert!(
            !dir.path()
                .join("outside.json")
                .exists()
        );
    }

    #[test]
    fn startup_rejects_corrupt_compressed_payload_without_mutating_storage() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let original = fs::read(storage_root.join("channels/ch1.json")).unwrap();
        let zip_bytes = make_zip_with_entries(
            &[("channels/replacement.json", &vec![b'x'; 4096])],
            zip::CompressionMethod::Deflated,
        );
        let corrupted = corrupt_first_entry_payload(zip_bytes);
        let with_manifest = manifest::add_backup_manifest(&corrupted, "agent.example.com", false).unwrap();
        let encrypted = encryption::encrypt_backup(&[0x31; 32], &with_manifest).unwrap();
        fs::write(backup_restore_dir.join("backup.asbak"), encrypted).unwrap();

        let restored = check_and_restore_backup(
            &storage_root,
            &backup_restore_dir,
            Some(&"31".repeat(32)),
            None,
            "agent.example.com",
        );

        assert!(!restored);
        assert_eq!(fs::read(storage_root.join("channels/ch1.json")).unwrap(), original);
        assert!(
            !storage_root
                .join("channels/replacement.json")
                .exists()
        );
    }

    #[test]
    fn encrypted_startup_restore_rejects_the_former_default_key_when_unconfigured() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let original = fs::read_to_string(storage_root.join("channels/ch1.json")).unwrap();
        let zip_bytes = build_full_zip(&storage_root).unwrap();
        let former_default_key = [
            0x7a, 0x3f, 0x9b, 0x12, 0xe4, 0x58, 0xc1, 0xd6, 0x0a, 0x8e, 0x47, 0xf3, 0x2b, 0x91, 0x6d, 0xc5, 0xe8, 0x14,
            0xa7, 0x3d, 0x5f, 0x02, 0xb9, 0x86, 0xcd, 0x43, 0x70, 0x1e, 0xf6, 0x59, 0x28, 0xab,
        ];
        let encrypted = encryption::encrypt_backup(&former_default_key, &zip_bytes).unwrap();
        let backup_path = backup_restore_dir.join("backup.asbak");
        fs::write(&backup_path, &encrypted).unwrap();

        let restored = check_and_restore_backup(&storage_root, &backup_restore_dir, None, None, "agent.example.com");

        assert!(!restored);
        assert_eq!(fs::read_to_string(storage_root.join("channels/ch1.json")).unwrap(), original);
        assert_eq!(fs::read(backup_path).unwrap(), encrypted);
    }

    #[test]
    fn startup_current_key_rejects_manifestless_encrypted_backup() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let original = fs::read(storage_root.join("channels/ch1.json")).unwrap();
        let encrypted = encryption::encrypt_backup(&[0x31; 32], &build_full_zip(&storage_root).unwrap()).unwrap();
        fs::write(backup_restore_dir.join("backup.asbak"), encrypted).unwrap();

        let restored = check_and_restore_backup(
            &storage_root,
            &backup_restore_dir,
            Some(&"31".repeat(32)),
            None,
            "agent.example.com",
        );

        assert!(!restored);
        assert_eq!(fs::read(storage_root.join("channels/ch1.json")).unwrap(), original);
    }

    #[test]
    fn startup_accepts_manifestless_backup_only_with_explicit_legacy_key() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let encrypted = encryption::encrypt_backup(&[0x32; 32], &build_full_zip(&storage_root).unwrap()).unwrap();
        fs::write(backup_restore_dir.join("backup.asbak"), encrypted).unwrap();
        let legacy_keys = "32".repeat(32);

        let restored = check_and_restore_backup(
            &storage_root,
            &backup_restore_dir,
            Some(&"31".repeat(32)),
            Some(&legacy_keys),
            "agent.example.com",
        );

        assert!(restored);
    }

    #[test]
    fn encrypted_startup_restore_accepts_an_explicit_key() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let zip_bytes =
            manifest::add_backup_manifest(&build_full_zip(&storage_root).unwrap(), "agent.example.com", false).unwrap();
        let key = [0xaa; 32];
        let encrypted = encryption::encrypt_backup(&key, &zip_bytes).unwrap();
        let backup_path = backup_restore_dir.join("backup.asbak");
        fs::write(&backup_path, encrypted).unwrap();
        let key_hex = "aa".repeat(32);

        let restored =
            check_and_restore_backup(&storage_root, &backup_restore_dir, Some(&key_hex), None, "agent.example.com");

        assert!(restored);
        assert!(!backup_path.exists());
        assert!(
            storage_root
                .join("channels/ch1.json")
                .exists()
        );
    }

    #[test]
    fn restore_removes_pre_restore_snapshot_after_success() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();

        let key_hex = stage_current_v2_backup(&storage_root, &backup_restore_dir);

        let restored =
            check_and_restore_backup(&storage_root, &backup_restore_dir, Some(&key_hex), None, "agent.example.com");
        assert!(restored, "restore must succeed");

        let local_backups = backup_restore_dir.join(LOCAL_BACKUPS_DIR);
        let archives: Vec<_> = fs::read_dir(&local_backups)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert!(archives.is_empty(), "pre-restore snapshots must not remain after success");
    }

    #[test]
    fn failed_install_restores_the_pre_restore_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let storage_root = directory
            .path()
            .join("_storage");
        std::fs::create_dir_all(&storage_root).unwrap();
        std::fs::write(storage_root.join("original.json"), b"original").unwrap();
        let snapshot_path = directory
            .path()
            .join("snapshot.zip");
        std::fs::write(&snapshot_path, build_full_zip(&storage_root).unwrap()).unwrap();

        let failure = install_staged_restore_with(&storage_root, true, &snapshot_path, || {
            clear_directory_contents(&storage_root)?;
            std::fs::write(storage_root.join("partial.json"), b"partial")?;
            anyhow::bail!("injected installation failure")
        })
        .unwrap_err();

        assert!(
            failure
                .rollback_error
                .is_none()
        );
        assert_eq!(std::fs::read(storage_root.join("original.json")).unwrap(), b"original");
        assert!(
            !storage_root
                .join("partial.json")
                .exists()
        );
    }

    #[test]
    fn restore_extracts_zip_contents() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();

        let backup_zip_path = backup_restore_dir.join("backup.asbak");
        let key_hex = stage_current_v2_backup(&storage_root, &backup_restore_dir);

        let restored =
            check_and_restore_backup(&storage_root, &backup_restore_dir, Some(&key_hex), None, "agent.example.com");
        assert!(restored, "restore must succeed");

        // backup.asbak must have been removed
        assert!(!backup_zip_path.exists(), "backup.asbak should be removed after restore");

        // _storage must exist again (it was deleted then re-created from the zip)
        assert!(storage_root.is_dir(), "_storage must be recreated");
    }

    #[test]
    fn restores_backup_staged_under_legacy_name() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let key_hex = stage_current_v2_backup(&storage_root, &backup_restore_dir);
        let legacy_path = backup_restore_dir.join(LEGACY_BACKUP_FILE_NAME);
        fs::rename(backup_restore_dir.join(BACKUP_FILE_NAME), &legacy_path).unwrap();

        let restored =
            check_and_restore_backup(&storage_root, &backup_restore_dir, Some(&key_hex), None, "agent.example.com");

        assert!(restored, "a legacy-named backup must restore");
        assert!(!legacy_path.exists(), "the legacy file is removed after restore");
        assert!(
            storage_root
                .join("channels/ch1.json")
                .exists()
        );
    }

    #[test]
    fn restore_removes_a_leftover_legacy_backup() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();
        let key_hex = stage_current_v2_backup(&storage_root, &backup_restore_dir);
        let legacy_path = backup_restore_dir.join(LEGACY_BACKUP_FILE_NAME);
        fs::write(&legacy_path, b"stale").unwrap();

        let restored =
            check_and_restore_backup(&storage_root, &backup_restore_dir, Some(&key_hex), None, "agent.example.com");

        assert!(restored);
        assert!(!legacy_path.exists(), "a stale legacy file must not be restored on the next start");
        assert!(
            !backup_restore_dir
                .join(BACKUP_FILE_NAME)
                .exists()
        );
    }

    #[test]
    fn restore_structure_matches_original() {
        let dir = create_test_storage();
        let storage_root = dir.path().join("_storage");
        let backup_restore_dir = dir
            .path()
            .join("_backup_restore");
        fs::create_dir_all(&backup_restore_dir).unwrap();

        // Snapshot original file contents before restore
        let orig_ch1 = fs::read_to_string(storage_root.join("channels/ch1.json")).unwrap();
        let orig_deep = fs::read_to_string(storage_root.join("channels/sub/deep.txt")).unwrap();
        let orig_m = fs::read_to_string(storage_root.join("metrics/m.json")).unwrap();

        let key_hex = stage_current_v2_backup(&storage_root, &backup_restore_dir);

        let restored =
            check_and_restore_backup(&storage_root, &backup_restore_dir, Some(&key_hex), None, "agent.example.com");
        assert!(restored, "restore must succeed");

        // Verify every file exists with identical content
        assert_eq!(
            fs::read_to_string(storage_root.join("channels/ch1.json")).unwrap(),
            orig_ch1,
            "channels/ch1.json content must match"
        );
        assert_eq!(
            fs::read_to_string(storage_root.join("channels/sub/deep.txt")).unwrap(),
            orig_deep,
            "channels/sub/deep.txt content must match"
        );
        assert_eq!(
            fs::read_to_string(storage_root.join("metrics/m.json")).unwrap(),
            orig_m,
            "metrics/m.json content must match"
        );

        // Verify no unexpected top-level dirs leaked in
        let restored_dirs: Vec<String> = fs::read_dir(&storage_root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();

        assert!(restored_dirs.contains(&"channels".to_string()));
        assert!(restored_dirs.contains(&"metrics".to_string()));
        assert_eq!(restored_dirs.len(), 2, "only channels and metrics expected at top level");
    }

    // ── path-traversal security tests ────────────────────────────────────

    fn make_zip_with_entries(
        entries: &[(&str, &[u8])],
        compression_method: zip::CompressionMethod,
    ) -> Vec<u8> {
        use std::io::{Cursor, Write};
        use zip::write::{FileOptions, SimpleFileOptions, ZipWriter};

        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let options: SimpleFileOptions = FileOptions::default().compression_method(compression_method);
        for (entry_name, content) in entries {
            zip.start_file(*entry_name, options)
                .unwrap();
            zip.write_all(content)
                .unwrap();
        }
        zip.finish()
            .unwrap()
            .into_inner()
    }

    fn make_zip_with_entry(
        entry_name: &str,
        content: &[u8],
    ) -> Vec<u8> {
        make_zip_with_entries(&[(entry_name, content)], zip::CompressionMethod::Stored)
    }

    fn corrupt_first_entry_payload(mut zip_bytes: Vec<u8>) -> Vec<u8> {
        let name_len = u16::from_le_bytes([zip_bytes[26], zip_bytes[27]]) as usize;
        let extra_len = u16::from_le_bytes([zip_bytes[28], zip_bytes[29]]) as usize;
        let compressed_size = u32::from_le_bytes([zip_bytes[18], zip_bytes[19], zip_bytes[20], zip_bytes[21]]) as usize;
        let data_start = 30 + name_len + extra_len;
        zip_bytes[data_start + compressed_size / 2] ^= 0xff;
        zip_bytes
    }

    fn test_archive_limits() -> ArchiveLimits {
        ArchiveLimits {
            max_entries: 10,
            max_entry_uncompressed_bytes: 1024,
            max_total_uncompressed_bytes: 4096,
            max_compression_ratio: 1000,
            max_manifest_bytes: 1024,
        }
    }

    #[test]
    fn zip_validation_enforces_entry_and_expansion_limits() {
        let two_entries = make_zip_with_entries(&[("one", b"1"), ("two", b"2")], zip::CompressionMethod::Stored);
        assert!(
            validate_zip_entries_with_limits(
                &two_entries,
                ArchiveLimits {
                    max_entries: 1,
                    ..test_archive_limits()
                },
            )
            .is_err()
        );

        let oversized_entry = make_zip_with_entry("large", b"1234");
        assert!(
            validate_zip_entries_with_limits(
                &oversized_entry,
                ArchiveLimits {
                    max_entry_uncompressed_bytes: 3,
                    ..test_archive_limits()
                },
            )
            .is_err()
        );

        assert!(
            validate_zip_entries_with_limits(
                &two_entries,
                ArchiveLimits {
                    max_total_uncompressed_bytes: 1,
                    ..test_archive_limits()
                },
            )
            .is_err()
        );

        let manifest = make_zip_with_entry(manifest::MANIFEST_PATH, b"1234");
        assert!(
            validate_zip_entries_with_limits(
                &manifest,
                ArchiveLimits {
                    max_manifest_bytes: 3,
                    ..test_archive_limits()
                },
            )
            .is_err()
        );

        let compressible = make_zip_with_entries(&[("compressed", &vec![0; 1024])], zip::CompressionMethod::Deflated);
        assert!(
            validate_zip_entries_with_limits(
                &compressible,
                ArchiveLimits {
                    max_compression_ratio: 2,
                    ..test_archive_limits()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn zip_validation_rejects_corrupt_payload_and_path_collisions() {
        let compressed = make_zip_with_entries(&[("payload", &vec![b'x'; 4096])], zip::CompressionMethod::Deflated);
        assert!(validate_zip_entries(&corrupt_first_entry_payload(compressed)).is_err());

        let duplicate = make_zip_with_entries(&[("same", b"one"), ("./same", b"two")], zip::CompressionMethod::Stored);
        assert!(validate_zip_entries(&duplicate).is_err());

        let collision =
            make_zip_with_entries(&[("parent", b"file"), ("parent/child", b"child")], zip::CompressionMethod::Stored);
        assert!(validate_zip_entries(&collision).is_err());
    }

    #[test]
    fn validated_entry_path_rejects_absolute_paths() {
        let cases = ["/etc/evil.conf", "/home/user/.ssh/authorized_keys", "/tmp/pwned"];
        for name in &cases {
            let result = validated_entry_path(name);
            assert!(result.is_err(), "should reject absolute path: {name}");
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("absolute"),
                "error for {name} should mention 'absolute'"
            );
        }
    }

    #[test]
    fn validated_entry_path_rejects_dot_dot_traversal() {
        let cases = ["../../../etc/passwd", "foo/../../bar", "a/../../../outside"];
        for name in &cases {
            let result = validated_entry_path(name);
            assert!(result.is_err(), "should reject '..' traversal: {name}");
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("traversal"),
                "error for {name} should mention 'traversal'"
            );
        }
    }

    #[test]
    fn validated_entry_path_accepts_safe_names() {
        let cases = ["channels/ch1.json", "subdir/nested/file.txt", "root-file.json", "./current-dir-file.txt"];
        for name in &cases {
            let result = validated_entry_path(name);
            assert!(result.is_ok(), "should accept safe name: {name}");
        }
    }

    #[test]
    fn extract_rejects_dot_dot_traversal() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("output");
        fs::create_dir_all(&target).unwrap();

        let zip_bytes = make_zip_with_entry("../../../etc/passwd", b"malicious");
        let zip_path = dir.path().join("evil.zip");
        fs::write(&zip_path, &zip_bytes).unwrap();

        let result = extract_zip_to_dir(&zip_path, &target);
        assert!(result.is_err(), ".. traversal entry must be rejected");
    }

    #[test]
    fn extract_accepts_safe_relative_paths() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("output");
        fs::create_dir_all(&target).unwrap();

        let zip_bytes = make_zip_with_entry("subdir/safe.txt", b"ok");
        let zip_path = dir.path().join("safe.zip");
        fs::write(&zip_path, &zip_bytes).unwrap();

        let count = extract_zip_to_dir(&zip_path, &target).expect("safe path must succeed");
        assert_eq!(count, 1);
        assert_eq!(fs::read_to_string(target.join("subdir/safe.txt")).unwrap(), "ok");
    }
}
