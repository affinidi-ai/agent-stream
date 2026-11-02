use axum::{
    Extension, Json,
    body::Body,
    extract::{Multipart, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tracing::{error, info, warn};

use crate::identity::state::IdentityApiState;

use super::audit::{StorageAuditEvent, StorageOperation, record_storage_audit};
use super::encryption::{
    BackupKeySource, decrypt_backup_with_keys, encrypt_backup, is_encrypted_backup, resolve_backup_key_checked,
    resolve_legacy_backup_keys,
};

static RESTORE_STAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn append_backup_chunk_with_limit(
    data: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> bool {
    let Some(new_len) = data
        .len()
        .checked_add(chunk.len())
    else {
        return false;
    };
    if new_len > limit {
        return false;
    }
    data.extend_from_slice(chunk);
    true
}

fn append_backup_chunk(
    data: &mut Vec<u8>,
    chunk: &[u8],
) -> bool {
    append_backup_chunk_with_limit(data, chunk, super::MAX_ENCRYPTED_ARCHIVE_BYTES)
}

fn stage_backup_atomically(
    backup_restore_dir: &std::path::Path,
    data: &[u8],
) -> anyhow::Result<std::path::PathBuf> {
    use std::io::Write;

    let _guard = RESTORE_STAGE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("restore staging lock is poisoned"))?;
    let target = backup_restore_dir.join(super::BACKUP_FILE_NAME);
    let temporary = backup_restore_dir.join(format!(".{}.{}.tmp", super::BACKUP_FILE_NAME, std::process::id()));
    if temporary.exists() {
        std::fs::remove_file(&temporary)?;
    }
    let result = (|| -> anyhow::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &target)?;
        std::fs::File::open(backup_restore_dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;
    Ok(target)
}

#[derive(Debug)]
struct PreparedRestore {
    zip_data: Vec<u8>,
    key_source: BackupKeySource,
    manifest: super::manifest::BackupManifest,
}

#[derive(Debug)]
struct RestorePreparationError {
    cause: anyhow::Error,
    category: &'static str,
    key_source: Option<BackupKeySource>,
    source_domain: Option<String>,
}

impl std::fmt::Display for RestorePreparationError {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        self.cause.fmt(formatter)
    }
}

fn preparation_error(
    cause: impl Into<anyhow::Error>,
    category: &'static str,
    key_source: Option<BackupKeySource>,
    source_domain: Option<String>,
) -> RestorePreparationError {
    RestorePreparationError {
        cause: cause.into(),
        category,
        key_source,
        source_domain,
    }
}

fn prepare_restore_upload(
    backup_data: &[u8],
    current_key: &[u8; 32],
    legacy_keys: &[[u8; 32]],
    target_domain: &str,
) -> Result<PreparedRestore, RestorePreparationError> {
    if !is_encrypted_backup(backup_data) {
        return Err(preparation_error(anyhow::anyhow!("backup is not encrypted"), "encryption_required", None, None));
    }

    let decrypted = decrypt_backup_with_keys(current_key, legacy_keys, backup_data)
        .map_err(|error| preparation_error(error, "authentication_failed", None, None))?;
    let key_source = decrypted.key_source;
    super::validate_zip_entries(&decrypted.bytes)
        .map_err(|error| preparation_error(error, "zip_invalid", Some(key_source), None))?;
    let parsed_manifest = super::manifest::read_optional_backup_manifest(&decrypted.bytes)
        .map_err(|error| preparation_error(error, "manifest_invalid", Some(key_source), None))?;
    let source_domain = parsed_manifest
        .as_ref()
        .and_then(|manifest| super::manifest::canonicalize_domain(&manifest.source_domain).ok());
    let (zip_data, manifest) = match parsed_manifest {
        Some(manifest) => {
            let manifest =
                super::manifest::validate_parsed_backup_manifest(manifest, target_domain).map_err(|error| {
                    preparation_error(error, "manifest_invalid", Some(key_source), source_domain.clone())
                })?;
            (decrypted.bytes, manifest)
        }
        None if key_source == BackupKeySource::Legacy => {
            let zip_data = super::manifest::add_backup_manifest(&decrypted.bytes, target_domain, true)
                .map_err(|error| preparation_error(error, "manifest_migration_failed", Some(key_source), None))?;
            let manifest = super::manifest::validate_backup_manifest(&zip_data, target_domain)
                .map_err(|error| preparation_error(error, "manifest_migration_failed", Some(key_source), None))?;
            (zip_data, manifest)
        }
        None => {
            return Err(preparation_error(
                anyhow::anyhow!("backup manifest is required"),
                "manifest_missing",
                Some(key_source),
                None,
            ));
        }
    };

    Ok(PreparedRestore { zip_data, key_source, manifest })
}

fn record_api_restore_failure(
    user_id: &str,
    target_domain: &str,
    failure_category: &'static str,
    archive_size_bytes: Option<usize>,
) {
    record_api_restore_failure_with_context(user_id, target_domain, failure_category, archive_size_bytes, None, None);
}

fn record_api_restore_failure_with_context(
    user_id: &str,
    target_domain: &str,
    failure_category: &'static str,
    archive_size_bytes: Option<usize>,
    key_source: Option<&str>,
    source_domain: Option<&str>,
) {
    record_storage_audit(StorageAuditEvent {
        operation: StorageOperation::Restore,
        actor_id: user_id,
        actor_type: "user",
        restore_path: Some("api"),
        key_source,
        source_domain,
        target_domain: Some(target_domain),
        outcome: "failure",
        failure_category: Some(failure_category),
        archive_size_bytes,
    });
}

/// Backup storage: zip the entire `_storage` folder (including PIIs), encrypt, and return as `backup.asbak`.
pub async fn backup_storage(
    Extension(user_id): Extension<String>,
    State(state): State<IdentityApiState>,
) -> Response {
    let source_domain = state
        .network_config
        .did
        .domain
        .clone();
    record_storage_audit(StorageAuditEvent {
        operation: StorageOperation::Backup,
        actor_id: &user_id,
        actor_type: "user",
        restore_path: None,
        key_source: None,
        source_domain: Some(&source_domain),
        target_domain: None,
        outcome: "attempt",
        failure_category: None,
        archive_size_bytes: None,
    });
    info!("Full storage backup requested via API (skipped directories: {:?})", super::BACKUP_SKIP_DIRS);

    let storage_root = crate::export::resolve_storage_root(
        &state
            .bootstrap_config
            .storage_paths
            .agent_surfaces,
        "",
    );
    let backup_key_config = state
        .bootstrap_config
        .backup_encryption_key
        .clone();
    let build_domain = source_domain.clone();
    let result = tokio::task::spawn_blocking(move || {
        let key = resolve_backup_key_checked(backup_key_config.as_deref())?;
        let zip_bytes = super::build_portable_zip(&storage_root, &build_domain)?;
        let encrypted = encrypt_backup(&key, &zip_bytes)?;
        if encrypted.len() > super::MAX_ENCRYPTED_ARCHIVE_BYTES {
            anyhow::bail!("generated backup exceeds the 64 MiB archive limit");
        }
        Ok(encrypted)
    })
    .await;

    match result {
        Ok(Ok(encrypted_bytes)) => {
            let size = encrypted_bytes.len();
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Backup,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: None,
                key_source: Some("current"),
                source_domain: Some(&source_domain),
                target_domain: None,
                outcome: "success",
                failure_category: None,
                archive_size_bytes: Some(size),
            });
            info!("Encrypted storage backup complete: {} bytes", size);

            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            headers
                .insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=\"backup.asbak\""));
            (StatusCode::OK, headers, Body::from(encrypted_bytes)).into_response()
        }
        Ok(Err(e)) => {
            error!("Storage backup failed: {:#}", e);
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Backup,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: None,
                key_source: None,
                source_domain: Some(&source_domain),
                target_domain: None,
                outcome: "failure",
                failure_category: Some("backup_failed"),
                archive_size_bytes: None,
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Backup failed"}))).into_response()
        }
        Err(e) => {
            error!("Storage backup task panicked: {:#}", e);
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Backup,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: None,
                key_source: None,
                source_domain: Some(&source_domain),
                target_domain: None,
                outcome: "failure",
                failure_category: Some("task_failed"),
                archive_size_bytes: None,
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Backup task failed"})))
                .into_response()
        }
    }
}

/// Restore storage: authenticate and validate `backup.asbak`, stage it encrypted, then exit.
pub async fn restore_storage(
    Extension(user_id): Extension<String>,
    State(state): State<IdentityApiState>,
    mut multipart: Multipart,
) -> Response {
    let target_domain = state
        .network_config
        .did
        .domain
        .clone();
    record_storage_audit(StorageAuditEvent {
        operation: StorageOperation::Restore,
        actor_id: &user_id,
        actor_type: "user",
        restore_path: Some("api"),
        key_source: None,
        source_domain: None,
        target_domain: Some(&target_domain),
        outcome: "attempt",
        failure_category: None,
        archive_size_bytes: None,
    });
    info!("Storage restore requested via API");

    let mut backup_data = None;
    while let Some(mut field) = match multipart.next_field().await {
        Ok(field) => field,
        Err(e) => {
            warn!("Failed to read restore multipart field: {e}");
            record_api_restore_failure(&user_id, &target_domain, "multipart_invalid", None);
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Failed to read backup upload"})))
                .into_response();
        }
    } {
        if field.name() == Some("backup") {
            let mut data = Vec::new();
            loop {
                match field.chunk().await {
                    Ok(Some(chunk)) => {
                        let attempted_size = data
                            .len()
                            .saturating_add(chunk.len());
                        if !append_backup_chunk(&mut data, &chunk) {
                            record_api_restore_failure(
                                &user_id,
                                &target_domain,
                                "archive_too_large",
                                Some(attempted_size),
                            );
                            return (
                                StatusCode::PAYLOAD_TOO_LARGE,
                                Json(serde_json::json!({"error": "Backup archive exceeds the 64 MiB limit"})),
                            )
                                .into_response();
                        }
                    }
                    Ok(None) => {
                        backup_data = Some(data);
                        break;
                    }
                    Err(e) => {
                        warn!("Failed to read restore file data: {e}");
                        record_api_restore_failure(&user_id, &target_domain, "upload_read_failed", Some(data.len()));
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "Failed to read backup upload"})),
                        )
                            .into_response();
                    }
                }
            }
            break;
        }
    }

    let backup_data = match backup_data {
        Some(data) => data,
        None => {
            record_api_restore_failure(&user_id, &target_domain, "backup_missing", None);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "No backup file provided. Upload a field named 'backup'."})),
            )
                .into_response();
        }
    };

    let current_key = match resolve_backup_key_checked(
        state
            .bootstrap_config
            .backup_encryption_key
            .as_deref(),
    ) {
        Ok(key) => key,
        Err(e) => {
            warn!("Cannot resolve backup encryption key: {e}");
            record_api_restore_failure(&user_id, &target_domain, "key_unavailable", Some(backup_data.len()));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Backup encryption is unavailable"})),
            )
                .into_response();
        }
    };
    let legacy_keys = match resolve_legacy_backup_keys(
        state
            .bootstrap_config
            .legacy_backup_encryption_keys
            .as_deref(),
    ) {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Legacy backup key configuration is invalid: {e}");
            record_api_restore_failure(
                &user_id,
                &target_domain,
                "legacy_key_configuration_invalid",
                Some(backup_data.len()),
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Backup encryption is unavailable"})),
            )
                .into_response();
        }
    };

    let prepared = match prepare_restore_upload(&backup_data, &current_key, &legacy_keys, &target_domain) {
        Ok(prepared) => prepared,
        Err(e) => {
            warn!("Backup validation failed: {e}");
            let key_source = e
                .key_source
                .map(|source| match source {
                    BackupKeySource::Current => "current",
                    BackupKeySource::Legacy => "legacy",
                });
            record_api_restore_failure_with_context(
                &user_id,
                &target_domain,
                e.category,
                Some(backup_data.len()),
                key_source,
                e.source_domain.as_deref(),
            );
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Backup validation failed"})))
                .into_response();
        }
    };
    let key_source = match prepared.key_source {
        BackupKeySource::Current => "current",
        BackupKeySource::Legacy => "legacy",
    };
    let source_domain = prepared
        .manifest
        .source_domain
        .clone();
    let staged_data = match encrypt_backup(&current_key, &prepared.zip_data) {
        Ok(staged_data) => staged_data,
        Err(e) => {
            error!("Failed to encrypt staged restore: {e}");
            record_storage_audit(StorageAuditEvent {
                operation: StorageOperation::Restore,
                actor_id: &user_id,
                actor_type: "user",
                restore_path: Some("api"),
                key_source: Some(key_source),
                source_domain: Some(&source_domain),
                target_domain: Some(&target_domain),
                outcome: "failure",
                failure_category: Some("staging_encryption_failed"),
                archive_size_bytes: Some(prepared.zip_data.len()),
            });
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to stage backup restore"})),
            )
                .into_response();
        }
    };

    let backup_restore_dir = std::path::PathBuf::from(
        &state
            .bootstrap_config
            .storage_paths
            .backup_restore,
    );
    if let Err(e) = std::fs::create_dir_all(&backup_restore_dir) {
        error!("Failed to create backups directory: {e}");
        record_api_restore_failure_with_context(
            &user_id,
            &target_domain,
            "staging_directory_failed",
            Some(staged_data.len()),
            Some(key_source),
            Some(&source_domain),
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to stage backup restore"})),
        )
            .into_response();
    }

    let backup_zip_path = match stage_backup_atomically(&backup_restore_dir, &staged_data) {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to write backup.asbak: {e}");
            record_api_restore_failure_with_context(
                &user_id,
                &target_domain,
                "staging_write_failed",
                Some(staged_data.len()),
                Some(key_source),
                Some(&source_domain),
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to stage backup restore"})),
            )
                .into_response();
        }
    };

    record_storage_audit(StorageAuditEvent {
        operation: StorageOperation::Restore,
        actor_id: &user_id,
        actor_type: "user",
        restore_path: Some("api"),
        key_source: Some(key_source),
        source_domain: Some(&source_domain),
        target_domain: Some(&target_domain),
        outcome: "success",
        failure_category: None,
        archive_size_bytes: Some(staged_data.len()),
    });
    info!(
        "backup.asbak written to {} ({} bytes, encrypted). Exiting for restart... Note: backup does not include directories {:?}",
        backup_zip_path.display(),
        staged_data.len(),
        super::BACKUP_SKIP_DIRS
    );

    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        warn!("Exiting with code 1 to trigger restart for backup restore");
        std::process::exit(1);
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "message": "backup.asbak saved. The service will restart to complete the restore."
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_upload_chunks_are_bounded_before_append() {
        let mut data = b"1234".to_vec();
        assert!(append_backup_chunk_with_limit(&mut data, b"56", 6));
        assert_eq!(data, b"123456");
        assert!(!append_backup_chunk_with_limit(&mut data, b"7", 6));
        assert_eq!(data, b"123456");
    }

    fn sample_zip() -> Vec<u8> {
        use std::io::{Cursor, Write};
        use zip::write::{FileOptions, SimpleFileOptions, ZipWriter};

        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let options: SimpleFileOptions = FileOptions::default();
        zip.start_file("record.json", options)
            .unwrap();
        zip.write_all(b"{}").unwrap();
        zip.finish()
            .unwrap()
            .into_inner()
    }

    #[test]
    fn restore_staging_atomically_replaces_the_published_archive() {
        let directory = tempfile::tempdir().unwrap();
        let target = stage_backup_atomically(directory.path(), b"first").unwrap();
        stage_backup_atomically(directory.path(), b"second").unwrap();

        assert_eq!(std::fs::read(target).unwrap(), b"second");
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .count(),
            1,
        );
    }

    #[test]
    fn concurrent_restore_staging_publishes_one_complete_archive() {
        let directory = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();
        for value in 0u8..8 {
            let path = directory.path().to_path_buf();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                stage_backup_atomically(&path, &[value; 128]).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let published = std::fs::read(
            directory
                .path()
                .join("backup.asbak"),
        )
        .unwrap();
        assert_eq!(published.len(), 128);
        assert!(
            published
                .iter()
                .all(|byte| *byte == published[0])
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .count(),
            1,
        );
    }

    #[test]
    fn uploaded_current_backup_validates_manifest_and_domain() {
        let current = [0x31; 32];
        let zip = super::super::manifest::add_backup_manifest(&sample_zip(), "agent.example.com", false).unwrap();
        let encrypted = encrypt_backup(&current, &zip).unwrap();

        let prepared = prepare_restore_upload(&encrypted, &current, &[], "Agent.Example.com.").unwrap();

        assert_eq!(prepared.key_source, BackupKeySource::Current);
        assert_eq!(
            prepared
                .manifest
                .source_domain,
            "agent.example.com"
        );
    }

    #[test]
    fn uploaded_backup_rejects_mismatched_domain() {
        let current = [0x31; 32];
        let zip = super::super::manifest::add_backup_manifest(&sample_zip(), "source.example.com", false).unwrap();
        let encrypted = encrypt_backup(&current, &zip).unwrap();

        let error = prepare_restore_upload(&encrypted, &current, &[], "target.example.com").unwrap_err();
        assert_eq!(error.key_source, Some(BackupKeySource::Current));
        assert_eq!(error.source_domain.as_deref(), Some("source.example.com"));
        assert_eq!(error.category, "manifest_invalid");
    }

    #[test]
    fn uploaded_current_key_backup_requires_manifest() {
        let current = [0x31; 32];
        let encrypted = encrypt_backup(&current, &sample_zip()).unwrap();

        assert!(prepare_restore_upload(&encrypted, &current, &[], "agent.example.com").is_err());
    }

    #[test]
    fn uploaded_legacy_backup_is_rebound_and_staged_with_current_key() {
        let current = [0x31; 32];
        let legacy = [0x32; 32];
        let encrypted = encrypt_backup(&legacy, &sample_zip()).unwrap();

        let prepared = prepare_restore_upload(&encrypted, &current, &[legacy], "agent.example.com").unwrap();
        let staged = encrypt_backup(&current, &prepared.zip_data).unwrap();
        let decrypted = decrypt_backup_with_keys(&current, &[], &staged).unwrap();
        let manifest = super::super::manifest::validate_backup_manifest(&decrypted.bytes, "agent.example.com").unwrap();

        assert_eq!(prepared.key_source, BackupKeySource::Legacy);
        assert!(manifest.legacy_import);
    }

    #[test]
    fn uploaded_legacy_backup_fails_when_compatibility_is_removed() {
        let current = [0x31; 32];
        let encrypted = encrypt_backup(&[0x32; 32], &sample_zip()).unwrap();

        assert!(prepare_restore_upload(&encrypted, &current, &[], "agent.example.com").is_err());
    }
}
