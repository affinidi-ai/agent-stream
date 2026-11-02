use std::path::{Path, PathBuf};
use std::time::Duration;

use cucumber::{given, then, when};

use crate::bdd_support::appliance_process::{ApplianceProcess, LaunchOptions, LaunchOutcome};
use crate::bdd_support::config::EncryptionSettings;
use crate::world::SurfaceWorld;

#[given("the deployment operator has not configured encryption at rest at all")]
async fn no_encryption_settings(world: &mut SurfaceWorld) {
    world.encryption = Some(EncryptionSettings::Absent);
}

#[given("the deployment operator has not chosen whether the appliance encrypts data at rest")]
async fn no_encryption_choice(world: &mut SurfaceWorld) {
    world.encryption = Some(EncryptionSettings::DisabledOnly);
}

#[given("the deployment operator has enabled encryption at rest with a master key")]
async fn encryption_enabled(world: &mut SurfaceWorld) {
    world.encryption = Some(EncryptionSettings::Enabled);
}

#[given("the deployment operator has explicitly opted out of encryption at rest")]
async fn encryption_opted_out(world: &mut SurfaceWorld) {
    world.encryption = Some(EncryptionSettings::OptedOut);
}

#[when("the deployment operator starts the appliance")]
async fn deployment_operator_starts_appliance(world: &mut SurfaceWorld) {
    let options = LaunchOptions {
        encryption: world
            .encryption
            .unwrap_or_default(),
        ..LaunchOptions::default()
    };
    world.appliance_launch = Some(ApplianceProcess::launch(world.temp_dir.path(), &options).await);
}

#[then("the appliance does not start")]
async fn appliance_does_not_start(world: &mut SurfaceWorld) {
    match launch(world) {
        LaunchOutcome::Exited { success, log_tail, .. } => {
            assert!(!success, "expected a failed exit, got success:\n{log_tail}")
        }
        LaunchOutcome::Serving(_) => panic!("expected the appliance not to start, but it is serving"),
    }
}

#[then("the appliance reports that encryption at rest must be enabled or explicitly opted out of")]
async fn appliance_reports_encryption_choice_required(world: &mut SurfaceWorld) {
    let LaunchOutcome::Exited { log, log_tail, .. } = launch(world) else {
        panic!("expected the appliance to have exited with a startup error");
    };
    for expected in ["Encryption at rest is not configured", "enabled = true", "allow_unencrypted = true"] {
        assert!(log.contains(expected), "expected the startup error to mention {expected:?}, got:\n{log_tail}");
    }
}

#[then("the appliance starts")]
async fn appliance_starts(world: &mut SurfaceWorld) {
    if let LaunchOutcome::Exited { log_tail, .. } = launch(world) {
        panic!("expected the appliance to start, but it exited:\n{log_tail}");
    }
}

#[then("the appliance stores its records encrypted")]
async fn appliance_stores_records_encrypted(world: &mut SurfaceWorld) {
    let records = stored_member_records(
        &world
            .temp_dir
            .path()
            .join("_storage/members"),
    )
    .await;
    assert!(
        records
            .iter()
            .all(|record| has_suffix(record, ".json.enc")),
        "expected only encrypted records, got {records:?}"
    );
    let first = std::fs::read(&records[0]).expect("a stored record should be readable");
    assert!(first.starts_with(b"ENC["), "expected an encrypted envelope in {:?}", records[0]);
}

#[then("the appliance stores its records unencrypted")]
async fn appliance_stores_records_unencrypted(world: &mut SurfaceWorld) {
    let records = stored_member_records(
        &world
            .temp_dir
            .path()
            .join("_storage/members"),
    )
    .await;
    assert!(
        records
            .iter()
            .all(|record| has_suffix(record, ".json")),
        "expected only plaintext records, got {records:?}"
    );
    let first = std::fs::read(&records[0]).expect("a stored record should be readable");
    serde_json::from_slice::<serde_json::Value>(&first)
        .unwrap_or_else(|error| panic!("expected a plaintext JSON record in {:?}: {error}", records[0]));
}

fn launch(world: &SurfaceWorld) -> &LaunchOutcome {
    world
        .appliance_launch
        .as_ref()
        .expect("the deployment operator should have started the appliance")
}

fn has_suffix(
    path: &Path,
    suffix: &str,
) -> bool {
    path.to_string_lossy()
        .ends_with(suffix)
}

/// The built-in member records the appliance seeds at startup, waiting briefly
/// for them to be written.
async fn stored_member_records(members_dir: &Path) -> Vec<PathBuf> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let records: Vec<PathBuf> = std::fs::read_dir(members_dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| has_suffix(path, ".json") || has_suffix(path, ".json.enc"))
            .collect();
        if !records.is_empty() {
            return records;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no member records were stored under {}",
            members_dir.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
