use std::path::Path;
use std::time::Duration;

use cucumber::given;
use serde_json::Value;

use crate::world::SurfaceWorld;

#[given("the appliance has restarted")]
async fn appliance_has_restarted(world: &mut SurfaceWorld) {
    wait_for_recorded_usage(world).await;
    world
        .infra
        .take()
        .expect("the appliance should be running")
        ._appliance
        .stop()
        .await;
    let restarted = world
        .start_appliance(world.temp_dir.path(), false)
        .await;
    world
        .serve_from(restarted)
        .await;
}

#[given("a Standby appliance shares storage with the Active appliance")]
async fn standby_shares_storage(world: &mut SurfaceWorld) {
    let root = world
        .temp_dir
        .path()
        .join("standby");
    std::fs::create_dir_all(&root).expect("Standby root should be created");
    std::os::unix::fs::symlink(
        world
            .temp_dir
            .path()
            .join("_storage"),
        root.join("_storage"),
    )
    .expect("the Standby should share the Active appliance's storage");
    world.standby = Some(
        world
            .start_appliance(&root, true)
            .await,
    );
}

#[given("the Standby appliance has been promoted to replace the Active appliance")]
async fn standby_promoted(world: &mut SurfaceWorld) {
    wait_for_recorded_usage(world).await;
    let standby = world
        .standby
        .take()
        .expect("a Standby appliance should be running");
    world
        .infra
        .as_ref()
        .expect("the Active appliance should be running")
        ._appliance
        .signal("USR2");
    standby.signal("USR1");
    standby
        .wait_until_ready_to_serve()
        .await;
    if let Some(demoted) = world
        .serve_from(standby)
        .await
    {
        demoted.stop().await;
    }
}

/// Wait until the usage files under `_storage` hold the tokens the scenario
/// recorded, so a restart or promotion does not race their background write.
async fn wait_for_recorded_usage(world: &SurfaceWorld) {
    let storage = world
        .temp_dir
        .path()
        .join("_storage");
    let mut dirs = vec![storage.join("surface_usage")];
    if !world.member_ids.is_empty() {
        dirs.push(storage.join("team_usage"));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !dirs
        .iter()
        .all(|dir| records_tokens(dir))
    {
        assert!(tokio::time::Instant::now() < deadline, "no recorded tokens were stored under {dirs:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn records_tokens(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("usage.") && name.ends_with(".json"))
        })
        .filter_map(|path| std::fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .any(|usage| has_tokens(&usage))
}

fn has_tokens(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields
            .iter()
            .any(|(key, value)| {
                (key == "total_tokens"
                    && value
                        .as_u64()
                        .is_some_and(|tokens| tokens > 0))
                    || has_tokens(value)
            }),
        Value::Array(items) => items.iter().any(has_tokens),
        _ => false,
    }
}
