//! The scheduled half of governance retention. Each write prunes its own
//! surface when due; this sweep reaches surfaces that have gone quiet. It walks
//! every governance log on disk: a surface that still exists is pruned by its
//! recording block (with the appliance-wide surface defaults applied), and a
//! deleted surface (an archived log, or a log whose surface is gone) by the
//! window it last recorded or was pruned with.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use crate::pipes::{FileSystemPipeStore, PipeConfig};

/// How often the sweep runs. With the store's one-hour grace, a record is
/// removed within about two hours of leaving its window.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Prune every governance log with a retention window as soon as the instance
/// is Active and ready, then hourly. A surface's failure is logged and does not
/// stop the others.
pub async fn periodic_retention_sweep(pipe_store: Arc<FileSystemPipeStore>) {
    let mut ticker = crate::server::mode::ReadyTicker::new(SWEEP_INTERVAL);
    loop {
        // Pruning rewrites the shared logs, which only the Active instance may do.
        ticker.tick().await;
        let Some(store) = super::capture::store() else {
            continue;
        };
        let surfaces = match store.list_surfaces() {
            Ok(surfaces) => surfaces,
            Err(e) => {
                warn!(error = %e, "governance retention sweep could not list surfaces");
                continue;
            }
        };
        let live = live_windows(pipe_store.list().await);
        for (surface_id, days) in sweep_plan(&surfaces, &live, |surface| store.retention_window(surface)) {
            if let Err(e) = store
                .prune(&surface_id, days)
                .await
            {
                warn!(surface_id = %surface_id, error = %e, "governance retention sweep failed");
            }
        }
    }
}

/// Each surface's retention window in days (0 keeps everything).
fn live_windows(pipes: Vec<PipeConfig>) -> HashMap<String, u32> {
    pipes
        .into_iter()
        .map(|pipe| {
            let id = pipe.id.clone();
            let days = pipe
                .with_global_surface_defaults()
                .governance_recording
                .map_or(0, |g| g.retention_days);
            (id, days)
        })
        .collect()
}

/// The logs to prune, each with its window: a surface that exists takes its
/// own window (passed on even when it is 0 and differs from the kept one, so
/// the log keeps the current window), any other log the window it kept.
fn sweep_plan(
    surfaces: &[String],
    live: &HashMap<String, u32>,
    kept: impl Fn(&str) -> u32,
) -> Vec<(String, u32)> {
    surfaces
        .iter()
        .filter_map(|surface| {
            let kept = kept(surface);
            let days = live
                .get(surface)
                .copied()
                .unwrap_or(kept);
            (days > 0 || days != kept).then(|| (surface.clone(), days))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::GovernanceRecordingConfig;
    use crate::pipes::PipeType;

    fn pipe(
        id: &str,
        recording: Option<GovernanceRecordingConfig>,
    ) -> PipeConfig {
        let mut pipe = PipeConfig::new(
            id.into(),
            id.into(),
            PipeType::Webhook {
                endpoint: "https://example.test".into(),
            },
        );
        pipe.governance_recording = recording;
        pipe
    }

    #[test]
    fn each_surface_takes_its_own_window() {
        let windows = live_windows(vec![
            pipe("none", None),
            pipe("keep-forever", Some(GovernanceRecordingConfig::default())),
            pipe(
                "thirty",
                Some(GovernanceRecordingConfig {
                    retention_days: 30,
                    ..Default::default()
                }),
            ),
            pipe(
                "off-but-windowed",
                Some(GovernanceRecordingConfig {
                    enabled: false,
                    retention_days: 7,
                    ..Default::default()
                }),
            ),
        ]);
        assert_eq!(windows.len(), 4);
        assert_eq!((windows["none"], windows["keep-forever"]), (0, 0));
        assert_eq!((windows["thirty"], windows["off-but-windowed"]), (30, 7));
    }

    #[test]
    fn deleted_surfaces_are_swept_by_the_window_they_kept() {
        let surfaces: Vec<String> = [
            "live-30",
            "live-forever",
            "live-now-forever",
            "gone-14",
            "gone-forever",
            "live-30.deleted-20261005T101112345Z",
        ]
        .map(str::to_string)
        .to_vec();
        let live = HashMap::from([
            ("live-30".to_string(), 30),
            ("live-forever".to_string(), 0),
            ("live-now-forever".to_string(), 0),
        ]);
        let kept = |surface: &str| match surface {
            "live-30" => 7,
            "live-now-forever" | "gone-14" => 14,
            "live-30.deleted-20261005T101112345Z" => 90,
            _ => 0,
        };
        assert_eq!(
            sweep_plan(&surfaces, &live, kept),
            [
                ("live-30".to_string(), 30),
                ("live-now-forever".to_string(), 0),
                ("gone-14".to_string(), 14),
                ("live-30.deleted-20261005T101112345Z".to_string(), 90),
            ],
            "a live surface's own window wins, a 0 that differs from the kept window is passed on to be kept, and \
             a deleted surface's log keeps the window it last had"
        );
    }

    #[test]
    fn the_sweep_prunes_as_soon_as_the_instance_is_ready_not_after_the_period() {
        use crate::governance::store::tests::{draft_at, signer};
        use crate::governance::{GovernanceStore, RecordQuery};
        use crate::server::mode::{
            MODE_TEST_LOCK, ServerMode, current_activation_generation, mark_activation_ready, set_server_mode,
        };

        let _guard = MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let dir = tempfile::tempdir().unwrap();
                crate::governance::init_store(GovernanceStore::new(dir.path().join("governance"), signer(), None));
                let store = crate::governance::capture::store().expect("the global store is installed");
                let surface = "sweep-surface";
                let now = chrono::Utc::now().to_rfc3339();
                for (prompt, at) in [("old", "2020-01-01T00:00:00Z"), ("new", now.as_str())] {
                    store
                        .record(draft_at(surface, prompt, at, None), 0)
                        .await
                        .unwrap();
                }
                let pipes = Arc::new(
                    FileSystemPipeStore::new(
                        dir.path()
                            .join("pipes")
                            .display()
                            .to_string(),
                    )
                    .await
                    .unwrap(),
                );
                pipes
                    .save(pipe(
                        surface,
                        Some(GovernanceRecordingConfig {
                            retention_days: 30,
                            ..Default::default()
                        }),
                    ))
                    .await
                    .unwrap();
                let recorded = || async {
                    store
                        .query(surface, RecordQuery::default())
                        .await
                        .unwrap()
                        .records
                        .len()
                };

                set_server_mode(ServerMode::Standby);
                let task = tokio::spawn(periodic_retention_sweep(pipes));
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert_eq!(recorded().await, 2, "a Standby leaves the shared logs alone");

                set_server_mode(ServerMode::Active);
                assert!(mark_activation_ready(current_activation_generation()));
                tokio::time::timeout(Duration::from_secs(5), async {
                    while recorded().await != 1 {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("the expired record is pruned once ready, well before the hourly period");
                task.abort();
            });
    }
}
