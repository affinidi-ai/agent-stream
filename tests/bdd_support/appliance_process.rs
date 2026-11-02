use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

use crate::bdd_support::config::{
    EncryptionSettings, ScenarioConfig, provider_endpoint_allowlist, write_scenario_config,
};
use crate::bdd_support::ports::{ReservedPort, reserve_free_port};

const TEST_TOKEN: &str = "bdd-test-token";
const TEST_USERNAME: &str = "bdd-operator@example.test";
const LOG_TAIL_LINES: usize = 80;

#[derive(Debug)]
pub struct ApplianceProcess {
    child: Child,
    base_url: String,
    config: ScenarioConfig,
    log_path: PathBuf,
    _port_reservation: ReservedPort,
}

/// What an appliance is launched with.
#[derive(Debug, Default)]
pub struct LaunchOptions<'a> {
    pub provider_base_urls: &'a [String],
    pub terms_enabled: bool,
    pub affinidi_terms_url: Option<&'a str>,
    pub encryption: EncryptionSettings,
    /// Start in Standby mode instead of Active.
    pub standby: bool,
}

/// How an appliance launch ended: serving requests, or exited before it was ready.
/// `log` is the whole log for content checks; `log_tail` is the bounded tail for messages.
#[derive(Debug)]
pub enum LaunchOutcome {
    Serving(Box<ApplianceProcess>),
    Exited { success: bool, log: String, log_tail: String },
}

impl ApplianceProcess {
    pub async fn start_with_terms(
        root: &Path,
        provider_base_urls: &[String],
        terms_enabled: bool,
        affinidi_terms_url: Option<String>,
    ) -> Self {
        let options = LaunchOptions {
            provider_base_urls,
            terms_enabled,
            affinidi_terms_url: affinidi_terms_url.as_deref(),
            ..LaunchOptions::default()
        };
        match Self::launch(root, &options).await {
            LaunchOutcome::Serving(appliance) => *appliance,
            LaunchOutcome::Exited { log_tail, .. } => {
                panic!("agent-stream exited before it became ready\n\nagent-stream.log tail:\n{log_tail}")
            }
        }
    }

    /// Write the scenario configuration under `root`, start an appliance on it,
    /// and report whether it came up.
    pub async fn launch(
        root: &Path,
        options: &LaunchOptions<'_>,
    ) -> LaunchOutcome {
        let (port, mut port_reservation) = reserve_free_port("Agent Stream BDD listener");
        let config = write_scenario_config(
            root,
            port,
            options.provider_base_urls,
            options.terms_enabled,
            options.affinidi_terms_url,
            options.encryption,
            options.standby,
        );
        let base_url = format!("http://127.0.0.1:{port}");
        let allowlist = provider_endpoint_allowlist(options.provider_base_urls);
        let log_path = root.join("agent-stream.log");
        let log_file = std::fs::File::create(&log_path).expect("agent-stream log should be created");
        let stderr_log = log_file
            .try_clone()
            .expect("agent-stream log handle should be cloned");

        port_reservation.release_listener();
        let mut child = Command::new(agent_stream_binary())
            .arg("--config")
            .arg(&config.config_path)
            .current_dir(&config.config_dir)
            .env("AS_TEST_MODE", "true")
            .env("AS_TEST_TOKEN", TEST_TOKEN)
            .env("AS_TEST_ALLOW_ROLE_OVERRIDE", "true")
            .env("AS_TEST_SERVICE_ENDPOINT_ALLOWLIST", allowlist)
            .env("AFFINIDI_TERMS_REFRESH_INTERVAL_SECONDS", "1")
            .env("RUST_LOG", "warn")
            .envs(
                options
                    .encryption
                    .env()
                    .iter()
                    .copied(),
            )
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr_log))
            .kill_on_drop(true)
            .spawn()
            .expect("agent-stream process should start");

        match wait_until_ready(&base_url, &mut child).await {
            Readiness::Serving => LaunchOutcome::Serving(Box::new(Self {
                child,
                base_url,
                config,
                log_path,
                _port_reservation: port_reservation,
            })),
            Readiness::Exited(status) => LaunchOutcome::Exited {
                success: status.success(),
                log: std::fs::read_to_string(&log_path).unwrap_or_default(),
                log_tail: read_log_tail(&log_path, LOG_TAIL_LINES),
            },
            Readiness::TimedOut(error) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                let log_tail = read_log_tail(&log_path, LOG_TAIL_LINES);
                panic!(
                    "agent-stream did not become ready at {base_url}: {error}\n\nagent-stream.log tail:\n{log_tail}"
                );
            }
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn test_token(&self) -> &'static str {
        TEST_TOKEN
    }

    pub fn test_username(&self) -> &'static str {
        TEST_USERNAME
    }

    #[allow(dead_code)]
    pub fn config_dir(&self) -> &Path {
        &self.config.config_dir
    }

    /// Send a Unix signal, such as `USR1` to promote or `USR2` to demote.
    pub fn signal(
        &self,
        signal: &str,
    ) {
        let pid = self
            .child
            .id()
            .expect("agent-stream should still be running");
        let status = std::process::Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(pid.to_string())
            .status()
            .expect("kill should run");
        assert!(status.success(), "sending SIG{signal} to agent-stream {pid} failed");
    }

    /// Stop the process and wait for it to exit.
    pub async fn stop(mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }

    /// Wait until readiness (`/v1/health` under the identity routes' prefix,
    /// `/api` outside the BDD configuration) reports the appliance ready to serve.
    pub async fn wait_until_ready_to_serve(&self) {
        let client = reqwest::Client::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut last = String::new();
        while tokio::time::Instant::now() < deadline {
            for prefix in ["", "/api"] {
                match client
                    .get(format!("{}{prefix}/v1/health", self.base_url))
                    .send()
                    .await
                {
                    Ok(response) if response.status().is_success() => return,
                    Ok(response) if response.status() != reqwest::StatusCode::NOT_FOUND => {
                        last = format!("HTTP {}", response.status())
                    }
                    Ok(_) => {}
                    Err(error) => last = error.to_string(),
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let log_tail = read_log_tail(&self.log_path, LOG_TAIL_LINES);
        panic!("agent-stream at {} never reported ready: {last}\n\nagent-stream.log tail:\n{log_tail}", self.base_url);
    }
}

impl Drop for ApplianceProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

enum Readiness {
    Serving,
    Exited(std::process::ExitStatus),
    TimedOut(String),
}

async fn wait_until_ready(
    base_url: &str,
    child: &mut Child,
) -> Readiness {
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut last_error = String::new();

    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Readiness::Exited(status);
        }
        match client
            .get(format!("{base_url}/ping"))
            .send()
            .await
        {
            Ok(response) if response.status().as_u16() < 500 => return Readiness::Serving,
            Ok(response) => last_error = format!("HTTP {}", response.status()),
            Err(error) => last_error = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Readiness::TimedOut(last_error)
}

pub(crate) fn read_log_tail(
    path: &Path,
    line_count: usize,
) -> String {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return "<log unavailable>".to_string();
    };
    let lines = contents
        .lines()
        .collect::<Vec<_>>();
    lines[lines
        .len()
        .saturating_sub(line_count)..]
        .join("\n")
}

fn agent_stream_binary() -> String {
    option_env!("CARGO_BIN_EXE_agent-stream")
        .map(str::to_string)
        .unwrap_or_else(|| "target/debug/agent-stream".to_string())
}
