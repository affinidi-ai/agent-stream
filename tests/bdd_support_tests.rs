#![allow(dead_code)]

#[path = "bdd_support/mod.rs"]
mod bdd_support;

use std::time::{Duration, Instant};

use bdd_support::{
    appliance_process::read_log_tail,
    config::{EncryptionSettings, write_scenario_config},
    mock_llm::MockLlmProvider,
    ports::reserve_free_port,
};

#[test]
fn scenario_config_carries_the_requested_encryption_settings() {
    for (settings, expected) in [
        (EncryptionSettings::OptedOut, Some("[encryption]\nallow_unencrypted = true\n")),
        (EncryptionSettings::DisabledOnly, Some("[encryption]\nenabled = false\n")),
        (EncryptionSettings::Enabled, Some("[encryption]\nenabled = true\n")),
        (EncryptionSettings::Absent, None),
    ] {
        let root = tempfile::tempdir().expect("temporary scenario root should be created");
        let (port, _reservation) = reserve_free_port("encryption support config test");
        let config = write_scenario_config(root.path(), port, &[], false, None, settings, false);

        let written = std::fs::read_to_string(&config.config_path).expect("scenario config should be readable");
        let parsed: toml::Table = written
            .parse()
            .unwrap_or_else(|error| panic!("{settings:?} config should be TOML: {error}\n{written}"));
        assert!(parsed.contains_key("logging"), "{settings:?} must keep the other tables");
        match expected {
            Some(table) => {
                assert_eq!(
                    written
                        .matches("[encryption]")
                        .count(),
                    1,
                    "{settings:?}:\n{written}"
                );
                assert!(written.contains(table), "{settings:?}:\n{written}");
            }
            None => assert!(!parsed.contains_key("encryption"), "{settings:?}:\n{written}"),
        }
    }
    assert_eq!(EncryptionSettings::Enabled.env()[0].0, "AS_MASTER_KEY");
    assert!(
        EncryptionSettings::OptedOut
            .env()
            .is_empty()
    );
}

#[test]
fn scenario_config_seeds_anonymous_team_entities() {
    let root = tempfile::tempdir().expect("temporary scenario root should be created");
    let (port, _reservation) = reserve_free_port("support config test");
    let config = write_scenario_config(root.path(), port, &[], false, None, EncryptionSettings::default(), false);

    assert!(config.config_path.exists());
    let member = std::fs::read_to_string(
        config
            .config_dir
            .join("defaults/default_members/anonymous.json"),
    )
    .expect("anonymous member should be readable");
    let team = std::fs::read_to_string(
        config
            .config_dir
            .join("defaults/default_teams/anonymous.json"),
    )
    .expect("anonymous team should be readable");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&member).unwrap()["id"], "anonymous");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&team).unwrap()["members"][0], "anonymous");
}

#[test]
fn scenario_config_can_start_a_standby() {
    for (standby, expected) in [(true, Some("standby")), (false, None)] {
        let root = tempfile::tempdir().expect("temporary scenario root should be created");
        let (port, _reservation) = reserve_free_port("standby support config test");
        let config = write_scenario_config(root.path(), port, &[], false, None, EncryptionSettings::default(), standby);

        let parsed: toml::Table = std::fs::read_to_string(&config.config_path)
            .expect("scenario config should be readable")
            .parse()
            .expect("scenario config should be TOML");
        assert_eq!(
            parsed
                .get("server_mode")
                .and_then(toml::Value::as_str),
            expected,
            "server_mode must be a top-level key"
        );
    }
}

#[test]
fn scenario_config_can_enable_terms() {
    let root = tempfile::tempdir().expect("temporary scenario root should be created");
    let (port, _reservation) = reserve_free_port("Terms support config test");
    let config = write_scenario_config(
        root.path(),
        port,
        &[],
        true,
        Some("http://127.0.0.1:32002/terms/v1/current.json"),
        EncryptionSettings::default(),
        false,
    );
    let network: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            config
                .config_dir
                .join("agent-stream.json"),
        )
        .expect("network config should be readable"),
    )
    .expect("network config should be JSON");

    assert_eq!(network["terms"], true);
}

#[test]
fn appliance_log_tail_keeps_only_requested_lines() {
    let root = tempfile::tempdir().expect("temporary log directory should be created");
    let path = root
        .path()
        .join("agent-stream.log");
    std::fs::write(&path, "one\ntwo\nthree\nfour\n").expect("test log should be written");

    assert_eq!(read_log_tail(&path, 2), "three\nfour");
}

#[tokio::test]
async fn mock_provider_records_configurable_delayed_completion() {
    let provider = MockLlmProvider::start("support-test").await;
    provider
        .set_chat_completion_content("configured response".to_string())
        .await;
    provider
        .set_chat_completion_delay(Duration::from_millis(50))
        .await;

    let started = Instant::now();
    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", provider.base_url()))
        .header("X-Support-Test", "recorded")
        .json(&serde_json::json!({
            "model": "mock-small",
            "messages": [{ "role": "user", "content": "support prompt" }]
        }))
        .send()
        .await
        .expect("mock request should complete");
    assert!(response.status().is_success());
    assert!(started.elapsed() >= Duration::from_millis(40));
    let body: serde_json::Value = response
        .json()
        .await
        .expect("mock response should be JSON");
    assert_eq!(body["choices"][0]["message"]["content"], "configured response");

    let requests = provider
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body["messages"][0]["content"], "support prompt");
    assert_eq!(
        requests[0]
            .headers
            .get("x-support-test")
            .map(String::as_str),
        Some("recorded")
    );
}

#[tokio::test]
async fn mock_provider_rejects_chat_completions_as_unauthorized() {
    let provider = MockLlmProvider::start("support-test").await;
    provider
        .make_chat_completions_unauthorized()
        .await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", provider.base_url()))
        .json(&serde_json::json!({
            "model": "mock-small",
            "messages": [{ "role": "user", "content": "support prompt" }]
        }))
        .send()
        .await
        .expect("mock request should complete");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = response
        .json()
        .await
        .expect("mock response should be JSON");
    assert_eq!(body["error"]["type"], "authentication_error");

    // The request is still recorded, so "received the request" assertions hold.
    let requests = provider
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn mock_provider_records_file_and_audio_requests_by_method_and_path() {
    let provider = MockLlmProvider::start("support-test").await;
    let client = reqwest::Client::new();

    let listed = client
        .get(format!("{}/v1/files", provider.base_url()))
        .send()
        .await
        .expect("file list request should complete");
    assert!(listed.status().is_success());
    let body: serde_json::Value = listed
        .json()
        .await
        .expect("mock response should be JSON");
    assert_eq!(body["provider"], "support-test");

    let form = reqwest::multipart::Form::new()
        .text("model", "whisper-1")
        .part("file", reqwest::multipart::Part::bytes(b"RIFF".to_vec()).file_name("clip.wav"));
    let transcribed = client
        .post(format!("{}/v1/audio/transcriptions", provider.base_url()))
        .multipart(form)
        .send()
        .await
        .expect("transcription request should complete");
    assert!(
        transcribed
            .status()
            .is_success()
    );

    assert_eq!(
        provider
            .received_api_requests("GET", "/v1/files")
            .await
            .len(),
        1
    );
    assert_eq!(
        provider
            .received_api_requests("POST", "/v1/audio/transcriptions")
            .await
            .len(),
        1
    );
    let stored = client
        .post(format!("{}/v1/vector_stores", provider.base_url()))
        .json(&serde_json::json!({ "name": "notes" }))
        .send()
        .await
        .expect("vector store request should complete");
    assert!(stored.status().is_success());
    assert_eq!(
        provider
            .received_api_requests("POST", "/v1/vector_stores")
            .await
            .len(),
        1
    );
    assert!(
        provider
            .received_api_requests("POST", "/v1/files")
            .await
            .is_empty(),
        "a file list must not be recorded as a file upload"
    );
    assert!(
        provider
            .received_chat_completions()
            .await
            .is_empty()
    );
}

#[test]
fn reserved_ports_remain_unique_while_guards_are_alive() {
    let (first_port, _first_reservation) = reserve_free_port("first support reservation");
    let (second_port, _second_reservation) = reserve_free_port("second support reservation");
    assert_ne!(first_port, second_port);
}
