use std::fs;
use std::path::{Path, PathBuf};

use rcgen::generate_simple_self_signed;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    pub config_dir: PathBuf,
    pub config_path: PathBuf,
}

const MASTER_KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// The `[encryption]` settings a scenario `config.toml` carries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EncryptionSettings {
    /// No `[encryption]` table at all.
    Absent,
    /// `enabled = false` with no opt-out.
    DisabledOnly,
    /// Encryption enabled with a master key from the environment.
    Enabled,
    /// The explicit opt-out every other scenario runs with.
    #[default]
    OptedOut,
}

impl EncryptionSettings {
    pub fn table(self) -> &'static str {
        match self {
            Self::Absent => "",
            Self::DisabledOnly => "\n[encryption]\nenabled = false\n",
            Self::Enabled => {
                "\n[encryption]\nenabled = true\nkey_source = \"environment\"\nkey_env_var = \"AS_MASTER_KEY\"\n"
            }
            Self::OptedOut => "\n[encryption]\nallow_unencrypted = true\n",
        }
    }

    /// The environment the appliance needs for these settings.
    pub fn env(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Enabled => &[("AS_MASTER_KEY", MASTER_KEY)],
            Self::Absent | Self::DisabledOnly | Self::OptedOut => &[],
        }
    }
}

pub fn write_scenario_config(
    root: &Path,
    appliance_port: u16,
    provider_base_urls: &[String],
    terms_enabled: bool,
    affinidi_terms_url: Option<&str>,
    encryption: EncryptionSettings,
    standby: bool,
) -> ScenarioConfig {
    let config_dir = root.join("config");
    fs::create_dir_all(&config_dir).expect("scenario config dir should be created");
    fs::create_dir_all(config_dir.join("certs")).expect("scenario cert dir should be created");
    fs::create_dir_all(config_dir.join("defaults/default_members")).expect("default member dir should be created");
    fs::create_dir_all(config_dir.join("defaults/default_teams")).expect("default team dir should be created");
    fs::create_dir_all(config_dir.join("surface_templates")).expect("surface template dir should be created");

    write_tls_files(&config_dir);
    write_default_team_entities(&config_dir);
    write_network_config(&config_dir, appliance_port, terms_enabled, affinidi_terms_url);
    write_metrics_config(&config_dir);

    fs::write(config_dir.join("rbac.json"), "{}\n").expect("rbac config should be written");
    fs::write(config_dir.join("llm.json"), "{\"providers\":[]}\n").expect("LLM catalog should be written");
    fs::write(config_dir.join("saml.json"), "{}\n").expect("SAML config should be written");
    fs::write(config_dir.join("prompt-guard.json"), "{}\n").expect("prompt guard config should be written");
    fs::write(config_dir.join("marketplace-models.json"), "[]\n").expect("marketplace catalog should be written");
    fs::write(config_dir.join("rejection_categories.json"), "{}\n").expect("rejection taxonomy should be written");

    let endpoint_allowlist = provider_endpoint_allowlist(provider_base_urls);
    let config_path = config_dir.join("config.toml");
    let bootstrap = r#"channel_config_source = "local"
secrets_backend = "filesystem"
auth_mode = "passkey"
session_timeout_minutes = 20
websocket_require_auth = false
metrics_retention_minutes = 60
metrics_cache_ttl_seconds = 1
marketplace_cache_ttl = 60
backup_encryption_key = "1111111111111111111111111111111111111111111111111111111111111111"

[config_files]
agent_stream = "agent-stream.json"
metrics = "metrics.json"
rbac = "rbac.json"
llm = "llm.json"
saml = "saml.json"
prompt_guard = "prompt-guard.json"
marketplace_models = "marketplace-models.json"
rejection_taxonomy = "rejection_categories.json"
surface_templates_dir = "surface_templates"

[tls]
cert_path = "certs/cert.pem"
key_path = "certs/key.pem"
verify_upstream = false

[a2a]
fabric_gateway_timeout_ms = 1000
message_expires_seconds = 2
max_inflight_dispatches = 16
sdk_inbound_cache_count = 16
sdk_inbound_cache_bytes = 1048576

[mcp]
fabric_gateway_timeout_ms = 1000

[logging]
level = "warn"
json = false
"#;
    let server_mode = if standby {
        "server_mode = \"standby\"\n"
    } else {
        ""
    };
    fs::write(&config_path, format!("{server_mode}{bootstrap}{}", encryption.table()))
        .expect("bootstrap config should be written");

    let allowlist_path = config_dir.join("endpoint-allowlist.txt");
    fs::write(&allowlist_path, &endpoint_allowlist).expect("endpoint allowlist should be written");

    ScenarioConfig { config_dir, config_path }
}

pub fn provider_endpoint_allowlist(provider_base_urls: &[String]) -> String {
    provider_base_urls
        .iter()
        .flat_map(|base_url| {
            let trimmed = base_url.trim_end_matches('/');
            [
                base_url.to_string(),
                format!("{trimmed}/v1/chat/completions"),
                format!("{trimmed}/v1/embeddings"),
                format!("{trimmed}/guardrail"),
                format!("{trimmed}/v1/models"),
                format!("{trimmed}/v1/files"),
                format!("{trimmed}/v1/batches"),
                format!("{trimmed}/v1/vector_stores"),
                format!("{trimmed}/v1/audio/transcriptions"),
                format!("{trimmed}/v1/audio/translations"),
            ]
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn write_tls_files(config_dir: &Path) {
    let cert =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("self-signed cert should be generated");
    fs::write(config_dir.join("certs/cert.pem"), cert.cert.pem()).expect("cert PEM should be written");
    fs::write(
        config_dir.join("certs/key.pem"),
        cert.signing_key
            .serialize_pem(),
    )
    .expect("key PEM should be written");
}

fn write_network_config(
    config_dir: &Path,
    appliance_port: u16,
    terms_enabled: bool,
    affinidi_terms_url: Option<&str>,
) {
    let external_url = format!("http://localhost:{appliance_port}");
    let network = json!({
        "did": { "domain": "localhost" },
        "webauthn": {
            "rp_id": "localhost",
            "external_origin": external_url
        },
        "integration": {
            "types": [],
            "categories": []
        },
        "cors": ["*"],
        "terms": terms_enabled,
        "affinidi_terms_url": affinidi_terms_url,
        "listeners": [
            {
                "id": "bdd-http",
                "name": "BDD HTTP",
                "bind_address": "127.0.0.1",
                "port": appliance_port,
                "protocol": "http",
                "external_urls": [external_url],
                "listener_type": "inbound"
            }
        ],
        "channels": [],
        "pipe_paths": [
            { "id": "chat", "name": "Chat", "prefix": "/chat" },
            { "id": "keyed-chat", "name": "Keyed Chat", "prefix": "/keyed-chat" },
            { "id": "jwt-chat", "name": "JWT Chat", "prefix": "/jwt-chat" },
            { "id": "guarded-chat", "name": "Guarded Chat", "prefix": "/guarded-chat" },
            { "id": "keyed-guarded-chat", "name": "Keyed Guarded Chat", "prefix": "/keyed-guarded-chat" },
            { "id": "backup-chat", "name": "Backup Chat", "prefix": "/backup-chat" },
            { "id": "policy-chat", "name": "Policy Chat", "prefix": "/policy-chat" },
            { "id": "tenant-chat", "name": "Tenant Chat", "prefix": "/tenant-chat" },
            { "id": "lifecycle-chat", "name": "Lifecycle Chat", "prefix": "/lifecycle-chat" },
            { "id": "backup-lifecycle-chat", "name": "Backup Lifecycle Chat", "prefix": "/backup-lifecycle-chat" },
            { "id": "ide-alpha-chat", "name": "IDE Alpha Chat", "prefix": "/ide-alpha-chat" },
            { "id": "ide-beta-chat", "name": "IDE Beta Chat", "prefix": "/ide-beta-chat" },
            { "id": "ide-platform-chat", "name": "IDE Platform Chat", "prefix": "/ide-platform-chat" },
            { "id": "ide-research-chat", "name": "IDE Research Chat", "prefix": "/ide-research-chat" },
            { "id": "ide-chat", "name": "IDE Chat", "prefix": "/ide-chat" },
            { "id": "judged-chat", "name": "Judged Chat", "prefix": "/judged-chat" },
            { "id": "reviewed-chat", "name": "Reviewed Chat", "prefix": "/reviewed-chat" },
            { "id": "decided-chat", "name": "Decided Chat", "prefix": "/decided-chat" },
            { "id": "witnessed-chat", "name": "Witnessed Chat", "prefix": "/witnessed-chat" },
            { "id": "variant-chat", "name": "Variant Chat", "prefix": "/variant-chat" },
            { "id": "resilient-chat", "name": "Resilient Chat", "prefix": "/resilient-chat" },
            { "id": "cached-chat", "name": "Cached Chat", "prefix": "/cached-chat" },
            { "id": "streaming-chat", "name": "Streaming Chat", "prefix": "/streaming-chat" },
            { "id": "balanced-chat", "name": "Balanced Chat", "prefix": "/balanced-chat" },
            { "id": "governed-chat", "name": "Governed Chat", "prefix": "/governed-chat" },
            { "id": "governed-chat-two", "name": "Governed Chat Two", "prefix": "/governed-chat-two" },
            { "id": "private-chat", "name": "Private Chat", "prefix": "/private-chat" },
            { "id": "ordinary-chat", "name": "Ordinary Chat", "prefix": "/ordinary-chat" },
            { "id": "accounted-chat", "name": "Accounted Chat", "prefix": "/accounted-chat" }
        ],
        "routes": {
            "identity": { "type": "identity_api", "prefix": "/" }
        }
    });
    fs::write(
        config_dir.join("agent-stream.json"),
        serde_json::to_string_pretty(&network).expect("network config should serialize"),
    )
    .expect("network config should be written");
}

fn write_default_team_entities(config_dir: &Path) {
    fs::write(
        config_dir.join("defaults/default_members/anonymous.json"),
        serde_json::to_string_pretty(&json!({
            "id": "anonymous",
            "name": "Anonymous",
            "status": "enabled",
            "system": true,
            "identifiers": [{ "kind": "custom", "value": "anonymous" }],
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }))
        .expect("anonymous member should serialize"),
    )
    .expect("anonymous member should be written");
    fs::write(
        config_dir.join("defaults/default_teams/anonymous.json"),
        serde_json::to_string_pretty(&json!({
            "id": "anonymous",
            "name": "Anonymous",
            "status": "enabled",
            "system": true,
            "members": ["anonymous"],
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }))
        .expect("anonymous team should serialize"),
    )
    .expect("anonymous team should be written");
}

fn write_metrics_config(config_dir: &Path) {
    let metrics = json!({
        "opentelemetry": {
            "enabled": false,
            "endpoint": "http://localhost:4317",
            "service_name": "agent-stream-bdd",
            "environment": "test",
            "traces": { "enabled": false, "sample_rate": 0.0, "target_crates": ["agent_stream"] },
            "metrics": {
                "enabled": false,
                "export_interval_seconds": 60,
                "batch_max_queue_size": null,
                "batch_scheduled_delay_ms": null,
                "batch_max_export_size": null
            },
            "logs": { "enabled": false }
        },
        "cloudwatch": {
            "enabled": false,
            "region": null,
            "namespace": "AgentStreamBDD",
            "dimensions": null
        }
    });
    fs::write(
        config_dir.join("metrics.json"),
        serde_json::to_string_pretty(&metrics).expect("metrics config should serialize"),
    )
    .expect("metrics config should be written");
}
