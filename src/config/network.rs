//! Network configuration types for defining listeners, routes, and paths

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Network configuration containing all listeners and their routes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// DID configuration
    pub did: DidConfig,

    /// Require human users to accept applicable Terms before product access.
    #[serde(default)]
    pub terms: bool,

    /// Affinidi Well endpoint serving the current Affinidi T&C metadata.
    #[serde(default)]
    pub affinidi_terms_url: Option<Url>,

    /// WebAuthn configuration
    pub webauthn: WebAuthnConfig,

    /// Integration configuration (types and categories with metadata)
    pub integration: crate::config::IntegrationConfig,

    /// Encryption at rest configuration
    #[serde(default)]
    pub encryption: Option<crate::config::EncryptionConfig>,

    /// CORS origins allowed to access the API
    #[serde(default)]
    pub cors: Vec<String>,

    /// List of port listeners to bind
    pub listeners: Vec<Listener>,

    /// Available channel prefixes for proxy routes
    #[serde(default)]
    pub channels: Vec<ChannelPrefix>,

    /// Route categories available across all listeners
    pub routes: HashMap<String, RouteCategory>,

    /// OAuth callback route prefix (e.g. "/oauth/callback")
    /// Defaults to "/v1/identity/oauth/callback" if not set
    #[serde(default = "default_oauth_callback_route")]
    pub oauth_callback_route: String,

    /// LLM pipe route prefixes (e.g. `/llm`, `/models`) fronting the LLM pipe
    /// proxy routes registered at startup. The provider catalog itself lives in
    /// the editable storage file under `storage_paths.llm_configuration`.
    #[serde(default)]
    pub pipe_paths: Vec<ChannelPrefix>,

    /// Built-in LLM catalog refresh source. When set, the dashboard's "Refresh
    /// Builtin Models" action fetches the published master `llm.json` from this
    /// location, validates it, and swaps it into storage (keeping the previous
    /// file as `llm.json.bak`).
    #[serde(default)]
    pub llm_catalog: Option<LlmCatalogConfig>,

    /// Appliance-wide LLM drift operational settings (replay-evaluation runner).
    #[serde(default)]
    pub drift: Option<DriftAppConfig>,

    /// Secrets vault settings (`secrets` in agent-stream.json).
    #[serde(default)]
    pub secrets: SecretsConfig,

    /// Logging overrides (only redaction rules are used from gateway.json;
    /// level/json/log_directory come from config.toml)
    #[serde(default)]
    pub logging: Option<crate::config::LoggingConfig>,
}

/// Built-in LLM catalog refresh configuration (`llm_catalog` in agent-stream.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmCatalogConfig {
    /// URL of the published master `llm.json` catalog Affinidi maintains. The
    /// "Refresh Builtin Models" flow downloads, schema-validates, and installs
    /// this file. When unset, the refresh action is unavailable. By default it
    /// must be an https URL on a public host without credentials.
    #[serde(default)]
    pub refresh_url: Option<String>,

    /// Accept a plain `http://` source or one on a private network (an
    /// internal mirror). Loopback, link-local and cloud metadata hosts are
    /// refused either way.
    #[serde(default)]
    pub allow_insecure_source: bool,
}

impl LlmCatalogConfig {
    /// The refresh source, or `None` when unset or blank.
    pub fn refresh_url(&self) -> Option<&str> {
        self.refresh_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
    }

    /// Refuse a refresh source the appliance should not download a catalog
    /// from: a malformed URL, one carrying credentials, a loopback, link-local
    /// or cloud metadata host, or, unless `allow_insecure_source` is set, one
    /// that is not https on a public host.
    fn validate(&self) -> anyhow::Result<()> {
        let Some(raw) = self.refresh_url() else {
            return Ok(());
        };
        let url = Url::parse(raw).map_err(|e| anyhow::anyhow!("llm_catalog.refresh_url is not a valid URL: {e}"))?;
        if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
            anyhow::bail!("llm_catalog.refresh_url must be an absolute URL without credentials");
        }
        if self.allow_insecure_source {
            return crate::url_validation::validate_url_not_cloud_metadata(raw)
                .map(|_| ())
                .map_err(|reason| anyhow::anyhow!("llm_catalog.refresh_url is refused: {reason}"));
        }
        if url.scheme() != "https" {
            anyhow::bail!(
                "llm_catalog.refresh_url must be an https URL; set llm_catalog.allow_insecure_source to true for a plain http mirror"
            );
        }
        crate::url_validation::validate_webhook_url(raw).map(|_| ()).map_err(|reason| {
            anyhow::anyhow!(
                "llm_catalog.refresh_url is refused: {reason}; set llm_catalog.allow_insecure_source to true for a mirror on a private network"
            )
        })
    }
}

/// Secrets vault settings (`secrets` in agent-stream.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Secret types the dashboard offers when a secret is created.
    #[serde(default)]
    pub secret_types: Vec<String>,

    /// Whether a read of one secret (`GET /api/v1/secrets/{id}`) answers with
    /// its stored value and the dashboard offers to show it. `false` keeps
    /// values write-only: they can be set and replaced, never read back.
    #[serde(default = "default_reveal_values")]
    pub reveal_values: bool,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            secret_types: Vec::new(),
            reveal_values: default_reveal_values(),
        }
    }
}

fn default_reveal_values() -> bool {
    true
}

/// Appliance-wide LLM drift operational settings (`drift` in agent-stream.json).
/// Governs the replay-evaluation runner; per-surface eval config still lives on
/// the surface's `drift.eval` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftAppConfig {
    /// Consecutive failed replay-eval runs after which the scheduler
    /// auto-suspends a surface's evaluation (`0` disables auto-suspend).
    #[serde(default = "default_eval_max_consecutive_failures")]
    pub eval_max_consecutive_failures: u32,
    /// Per-session wall-clock cap (seconds) for a replayed session, so one
    /// wedged upstream can't hang a whole run. Clamped to a sane range.
    #[serde(default = "default_eval_session_timeout_secs")]
    pub eval_session_timeout_secs: u64,
    /// Appliance-wide ceiling on the provider spend (USD) a single replay-eval
    /// run may consume before it stops part-way, for surfaces that set no
    /// ceiling of their own. Null = no appliance ceiling (a run is still bounded
    /// by its session cap and the target surface's usage limits).
    #[serde(default = "default_eval_max_run_cost_usd")]
    pub eval_max_run_cost_usd: Option<f64>,
    /// Max evaluation runs retained per surface (older ones pruned on write).
    /// Bounds run-history disk regardless of traffic.
    #[serde(default = "default_max_runs_per_surface")]
    pub max_runs_per_surface: usize,
    /// Max captured sessions ("indicative surface data") retained per surface.
    #[serde(default = "default_max_sessions_per_surface")]
    pub max_sessions_per_surface: usize,
    /// Optional age cap (days) for run history — drop runs older than this. Null
    /// or `0` = no age limit (the count cap still applies).
    #[serde(default)]
    pub max_run_age_days: Option<u64>,
    /// Optional age cap (days) for captured sessions. Null or `0` = no age limit.
    #[serde(default)]
    pub max_session_age_days: Option<u64>,
}

impl Default for DriftAppConfig {
    fn default() -> Self {
        Self {
            eval_max_consecutive_failures: default_eval_max_consecutive_failures(),
            eval_session_timeout_secs: default_eval_session_timeout_secs(),
            eval_max_run_cost_usd: default_eval_max_run_cost_usd(),
            max_runs_per_surface: default_max_runs_per_surface(),
            max_sessions_per_surface: default_max_sessions_per_surface(),
            max_run_age_days: None,
            max_session_age_days: None,
        }
    }
}

fn default_eval_max_consecutive_failures() -> u32 {
    3
}

fn default_eval_session_timeout_secs() -> u64 {
    30
}

fn default_eval_max_run_cost_usd() -> Option<f64> {
    Some(5.0)
}

fn default_max_runs_per_surface() -> usize {
    50
}

fn default_max_sessions_per_surface() -> usize {
    200
}

/// DID configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidConfig {
    /// Domain used for did:web generation
    pub domain: String,

    /// DIDs of other appliances whose agent credentials this appliance accepts
    /// inside a presented VP. This appliance's own DID is always trusted.
    #[serde(default)]
    pub trusted_issuers: Vec<String>,
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying Party ID (typically the domain)
    pub rp_id: String,

    /// External origin URL (for WebAuthn when behind proxy)
    pub external_origin: String,
}

fn default_listener_type_inbound() -> String {
    "inbound".to_string()
}

fn default_oauth_callback_route() -> String {
    "/v1/identity/oauth/callback".to_string()
}

/// A single port listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    /// Unique identifier for this listener
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Bind address (typically "0.0.0.0")
    pub bind_address: String,

    /// Port to bind to
    pub port: u16,

    /// Protocol: "http" or "https"
    pub protocol: String,

    /// External URLs that route to this listener (e.g., ngrok URLs)
    pub external_urls: Vec<String>,

    /// Listener direction: `"inbound"` (default) or `"outbound"`.
    /// Existing configs that omit this field default to `"inbound"`.
    #[serde(default = "default_listener_type_inbound")]
    pub listener_type: String,
}

/// A channel prefix configuration for proxy routes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPrefix {
    /// Unique identifier for this channel prefix
    pub id: String,

    /// Human-readable name (displayed in UI dropdown)
    pub name: String,

    /// Route prefix (e.g., "/channels", "/cats")
    pub prefix: String,
}

/// Type of route handler
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RouteType {
    /// Serve the Identity API endpoints
    IdentityApi,
    /// Serve static files from a directory
    Static,
    /// Serve connection point DID documents
    ConnectionPoint,
    /// Redirect to another path
    Redirect,
    /// Serve onboarding endpoints
    Onboarding,
}

/// A category of routes (e.g., "channels", "agents", "routes")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCategory {
    /// Type of route handler
    #[serde(rename = "type")]
    pub route_type: RouteType,

    /// Prefix for this category (e.g., "/channels")
    pub prefix: String,

    /// For static routes: filesystem path to serve
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// For redirect routes: target URL to redirect to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// For static routes: whether this should be the fallback handler
    #[serde(default)]
    pub fallback: bool,
}

impl NetworkConfig {
    /// Load network configuration from a JSON file
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: NetworkConfig = serde_json::from_str(&contents)?;
        config.validate_listeners()?;
        config.validate_terms()?;
        config.validate_llm_catalog()?;
        Ok(config)
    }

    fn validate_llm_catalog(&self) -> anyhow::Result<()> {
        self.llm_catalog
            .as_ref()
            .map_or(Ok(()), LlmCatalogConfig::validate)
    }

    /// Reject configurations that would race the OS for the same socket or
    /// produce ambiguous id-based lookups. Two listeners on the same
    /// `bind_address:port` can never both bind, and duplicate `id` values
    /// silently shadow each other in routing tables — we surface both at
    /// startup rather than letting the second `bind()` fail mid-boot.
    fn validate_listeners(&self) -> anyhow::Result<()> {
        validate_listener_set(&self.listeners)
    }

    fn validate_terms(&self) -> anyhow::Result<()> {
        if !self.terms {
            return Ok(());
        }
        let url = self
            .affinidi_terms_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("affinidi_terms_url is required when terms are enabled"))?;
        validate_affinidi_terms_url(url, cfg!(debug_assertions))
    }

    /// Get all unique ports that should be bound
    pub fn get_ports(&self) -> Vec<u16> {
        self.listeners
            .iter()
            .map(|l| l.port)
            .collect()
    }

    /// Get listener by port
    #[allow(dead_code)]
    pub fn get_listener_by_port(
        &self,
        port: u16,
    ) -> Option<&Listener> {
        self.listeners
            .iter()
            .find(|l| l.port == port)
    }

    /// Get all external URLs across all listeners
    pub fn get_all_external_urls(&self) -> Vec<String> {
        self.listeners
            .iter()
            .flat_map(|l| {
                l.external_urls
                    .iter()
                    .cloned()
            })
            .collect()
    }

    /// Get external URLs from outbound listeners only
    pub fn get_outbound_external_urls(&self) -> Vec<String> {
        self.listeners
            .iter()
            .filter(|l| l.listener_type == "outbound")
            .flat_map(|l| {
                l.external_urls
                    .iter()
                    .cloned()
            })
            .collect()
    }

    /// Get all route prefixes from the top-level routes
    #[allow(dead_code)]
    pub fn get_all_route_prefixes(&self) -> Vec<String> {
        self.routes
            .keys()
            .cloned()
            .collect()
    }

    /// Get channel prefixes (for UI dropdown)
    #[allow(dead_code)]
    pub fn get_channel_prefixes(&self) -> Vec<String> {
        self.channels
            .iter()
            .map(|c| c.prefix.clone())
            .collect()
    }

    /// Get channel prefix configurations (for UI dropdown with names)
    pub fn get_channel_prefix_configs(&self) -> &Vec<ChannelPrefix> {
        &self.channels
    }

    /// Map an external URL to its internal port
    pub fn map_url_to_port(
        &self,
        url: &str,
    ) -> Option<u16> {
        self.map_url_to_port_for_type(url, None)
    }

    /// Map an external URL to its internal port, restricted to listeners of
    /// the given type. When `preferred_type` is `None`, any listener match is
    /// returned. When `preferred_type` is `Some`, only listeners whose
    /// `listener_type` equals the preference are considered — never falls back
    /// to a listener of a different type, because callers asking for a
    /// specific kind (e.g. `"outbound"`) would otherwise receive (and later
    /// abort) the inbound listener that happens to share the URL.
    pub fn map_url_to_port_for_type(
        &self,
        url: &str,
        preferred_type: Option<&str>,
    ) -> Option<u16> {
        let normalized_url = url
            .trim_start_matches("https://")
            .trim_start_matches("http://");

        for listener in &self.listeners {
            if let Some(t) = preferred_type
                && listener.listener_type != t
            {
                continue;
            }
            for ext_url in &listener.external_urls {
                let normalized_ext = ext_url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://");

                if normalized_ext == normalized_url || ext_url == url {
                    return Some(listener.port);
                }
            }
        }

        None
    }
}

fn validate_listener_set(listeners: &[Listener]) -> anyhow::Result<()> {
    use std::collections::HashSet;

    let mut ids: HashSet<&str> = HashSet::new();
    for l in listeners {
        if !ids.insert(l.id.as_str()) {
            anyhow::bail!("Invalid network config: duplicate listener id '{}'", l.id);
        }
    }

    let mut sockets: HashSet<(&str, u16)> = HashSet::new();
    for l in listeners {
        if !sockets.insert((l.bind_address.as_str(), l.port)) {
            anyhow::bail!(
                "Invalid network config: duplicate listener bind address {}:{} (listener id '{}')",
                l.bind_address,
                l.port,
                l.id
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod listener_validation_tests {
    use super::*;

    fn listener(
        id: &str,
        bind: &str,
        port: u16,
    ) -> Listener {
        Listener {
            id: id.to_string(),
            name: id.to_string(),
            bind_address: bind.to_string(),
            port,
            protocol: "http".to_string(),
            external_urls: vec![],
            listener_type: "inbound".to_string(),
        }
    }

    #[test]
    fn duplicate_port_is_rejected() {
        let err = validate_listener_set(&[listener("a", "0.0.0.0", 8080), listener("b", "0.0.0.0", 8080)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate listener bind address 0.0.0.0:8080"), "got: {err}");
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let err = validate_listener_set(&[listener("same", "0.0.0.0", 8080), listener("same", "0.0.0.0", 9090)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate listener id 'same'"), "got: {err}");
    }

    #[test]
    fn distinct_ports_and_ids_pass() {
        validate_listener_set(&[listener("a", "0.0.0.0", 8080), listener("b", "0.0.0.0", 9090)]).unwrap();
    }

    #[test]
    fn same_port_on_different_bind_addresses_passes() {
        validate_listener_set(&[listener("a", "127.0.0.1", 8080), listener("b", "10.0.0.1", 8080)]).unwrap();
    }
}

fn validate_affinidi_terms_url(
    url: &Url,
    allow_loopback_http: bool,
) -> anyhow::Result<()> {
    let loopback_http = allow_loopback_http
        && url.scheme() == "http"
        && url
            .host()
            .is_some_and(|host| match host {
                url::Host::Domain(host) => host == "localhost",
                url::Host::Ipv4(address) => address.is_loopback(),
                url::Host::Ipv6(address) => address.is_loopback(),
            });
    if (url.scheme() != "https" && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        anyhow::bail!("affinidi_terms_url must be an absolute HTTPS URL without credentials");
    }
    Ok(())
}

#[cfg(test)]
mod url_mapping_tests {
    use super::*;

    fn cfg_with_listeners(listeners_json: serde_json::Value) -> NetworkConfig {
        let cfg = serde_json::json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
            "integration": { "types": [], "categories": [] },
            "listeners": listeners_json,
            "routes": {},
        });
        serde_json::from_value(cfg).expect("test network config should deserialize")
    }

    #[test]
    fn terms_defaults_to_disabled() {
        assert!(!cfg_with_listeners(serde_json::json!([])).terms);
    }

    fn llm_catalog(
        refresh_url: &str,
        allow_insecure_source: bool,
    ) -> LlmCatalogConfig {
        LlmCatalogConfig {
            refresh_url: Some(refresh_url.to_string()),
            allow_insecure_source,
        }
    }

    #[test]
    fn llm_catalog_refresh_source_must_be_https_on_a_public_host_by_default() {
        llm_catalog("https://boris.example.com/api/v1/llm", false)
            .validate()
            .expect("an https public source is accepted");
        llm_catalog("", false)
            .validate()
            .expect("a blank source only disables the action");

        for (url, reason) in [
            ("http://boris.example.com/api/v1/llm", "plain http"),
            ("https://10.0.0.5/llm.json", "a private address"),
            ("https://127.0.0.1/llm.json", "loopback"),
            ("https://user:pw@boris.example.com/llm.json", "credentials"),
            ("boris.example.com/llm.json", "no scheme"),
        ] {
            let error = llm_catalog(url, false)
                .validate()
                .expect_err(reason);
            assert!(
                error
                    .to_string()
                    .contains("llm_catalog.refresh_url"),
                "{reason}: {error}"
            );
        }
    }

    #[test]
    fn llm_catalog_allow_insecure_source_admits_a_private_mirror_only() {
        llm_catalog("http://10.0.0.5/llm.json", true)
            .validate()
            .expect("an internal http mirror is accepted once opted in");
        for (url, reason) in [
            ("http://169.254.169.254/latest/meta-data", "cloud metadata"),
            ("http://169.254.10.1/llm.json", "link-local"),
            ("http://[fe80::1]/llm.json", "IPv6 link-local"),
            ("http://127.0.0.1/llm.json", "loopback"),
            ("http://localhost/llm.json", "localhost"),
        ] {
            let error = llm_catalog(url, true)
                .validate()
                .expect_err(reason);
            assert!(
                error
                    .to_string()
                    .contains("llm_catalog.refresh_url"),
                "{reason}: {error}"
            );
        }
    }

    #[test]
    fn secret_values_are_revealed_unless_switched_off() {
        assert!(
            cfg_with_listeners(serde_json::json!([]))
                .secrets
                .reveal_values
        );

        let cfg: NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
            "integration": { "types": [], "categories": [] },
            "listeners": [],
            "routes": {},
            "secrets": { "secret_types": ["General"], "reveal_values": false },
        }))
        .expect("test network config should deserialize");
        assert!(!cfg.secrets.reveal_values);
        assert_eq!(cfg.secrets.secret_types, vec!["General".to_string()]);
    }

    #[test]
    fn local_testing_allows_a_loopback_http_metadata_url() {
        let url = Url::parse("http://127.0.0.1:8080/terms").unwrap();

        validate_affinidi_terms_url(&url, true).unwrap();
    }

    #[test]
    fn production_terms_reject_a_loopback_http_metadata_url() {
        let url = Url::parse("http://127.0.0.1:8080/terms").unwrap();

        let error = validate_affinidi_terms_url(&url, false)
            .unwrap_err()
            .to_string();

        assert!(error.contains("absolute HTTPS URL"), "got: {error}");
    }

    #[test]
    fn enabled_terms_require_an_affinidi_metadata_url() {
        let mut config = cfg_with_listeners(serde_json::json!([]));
        config.terms = true;

        let error = config
            .validate_terms()
            .unwrap_err()
            .to_string();

        assert!(error.contains("affinidi_terms_url"), "got: {error}");
    }

    /// Regression: resolving an outbound listener by URL must NOT map to
    /// an **inbound** listener's port when the caller asks specifically for
    /// an outbound listener. Otherwise the dynamic outbound-rebuild path
    /// will abort the inbound listener (dashboard + channel proxies go dark
    /// after save).
    #[test]
    fn preferred_outbound_does_not_fall_back_to_inbound() {
        let cfg = cfg_with_listeners(serde_json::json!([
            {
                "id": "dashboard",
                "name": "dashboard",
                "bind_address": "0.0.0.0",
                "port": 8443,
                "protocol": "https",
                "external_urls": ["https://gw.example.com"],
                "listener_type": "inbound"
            }
        ]));

        assert_eq!(cfg.map_url_to_port_for_type("https://gw.example.com", Some("outbound")), None);
        assert_eq!(cfg.map_url_to_port_for_type("https://gw.example.com", Some("inbound")), Some(8443));
        assert_eq!(cfg.map_url_to_port("https://gw.example.com"), Some(8443));
    }

    #[test]
    fn preferred_outbound_picks_outbound_when_both_share_url() {
        let cfg = cfg_with_listeners(serde_json::json!([
            {
                "id": "in", "name": "in", "bind_address": "0.0.0.0", "port": 8443,
                "protocol": "https", "external_urls": ["https://gw.example.com"], "listener_type": "inbound"
            },
            {
                "id": "out", "name": "out", "bind_address": "0.0.0.0", "port": 9443,
                "protocol": "https", "external_urls": ["https://gw.example.com"], "listener_type": "outbound"
            }
        ]));

        assert_eq!(cfg.map_url_to_port_for_type("https://gw.example.com", Some("outbound")), Some(9443));
        assert_eq!(cfg.map_url_to_port_for_type("https://gw.example.com", Some("inbound")), Some(8443));
    }

    #[test]
    fn unspecified_preference_returns_any_match() {
        let cfg = cfg_with_listeners(serde_json::json!([
            {
                "id": "out", "name": "out", "bind_address": "0.0.0.0", "port": 9443,
                "protocol": "https", "external_urls": ["https://gw.example.com"], "listener_type": "outbound"
            }
        ]));
        assert_eq!(cfg.map_url_to_port("https://gw.example.com"), Some(9443));
    }
}
