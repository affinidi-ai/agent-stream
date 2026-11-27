use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Authentication mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum AuthMode {
    /// WebAuthn passkey authentication
    #[default]
    Passkey,
    /// SAML 2.0 authentication
    Saml,
    /// OpenID Connect sign-in with one OpenID provider
    Oidc,
}

impl AuthMode {
    /// The mode's name in `config.toml` and on `/v1/auth/mode`.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMode::Passkey => "passkey",
            AuthMode::Saml => "saml",
            AuthMode::Oidc => "oidc",
        }
    }
}

/// SAML authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// Azure AD entity ID (Identity Provider)
    pub idp_entity_id: String,

    /// Azure AD Single Sign-On URL
    pub idp_sso_url: String,

    /// Must be `null` or absent; a value refuses startup because SAML single logout is not supported.
    pub idp_slo_url: Option<String>,

    /// Service Provider entity ID (your application)
    pub sp_entity_id: String,

    /// Assertion Consumer Service URL (where Azure AD posts SAML response)
    pub sp_acs_url: String,

    /// Path to Azure AD certificate for signature verification
    pub idp_cert_path: String,

    /// Attribute mappings from SAML to user fields
    #[serde(default)]
    pub attribute_mapping: SamlAttributeMapping,

    /// Role mapping from Azure AD roles/groups to RBAC roles
    #[serde(default)]
    pub role_mapping: HashMap<String, String>,

    /// Role for a sign-in whose role attribute has no `role_mapping` entry; without it that sign-in is refused
    #[serde(default)]
    pub default_role: Option<String>,

    /// Must be `false` or absent; `true` refuses startup because assertions are not decrypted.
    #[serde(default)]
    pub require_encrypted_assertions: bool,

    /// Sign authentication requests (default: true)
    #[serde(default = "default_true")]
    pub sign_requests: bool,

    /// Path to SP private key for signing (required if sign_requests = true)
    pub sp_key_path: Option<String>,

    /// Path to SP certificate (required if sign_requests = true)
    pub sp_cert_path: Option<String>,

    /// Microsoft Graph API configuration for fetching user avatars (optional)
    #[serde(default)]
    pub graph_api: Option<GraphApiConfig>,
}

/// Microsoft Graph API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphApiConfig {
    /// Azure AD tenant ID
    pub tenant_id: String,

    /// Azure AD application (client) ID
    pub client_id: String,

    /// Azure AD application client secret
    pub client_secret: String,

    /// Fetch user avatar on login (default: false)
    #[serde(default)]
    pub fetch_avatar: bool,
}

/// SAML attribute mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeMapping {
    /// Attribute containing user ID
    #[serde(default = "default_saml_user_id_attribute")]
    pub user_id: String,

    /// Attribute containing username
    #[serde(default = "default_saml_username_attribute")]
    pub username: String,

    /// Attribute containing email
    #[serde(default = "default_saml_email_attribute")]
    pub email: String,

    /// Attribute containing first name
    #[serde(default = "default_saml_first_name_attribute")]
    pub first_name: String,

    /// Attribute containing last name
    #[serde(default = "default_saml_last_name_attribute")]
    pub last_name: String,

    /// Attribute containing role/group information
    #[serde(default = "default_saml_role_attribute")]
    pub role: String,

    /// Attribute containing department
    #[serde(default = "default_saml_department_attribute")]
    pub department: String,

    /// Attribute containing job title
    #[serde(default = "default_saml_job_title_attribute")]
    pub job_title: String,
}

impl Default for SamlAttributeMapping {
    fn default() -> Self {
        Self {
            user_id: default_saml_user_id_attribute(),
            username: default_saml_username_attribute(),
            email: default_saml_email_attribute(),
            first_name: default_saml_first_name_attribute(),
            last_name: default_saml_last_name_attribute(),
            role: default_saml_role_attribute(),
            department: default_saml_department_attribute(),
            job_title: default_saml_job_title_attribute(),
        }
    }
}

// Default functions - made public so they can be used from config/types.rs
pub fn default_passkey_storage_path() -> String {
    "../_storage/passkeys".to_string()
}

pub fn default_avatars_storage_path() -> String {
    "../_storage/avatars".to_string()
}

pub fn default_saml_config_path() -> String {
    "saml.json".to_string()
}

pub fn default_oidc_config_path() -> String {
    "oidc.json".to_string()
}

#[allow(dead_code)]
pub fn default_session_timeout_minutes() -> u64 {
    20
}

fn default_saml_user_id_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier".to_string()
}

fn default_saml_username_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".to_string()
}

fn default_saml_email_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".to_string()
}

fn default_saml_first_name_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname".to_string()
}

fn default_saml_last_name_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname".to_string()
}

fn default_saml_role_attribute() -> String {
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role".to_string()
}

fn default_saml_department_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department".to_string()
}

fn default_saml_job_title_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/title".to_string()
}

fn default_true() -> bool {
    true
}

impl SamlConfig {
    /// Load SAML configuration from a JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content =
            fs::read_to_string(path.as_ref()).map_err(|e| format!("Failed to read SAML config file: {}", e))?;

        Self::from_json(&content)
    }

    /// Parses SAML configuration JSON. `"require_encrypted_assertions": true`, a
    /// non-null `"idp_slo_url"` and a role name that is not `administrator`, `poweruser` or `user`
    /// in `role_mapping` or `default_role` are refused. Keys Agent Stream does not read log one warning.
    pub(crate) fn from_json(content: &str) -> Result<Self, String> {
        let config: Self =
            serde_json::from_str(content).map_err(|e| format!("Failed to parse SAML config JSON: {}", e))?;

        if config.require_encrypted_assertions {
            return Err("require_encrypted_assertions must be false or absent: encrypted SAML assertions are not \
                 supported. Configure the identity provider to send unencrypted signed assertions. See \
                 docs/CONFIGURATION_REFERENCE.md#samljson"
                .to_string());
        }

        if config.idp_slo_url.is_some() {
            return Err("idp_slo_url must be null or absent: SAML single logout is not supported, and signing out \
                 ends only the dashboard session. Remove it. See docs/CONFIGURATION_REFERENCE.md#samljson"
                .to_string());
        }

        config.validate_roles()?;

        let unread = unread_saml_keys(&config, content);
        if !unread.is_empty() {
            tracing::warn!(
                keys = ?logged_unread_keys(&unread),
                count = unread.len(),
                "saml.json sets keys Agent Stream does not read; they are ignored"
            );
        }

        Ok(config)
    }
}

impl SamlConfig {
    fn validate_roles(&self) -> Result<(), String> {
        let mut entries: Vec<(&String, &String)> = self
            .role_mapping
            .iter()
            .collect();
        entries.sort();
        for (value, role) in entries {
            if crate::auth::types::UserRole::from_config_name(role).is_none() {
                return Err(format!(
                    "role_mapping entry {value:?} names the unknown role {role:?}: expected administrator, poweruser \
                     or user. See docs/CONFIGURATION_REFERENCE.md#samljson"
                ));
            }
        }
        if let Some(role) = &self.default_role
            && crate::auth::types::UserRole::from_config_name(role).is_none()
        {
            return Err(format!(
                "default_role names the unknown role {role:?}: expected administrator, poweruser or user. See \
                 docs/CONFIGURATION_REFERENCE.md#samljson"
            ));
        }
        Ok(())
    }
}

/// `saml.json` keys Agent Stream accepts without reading and without a warning, as dotted paths.
const IGNORED_SAML_KEYS: [&str; 2] = ["idp_metadata_url", "graph_api.note"];

/// The startup warning names at most this many unread keys.
const MAX_LOGGED_UNREAD_SAML_KEYS: usize = 20;

/// The startup warning prints at most this many characters of each key path.
const MAX_LOGGED_KEY_CHARS: usize = 64;

/// The unread key paths the startup warning names: the first [`MAX_LOGGED_UNREAD_SAML_KEYS`],
/// each cut to [`MAX_LOGGED_KEY_CHARS`] characters.
fn logged_unread_keys(unread: &[String]) -> Vec<String> {
    unread
        .iter()
        .take(MAX_LOGGED_UNREAD_SAML_KEYS)
        .map(|key| {
            key.chars()
                .take(MAX_LOGGED_KEY_CHARS)
                .collect()
        })
        .collect()
}

/// The dotted paths of the non-null keys in `content` that `config` does not read, sorted,
/// leaving out [`IGNORED_SAML_KEYS`]. A key is read when `config` serializes it back.
fn unread_saml_keys(
    config: &SamlConfig,
    content: &str,
) -> Vec<String> {
    let (Ok(serde_json::Value::Object(raw)), Ok(serde_json::Value::Object(read))) =
        (serde_json::from_str::<serde_json::Value>(content), serde_json::to_value(config))
    else {
        return Vec::new();
    };
    let mut unread = Vec::new();
    collect_unread_keys("", &raw, &read, &mut unread);
    unread.sort();
    unread
}

fn collect_unread_keys(
    prefix: &str,
    raw: &serde_json::Map<String, serde_json::Value>,
    read: &serde_json::Map<String, serde_json::Value>,
    unread: &mut Vec<String>,
) {
    for (key, value) in raw {
        if value.is_null() {
            continue;
        }
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if IGNORED_SAML_KEYS.contains(&path.as_str()) {
            continue;
        }
        match (value, read.get(key)) {
            (_, None) => unread.push(path),
            (serde_json::Value::Object(raw_child), Some(serde_json::Value::Object(read_child))) => {
                collect_unread_keys(&path, raw_child, read_child, unread);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saml_json(extra: &str) -> String {
        format!(
            r#"{{
                "idp_entity_id": "https://idp.example.com/",
                "idp_sso_url": "https://idp.example.com/sso",
                "sp_entity_id": "https://sp.example.com/metadata",
                "sp_acs_url": "https://sp.example.com/acs",
                "idp_cert_path": "certs/idp.cer"{extra}
            }}"#
        )
    }

    fn assert_refuses_encrypted_assertions(error: &str) {
        assert!(error.starts_with("require_encrypted_assertions must be false or absent"), "{error}");
        assert!(error.contains("unencrypted signed assertions"), "{error}");
        assert!(error.contains("docs/CONFIGURATION_REFERENCE.md#samljson"), "{error}");
    }

    fn assert_refuses_idp_slo_url(error: &str) {
        assert!(error.starts_with("idp_slo_url must be null or absent"), "{error}");
        assert!(error.contains("SAML single logout is not supported"), "{error}");
        assert!(error.contains("docs/CONFIGURATION_REFERENCE.md#samljson"), "{error}");
    }

    #[test]
    fn from_json_refuses_require_encrypted_assertions_true() {
        let error = SamlConfig::from_json(&saml_json(r#", "require_encrypted_assertions": true"#)).unwrap_err();

        assert_refuses_encrypted_assertions(&error);
    }

    #[test]
    fn from_json_accepts_require_encrypted_assertions_false() {
        let config = SamlConfig::from_json(&saml_json(r#", "require_encrypted_assertions": false"#)).unwrap();

        assert!(!config.require_encrypted_assertions);
    }

    #[test]
    fn from_json_accepts_absent_settings() {
        let config = SamlConfig::from_json(&saml_json("")).unwrap();

        assert!(!config.require_encrypted_assertions);
        assert_eq!(config.idp_slo_url, None);
    }

    #[test]
    fn from_json_refuses_idp_slo_url() {
        let error = SamlConfig::from_json(&saml_json(r#", "idp_slo_url": "https://idp.example.com/slo""#)).unwrap_err();

        assert_refuses_idp_slo_url(&error);
    }

    #[test]
    fn from_json_refuses_empty_idp_slo_url() {
        let error = SamlConfig::from_json(&saml_json(r#", "idp_slo_url": """#)).unwrap_err();

        assert_refuses_idp_slo_url(&error);
    }

    #[test]
    fn from_json_accepts_null_idp_slo_url() {
        let config = SamlConfig::from_json(&saml_json(r#", "idp_slo_url": null"#)).unwrap();

        assert_eq!(config.idp_slo_url, None);
    }

    #[test]
    fn from_json_reports_encrypted_assertions_first_when_both_are_set() {
        let error = SamlConfig::from_json(&saml_json(
            r#", "idp_slo_url": "https://idp.example.com/slo", "require_encrypted_assertions": true"#,
        ))
        .unwrap_err();

        assert_refuses_encrypted_assertions(&error);
    }

    #[test]
    fn from_json_reports_invalid_json() {
        let error = SamlConfig::from_json("{").unwrap_err();

        assert!(error.starts_with("Failed to parse SAML config JSON"), "{error}");
    }

    #[test]
    fn example_saml_config_loads() {
        let config = SamlConfig::from_json(include_str!("../../config/examples/saml.example.json")).unwrap();

        assert!(!config.require_encrypted_assertions);
        assert_eq!(config.idp_slo_url, None);
    }

    #[test]
    fn a_role_mapping_entry_naming_an_unknown_role_refuses_the_file_and_names_the_entry() {
        let content = saml_json(r#", "role_mapping": {"ops": "poweruser", "staff": "root"}"#);

        let error = SamlConfig::from_json(&content).unwrap_err();

        assert!(error.starts_with(r#"role_mapping entry "staff" names the unknown role "root""#), "{error}");
    }

    #[test]
    fn a_default_role_naming_an_unknown_role_refuses_the_file() {
        let content = saml_json(r#", "default_role": "root""#);

        let error = SamlConfig::from_json(&content).unwrap_err();

        assert!(error.starts_with(r#"default_role names the unknown role "root""#), "{error}");
    }

    #[test]
    fn role_names_are_read_whatever_their_case() {
        let content = saml_json(r#", "role_mapping": {"ops": "PowerUser"}, "default_role": "User""#);

        let config = SamlConfig::from_json(&content).unwrap();

        assert_eq!(config.default_role.as_deref(), Some("User"));
    }

    fn unread_keys_of(content: &str) -> Vec<String> {
        let config = SamlConfig::from_json(content).unwrap();

        unread_saml_keys(&config, content)
    }

    #[test]
    fn unread_saml_keys_names_unknown_top_level_and_nested_keys() {
        let content = saml_json(
            r#", "idp_sso_urll": "https://idp.example.com/sso",
                "attribute_mapping": {"email": "mail", "emial": "secret-value"},
                "graph_api": {"tenant_id": "t", "client_id": "c", "client_secret": "s", "scope": "x"}"#,
        );

        let unread = unread_keys_of(&content);

        assert_eq!(
            unread,
            vec!["attribute_mapping.emial".to_string(), "graph_api.scope".to_string(), "idp_sso_urll".to_string()]
        );
        assert!(
            unread
                .iter()
                .all(|key| !key.contains("secret-value")),
            "{unread:?}"
        );
    }

    #[test]
    fn unread_saml_keys_leaves_out_ignored_keys() {
        let content = saml_json(
            r#", "idp_metadata_url": "https://idp.example.com/metadata",
                "graph_api": {"tenant_id": "t", "client_id": "c", "client_secret": "s", "note": "n"}"#,
        );

        assert_eq!(unread_keys_of(&content), Vec::<String>::new());
    }

    #[test]
    fn unread_saml_keys_reads_every_known_key() {
        let content = saml_json(
            r#", "idp_slo_url": null, "require_encrypted_assertions": false, "sign_requests": false,
                "sp_key_path": "k.pem", "sp_cert_path": "c.pem",
                "role_mapping": {"any-idp-role": "user"}, "default_role": "user",
                "attribute_mapping": {"user_id": "u", "username": "n", "email": "e", "first_name": "f",
                    "last_name": "l", "role": "r", "department": "d", "job_title": "j"},
                "graph_api": {"tenant_id": "t", "client_id": "c", "client_secret": "s", "fetch_avatar": true}"#,
        );

        assert_eq!(unread_keys_of(&content), Vec::<String>::new());
    }

    #[test]
    fn unread_saml_keys_skips_null_values() {
        let content = saml_json(r#", "unused_setting": null"#);

        assert_eq!(unread_keys_of(&content), Vec::<String>::new());
    }

    #[test]
    fn logged_unread_keys_names_at_most_20_keys() {
        let unread: Vec<String> = (0..25)
            .map(|i| format!("key_{i:02}"))
            .collect();

        assert_eq!(logged_unread_keys(&unread), unread[..20].to_vec());
    }

    #[test]
    fn logged_unread_keys_cuts_each_key_to_64_chars() {
        let logged = logged_unread_keys(&["k".repeat(100)]);

        assert_eq!(logged, vec!["k".repeat(64)]);
    }

    #[test]
    fn unread_saml_keys_is_empty_for_the_example() {
        assert_eq!(unread_keys_of(include_str!("../../config/examples/saml.example.json")), Vec::<String>::new());
    }

    #[test]
    fn from_json_accepts_unknown_keys() {
        let config = SamlConfig::from_json(&saml_json(r#", "unknown_setting": true"#)).unwrap();

        assert_eq!(config.sp_acs_url, "https://sp.example.com/acs");
    }

    #[test]
    fn load_from_file_loads_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saml.json");
        fs::write(&path, saml_json("")).unwrap();

        let config = SamlConfig::load_from_file(&path).unwrap();

        assert_eq!(config.sp_acs_url, "https://sp.example.com/acs");
    }

    #[test]
    fn load_from_file_refuses_idp_slo_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saml.json");
        fs::write(&path, saml_json(r#", "idp_slo_url": "https://idp.example.com/slo""#)).unwrap();

        let error = SamlConfig::load_from_file(&path).unwrap_err();

        assert_refuses_idp_slo_url(&error);
    }

    #[test]
    fn load_from_file_refuses_require_encrypted_assertions_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saml.json");
        fs::write(&path, saml_json(r#", "require_encrypted_assertions": true"#)).unwrap();

        let error = SamlConfig::load_from_file(&path).unwrap_err();

        assert_refuses_encrypted_assertions(&error);
    }

    #[test]
    fn load_from_file_reports_missing_file() {
        let dir = tempfile::tempdir().unwrap();

        let error = SamlConfig::load_from_file(
            dir.path()
                .join("missing.json"),
        )
        .unwrap_err();

        assert!(error.starts_with("Failed to read SAML config file"), "{error}");
    }
}
