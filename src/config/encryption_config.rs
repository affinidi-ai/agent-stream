//! Encryption at rest configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Encryption at rest configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Whether encryption is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Source for the master encryption key
    #[serde(default)]
    pub key_source: KeySourceConfig,

    /// Environment variable name for master key (when using 'environment' source)
    #[serde(default = "default_key_env_var")]
    pub key_env_var: String,

    /// File path for master key (when using 'file' source)
    pub key_file: Option<PathBuf>,

    /// AWS KMS key ID (when using 'aws_kms' source)
    pub kms_key_id: Option<String>,

    /// Maximum concurrent AWS KMS operations (bounds the per-value envelope
    /// backend's KMS round trips).
    #[serde(default = "default_kms_max_concurrent_ops")]
    pub kms_max_concurrent_ops: usize,

    /// Whether encryption is enabled for individual fields fo entities.
    /// TODO: once pub key is implemented, add dedicated key per field-encryption.
    #[serde(default)]
    pub field_encryption_enabled: bool,

    /// Explicitly accept storing data unencrypted. Startup refuses a
    /// configuration that neither enables encryption nor sets this.
    #[serde(default)]
    pub allow_unencrypted: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_source: KeySourceConfig::Environment,
            key_env_var: default_key_env_var(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: default_kms_max_concurrent_ops(),
            field_encryption_enabled: false,
            allow_unencrypted: false,
        }
    }
}

impl EncryptionConfig {
    /// Require an explicit choice: encryption enabled, or plaintext storage
    /// accepted with `allow_unencrypted`, never both and never neither.
    pub fn validate(&self) -> Result<(), String> {
        match (self.enabled, self.allow_unencrypted) {
            (true, false) | (false, true) => Ok(()),
            (true, true) => Err("[encryption] sets both enabled = true and allow_unencrypted = true. Remove \
                 allow_unencrypted to keep encrypting data at rest. Set enabled = false instead only if this \
                 appliance has never stored data encrypted: records written encrypted are not loaded while \
                 encryption is disabled."
                .to_string()),
            (false, false) => Err("Encryption at rest is not configured: enabled = false on its own is not an \
                 opt-out. Either enable it with [encryption] enabled = true and a key_source (\"environment\", \
                 \"file\" or \"aws_kms\"), or accept storing data unencrypted with [encryption] \
                 allow_unencrypted = true. See docs/ENCRYPTION_AT_REST.md."
                .to_string()),
        }
    }
}

/// Source for the master encryption key
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeySourceConfig {
    /// Load key from environment variable
    #[default]
    Environment,

    /// Load key from file
    File,

    /// Use AWS KMS (per-value envelope encryption; requires `kms_key_id`)
    AwsKms,
}

fn default_key_env_var() -> String {
    "AS_MASTER_KEY".to_string()
}

fn default_kms_max_concurrent_ops() -> usize {
    16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EncryptionConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.key_source, KeySourceConfig::Environment);
        assert_eq!(config.key_env_var, "AS_MASTER_KEY");
    }

    #[test]
    fn test_serialize_deserialize() {
        let config = EncryptionConfig {
            enabled: true,
            key_source: KeySourceConfig::Environment,
            key_env_var: "MY_KEY".to_string(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: 16,
            field_encryption_enabled: false,
            allow_unencrypted: false,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: EncryptionConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.enabled, config.enabled);
        assert_eq!(deserialized.key_source, config.key_source);
        assert_eq!(deserialized.key_env_var, config.key_env_var);
    }

    fn parse(table: &str) -> EncryptionConfig {
        toml::from_str(table).expect("the [encryption] table must parse")
    }

    #[test]
    fn a_missing_choice_is_refused_and_the_error_names_both_options() {
        for config in [EncryptionConfig::default(), parse(""), parse("enabled = false\n")] {
            let error = config
                .validate()
                .expect_err("neither encryption nor an opt-out must refuse to start");
            assert!(error.contains("enabled = true"), "error must name enabling encryption: {error}");
            assert!(error.contains("allow_unencrypted = true"), "error must name the opt-out: {error}");
        }
    }

    #[test]
    fn enabled_encryption_is_accepted() {
        assert_eq!(parse("enabled = true\nkey_source = \"environment\"\n").validate(), Ok(()));
    }

    #[test]
    fn the_explicit_opt_out_is_accepted() {
        assert_eq!(parse("allow_unencrypted = true\n").validate(), Ok(()));
        assert_eq!(parse("enabled = false\nallow_unencrypted = true\n").validate(), Ok(()));
    }

    #[test]
    fn enabling_encryption_and_opting_out_together_is_refused() {
        let error = parse("enabled = true\nallow_unencrypted = true\n")
            .validate()
            .expect_err("a contradictory choice must refuse to start");
        assert!(error.contains("both"), "unexpected error: {error}");
    }

    #[test]
    fn test_key_source_aws_kms_canonical() {
        let canonical: KeySourceConfig = serde_json::from_str("\"aws_kms\"").unwrap();
        assert_eq!(canonical, KeySourceConfig::AwsKms);

        assert_eq!(serde_json::to_string(&KeySourceConfig::AwsKms).unwrap(), "\"aws_kms\"");
    }
}
