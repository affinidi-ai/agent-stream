//! Serde helpers for transparent field-level encryption
//!
//! These modules allow encrypting specific fields in structs using
//! serde attributes:
//!
//! ```rust
//! #[derive(Serialize, Deserialize)]
//! struct MyStruct {
//!     pub name: String,  // Plain text
//!
//!     #[serde(with = "crate::encryption::serde_encrypted::string")]
//!     pub secret: String,  // Encrypted
//!
//!     #[serde(with = "crate::encryption::serde_encrypted::option_string")]
//!     pub optional_secret: Option<String>,  // Encrypted if present
//! }
//! ```
//!
//! The encryption service must be available via a thread-local or passed
//! through context. For simplicity, we use a global lazy_static service.

use once_cell::sync::Lazy;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::RwLock;
use tracing::{debug, warn};

use super::EncryptionService;

/// Global encryption config for storage operations
/// This is initialized by the application at startup and used throughout
/// storage creation to apply consistent encryption settings to all storage instances.
static GLOBAL_ENCRYPTION_CONFIG: Lazy<RwLock<Option<crate::config::EncryptionConfig>>> =
    Lazy::new(|| RwLock::new(None));

/// Global encryption service for serde operations
/// This is initialized by the application and used throughout serialization
static GLOBAL_ENCRYPTION_SERVICE: Lazy<RwLock<Option<EncryptionService>>> = Lazy::new(|| RwLock::new(None));

/// Initialize the global encryption service
///
/// Constructs the `EncryptionService` internally from the given config
/// via `init_encryption_service`. Must be called before any encrypted
/// structs are serialized/deserialized.
pub fn init_global_encryption(config: crate::config::EncryptionConfig) -> anyhow::Result<()> {
    let mut global_config = GLOBAL_ENCRYPTION_CONFIG
        .write()
        .unwrap();
    *global_config = Some(config.clone());

    let encryption_service = crate::encryption::init::init_encryption_service(&config)?;
    let mut global_encryption_service = GLOBAL_ENCRYPTION_SERVICE
        .write()
        .unwrap();
    *global_encryption_service = Some(encryption_service);

    debug!("Global encryption config and encryption service initialized for all serde operations");
    Ok(())
}

/// Get the global encryption config if set
fn get_global_encryption_config() -> Option<crate::config::EncryptionConfig> {
    GLOBAL_ENCRYPTION_CONFIG
        .read()
        .unwrap()
        .clone()
}

/// Get the global encryption service (internal)
fn get_global_encryption_service() -> Option<EncryptionService> {
    GLOBAL_ENCRYPTION_SERVICE
        .read()
        .unwrap()
        .clone()
}

/// Get the global encryption service for direct encrypt/decrypt operations
pub fn get_encryption_service() -> Option<EncryptionService> {
    get_global_encryption_service()
}

/// Encrypt a string field
fn encrypt_string(value: &str) -> Result<String, String> {
    match get_global_encryption_config() {
        Some(enc_config) => {
            if !enc_config.enabled {
                return Ok(value.to_string());
            }
            if !enc_config.field_encryption_enabled {
                return Ok(value.to_string());
            }
            match get_global_encryption_service() {
                Some(encryption_service) => encryption_service
                    .encrypt_field(value)
                    .map_err(|e| format!("Encryption failed: {}", e)),
                None => {
                    warn!("Encryption service not initialized, storing data unencrypted");
                    Ok(value.to_string())
                }
            }
        }
        None => Ok(value.to_string()),
    }
}

/// Decrypt a string field
fn decrypt_string(value: &str) -> Result<String, String> {
    match get_global_encryption_config() {
        Some(enc_config) => {
            if !enc_config.enabled {
                return Ok(value.to_string());
            }
            if !enc_config.field_encryption_enabled {
                return Ok(value.to_string());
            }

            // Check if encrypted
            if !value.starts_with("ENC[") {
                // Backward compatibility: return as-is
                return Ok(value.to_string());
            }

            match get_global_encryption_service() {
                Some(encryption_service) => encryption_service
                    .decrypt_field(value)
                    .map_err(|e| format!("Decryption failed: {}", e)),
                None => {
                    warn!("Encryption service not initialized, cannot decrypt data");
                    Err("Encryption service not available".to_string())
                }
            }
        }
        None => Ok(value.to_string()),
    }
}

/// Serialize/deserialize encrypted String fields
pub mod string {
    use super::*;

    pub fn serialize<S>(
        value: &str,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encrypted = encrypt_string(value).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&encrypted)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        decrypt_string(&s).map_err(serde::de::Error::custom)
    }
}

/// Serialize/deserialize encrypted Option<String> fields
pub mod option_string {
    use super::*;

    pub fn serialize<S>(
        value: &Option<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(s) => {
                let encrypted = encrypt_string(s).map_err(serde::ser::Error::custom)?;
                serializer.serialize_some(&encrypted)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let decrypted = decrypt_string(&s).map_err(serde::de::Error::custom)?;
                Ok(Some(decrypted))
            }
            None => Ok(None),
        }
    }
}

/// Serialize/deserialize encrypted Vec<String> fields
pub mod vec_string {
    use super::*;

    #[allow(unused)]
    pub fn serialize<S>(
        values: &[String],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encrypted_values: Result<Vec<String>, String> = values
            .iter()
            .map(|s| encrypt_string(s))
            .collect();

        let encrypted_values = encrypted_values.map_err(serde::ser::Error::custom)?;

        serializer.collect_seq(encrypted_values)
    }

    #[allow(unused)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encrypted_values = Vec::<String>::deserialize(deserializer)?;

        let decrypted_values: Result<Vec<String>, String> = encrypted_values
            .iter()
            .map(|s| decrypt_string(s))
            .collect();

        decrypted_values.map_err(serde::de::Error::custom)
    }
}

/// Serialize/deserialize encrypted Vec<Secret> fields
/// This serializes the entire Vec as JSON, encrypts it, and stores as a string
pub mod encrypted_secrets {
    use super::*;
    use serde_json;

    pub fn serialize<S, T>(
        values: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        // Serialize the entire vec to JSON
        let json = serde_json::to_string(values).map_err(serde::ser::Error::custom)?;

        // Encrypt the JSON string
        let encrypted = encrypt_string(&json).map_err(serde::ser::Error::custom)?;

        serializer.serialize_str(&encrypted)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: serde::de::DeserializeOwned,
    {
        let encrypted_str = String::deserialize(deserializer)?;

        // Check if encrypted or plain text (backward compatibility)
        let json = if encrypted_str.starts_with("ENC[") || encrypted_str.is_empty() || encrypted_str == "[]" {
            if encrypted_str.starts_with("ENC[") {
                decrypt_string(&encrypted_str).map_err(serde::de::Error::custom)?
            } else {
                // Empty array or already decrypted
                encrypted_str
            }
        } else {
            // Old format: try to parse directly
            encrypted_str
        };

        // Deserialize from JSON
        serde_json::from_str(&json).map_err(serde::de::Error::custom)
    }
}

/// Serialize/deserialize encrypted JSON Value fields
/// This is useful for encrypting structured data like OOB messages
pub mod encrypted_json {
    use super::*;
    use serde_json::Value;

    pub fn serialize<S>(
        value: &Value,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize value to JSON string
        let json_str = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;

        // Encrypt the JSON string
        let encrypted = encrypt_string(&json_str).map_err(serde::ser::Error::custom)?;

        serializer.serialize_str(&encrypted)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encrypted_str = String::deserialize(deserializer)?;

        // Check if encrypted or plain text (backward compatibility)
        let json_str = if encrypted_str.starts_with("ENC[") {
            decrypt_string(&encrypted_str).map_err(serde::de::Error::custom)?
        } else {
            // Old format: already plain JSON
            encrypted_str
        };

        // Parse JSON
        serde_json::from_str(&json_str).map_err(serde::de::Error::custom)
    }
}

/// Serialize/deserialize encrypted byte arrays as base64
pub mod bytes {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    #[allow(unused)]
    pub fn serialize<S>(
        value: &[u8],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encrypted = match get_global_encryption_service() {
            Some(encryption_service) => encryption_service
                .encrypt_bytes(value)
                .map_err(serde::ser::Error::custom)?,
            None => {
                warn!("Encryption service not initialized, storing bytes unencrypted");
                value.to_vec()
            }
        };

        let base64_str = BASE64.encode(encrypted);
        serializer.serialize_str(&base64_str)
    }

    #[allow(unused)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base64_str = String::deserialize(deserializer)?;
        let encrypted = BASE64
            .decode(base64_str)
            .map_err(serde::de::Error::custom)?;

        match get_global_encryption_service() {
            Some(encryption_service) => encryption_service
                .decrypt_bytes(&encrypted)
                .map_err(serde::de::Error::custom),
            None => {
                warn!("Encryption service not initialized, cannot decrypt bytes");
                Err(serde::de::Error::custom("Encryption service not available"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        pub name: String,

        #[serde(with = "string")]
        pub secret: String,

        #[serde(with = "option_string")]
        pub optional_secret: Option<String>,
    }

    fn init_test_encryption() {
        // A deterministic test key, set by `.cargo/config.toml` `[env]`.
        let config = crate::config::EncryptionConfig {
            enabled: true,
            field_encryption_enabled: true,
            key_env_var: "AS_TEST_ENCRYPTION_KEY".to_string(),
            ..Default::default()
        };

        init_global_encryption(config).unwrap();
    }

    #[test]
    fn test_encrypted_struct_serialization() {
        init_test_encryption();

        let test_data = TestStruct {
            name: "public name".to_string(),
            secret: "secret value".to_string(),
            optional_secret: Some("optional secret".to_string()),
        };

        // Serialize
        let json = serde_json::to_string(&test_data).unwrap();

        // Name should be plain, secret should be encrypted
        assert!(json.contains("public name"));
        assert!(!json.contains("secret value"));
        assert!(json.contains("ENC["));

        // Deserialize
        let deserialized: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, test_data);
    }

    #[test]
    fn test_backward_compatibility() {
        init_test_encryption();

        // Old format without encryption
        let old_json = r#"{
            "name": "test",
            "secret": "plain text secret",
            "optional_secret": "plain optional"
        }"#;

        // Should still deserialize correctly
        let deserialized: TestStruct = serde_json::from_str(old_json).unwrap();
        assert_eq!(deserialized.secret, "plain text secret");
        assert_eq!(deserialized.optional_secret, Some("plain optional".to_string()));
    }
}
