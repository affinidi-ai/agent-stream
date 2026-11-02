use crate::config::loaders::{environment::optional_env, load};

const LOG_TARGET: &str = "identity_hash";
const PEPPER_HASH_ENV_NAME: &str = "AS_IDENTITY_HASH_PEPPER";
const PRINCIPAL_KEY_SECRET_ENV_NAME: &str = "AS_PRINCIPAL_KEY_SECRET";

pub struct IdentityHashPepperConfig {
    pub pepper_hash: Vec<u8>,
}

fn decode_pepper_hex(
    source: &str,
    hex_str: &str,
) -> Option<Vec<u8>> {
    match hex::decode(hex_str.trim()) {
        Ok(bytes) if bytes.len() >= 32 => {
            tracing::info!(
                target: LOG_TARGET,
                source,
                bytes = bytes.len(),
                "Using configured identity hash pepper"
            );
            Some(bytes)
        }
        Ok(bytes) => {
            tracing::warn!(
                target: LOG_TARGET,
                source,
                bytes = bytes.len(),
                "Configured identity hash pepper decoded to <32 bytes; ignoring"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                target: LOG_TARGET,
                source,
                error = %e,
                "Configured identity hash pepper is not valid hex; ignoring"
            );
            None
        }
    }
}

impl IdentityHashPepperConfig {
    /// The pepper configured in `AS_IDENTITY_HASH_PEPPER`; `Ok(None)` when it is
    /// unset, an error when it is set but does not resolve to at least 32 bytes
    /// of hex.
    pub async fn load() -> Result<Option<Self>, String> {
        if optional_env(PEPPER_HASH_ENV_NAME).is_none() {
            return Ok(None);
        }
        load_hex_secret(PEPPER_HASH_ENV_NAME)
            .await
            .map(|pepper_hash| Some(Self { pepper_hash }))
            .ok_or_else(|| format!("{PEPPER_HASH_ENV_NAME} is set but is not at least 32 bytes of hex"))
    }

    /// A new random 32-byte pepper.
    pub fn generate() -> Self {
        let mut out = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut out);
        Self { pepper_hash: out }
    }
}

/// The secret Agent Stream shares with Agent Gateway for the `principal_key`
/// caller hash, from `AS_PRINCIPAL_KEY_SECRET`. `None` when it is unset or does
/// not resolve to at least 32 bytes of hex.
pub async fn load_principal_key_secret() -> Option<Vec<u8>> {
    load_hex_secret(PRINCIPAL_KEY_SECRET_ENV_NAME).await
}

/// Resolve `env_name` (raw hex or a loader reference such as
/// `aws_secrets://name`) to at least 32 bytes.
async fn load_hex_secret(env_name: &str) -> Option<Vec<u8>> {
    let env_value = optional_env(env_name)?;
    match load(&env_value).await {
        Ok(value) => decode_pepper_hex(env_name, value.trim()),
        Err(err) => {
            tracing::error!(target: LOG_TARGET, "{env_name} is set but could not be resolved: {err:?}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_valid_hex_pepper() {
        let pepper = "b3db103012fe4b728ec8df312b72b7f998bd799cb2033c4fd3b157cf65fe63f5";
        let decoded = decode_pepper_hex("test", pepper).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn rejects_short_hex_pepper() {
        assert!(decode_pepper_hex("test", "abcd").is_none());
    }

    #[test]
    fn rejects_non_hex_pepper() {
        assert!(decode_pepper_hex("test", "not-hex").is_none());
    }

    #[test]
    fn generated_pepper_is_valid_length_and_random() {
        let a = IdentityHashPepperConfig::generate().pepper_hash;
        assert_eq!(a.len(), 32);
        assert_ne!(a, IdentityHashPepperConfig::generate().pepper_hash);
    }
}
