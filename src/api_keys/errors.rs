//! API Key error types

use thiserror::Error;

/// API Key operation errors
#[derive(Debug, Error)]
pub enum ApiKeyError {
    /// Key not found (structured)
    #[error("API key not found: {key_id}")]
    KeyNotFound { key_id: String },

    /// Agent not found
    #[error("Agent not found: {agent_id}")]
    #[allow(unused)]
    AgentNotFound { agent_id: String },

    /// Key already revoked
    #[error("API key already revoked: {key_id}")]
    AlreadyRevoked { key_id: String },

    /// Invalid key status transition
    #[error("Invalid status transition from {from:?} to {to:?}")]
    #[allow(unused)]
    InvalidStatusTransition { from: super::ApiKeyStatus, to: super::ApiKeyStatus },

    /// Validation error
    #[error("Validation error: {message}")]
    Validation { message: String },

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] anyhow::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for API key operations
pub type ApiKeyResult<T> = Result<T, ApiKeyError>;

impl ApiKeyError {
    /// The `agent_stream_storage_load_errors_total` reason for a key file that
    /// failed to load with this error.
    pub(crate) fn load_failure_reason(&self) -> &'static str {
        match self {
            Self::Serialization(_) => "parse_failed",
            Self::Io(e) if e.kind() == std::io::ErrorKind::InvalidData => "parse_failed",
            _ => "read_failed",
        }
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation { message: message.into() }
    }

    /// Create a key not found error
    pub fn not_found(key_id: impl Into<String>) -> Self {
        Self::KeyNotFound { key_id: key_id.into() }
    }

    /// Create an agent not found error
    pub fn _agent_not_found(agent_id: impl Into<String>) -> Self {
        Self::AgentNotFound { agent_id: agent_id.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_failure_reason_separates_parse_from_read_failures() {
        let parse = ApiKeyError::from(serde_json::from_str::<serde_json::Value>("not json").unwrap_err());
        let read = ApiKeyError::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        let not_utf8 = ApiKeyError::from(std::io::Error::from(std::io::ErrorKind::InvalidData));

        assert_eq!(parse.load_failure_reason(), "parse_failed");
        assert_eq!(read.load_failure_reason(), "read_failed");
        assert_eq!(not_utf8.load_failure_reason(), "parse_failed");
    }
}
