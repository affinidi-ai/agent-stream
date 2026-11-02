//! Source authentication error types

use thiserror::Error;

use crate::jwt_bearer::errors::JwtBearerError;

/// Errors returned by the source authentication middleware.
#[derive(Debug, Clone, Error)]
pub enum SourceAuthError {
    /// The required credential was not found in the request.
    #[error("Missing credential: {reason}")]
    MissingCredential { reason: String },

    /// The credential was found but validation failed.
    #[error("Invalid credential: {reason}")]
    InvalidCredential { reason: String },

    /// The referenced authentication configuration was not found.
    #[error("Auth config not found: {id}")]
    ConfigNotFound { id: String },

    /// An internal error occurred (e.g. unimplemented auth method).
    #[error("Internal source auth error: {reason}")]
    Internal { reason: String },
}

impl From<JwtBearerError> for SourceAuthError {
    fn from(err: JwtBearerError) -> Self {
        match err {
            JwtBearerError::MissingToken => SourceAuthError::MissingCredential {
                reason: "Missing bearer token".to_string(),
            },
            JwtBearerError::StrategyNotFound(id) => SourceAuthError::ConfigNotFound { id },
            JwtBearerError::ExpiredToken => SourceAuthError::InvalidCredential {
                reason: "Token has expired".to_string(),
            },
            JwtBearerError::InvalidIssuer => SourceAuthError::InvalidCredential {
                reason: "Invalid issuer".to_string(),
            },
            JwtBearerError::InvalidAudience => SourceAuthError::InvalidCredential {
                reason: "Invalid audience".to_string(),
            },
            JwtBearerError::AudienceNotConfigured => SourceAuthError::Internal {
                reason: "No accepted audience configured on this surface's caller auth — every \
                         token is refused. Add the audience the identity provider stamps on the \
                         token (Caller Context → Accepted Audiences), or opt into \
                         allow_missing_audience for an issuer that emits no aud claim."
                    .to_string(),
            },
            JwtBearerError::InvalidToken(msg) => SourceAuthError::InvalidCredential {
                reason: format!("Invalid token: {msg}"),
            },
            JwtBearerError::KeyNotFound(kid) => SourceAuthError::InvalidCredential {
                reason: format!("Key not found for kid: {kid}"),
            },
            JwtBearerError::JwksFetchFailed(msg) => SourceAuthError::Internal {
                reason: format!("JWKS fetch failed: {msg}"),
            },
            JwtBearerError::Storage(msg) => SourceAuthError::Internal {
                reason: format!("Storage error: {msg}"),
            },
        }
    }
}

/// Result alias for source authentication operations.
pub type SourceAuthResult<T> = Result<T, SourceAuthError>;
