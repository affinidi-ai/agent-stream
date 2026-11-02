//! Unified source authentication module
//!
//! Provides a single `SourceAuthMiddleware` that dispatches authentication for
//! all supported source authentication methods: JWT Bearer, API Key, and mTLS.
//!
//! # Module layout
//! - [`models`]      — `SourceAuthConfig`, `AuthenticatedIdentity`, `CredentialExtraction`, etc.
//! - [`errors`]      — `SourceAuthError` / `SourceAuthResult`
//! - [`middleware`]   — `SourceAuthMiddleware` — the unified authentication gate
//! - [`mtls`]         — mTLS verification helpers (pure logic; no I/O)

pub mod errors;
pub mod middleware;
pub mod mtls;

pub mod models;
pub mod peer_cert;

pub use middleware::SourceAuthMiddleware;
pub use models::{AuthenticatedIdentity, ManagedIdentityConfig, SourceAuthConfig};

/// What a route must do about source authentication before it serves a
/// request.
pub enum SourceAuthGate<'a> {
    /// The route declares no source authentication.
    Open,
    /// Authenticate the caller with this middleware against this config.
    Required(&'a SourceAuthMiddleware, &'a SourceAuthConfig),
    /// The route declares source authentication but the middleware failed to
    /// start, so no caller can be checked: refuse the request, never admit it.
    Unavailable,
}

/// The source-auth gate for a route that declares `config`, given the
/// middleware the appliance started (`None` when it failed to start).
pub fn source_auth_gate<'a>(
    config: Option<&'a SourceAuthConfig>,
    middleware: Option<&'a SourceAuthMiddleware>,
) -> SourceAuthGate<'a> {
    match (config, middleware) {
        (None, _) => SourceAuthGate::Open,
        (Some(config), Some(middleware)) => SourceAuthGate::Required(middleware, config),
        (Some(_), None) => SourceAuthGate::Unavailable,
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::source_auth::models::{ApiKeyAuthConfig, CredentialExtraction};

    fn api_key_config() -> SourceAuthConfig {
        SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "caller-keys".to_string(),
        })
    }

    #[test]
    fn a_route_that_declares_source_auth_is_refused_when_the_middleware_is_missing() {
        let config = api_key_config();
        assert!(matches!(source_auth_gate(Some(&config), None), SourceAuthGate::Unavailable));
        assert!(matches!(source_auth_gate(None, None), SourceAuthGate::Open));
    }
}
