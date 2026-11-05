// Dashboard authentication module
//
// This module provides the management dashboard's sign-in: WebAuthn passkeys,
// SAML, or OpenID Connect, one mode at a time. The public sign-in endpoints are
// throttled per client, with a lockout after repeated failures (`throttle`).

pub mod auth_config;
pub mod handlers;
pub mod mode_handler;
pub mod oidc;
pub mod saml;
pub mod session;
pub mod session_cleanup;
pub mod session_cookie;
pub mod session_finalizer;
pub mod sign_in_pages;
pub mod state;
pub mod storage;
#[cfg(debug_assertions)]
pub mod test_auth;
pub mod throttle;
pub mod types;

pub use auth_config::{AuthMode, SamlConfig};
pub use session::SessionManager;
pub use session_cleanup::periodic_session_cleanup;
pub use state::AuthState;
pub use types::{UserRole, UserStatus};

/// Returns true only in debug builds with test-auth explicitly enabled via env.
/// Always false in release so the path `test_auth` is never referenced in release.
pub fn test_auth_enabled() -> bool {
    #[cfg(debug_assertions)]
    {
        test_auth::TestAuthConfig::from_env().enabled
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}
