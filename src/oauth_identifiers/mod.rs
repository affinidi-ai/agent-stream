//! OAuth Identifiers — a first-class store of **public** OAuth 2.0 / OIDC
//! sign-in identifiers (tenant/authority, client id, scopes) referenced by id
//! from surfaces that need a sign-in profile: the IDE Surface front-door
//! (`client_auth`), a member's upstream sign-in slot, and the dashboard sandbox
//! sign-in. Editing a profile once updates every referencing surface (central
//! management), and the values are safe to publish unauthenticated because they
//! are never secrets.
//!
//! The identifiers are **shape-tagged** (Entra / Okta / OIDC) rather than
//! Entra-assuming — `tenant_id` is Entra-only and lives in that variant.
//!
//! # Module layout
//! - [`models`]  — `OAuthIdentifier`, `OAuthIdentifierShape`
//! - [`storage`] — `OAuthIdentifierStorage` trait + `FileSystemOAuthIdentifierStore` + global accessor
//! - [`handlers`]/[`router`] — CRUD HTTP API under `/v1/oauth-identifiers`

pub mod handlers;
pub mod models;
pub mod router;
pub mod storage;

pub use storage::{
    FileSystemOAuthIdentifierStore, OAuthIdentifierStorage, global_oauth_identifier_store,
    set_global_oauth_identifier_store,
};
