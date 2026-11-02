//! Teams: group appliance members (by UUID) and aggregate/cap their
//! cross-surface usage.
//!
//! - [`types`]          — [`Team`] entity (members referenced by UUID).
//! - [`store`]          — file-backed, DashMap-cached [`store::FileSystemTeamStore`].
//! - [`caller_identity`]— locate the caller's identifier in an inbound request.
//! - [`attribution`]    — surface opt-in config ([`attribution::TeamAttributionConfig`]).
//! - [`usage_tracker`]  — cross-surface monthly team/member usage buckets.
//! - [`call_budget`]    - the budgets each platform-key model call is checked against.

pub mod attribution;
pub mod call_budget;
pub mod caller_identity;
pub mod gate;
pub mod migration;
pub mod rate_limiter;
pub mod store;
pub mod types;
pub mod usage_tracker;

pub use attribution::TeamAttributionConfig;
pub use gate::{TeamGateDecision, model_scope_allows, record_team_usage, team_pre_check};
pub use migration::migrate_legacy_teams;
pub use rate_limiter::{MemberRateLimiter, global_member_rate_limiter, set_global_member_rate_limiter};
pub use store::{FileSystemTeamStore, set_global_team_store};
pub use usage_tracker::{TeamUsageTracker, set_global_team_usage_tracker};
