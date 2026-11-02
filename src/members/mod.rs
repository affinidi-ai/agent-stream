//! Members: the registry of appliance **clients** — callers that consume LLM
//! (or any future surface) capacity, identified by a configurable credential and
//! deliberately detached from the administrator users who sign in to operate the
//! appliance.
//!
//! - [`types`] — [`types::Member`] / [`types::MemberIdentifier`] entities.
//! - [`budget_period`] - the monthly window a member's caps are measured over.
//! - [`store`] — file-backed, DashMap-cached [`store::FileSystemMemberStore`].
//! - [`provisioning`] — on-the-fly auto-provisioning of members from verified
//!   caller identities ([`provisioning::MemberProvisioningConfig`]).

pub mod budget_period;
pub mod provisioning;
pub mod store;
pub mod types;

pub use budget_period::BudgetPeriod;
pub use provisioning::{
    MemberProvisioner, MemberProvisioningConfig, global_member_provisioner, set_global_member_provisioner,
};
pub use store::{FileSystemMemberStore, set_global_member_store};
pub use types::Member;
