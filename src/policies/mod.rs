pub mod agent_context;
pub mod gateway_manager;
pub mod global_policy;
pub mod opa;
pub mod policy_definitions;
pub mod surface_manager;

pub use agent_context::build_agent_context;
pub use gateway_manager::GatewayPolicyManager;
pub use global_policy::{FileSystemGlobalPolicyStore, GlobalPolicyAssignments};
pub use opa::{OpaEngine, validate_policy_inputs};
pub use policy_definitions::{FileSystemPolicyDefinitionStore, validate_policy_scope};
pub use surface_manager::{SurfacePolicyManager, surface_references_policy};

/// Canonical Rego package an appliance-wide ("Agent Stream") policy
/// (`PolicyType::Appliance`) must declare. This is the gateway/instance-scoped
/// layer (query `data.agentstream.policy.allow`); an `appliance` reusable
/// definition seeds the gateway's inline `opa_policy_config`.
pub const AGENTSTREAM_POLICY_PACKAGE: &str = "agentstream.policy";

/// Canonical Rego package for the surface / fabric layer, evaluated via
/// [`SURFACE_POLICY_QUERY`] by [`surface_manager::SurfacePolicyManager`].
/// Renamed from the legacy `channel.policy`. This is the A2A/MCP fabric surface layer; it is not one of the
/// creatable reusable policy types (`appliance`/`llm`/`ide`).
pub const SURFACE_POLICY_PACKAGE: &str = "surface.policy";

/// Canonical Rego package an LLM-surface (`PolicyType::Llm`) policy must declare.
pub const LLM_POLICY_PACKAGE: &str = "llm.policy";

/// Canonical Rego package an IDE-catalogue (`PolicyType::Ide`) policy must declare.
pub const IDE_POLICY_PACKAGE: &str = "ide.policy";

/// Legacy surface package name, renamed to [`SURFACE_POLICY_PACKAGE`]
/// Definitions stored with this
/// package are migrated in place at startup and on config reload via
/// [`FileSystemPolicyDefinitionStore::migrate_legacy_packages`], and normalized
/// on write. No runtime query-time fallback exists — the surface manager only
/// ever queries [`SURFACE_POLICY_QUERY`].
pub const LEGACY_SURFACE_POLICY_PACKAGE: &str = "channel.policy";

/// Query path for surface-scoped policies. Kept in lockstep with
/// [`SURFACE_POLICY_PACKAGE`].
pub const SURFACE_POLICY_QUERY: &str = "data.surface.policy.allow";

/// Query path for appliance-wide / gateway (fabric) policies. Kept in lockstep
/// with [`AGENTSTREAM_POLICY_PACKAGE`]. Used by the gateway policy manager for
/// per-gateway sets and by the global policy manager for the `appliance`
/// appliance-wide set.
pub const AGENTSTREAM_POLICY_QUERY: &str = "data.agentstream.policy.allow";

/// Substring of the Regorus error string returned when a query resolves to
/// no value (e.g. the module does not declare the expected `package` or omits
/// `default allow`). [`opa::OpaEngine::evaluate_query`] matches on this text
/// to translate a `no-value` query outcome into an actionable fail-closed
/// deny reason instead of an opaque engine error. It is therefore **coupled
/// to the Regorus error wording** for the pinned version in `Cargo.toml`:
/// if a Regorus upgrade rewords it, that "no value" case would fall through
/// to an opaque engine error. The `regorus_no_value_marker_matches_live_error`
/// unit test in `opa.rs` asserts this constant against the raw Regorus error,
/// so a wording change breaks that test first and points straight here —
/// update this constant when bumping Regorus if that test fails.
pub const REGORUS_QUERY_NO_VALUE_MARKER: &str = "did not produce any values";
