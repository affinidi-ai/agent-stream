// Handler modules for Identity API
pub mod agents;
pub mod audit_log;
pub(crate) mod authz;
pub mod config;
pub mod credentials;
pub mod debug_export;
pub mod didcomm;
pub mod drift;
pub mod governance;
pub mod health;
pub mod limits;
pub mod logs;
pub mod member_provisioning;
pub mod members;
pub mod metrics;
pub mod metrics_config;
pub(crate) mod pipe_caller;
pub mod pipe_metrics;
pub(crate) mod pipe_pricing;
pub(crate) mod pipe_secret_bindings;
pub(crate) mod pipe_tenancy;
pub mod pipes;
pub mod policy_definitions;
pub mod policy_validation;
pub mod prompts;
pub mod scoped_id;
pub mod settings;
pub mod spend_report;
pub(crate) mod surface_tenancy;
pub mod teams;
pub mod telemetry;
pub(crate) mod tenant_ownership;
pub mod user_settings;
pub mod version;

// Re-export commonly used types and functions for convenience
pub use agents::get_agents;
pub use config::{get_networking_config, get_surface_routing_config, reload_configuration, reload_single_channel};
pub use credentials::{
    get_did_document, issue_credential, resolve_did_document, resolve_did_document_spec, serve_agent_did_document,
    serve_gateway_did_document, serve_gateway_did_jsonl, serve_status_list, serve_surface_did_jsonl,
};
pub use debug_export::export_storage;
pub use didcomm::{didcomm_endpoint, didcomm_ws_endpoint};
pub use drift::{
    baseline as drift_baseline, cancel_eval as drift_cancel_eval, capture_baseline as drift_capture_baseline,
    dimensions as drift_dimensions, get_run as drift_get_run, list_runs as drift_list_runs,
    list_sessions as drift_list_sessions, run_eval as drift_run_eval, series as drift_series, verdict as drift_verdict,
};
pub use governance::{
    coverage as governance_coverage, record as governance_record, records as governance_records,
    surfaces as governance_surfaces, verify as governance_verify,
};
pub use health::{alive_check, health_check};
pub use limits::list_limits;
pub use logs::{download_logs, truncate_old_logs};
pub use member_provisioning::{get_provisioning_config, preview_provisioning, update_provisioning_config};
pub use members::{create_member, delete_member, get_member, get_member_usage, list_members, update_member};
pub use metrics::{prometheus_metrics, truncate_metrics};
pub use metrics_config::{get_metrics_config, test_otlp_connection, update_metrics_config};
pub use pipes::{
    create_pipe, create_variant, delete_pipe, delete_test_surfaces, delete_variant, get_pipe, get_resolved_variant,
    list_pipes, preview_ide_bootstrap, preview_ide_catalog, promote_variant_to_default, purge_test_fixtures,
    test_llm_connection, test_pipe, update_pipe, update_variant,
};
pub use policy_definitions::{
    create_policy_definition, delete_policy_definition, get_policy_assignments, get_policy_definition,
    list_policy_definitions, list_policy_versions, policy_definition_impact, simulate_policy_definition,
    update_policy_assignments, update_policy_definition,
};
pub use policy_validation::validate_policy;
pub use prompts::{create_prompt, delete_prompt, get_prompt, list_prompts, render_prompt, update_prompt};
pub use settings::{get_settings, reset_settings, update_settings};
pub use spend_report::spend_report;
pub use teams::{add_member, create_team, delete_team, get_team, list_teams, remove_member, team_usage, update_team};
pub use telemetry::cache_stats;
pub use telemetry::detector_stats;
pub use telemetry::detector_test;
pub use telemetry::ops_series;
pub use telemetry::rejections as telemetry_rejections;
pub use telemetry::series as telemetry_series;
pub use user_settings::{get_user_settings, get_user_settings_overrides, reset_user_settings, update_user_settings};
pub use version::get_version;
