//! Identity API state and shared structures

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::GatewayConfig;
use crate::identity::VCIssuer;

/// Shared state for the identity API
#[derive(Clone)]
pub struct IdentityApiState {
    pub vc_issuer: Arc<VCIssuer>,
    pub config: Arc<GatewayConfig>,
    pub network_config: Arc<crate::config::NetworkConfig>,
    pub ws_state: Arc<crate::server::WsState>,
    pub settings_store: Arc<crate::storage::SettingsStore>,
    pub user_settings_store: Arc<crate::storage::UserSettingsStore>,
    pub metrics_store: Arc<crate::metrics::MetricsStore>,
    pub channel_manager: Arc<crate::server::SurfaceTaskManager>,
    pub tls_acceptor: tokio_rustls::TlsAcceptor,
    pub client: reqwest::Client,
    pub bootstrap_config: Arc<crate::config::BootstrapConfig>,
    pub rbac_config: Arc<crate::rbac::RbacConfig>,
    pub task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    pub notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    pub pipe_store: Option<Arc<crate::pipes::FileSystemPipeStore>>,
    pub budget_tracker: Arc<crate::pipes::budget_tracker::BudgetTracker>,
    pub pipe_route_manager: Option<Arc<crate::pipes::PipeRouteManager>>,
    pub pipe_task_manager: Option<Arc<crate::pipes::PipeTaskManager>>,
    pub policy_definition_store: Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>>,
    /// Appliance-wide (global) policy assignments store — which reusable
    /// policies are enforced on every surface of a type.
    pub global_policy_store: Option<Arc<crate::policies::FileSystemGlobalPolicyStore>>,
    /// Team store (groups of members, by UUID). Authoritative for team CRUD.
    pub team_store: Option<Arc<crate::teams::FileSystemTeamStore>>,
    /// Member store (appliance clients, the LLM consumers). Authoritative for
    /// member CRUD and identifier→member resolution at the request boundary.
    pub member_store: Option<Arc<crate::members::FileSystemMemberStore>>,
    /// Member auto-provisioning engine + config. Authoritative for the
    /// appliance-level provisioning config CRUD and first-sight member creation.
    pub member_provisioner: Option<Arc<crate::members::MemberProvisioner>>,
    /// Prompt store (versioned prompt templates). Authoritative for prompt CRUD
    /// and request-time prompt resolution.
    pub prompt_store: Option<Arc<crate::prompts::FileSystemPromptStore>>,
    /// Cross-surface monthly team/member usage tracker (for reporting).
    pub team_usage_tracker: Option<Arc<crate::teams::TeamUsageTracker>>,
    /// LLM-surface (LLM pipe) templates, persisted under
    /// `_storage/surface_templates` via `FileSystemPipeTemplateStore`.
    pub llm_surface_template_store: Option<Arc<crate::pipe_templates::FileSystemPipeTemplateStore>>,

    // DID:webvh support (optional, behind feature gate)
    #[cfg(feature = "didwebvh")]
    pub didwebvh_identity_store: Option<Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
    #[cfg(feature = "didwebvh")]
    pub didwebvh_log_storage: Option<Arc<dyn crate::storage::DidLogStorage>>,
    #[cfg(feature = "didwebvh")]
    pub didwebvh_base_url: Option<String>,
}

/// Request body for issuing a credential
#[derive(Debug, Deserialize)]
pub struct IssueCredentialRequest {
    /// The agent identity payload
    pub agent_identity: serde_json::Value,
}

/// Error response
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}
