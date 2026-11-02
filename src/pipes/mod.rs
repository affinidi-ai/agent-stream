//! Pipes Module
//!
//! Pipes represent connections from agents to external services (LLMs, APIs, databases, etc.)
//! This is distinct from Channels which represent agent-to-agent communication.

pub mod api;
pub mod audio;
pub mod audio_streams;
pub mod breach_alerts;
pub mod budget_alerts;
pub mod budget_tracker;
pub mod cache;
pub mod cache_embedder;
pub mod catalog;
pub mod config;
pub mod context_transform;
pub mod defaults;
pub mod document_ingestion;
pub mod executor;
pub mod filesystem;
pub mod handlers;
pub mod image_input;
pub mod ingress;
pub mod judge_jury;
pub mod key_source;
pub mod manager;
pub mod metering;
pub mod metrics;
pub mod metrics_store;
pub mod modality;
pub mod parsers;
pub mod pipe_variants;
pub mod policy_manager;
pub mod prompt_guard;
pub mod realtime;
pub mod realtime_safety;
pub mod reasoning;
pub mod request_routing;
pub mod request_shaping;
pub mod response_cache;
pub mod route_manager;
pub mod server_tools;
pub mod shared_credential;
pub mod streaming;
pub mod streaming_skin;
pub mod structured_output;
pub mod surface_defaults;
pub mod types;
pub mod upstream_headers;

#[cfg(test)]
pub(crate) mod test_upstreams;

pub use api::{execute_pipe, execute_pipe_stream, get_budget_usage};
pub use config::{PipeConfig, PipeType};
pub use filesystem::FileSystemPipeStore;
pub use manager::PipeTaskManager;
pub use metrics_store::MetricsStore;
pub use policy_manager::{
    PIPE_POLICY_MANAGER, PipePolicyManager, PolicyEvidence, pipe_policy_type, pipe_references_policy,
};
pub use route_manager::PipeRouteManager;
