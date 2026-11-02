//! Proxy module for channel management and server operations

pub mod channel_logging;
pub mod credential_delegation;
pub mod handler;
pub mod paths;
pub mod route_variant;
pub mod security_headers;
pub mod server;
pub mod surface_manager;

pub use surface_manager::SurfaceTaskManager;
