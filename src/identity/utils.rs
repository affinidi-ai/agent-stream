//! Utility functions for identity API

/// Canonicalize a route path to ensure consistent comparison
/// Rules:
/// - Root route "/" stays as "/"
/// - All routes must start with "/"
/// - Trailing slashes are removed (except for root)
/// - Wildcards like "/*" or "/*/*" are rejected
pub fn canonicalize_route(route: &str) -> Result<String, String> {
    // Reject empty routes
    if route.is_empty() {
        return Err("Route cannot be empty".to_string());
    }

    // Check for wildcards
    if route.contains('*') {
        return Err("Route cannot contain wildcards (*)".to_string());
    }

    // Ensure route starts with /
    let mut canonical = if route.starts_with('/') {
        route.to_string()
    } else {
        format!("/{}", route)
    };

    // Remove trailing slashes unless it's the root route
    if canonical != "/" {
        canonical = canonical
            .trim_end_matches('/')
            .to_string();
    }

    // Ensure we have a valid route
    if canonical.is_empty() {
        canonical = "/".to_string();
    }

    Ok(canonical)
}

pub fn default_true() -> bool {
    true
}

pub fn default_route_path() -> String {
    "/".to_string()
}
pub fn default_protocol() -> crate::config::ChannelProtocol {
    crate::config::ChannelProtocol::A2a
}
