//! Dynamic route management for pipes
//!
//! This module provides runtime route registration similar to how channels work.
//! When a pipe is created or updated, its route is registered in the shared HashMap
//! without requiring a server restart.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::{Listener, NetworkConfig};
use crate::pipes::PipeConfig;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PipeRouteKey {
    pub listener_scope: Option<String>,
    pub route: String,
}

pub type PipeRouteMap = HashMap<PipeRouteKey, String>;

fn normalize_route(route: &str) -> String {
    let trimmed = route.trim();
    let without_trailing = trimmed.trim_end_matches('/');
    let normalized = if without_trailing.starts_with('/') {
        without_trailing.to_string()
    } else {
        format!("/{}", without_trailing)
    };
    if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized
    }
}

pub fn normalize_listener_scope(scope: &str) -> String {
    scope
        .trim()
        .trim_end_matches('/')
        .to_string()
}

pub fn canonical_listener_scope(listener: &Listener) -> String {
    if listener.id.trim().is_empty() {
        format!("{}:{}", listener.bind_address, listener.port)
    } else {
        format!("listener:{}", listener.id)
    }
}

fn listener_candidates(listener: &Listener) -> Vec<String> {
    listener
        .external_urls
        .iter()
        .cloned()
        .chain(std::iter::once(format!("{}:{}", listener.bind_address, listener.port)))
        .chain(std::iter::once(format!("{}://{}:{}", listener.protocol, listener.bind_address, listener.port)))
        .map(|scope| normalize_listener_scope(&scope))
        .filter(|scope| !scope.is_empty())
        .collect()
}

pub fn resolve_listener_scope(
    listen_address: &str,
    network_config: Option<&NetworkConfig>,
) -> String {
    let normalized = normalize_listener_scope(listen_address);
    if let Some(network_config) = network_config {
        for listener in &network_config.listeners {
            if listener_candidates(listener)
                .iter()
                .any(|candidate| candidate == &normalized)
            {
                return canonical_listener_scope(listener);
            }
        }
    }
    normalized
}

fn listener_label(key: &PipeRouteKey) -> &str {
    key.listener_scope
        .as_deref()
        .unwrap_or("<any listener>")
}

fn pipe_route_key(
    pipe: &PipeConfig,
    network_config: Option<&NetworkConfig>,
) -> Option<PipeRouteKey> {
    if !pipe.status.is_enabled() {
        return None;
    }

    let route = match pipe.route.as_deref() {
        Some(r) if !r.trim().is_empty() => normalize_route(r),
        _ => return None,
    };

    let listener_scope = pipe
        .listen_address
        .as_deref()
        .map(|listen_address| resolve_listener_scope(listen_address, network_config))
        .filter(|s| !s.is_empty());

    Some(PipeRouteKey { listener_scope, route })
}

fn require_pipe_route_key(
    pipe: &PipeConfig,
    network_config: Option<&NetworkConfig>,
) -> Result<Option<PipeRouteKey>, String> {
    if !pipe.status.is_enabled() {
        return Ok(None);
    }
    pipe_route_key(pipe, network_config)
        .map(Some)
        .ok_or_else(|| format!("Pipe '{}' ({}) has no route configured", pipe.name, pipe.id))
}

fn route_keys_conflict(
    a: &PipeRouteKey,
    b: &PipeRouteKey,
) -> bool {
    a.route == b.route
        && (a.listener_scope.is_none() || b.listener_scope.is_none() || a.listener_scope == b.listener_scope)
}

pub fn route_key_matches_listener(
    key: &PipeRouteKey,
    listener_scopes: &[String],
) -> bool {
    match key.listener_scope.as_deref() {
        Some(addr) => listener_scopes
            .iter()
            .any(|scope| scope == addr),
        None => true,
    }
}

pub fn check_pipe_route_collisions(
    pipe: &PipeConfig,
    others: &[PipeConfig],
    network_config: Option<&NetworkConfig>,
) -> Result<(), String> {
    let Some(key) = pipe_route_key(pipe, network_config) else {
        return Ok(());
    };

    for other in others {
        if other.id == pipe.id {
            continue;
        }
        let Some(other_key) = pipe_route_key(other, network_config) else {
            continue;
        };
        if route_keys_conflict(&key, &other_key) {
            return Err(format!(
                "Route '{}' on listener '{}' is already in use by surface '{}' ({}); choose a different route or listener",
                key.route,
                listener_label(&key),
                other.name,
                other.id
            ));
        }
    }

    Ok(())
}

/// Manages dynamic route registration for pipes
#[derive(Clone)]
pub struct PipeRouteManager {
    /// Map from listener-scoped route to pipe ID (shared with handlers)
    pub route_to_pipe: Arc<RwLock<PipeRouteMap>>,
    network_config: Option<Arc<NetworkConfig>>,
}

impl PipeRouteManager {
    /// Create a new route manager with the given shared mapping
    #[cfg(test)]
    pub fn new(route_to_pipe: Arc<RwLock<PipeRouteMap>>) -> Self {
        Self {
            route_to_pipe,
            network_config: None,
        }
    }

    pub fn new_with_network_config(
        route_to_pipe: Arc<RwLock<PipeRouteMap>>,
        network_config: Arc<NetworkConfig>,
    ) -> Self {
        Self {
            route_to_pipe,
            network_config: Some(network_config),
        }
    }

    fn network_config(&self) -> Option<&NetworkConfig> {
        self.network_config.as_deref()
    }

    /// Register or update a pipe's route
    pub async fn register_pipe(
        &self,
        pipe: &PipeConfig,
    ) -> Result<(), String> {
        let Some(key) = require_pipe_route_key(pipe, self.network_config())? else {
            debug!("Skipping route registration for disabled pipe: {} ({})", pipe.name, pipe.id);
            return Ok(());
        };

        let mut route_map = self
            .route_to_pipe
            .write()
            .await;

        for (existing_key, existing_pipe_id) in route_map.iter() {
            if existing_pipe_id != &pipe.id && route_keys_conflict(&key, existing_key) {
                return Err(format!(
                    "Route '{}' on listener '{}' is already registered to surface '{}'; refusing to overwrite with surface '{}' ({})",
                    key.route,
                    listener_label(&key),
                    existing_pipe_id,
                    pipe.name,
                    pipe.id
                ));
            }
        }

        route_map.insert(key.clone(), pipe.id.clone());

        info!("✅ Registered pipe route: {} on {} -> {} ({})", key.route, listener_label(&key), pipe.name, pipe.id);

        Ok(())
    }

    /// Unregister a pipe's route
    pub async fn unregister_pipe(
        &self,
        pipe: &PipeConfig,
    ) -> Result<(), String> {
        let Some(key) = pipe_route_key(pipe, self.network_config()) else {
            debug!("Pipe '{}' has no active route to unregister", pipe.name);
            return Ok(());
        };

        let mut route_map = self
            .route_to_pipe
            .write()
            .await;
        if route_map
            .get(&key)
            .is_some_and(|owner| owner == &pipe.id)
        {
            route_map.remove(&key);
            info!("🗑️  Unregistered pipe route: {} on {}", key.route, listener_label(&key));
        }

        Ok(())
    }

    /// Re-sync a single pipe's routes in place: drop every route currently
    /// owned by this pipe id (its previous route / listener), then register its
    /// current route when the pipe is enabled and routable. This is the
    /// per-pipe primitive used by the pipe storage subscription — it
    /// handles a route change, a listener change, and a disable in one atomic
    /// operation without rebuilding the whole route table. Returns an error
    /// (leaving the pipe's existing routes untouched) when the new route
    /// conflicts with a different pipe.
    pub async fn sync_pipe(
        &self,
        pipe: &PipeConfig,
    ) -> Result<(), String> {
        let new_key = pipe_route_key(pipe, self.network_config());

        let mut route_map = self
            .route_to_pipe
            .write()
            .await;

        // Conflict check against OTHER pipes before mutating anything.
        if let Some(ref key) = new_key {
            for (existing_key, existing_pipe_id) in route_map.iter() {
                if existing_pipe_id != &pipe.id && route_keys_conflict(key, existing_key) {
                    return Err(format!(
                        "Route '{}' on listener '{}' is already registered to surface '{}'; refusing to overwrite with surface '{}' ({})",
                        key.route,
                        listener_label(key),
                        existing_pipe_id,
                        pipe.name,
                        pipe.id
                    ));
                }
            }
        }

        // Drop this pipe's previous route(s) so a route/listener change does not
        // leave a stale entry pointing at the same pipe id.
        let before = route_map.len();
        route_map.retain(|_, owner| owner != &pipe.id);
        let removed = before - route_map.len();

        match new_key {
            Some(key) => {
                route_map.insert(key.clone(), pipe.id.clone());
                info!(
                    "🔄 Synced pipe route: {} on {} -> {} ({}){}",
                    key.route,
                    listener_label(&key),
                    pipe.name,
                    pipe.id,
                    if removed > 0 {
                        " (replaced previous route)"
                    } else {
                        ""
                    }
                );
            }
            None if removed > 0 => {
                info!(
                    "🗑️  Pipe '{}' ({}) is disabled or has no route; removed {} stale route(s)",
                    pipe.name, pipe.id, removed
                );
            }
            None => {}
        }

        Ok(())
    }

    /// Remove every route owned by a pipe id. Used by the storage subscription
    /// when a pipe is deleted on another node.
    pub async fn remove_pipe_by_id(
        &self,
        pipe_id: &str,
    ) {
        let mut route_map = self
            .route_to_pipe
            .write()
            .await;
        let before = route_map.len();
        route_map.retain(|_, owner| owner != pipe_id);
        let removed = before - route_map.len();
        if removed > 0 {
            info!("🗑️  Unregistered {} route(s) for deleted pipe id {}", removed, pipe_id);
        }
    }

    /// Reload all pipes from storage and register their routes
    #[allow(dead_code)]
    pub async fn reload_all_pipes(
        &self,
        pipe_store: &crate::pipes::FileSystemPipeStore,
    ) -> Result<usize, String> {
        let pipes = pipe_store.list().await;
        let mut next_routes = PipeRouteMap::new();

        for pipe in pipes {
            let Some(key) = pipe_route_key(&pipe, self.network_config()) else {
                continue;
            };

            if let Some((_existing_key, existing_pipe_id)) =
                next_routes
                    .iter()
                    .find(|(existing_key, existing_pipe_id)| {
                        *existing_pipe_id != &pipe.id && route_keys_conflict(&key, existing_key)
                    })
            {
                return Err(format!(
                    "Route '{}' on listener '{}' for surface '{}' ({}) conflicts with surface '{}'; reload aborted",
                    key.route,
                    listener_label(&key),
                    pipe.name,
                    pipe.id,
                    existing_pipe_id
                ));
            }

            if next_routes
                .insert(key, pipe.id)
                .is_some()
            {
                warn!("Duplicate route entry for same pipe replaced during reload");
            }
        }

        let registered_count = next_routes.len();
        {
            let mut route_map = self
                .route_to_pipe
                .write()
                .await;
            *route_map = next_routes;
        }

        info!("🔄 Reloaded {} pipe routes", registered_count);
        Ok(registered_count)
    }

    /// Get current route count
    #[allow(dead_code)]
    pub async fn route_count(&self) -> usize {
        self.route_to_pipe
            .read()
            .await
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_status::EntityStatus;
    use crate::pipes::PipeType;

    fn pipe(
        id: &str,
        name: &str,
        listener: Option<&str>,
        route: &str,
    ) -> PipeConfig {
        let mut pipe = PipeConfig::new(
            id.to_string(),
            name.to_string(),
            PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        );
        pipe.listen_address = listener.map(str::to_string);
        pipe.route = Some(route.to_string());
        pipe
    }

    fn network_with_listener_aliases() -> NetworkConfig {
        NetworkConfig {
            did: crate::config::DidConfig {
                domain: "example.com".to_string(),
                trusted_issuers: Vec::new(),
            },
            terms: false,
            affinidi_terms_url: None,
            webauthn: crate::config::WebAuthnConfig {
                rp_id: "example.com".to_string(),
                external_origin: "https://example.com".to_string(),
            },
            integration: crate::config::IntegrationConfig::default_config(),
            encryption: None,
            cors: Vec::new(),
            listeners: vec![Listener {
                id: "inbound-a".to_string(),
                name: "Inbound A".to_string(),
                bind_address: "0.0.0.0".to_string(),
                port: 9443,
                protocol: "https".to_string(),
                external_urls: vec!["https://public-a".to_string(), "https://alias-a".to_string()],
                listener_type: "inbound".to_string(),
            }],
            channels: Vec::new(),
            routes: HashMap::new(),
            oauth_callback_route: "/v1/identity/oauth/callback".to_string(),
            pipe_paths: Vec::new(),
            llm_catalog: None,
            drift: None,
            secrets: Default::default(),
            logging: None,
        }
    }

    #[test]
    fn collision_rejects_same_route_same_listener() {
        let a = pipe("a", "Alpha", Some("https://listener-a"), "/llm/team");
        let b = pipe("b", "Beta", Some("https://listener-a"), "/llm/team");

        let err = check_pipe_route_collisions(&a, &[b], None).unwrap_err();
        assert!(err.contains("/llm/team"), "got: {err}");
        assert!(err.contains("Beta"), "got: {err}");
        assert!(err.contains("https://listener-a"), "got: {err}");
    }

    #[test]
    fn collision_allows_same_route_on_different_listeners() {
        let a = pipe("a", "Alpha", Some("https://listener-a"), "/llm/team");
        let b = pipe("b", "Beta", Some("https://listener-b"), "/llm/team");

        check_pipe_route_collisions(&a, &[b], None).unwrap();
    }

    #[test]
    fn collision_rejects_same_route_on_listener_aliases() {
        let network = network_with_listener_aliases();
        let a = pipe("a", "Alpha", Some("https://public-a"), "/llm/team");
        let b = pipe("b", "Beta", Some("https://alias-a"), "/llm/team");

        let err = check_pipe_route_collisions(&a, &[b], Some(&network)).unwrap_err();
        assert!(err.contains("listener:inbound-a"), "got: {err}");
    }

    #[test]
    fn collision_allows_different_routes_on_same_listener() {
        let a = pipe("a", "Alpha", Some("https://listener-a"), "/llm/team-a");
        let b = pipe("b", "Beta", Some("https://listener-a"), "/llm/team-b");

        check_pipe_route_collisions(&a, &[b], None).unwrap();
    }

    #[test]
    fn collision_excludes_self_on_update() {
        let updated = pipe("a", "Alpha edited", Some("https://listener-a"), "/llm/team");
        let persisted = pipe("a", "Alpha", Some("https://listener-a"), "/llm/team");

        check_pipe_route_collisions(&updated, &[persisted], None).unwrap();
    }

    #[test]
    fn collision_ignores_disabled_and_deleted_surfaces() {
        let active = pipe("a", "Alpha", Some("https://listener-a"), "/llm/team");
        let mut disabled = pipe("b", "Beta", Some("https://listener-a"), "/llm/team");
        disabled.status = EntityStatus::Disabled;
        let mut deleted = pipe("c", "Gamma", Some("https://listener-a"), "/llm/team");
        deleted.status = EntityStatus::Deleted;

        check_pipe_route_collisions(&active, &[disabled, deleted], None).unwrap();
    }

    #[test]
    fn unscoped_route_collides_with_any_listener() {
        let unscoped = pipe("a", "Alpha", None, "/llm/team");
        let scoped = pipe("b", "Beta", Some("https://listener-a"), "/llm/team");

        let err = check_pipe_route_collisions(&unscoped, &[scoped], None).unwrap_err();
        assert!(err.contains("<any listener>"), "got: {err}");
    }

    #[tokio::test]
    async fn dynamic_registration_rejects_duplicate_without_overwrite() {
        let manager = PipeRouteManager::new(Arc::new(RwLock::new(PipeRouteMap::new())));
        let a = pipe("a", "Alpha", Some("https://listener-a"), "/llm/team");
        let b = pipe("b", "Beta", Some("https://listener-a"), "/llm/team");

        manager
            .register_pipe(&a)
            .await
            .unwrap();
        let err = manager
            .register_pipe(&b)
            .await
            .unwrap_err();
        assert!(err.contains("refusing to overwrite"), "got: {err}");

        let routes = manager
            .route_to_pipe
            .read()
            .await;
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes
                .values()
                .next()
                .unwrap(),
            "a"
        );
    }

    #[tokio::test]
    async fn dynamic_registration_supports_valid_route_change() {
        let manager = PipeRouteManager::new(Arc::new(RwLock::new(PipeRouteMap::new())));
        let before = pipe("a", "Alpha", Some("https://listener-a"), "/llm/old");
        let after = pipe("a", "Alpha", Some("https://listener-a"), "/llm/new");

        manager
            .register_pipe(&before)
            .await
            .unwrap();
        manager
            .unregister_pipe(&before)
            .await
            .unwrap();
        manager
            .register_pipe(&after)
            .await
            .unwrap();

        let routes = manager
            .route_to_pipe
            .read()
            .await;
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes
                .values()
                .next()
                .unwrap(),
            "a"
        );
        assert!(
            routes
                .keys()
                .any(|key| key.route == "/llm/new")
        );
    }

    #[tokio::test]
    async fn reload_rejects_duplicates_and_keeps_existing_routes() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::pipes::FileSystemPipeStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .unwrap();
        store
            .save(pipe("b", "Beta", Some("https://listener-a"), "/llm/team"))
            .await
            .unwrap();
        store
            .save(pipe("c", "Gamma", Some("https://listener-a"), "/llm/team"))
            .await
            .unwrap();

        let manager = PipeRouteManager::new(Arc::new(RwLock::new(PipeRouteMap::new())));
        let existing = pipe("a", "Alpha", Some("https://listener-a"), "/llm/existing");
        manager
            .register_pipe(&existing)
            .await
            .unwrap();

        let err = manager
            .reload_all_pipes(&store)
            .await
            .unwrap_err();
        assert!(err.contains("reload aborted"), "got: {err}");

        let routes = manager
            .route_to_pipe
            .read()
            .await;
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes
                .values()
                .next()
                .unwrap(),
            "a"
        );
    }

    #[test]
    fn route_key_matches_only_its_listener_scope() {
        let key = PipeRouteKey {
            listener_scope: Some("https://listener-a".to_string()),
            route: "/llm/team".to_string(),
        };
        assert!(route_key_matches_listener(&key, &["https://listener-a".to_string()]));
        assert!(!route_key_matches_listener(&key, &["https://listener-b".to_string()]));
    }
}
