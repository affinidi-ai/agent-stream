use crate::observability::policy_audit::{self, PolicyFlow, PolicyOutcome, PolicyScope};
use crate::policies::policy_definitions::FileSystemPolicyDefinitionStore;
use crate::policies::{OpaEngine, SURFACE_POLICY_QUERY};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// A compiled surface OPA engine plus the policy-definition metadata it was
/// compiled from, retained for audit evidence.
struct CompiledSurfacePolicy {
    engine: OpaEngine,
    policy_definition_id: Option<String>,
    policy_version: Option<String>,
    policy_content_hash: Option<String>,
    policy_name: Option<String>,
}

/// Surface-level policy manager: handles surface OPA per surface.
pub struct SurfacePolicyManager {
    /// Pre-compiled OPA engine templates per surface (keyed by config_id).
    /// Uses std::sync::RwLock because reads are sub-microsecond (clone the template)
    /// and writes only happen during surface config updates.
    opa_engines: std::sync::RwLock<HashMap<String, CompiledSurfacePolicy>>,

    /// Policy definition store for resolving policy text from `opa_policy_definition_id`
    policy_definition_store: std::sync::RwLock<Option<Arc<FileSystemPolicyDefinitionStore>>>,
}

impl SurfacePolicyManager {
    pub fn new() -> Self {
        Self {
            opa_engines: std::sync::RwLock::new(HashMap::new()),
            policy_definition_store: std::sync::RwLock::new(None),
        }
    }

    /// Set (or replace) the policy definition store used to resolve policies at compile time
    pub fn set_policy_definition_store(
        &self,
        store: Arc<FileSystemPolicyDefinitionStore>,
    ) {
        *self
            .policy_definition_store
            .write()
            .expect("policy_definition_store lock poisoned") = Some(store);
    }

    /// Returns true when a compiled OPA engine exists for the given surface
    pub fn has_policy(
        &self,
        channel_id: &str,
    ) -> bool {
        self.opa_engines
            .read()
            .expect("opa_engines lock poisoned")
            .contains_key(channel_id)
    }

    /// Initialize or update policy for a surface
    pub async fn update_channel_policy(
        &self,
        surface: &crate::config::agent_surface::AgentSurface,
    ) -> Result<(), String> {
        let config_id = surface
            .config_id()
            .map(|s| s.to_string())
            .ok_or_else(|| "Channel missing config_id".to_string())?;
        let config_id = &config_id;

        // Resolve the effective surface so that variant-level overrides
        // (opa_policy_definition_id, rate_limit, circuit_breaker) are visible here.
        let effective = surface
            .resolve_variant(None)
            .unwrap_or_else(|_| surface.clone());

        // Handle OPA policy — resolve text from the definition store, compile synchronously
        if effective.opa_enabled() {
            if let Some(def_id) = effective.opa_policy_definition_id() {
                // Resolve the policy text from the definition store
                // Clone the Arc so we release the std::sync lock before awaiting
                let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                    .policy_definition_store
                    .read()
                    .expect("policy_definition_store lock poisoned")
                    .clone();
                let policy_text = if let Some(ref store) = maybe_store {
                    store.get(def_id).await
                } else {
                    warn!(channel_id = %config_id, def_id = %def_id, "Policy definition store not available; skipping policy compile");
                    None
                };

                match policy_text {
                    Some(def) if def.enabled && !def.policy.is_empty() => {
                        info!(channel_id = %config_id, def_id = %def_id, "Compiling OPA policy for channel");
                        let policy_definition_id = Some(def.id.clone());
                        let policy_version = def
                            .version
                            .map(|v| v.to_string());
                        let policy_content_hash = def.content_hash.clone();
                        let policy_name = Some(def.name.clone());
                        let engine = OpaEngine::new();
                        // Fail closed: if the new Rego fails to compile, evict any
                        // previously-compiled engine so a bad recompile can never
                        // leave stale permissive logic active for this surface.
                        if let Err(e) = engine.load_policy(config_id, &def.policy) {
                            warn!(channel_id = %config_id, def_id = %def_id, error = %e, "OPA policy failed to compile; evicting engine (fail closed)");
                            self.opa_engines
                                .write()
                                .expect("opa_engines lock poisoned")
                                .remove(config_id);
                            return Err(e);
                        }
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.insert(
                            config_id.clone(),
                            CompiledSurfacePolicy {
                                engine,
                                policy_definition_id,
                                policy_version,
                                policy_content_hash,
                                policy_name,
                            },
                        );
                        info!(channel_id = %config_id, "OPA policy compiled and cached");
                    }
                    Some(def) if !def.enabled => {
                        warn!(channel_id = %config_id, def_id = %def_id, "Policy definition is disabled; removing engine");
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.remove(config_id);
                    }
                    Some(_) => {
                        warn!(channel_id = %config_id, def_id = %def_id, "Policy definition has empty Rego body; removing engine");
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.remove(config_id);
                    }
                    None => {
                        warn!(channel_id = %config_id, def_id = %def_id, "Policy definition not found; removing engine");
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.remove(config_id);
                    }
                }
            } else {
                // opa_enabled but no definition_id — remove any stale engine
                let mut engines = self
                    .opa_engines
                    .write()
                    .expect("opa_engines lock poisoned");
                if engines
                    .remove(config_id)
                    .is_some()
                {
                    info!(channel_id = %config_id, "Removed OPA policy for channel (no definition_id)");
                }
            }
        } else {
            let mut engines = self
                .opa_engines
                .write()
                .expect("opa_engines lock poisoned");
            if engines
                .remove(config_id)
                .is_some()
            {
                info!(channel_id = %config_id, "Removed OPA policy for channel");
            }
        }

        // Handle response OPA policy — uses key "response:{definition_id}" so response policies
        // can coexist with inbound and outbound policies.
        let response_def_id = surface.response_policy_definition_id();
        let response_key = format!("response:{}", response_def_id.unwrap_or(""));
        if let Some(def_id) = response_def_id {
            let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                .policy_definition_store
                .read()
                .expect("policy_definition_store lock poisoned")
                .clone();
            let policy_text = if let Some(ref store) = maybe_store {
                store.get(def_id).await
            } else {
                warn!(channel_id = %config_id, def_id = %def_id, "Policy definition store not available; skipping response policy compile");
                None
            };

            match policy_text {
                Some(def) if def.enabled && !def.policy.is_empty() => {
                    info!(channel_id = %config_id, def_id = %def_id, "Compiling response OPA policy for channel");
                    let policy_definition_id = Some(def.id.clone());
                    let policy_version = def
                        .version
                        .map(|v| v.to_string());
                    let policy_content_hash = def.content_hash.clone();
                    let policy_name = Some(def.name.clone());
                    let engine = OpaEngine::new();
                    // Fail closed on a bad response-policy recompile too.
                    if let Err(e) = engine.load_policy(&response_key, &def.policy) {
                        warn!(channel_id = %config_id, def_id = %def_id, error = %e, "Response OPA policy failed to compile; evicting engine (fail closed)");
                        self.opa_engines
                            .write()
                            .expect("opa_engines lock poisoned")
                            .remove(&response_key);
                        return Err(e);
                    }
                    let mut engines = self
                        .opa_engines
                        .write()
                        .expect("opa_engines lock poisoned");
                    engines.insert(
                        response_key.clone(),
                        CompiledSurfacePolicy {
                            engine,
                            policy_definition_id,
                            policy_version,
                            policy_content_hash,
                            policy_name,
                        },
                    );
                    info!(channel_id = %config_id, "Response OPA policy compiled and cached (key={})", response_key);
                }
                Some(def) if !def.enabled => {
                    warn!(channel_id = %config_id, def_id = %def_id, "Response policy definition is disabled; removing engine");
                    let mut engines = self
                        .opa_engines
                        .write()
                        .expect("opa_engines lock poisoned");
                    engines.remove(&response_key);
                }
                Some(_) => {
                    warn!(channel_id = %config_id, def_id = %def_id, "Response policy definition has empty Rego body; removing engine");
                    let mut engines = self
                        .opa_engines
                        .write()
                        .expect("opa_engines lock poisoned");
                    engines.remove(&response_key);
                }
                None => {
                    warn!(channel_id = %config_id, def_id = %def_id, "Response policy definition not found; removing engine");
                    let mut engines = self
                        .opa_engines
                        .write()
                        .expect("opa_engines lock poisoned");
                    engines.remove(&response_key);
                }
            }
        } else {
            // No response policy — remove any stale engine
            let mut engines = self
                .opa_engines
                .write()
                .expect("opa_engines lock poisoned");
            engines.remove(&response_key);
        }

        Ok(())
    }

    /// Evaluate policy for a channel.
    /// Uses clone-per-eval on the pre-compiled template — fully concurrent, no write lock.
    pub fn evaluate_policy(
        &self,
        channel_id: &str,
        input: serde_json::Value,
    ) -> Result<bool, String> {
        let engines = self
            .opa_engines
            .read()
            .expect("opa_engines lock poisoned");

        // Extract the redacted caller/HTTP/workload summary before evaluation
        // consumes the input.
        let input_ctx = policy_audit::extract_input_context(&input);

        if let Some(compiled) = engines.get(channel_id) {
            debug!(channel_id = %channel_id, "Evaluating OPA policy");
            let decision = match compiled
                .engine
                .evaluate(input)
            {
                Ok(d) => d,
                Err(e) => {
                    warn!(surface_id = %channel_id, error = %e, "OPA evaluation error; denying (fail-closed)");
                    policy_audit::record_decision(
                        PolicyScope::Surface,
                        PolicyFlow::AccessPoint,
                        PolicyOutcome::Error,
                        Some(&e),
                        SURFACE_POLICY_QUERY,
                        compiled
                            .policy_definition_id
                            .as_deref(),
                        compiled
                            .policy_version
                            .as_deref(),
                        compiled
                            .policy_content_hash
                            .as_deref(),
                        compiled
                            .policy_name
                            .as_deref(),
                        Some(channel_id),
                        None,
                        &input_ctx,
                    );
                    return Err(e);
                }
            };

            if !decision.allow {
                warn!(
                    surface_id = %channel_id,
                    reason = ?decision.reason,
                    "Policy denied request"
                );
            }

            policy_audit::record_decision(
                PolicyScope::Surface,
                PolicyFlow::AccessPoint,
                if decision.allow {
                    PolicyOutcome::Allow
                } else {
                    PolicyOutcome::Deny
                },
                decision.reason.as_deref(),
                SURFACE_POLICY_QUERY,
                compiled
                    .policy_definition_id
                    .as_deref(),
                compiled
                    .policy_version
                    .as_deref(),
                compiled
                    .policy_content_hash
                    .as_deref(),
                compiled
                    .policy_name
                    .as_deref(),
                Some(channel_id),
                None,
                &input_ctx,
            );
            Ok(decision.allow)
        } else {
            warn!(channel_id = %channel_id, "Engine not found for channel, denying request");
            policy_audit::record_decision(
                PolicyScope::Surface,
                PolicyFlow::AccessPoint,
                PolicyOutcome::MissingEngine,
                Some("No compiled OPA engine for OPA-enabled surface; denied (fail-closed)"),
                "",
                None,
                None,
                None,
                None,
                Some(channel_id),
                None,
                &input_ctx,
            );
            Ok(false)
        }
    }

    /// Load a policy engine directly from Rego text (test helper).
    #[cfg(test)]
    pub fn load_policy_text(
        &self,
        channel_id: &str,
        policy_text: &str,
    ) -> Result<(), String> {
        let engine = OpaEngine::new();
        engine.load_policy(channel_id, policy_text)?;
        let mut engines = self
            .opa_engines
            .write()
            .expect("opa_engines lock poisoned");
        engines.insert(
            channel_id.to_string(),
            CompiledSurfacePolicy {
                engine,
                policy_definition_id: None,
                policy_version: None,
                policy_content_hash: None,
                policy_name: None,
            },
        );
        Ok(())
    }
}

impl Default for SurfacePolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true when `surface` references `policy_id` in any OPA slot the
/// [`SurfacePolicyManager`] can compile: the request-side (inbound) policy, the
/// response-side policy, or any variant's `target.policy` / `target.response_policy`
/// override. This is the reverse index from a mutated reusable policy definition
/// back to the surfaces whose engines embed its Rego — a match means
/// the surface must be recompiled via [`SurfacePolicyManager::update_channel_policy`].
pub fn surface_references_policy(
    surface: &crate::config::agent_surface::AgentSurface,
    policy_id: &str,
) -> bool {
    if surface.opa_policy_definition_id() == Some(policy_id) {
        return true;
    }
    if surface.response_policy_definition_id() == Some(policy_id) {
        return true;
    }
    surface
        .variants
        .iter()
        .any(|v| {
            v.overrides
                .target
                .as_ref()
                .is_some_and(|t| {
                    t.policy.as_ref().map(|p| {
                        p.policy_definition_id
                            .as_str()
                    }) == Some(policy_id)
                        || t.response_policy
                            .as_ref()
                            .map(|p| {
                                p.policy_definition_id
                                    .as_str()
                            })
                            == Some(policy_id)
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_opa_policy_allow() {
        let manager = SurfacePolicyManager::new();

        manager
            .load_policy_text(
                "test-2",
                r#"
package surface.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}
"#,
            )
            .unwrap();

        let input = serde_json::json!({
            "mcp": {
                "method": "tools/call",
                "tool_name": "echo"
            }
        });

        let allowed = manager
            .evaluate_policy("test-2", input)
            .unwrap();
        assert!(allowed);
    }

    // ── Reusable-definition mutation must reach live surfaces ─────

    use crate::config::agent_surface::{AgentSurface, PolicyRef};
    use crate::policies::FileSystemPolicyDefinitionStore;
    use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

    const ALLOW_ALL_SURFACE: &str = "package surface.policy\nimport rego.v1\ndefault allow := true";
    const DENY_ALL_SURFACE: &str = "package surface.policy\nimport rego.v1\ndefault allow := false";

    async fn save_surface_def(
        store: &FileSystemPolicyDefinitionStore,
        body: &str,
        enabled: bool,
    ) {
        store
            .save(PolicyDefinition {
                id: "def".to_string(),
                name: "def".to_string(),
                description: String::new(),
                policy_type: PolicyType::Appliance,
                policy: body.to_string(),
                enabled,
                created_at: "2026-06-07T00:00:00Z".to_string(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
                tenant_id: None,
            })
            .await
            .expect("save surface def");
    }

    fn surface_with_policy(def_id: &str) -> AgentSurface {
        let mut s = AgentSurface {
            surface_id: "surf-1".to_string(),
            name: "surf".to_string(),
            ..Default::default()
        };
        s.target.policy = Some(PolicyRef {
            policy_definition_id: def_id.to_string(),
        });
        s
    }

    /// Changing an allow surface policy to deny takes effect immediately for an
    /// already-compiled surface — the recompile is the only action.
    #[tokio::test]
    async fn surface_definition_update_takes_effect() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        save_surface_def(&store, ALLOW_ALL_SURFACE, true).await;
        let store = Arc::new(store);

        let mgr = SurfacePolicyManager::new();
        mgr.set_policy_definition_store(store.clone());
        let surface = surface_with_policy("def");

        mgr.update_channel_policy(&surface)
            .await
            .expect("compile");
        assert_eq!(mgr.evaluate_policy("surf-1", serde_json::json!({})), Ok(true));

        save_surface_def(&store, DENY_ALL_SURFACE, true).await;
        mgr.update_channel_policy(&surface)
            .await
            .expect("recompile");
        assert_eq!(mgr.evaluate_policy("surf-1", serde_json::json!({})), Ok(false), "deny takes effect immediately");
    }

    /// A policy set only on the default variant is compiled, and a later
    /// update that drops it evicts the engine.
    #[tokio::test]
    async fn default_variant_policy_is_compiled_and_evicted_when_removed() {
        use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant, TargetOverrides};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        save_surface_def(&store, DENY_ALL_SURFACE, true).await;
        let mgr = SurfacePolicyManager::new();
        mgr.set_policy_definition_store(Arc::new(store));

        let mut surface = AgentSurface {
            surface_id: "surf-1".to_string(),
            default_variant_id: Some("v1".to_string()),
            variants: vec![SurfaceVariant {
                id: "v1".to_string(),
                alias: "default".to_string(),
                name: "Default".to_string(),
                description: String::new(),
                enabled: true,
                overrides: SurfaceOverrides {
                    target: Some(TargetOverrides {
                        policy: Some(PolicyRef {
                            policy_definition_id: "def".to_string(),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        assert!(!surface.opa_enabled(), "the base target carries no policy");
        mgr.update_channel_policy(&surface)
            .await
            .expect("compile");
        assert!(mgr.has_policy("surf-1"), "the default variant's policy is compiled");

        surface.variants.clear();
        surface.default_variant_id = None;
        mgr.update_channel_policy(&surface)
            .await
            .expect("recompile");
        assert!(!mgr.has_policy("surf-1"), "removing the policy evicts the engine");
    }

    /// Disabling or breaking a surface definition evicts the engine (fail closed).
    #[tokio::test]
    async fn surface_disable_and_bad_recompile_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        save_surface_def(&store, ALLOW_ALL_SURFACE, true).await;
        let store = Arc::new(store);

        let mgr = SurfacePolicyManager::new();
        mgr.set_policy_definition_store(store.clone());
        let surface = surface_with_policy("def");
        mgr.update_channel_policy(&surface)
            .await
            .expect("compile");
        assert!(mgr.has_policy("surf-1"));

        // Disable → evict.
        save_surface_def(&store, ALLOW_ALL_SURFACE, false).await;
        mgr.update_channel_policy(&surface)
            .await
            .expect("recompile");
        assert!(!mgr.has_policy("surf-1"), "disabled definition evicts the surface engine");
        assert_eq!(mgr.evaluate_policy("surf-1", serde_json::json!({})), Ok(false));

        // Re-enable with valid Rego, then break it → evict, no stale allow.
        save_surface_def(&store, ALLOW_ALL_SURFACE, true).await;
        mgr.update_channel_policy(&surface)
            .await
            .expect("recompile");
        assert!(mgr.has_policy("surf-1"));
        save_surface_def(&store, "package surface.policy\nnot valid {{{", true).await;
        assert!(
            mgr.update_channel_policy(&surface)
                .await
                .is_err(),
            "bad recompile should error"
        );
        assert!(!mgr.has_policy("surf-1"), "bad recompile evicts the stale surface engine");
        assert_eq!(mgr.evaluate_policy("surf-1", serde_json::json!({})), Ok(false), "fail closed after bad recompile");
    }

    /// The reverse index detects a policy referenced inbound, on the response
    /// side, or via a variant's target override.
    #[test]
    fn surface_references_policy_detects_all_slots() {
        use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant, TargetOverrides};

        let mut inbound = AgentSurface {
            surface_id: "s".to_string(),
            ..Default::default()
        };
        assert!(!surface_references_policy(&inbound, "def"));
        inbound.target.policy = Some(PolicyRef {
            policy_definition_id: "def-inbound".to_string(),
        });
        assert!(surface_references_policy(&inbound, "def-inbound"));

        let mut response = AgentSurface::default();
        response
            .target
            .response_policy = Some(PolicyRef {
            policy_definition_id: "def-resp".to_string(),
        });
        assert!(surface_references_policy(&response, "def-resp"));

        let variant = AgentSurface {
            variants: vec![SurfaceVariant {
                id: "v1".to_string(),
                alias: "canary".to_string(),
                name: "Canary".to_string(),
                description: String::new(),
                enabled: true,
                overrides: SurfaceOverrides {
                    target: Some(TargetOverrides {
                        policy: Some(PolicyRef {
                            policy_definition_id: "def-variant".to_string(),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        assert!(surface_references_policy(&variant, "def-variant"));
        assert!(!surface_references_policy(&variant, "other"));
    }
}
