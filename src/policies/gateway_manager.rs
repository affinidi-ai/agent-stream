use crate::gateways::types::Gateway;
use crate::observability::policy_audit::{self, PolicyFlow, PolicyOutcome, PolicyScope};
use crate::policies::OpaEngine;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

/// Rego query path a gateway policy is evaluated against (`package agentstream.policy`).
const GATEWAY_POLICY_QUERY: &str = crate::policies::AGENTSTREAM_POLICY_QUERY;

/// A compiled gateway OPA engine plus the policy-definition id it was compiled
/// from (kept for audit evidence; gateway policies are stored inline so they
/// carry no separate version/name).
struct CompiledGatewayPolicy {
    engine: OpaEngine,
    policy_definition_id: Option<String>,
    /// Monotonic version of the referenced policy definition this engine
    /// compiled (when resolved from a definition), recorded in audit evidence so
    /// a gateway decision resolves back to the exact enforced revision.
    policy_version: Option<String>,
    /// Content hash (`sha256:<hex>`) of the Rego this engine compiled — makes a
    /// gateway decision reproducible against exact bytes.
    policy_content_hash: Option<String>,
}

/// Gateway policy manager that handles OPA policies at the gateway level.
///
/// - For the **self** gateway: policy is enforced on all inbound traffic.
/// - For **remote** gateways: policy is enforced on outbound traffic to that gateway.
///
/// Gateway policy is evaluated **before** surface-level policy.
/// A gateway deny cannot be overridden by a surface allow (no privilege escalation).
///
/// ## Performance
///
/// Policies are pre-compiled via `regorus::Engine::add_policy()` and stored as
/// template engines. On each evaluation, the template is **cloned** (cheap —
/// regorus uses `Arc` internally with the `arc` feature) and evaluated on the
/// clone. This avoids write-lock serialization: concurrent requests evaluate in
/// parallel on independent engine clones with no contention.
///
/// The self-gateway ID uses `std::sync::RwLock` (not tokio) for lock-free reads
/// on the hot path — no async context switch for a simple string lookup.
pub struct GatewayPolicyManager {
    /// Pre-compiled template engine **sets** per gateway (keyed by gateway id),
    /// evaluated under deny-overrides (any member deny blocks).
    /// Uses std::sync::RwLock (not tokio) because:
    /// - Read lock is held sub-microsecond (HashMap lookup + Engine clone)
    /// - Write lock is only taken during rare policy updates
    /// - Avoids async overhead and blocking_read panics in mixed contexts
    engines: Arc<RwLock<HashMap<String, Vec<CompiledGatewayPolicy>>>>,
    /// Cached self-gateway ID. Uses std::sync::RwLock for non-async, non-yielding reads.
    self_gateway_id: RwLock<Option<String>>,
    /// Gateway ids with OPA **enabled in config**, independent of whether the
    /// Rego compiled. The enforcement point gates on this so a compile failure
    /// fails closed (the request still reaches `evaluate_policy`, which denies
    /// on a missing engine) instead of silently skipping enforcement.
    enforced: RwLock<HashSet<String>>,
    /// Policy-definition store used to resolve a gateway's referenced policy
    /// Rego at compile time. A gateway record stores only the definition id, so
    /// editing the definition (not the gateway) recompiles enforcement — the
    /// Rego is never copied into the gateway. Set once at boot.
    policy_definition_store: RwLock<Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>>>,
}

impl GatewayPolicyManager {
    pub fn new() -> Self {
        Self {
            engines: Arc::new(RwLock::new(HashMap::new())),
            self_gateway_id: RwLock::new(None),
            enforced: RwLock::new(HashSet::new()),
            policy_definition_store: RwLock::new(None),
        }
    }

    /// Set the self-gateway ID (called once at startup or on config reload)
    pub fn set_self_gateway_id(
        &self,
        id: String,
    ) {
        *self
            .self_gateway_id
            .write()
            .expect("self_gateway_id lock poisoned") = Some(id);
    }

    /// Get the self-gateway ID (lock-free read, no async overhead)
    pub fn get_self_gateway_id(&self) -> Option<String> {
        self.self_gateway_id
            .read()
            .expect("self_gateway_id lock poisoned")
            .clone()
    }

    /// Inject the policy-definition store used to resolve a gateway's referenced
    /// policy Rego at compile time. Called once at startup, before the initial
    /// gateway policy compile pass.
    pub fn set_policy_definition_store(
        &self,
        store: Arc<crate::policies::FileSystemPolicyDefinitionStore>,
    ) {
        *self
            .policy_definition_store
            .write()
            .expect("policy_definition_store lock poisoned") = Some(store);
    }

    /// Load or update the OPA policy for a gateway.
    /// The policy is pre-compiled into a regorus Engine template. When the
    /// gateway references a policy definition, its Rego is resolved from the
    /// definition store here (reference-only) rather than read from the gateway
    /// record.
    pub async fn update_gateway_policy(
        &self,
        gateway: &Gateway,
    ) -> Result<(), String> {
        let gateway_id = &gateway.id;

        // Cases 3 & 4: not configured, or configured but disabled — remove existing engine
        let remove_engine = gateway
            .opa_policy_config
            .as_ref()
            .is_some_and(|c| c.enabled);

        if !remove_engine {
            let mut engines = self
                .engines
                .write()
                .expect("engines lock poisoned");
            if engines
                .remove(gateway_id)
                .is_some()
            {
                info!(gateway_id = %gateway_id, "Removed OPA policy for gateway");
            }
            self.enforced
                .write()
                .expect("enforced lock poisoned")
                .remove(gateway_id);
            return Ok(());
        }

        // Cases 1 & 2: enabled — safe to unwrap, proven by should_enforce
        let policy_config = gateway
            .opa_policy_config
            .as_ref()
            .unwrap();

        // Cases 1 & 2: policy is enabled — validate and compile.
        info!(gateway_id = %gateway_id, "Compiling OPA policy for gateway");

        // Mark enforced from config BEFORE compiling: a compile failure below
        // returns Err and caches no engine, but the enforcement point must still
        // deny (fail-closed) rather than skip this gateway.
        self.enforced
            .write()
            .expect("enforced lock poisoned")
            .insert(gateway_id.clone());

        // Resolve the Rego set to compile. A gateway references reusable policy
        // definitions by id (the single source of truth, resolved here at
        // compile time — the gateway record never stores a copy of the Rego),
        // evaluated together under deny-overrides. A gateway with no referenced
        // definition falls back to any inline Rego it carries (legacy /
        // hand-authored), compiled as a single-policy set.
        let def_ids = policy_config.all_policy_definition_ids();
        let mut compiled: Vec<CompiledGatewayPolicy> = Vec::new();

        if def_ids.is_empty() {
            let rego = policy_config.policy.clone();
            if rego.trim().is_empty() {
                // Enabled but nothing referenced or inlined — fail closed: drop
                // any engine so evaluation denies on a missing engine.
                self.engines
                    .write()
                    .expect("engines lock poisoned")
                    .remove(gateway_id);
                warn!(gateway_id = %gateway_id, "Gateway OPA enabled but no policy referenced or inlined; denying (fail-closed)");
                return Ok(());
            }
            let engine = OpaEngine::new();
            engine
                .load_policy(&format!("gateway_{}", gateway_id), &rego)
                .map_err(|e| format!("Failed to compile gateway policy: {}", e))?;
            let hash = Some(crate::policies::policy_definitions::content_hash(
                &crate::policies::policy_definitions::PolicyType::Appliance,
                &rego,
            ));
            compiled.push(CompiledGatewayPolicy {
                engine,
                policy_definition_id: None,
                policy_version: None,
                policy_content_hash: hash,
            });
        } else {
            let store = self
                .policy_definition_store
                .read()
                .expect("policy_definition_store lock poisoned")
                .clone();
            let Some(store) = store else {
                return Err("Policy definition store not configured".to_string());
            };
            for def_id in &def_ids {
                match store.get(def_id).await {
                    Some(def) if def.enabled && !def.policy.is_empty() => {
                        let engine = OpaEngine::new();
                        // Fail closed: a bad compile evicts the whole set rather
                        // than leaving stale/partial logic active.
                        if let Err(e) = engine.load_policy(&format!("gateway_{}_{}", gateway_id, def_id), &def.policy) {
                            self.engines
                                .write()
                                .expect("engines lock poisoned")
                                .remove(gateway_id);
                            return Err(format!("Failed to compile gateway policy: {}", e));
                        }
                        compiled.push(CompiledGatewayPolicy {
                            engine,
                            policy_definition_id: Some(def.id.clone()),
                            policy_version: def
                                .version
                                .map(|v| v.to_string()),
                            policy_content_hash: def.content_hash.clone(),
                        });
                    }
                    Some(def) if !def.enabled => {
                        info!(gateway_id = %gateway_id, def_id = %def_id, "Gateway policy definition disabled; skipping in set");
                    }
                    Some(_) => {
                        // Referenced-but-empty definition — fail closed.
                        self.engines
                            .write()
                            .expect("engines lock poisoned")
                            .remove(gateway_id);
                        warn!(gateway_id = %gateway_id, def_id = %def_id, "Gateway policy definition has empty Rego; denying (fail-closed)");
                        return Ok(());
                    }
                    None => {
                        self.engines
                            .write()
                            .expect("engines lock poisoned")
                            .remove(gateway_id);
                        return Err(format!("Gateway policy definition not found: {def_id}"));
                    }
                }
            }
        }

        if compiled.is_empty() {
            // Every referenced definition was disabled — fail closed (no engine).
            self.engines
                .write()
                .expect("engines lock poisoned")
                .remove(gateway_id);
            warn!(gateway_id = %gateway_id, "All referenced gateway policy definitions disabled; denying (fail-closed)");
            return Ok(());
        }

        // Compilation succeeded — atomically replace the cached engine set.
        let count = compiled.len();
        self.engines
            .write()
            .expect("engines lock poisoned")
            .insert(gateway_id.clone(), compiled);

        info!(gateway_id = %gateway_id, count, "Gateway OPA policy set compiled and cached");

        Ok(())
    }

    /// Evaluate the gateway-level policy.
    ///
    /// Returns `Ok(true)` if allowed, `Ok(false)` if denied.
    /// A missing compiled engine for an OPA-enforced gateway denies (fail-closed).
    ///
    /// ## Concurrency
    /// The `engines` read lock is held across the whole evaluation — the same
    /// pattern as [`crate::policies::surface_manager`] and the pipe policy
    /// manager (this used to clone the engine out and evaluate lock-free, but was
    /// aligned to the others when it moved to [`OpaEngine`]). Concurrent
    /// evaluations do not block each other (the read lock is shared and
    /// `OpaEngine::evaluate_query` clones the compiled template internally per
    /// call); only a policy recompile — which takes the write lock and is rare —
    /// waits for in-flight evaluations to drain.
    pub fn evaluate_policy(
        &self,
        gateway_id: &str,
        input: serde_json::Value,
    ) -> Result<bool, String> {
        let engines = self
            .engines
            .read()
            .expect("engines lock poisoned");

        // Extract the redacted caller/HTTP/workload summary before evaluation
        // consumes the input.
        let input_ctx = policy_audit::extract_input_context(&input);

        let Some(compiled_set) = engines.get(gateway_id) else {
            // Fail CLOSED: an OPA-enforced gateway with no compiled engine (the
            // inline Rego failed to compile, or the store was unavailable at
            // boot) denies — parity with the surface and pipe layers. The
            // enforcement point only reaches here when `is_enforced` is true.
            warn!(gateway_id = %gateway_id, "No compiled gateway policy for enforced gateway; denying (fail-closed)");
            policy_audit::record_decision(
                PolicyScope::Gateway,
                PolicyFlow::Fabric,
                PolicyOutcome::MissingEngine,
                Some("No compiled gateway policy for OPA-enforced gateway; denied (fail-closed)"),
                "",
                None,
                None,
                None,
                None,
                Some(gateway_id),
                None,
                &input_ctx,
            );
            return Ok(false);
        };

        if compiled_set.is_empty() {
            // Enforced but empty set — fail closed (parity with a missing engine).
            warn!(gateway_id = %gateway_id, "Empty gateway policy set for enforced gateway; denying (fail-closed)");
            policy_audit::record_decision(
                PolicyScope::Gateway,
                PolicyFlow::Fabric,
                PolicyOutcome::MissingEngine,
                Some("Empty gateway policy set for OPA-enforced gateway; denied (fail-closed)"),
                "",
                None,
                None,
                None,
                None,
                Some(gateway_id),
                None,
                &input_ctx,
            );
            return Ok(false);
        }

        debug!(gateway_id = %gateway_id, count = compiled_set.len(), "Evaluating gateway-level OPA policy set (deny-overrides)");

        // Deny-overrides: the first member to deny (or error) blocks; all must
        // allow for the request to pass. `evaluate_query` clones the compiled
        // template internally, so concurrent requests do not contend on a lock.
        for compiled in compiled_set {
            match compiled
                .engine
                .evaluate_query(GATEWAY_POLICY_QUERY, input.clone())
            {
                Ok(decision) => {
                    policy_audit::record_decision(
                        PolicyScope::Gateway,
                        PolicyFlow::Fabric,
                        if decision.allow {
                            PolicyOutcome::Allow
                        } else {
                            PolicyOutcome::Deny
                        },
                        decision.reason.as_deref(),
                        GATEWAY_POLICY_QUERY,
                        compiled
                            .policy_definition_id
                            .as_deref(),
                        compiled
                            .policy_version
                            .as_deref(),
                        compiled
                            .policy_content_hash
                            .as_deref(),
                        None,
                        Some(gateway_id),
                        None,
                        &input_ctx,
                    );
                    if !decision.allow {
                        return Ok(false);
                    }
                }
                Err(e) => {
                    let msg = format!("Failed to evaluate gateway policy: {}", e);
                    policy_audit::record_decision(
                        PolicyScope::Gateway,
                        PolicyFlow::Fabric,
                        PolicyOutcome::Error,
                        Some(&msg),
                        GATEWAY_POLICY_QUERY,
                        compiled
                            .policy_definition_id
                            .as_deref(),
                        compiled
                            .policy_version
                            .as_deref(),
                        compiled
                            .policy_content_hash
                            .as_deref(),
                        None,
                        Some(gateway_id),
                        None,
                        &input_ctx,
                    );
                    return Err(msg);
                }
            }
        }

        Ok(true)
    }

    /// Returns true when gateway-level OPA is **enabled in config** for this
    /// gateway — independent of whether the Rego compiled. The enforcement
    /// point gates on this (not on the presence of a compiled engine) so a
    /// compile failure fails CLOSED: the request still reaches
    /// [`Self::evaluate_policy`], which denies on a missing engine.
    pub fn is_enforced(
        &self,
        gateway_id: &str,
    ) -> bool {
        self.enforced
            .read()
            .expect("enforced lock poisoned")
            .contains(gateway_id)
    }

    /// Remove policy for a gateway
    #[allow(dead_code)]
    pub fn remove_gateway(
        &self,
        gateway_id: &str,
    ) {
        let mut engines = self
            .engines
            .write()
            .expect("engines lock poisoned");
        if engines
            .remove(gateway_id)
            .is_some()
        {
            info!(gateway_id = %gateway_id, "Removed gateway policy");
        }
        drop(engines);
        self.enforced
            .write()
            .expect("enforced lock poisoned")
            .remove(gateway_id);
    }
}

impl Default for GatewayPolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::types::{GatewayCreationType, GatewayOpaPolicyConfig, GatewayStatus, GatewayType};

    fn create_test_gateway(
        id: &str,
        gateway_type: GatewayType,
        policy: Option<GatewayOpaPolicyConfig>,
    ) -> Gateway {
        Gateway {
            id: id.to_string(),
            name: format!("test-gateway-{}", id),
            description: "Test gateway".to_string(),
            did: "did:example:test".to_string(),
            gateway_type,
            status: GatewayStatus::Active,
            tenant_id: None,
            creation_type: GatewayCreationType::User,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            exposed_channels: Vec::new(),
            opa_policy_config: policy,
        }
    }

    #[tokio::test]
    async fn test_no_policy_is_not_enforced() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway("gw-1", GatewayType::SelfGateway, None);

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        // No policy configured → the gateway is not OPA-enforced, so the
        // enforcement point skips evaluation and the request proceeds.
        assert!(!manager.is_enforced("gw-1"), "A gateway with no policy must not be enforced");
    }

    #[tokio::test]
    async fn test_disabled_policy_is_not_enforced() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway(
            "gw-2",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: false,
                policy: "package agentstream.policy\ndefault allow = false".to_string(),
                policy_definition_id: None,
                policy_definition_ids: Vec::new(),
            }),
        );

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        // A disabled policy → not enforced; the enforcement point skips it.
        assert!(!manager.is_enforced("gw-2"), "A disabled gateway policy must not be enforced");
    }

    #[tokio::test]
    async fn test_policy_deny_unauthenticated() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway(
            "gw-3",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: r#"
package agentstream.policy

default allow = false

allow if {
    input.source_auth.claims.sub
}
"#
                .to_string(),
                policy_definition_id: None,
                policy_definition_ids: Vec::new(),
            }),
        );

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        // Request without source_auth — should be denied
        let input_no_jwt = serde_json::json!({
            "gateway": {
                "direction": "inbound"
            }
        });

        let allowed = manager
            .evaluate_policy("gw-3", input_no_jwt)
            .unwrap();
        assert!(!allowed, "Unauthenticated request should be denied");

        // Request with source_auth — should be allowed
        let input_with_jwt = serde_json::json!({
            "gateway": {
                "direction": "inbound"
            },
            "source_auth": {
                "method": "jwt_bearer",
                "subject": "user-123",
                "claims": { "sub": "user-123" }
            }
        });

        let allowed = manager
            .evaluate_policy("gw-3", input_with_jwt)
            .unwrap();
        assert!(allowed, "Authenticated request should be allowed");
    }

    #[tokio::test]
    async fn clearing_the_policy_evicts_a_compiled_engine() {
        let manager = GatewayPolicyManager::new();
        let mut gateway = create_test_gateway(
            "gw-cleared",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: "package agentstream.policy\ndefault allow = false".to_string(),
                policy_definition_id: None,
                policy_definition_ids: Vec::new(),
            }),
        );
        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();
        assert!(manager.is_enforced("gw-cleared"));

        gateway.opa_policy_config = None;
        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();
        assert!(!manager.is_enforced("gw-cleared"), "a removed policy is no longer enforced");
    }

    #[tokio::test]
    async fn test_remove_gateway_policy() {
        let manager = GatewayPolicyManager::new();
        let gateway = create_test_gateway(
            "gw-4",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: "package agentstream.policy\ndefault allow = true".to_string(),
                policy_definition_id: None,
                policy_definition_ids: Vec::new(),
            }),
        );

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        // Verify policy is loaded by evaluating it
        let input = serde_json::json!({});
        let allowed = manager
            .evaluate_policy("gw-4", input.clone())
            .unwrap();
        assert!(allowed, "Policy with default allow=true should allow");

        manager.remove_gateway("gw-4");

        // After removal the gateway is no longer enforced, so the enforcement
        // point skips it and the request proceeds.
        assert!(!manager.is_enforced("gw-4"), "A removed gateway policy must not be enforced");
    }

    #[tokio::test]
    async fn test_policy_allow_by_source_id() {
        let manager = GatewayPolicyManager::new();
        let did = "did:example:source-gateway";
        let policy = format!(
            r#"package agentstream.policy

default allow = false

allow if {{
    input.gateway.direction == "inbound"
    input.gateway.source_id == "{did}"
}}
"#
        );

        let gateway = create_test_gateway(
            "gw-src",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: policy.clone(),
                policy_definition_id: None,
                policy_definition_ids: Vec::new(),
            }),
        );

        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        let input = serde_json::json!({
            "http": {
                "method": "POST",
                "path": "/",
                "headers": {
                    "CONTENT-TYPE": "application/json"
                }
            },
            "gateway": {
                "direction": "inbound",
                "source_id": did
            },
            "channel": {
                "config_id": "05fa9e89-1f0e-48b0-b76f-585fd6ac2dff",
                "name": "mcp-channel-1779115681393"
            }
        });

        let allowed = manager
            .evaluate_policy("gw-src", input)
            .unwrap();
        assert!(allowed, "Request with matching direction + source_id should be allowed, policy:\n{}", policy);
    }

    #[tokio::test]
    async fn evaluate_records_missing_engine_and_denies_fail_closed() {
        let manager = GatewayPolicyManager::new();
        // Back the referenced definition with a real store so the gateway
        // resolves its Rego reference-only (the gateway record stores no copy).
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::policies::FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        store
            .save(crate::policies::policy_definitions::PolicyDefinition {
                id: "gw-def-1".to_string(),
                name: "gw-def-1".to_string(),
                description: String::new(),
                policy_type: crate::policies::policy_definitions::PolicyType::Appliance,
                policy: "package agentstream.policy\ndefault allow = false\nallow if { input.source_auth.claims.sub }"
                    .to_string(),
                enabled: true,
                created_at: "2026-06-07T00:00:00Z".to_string(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
                tenant_id: None,
            })
            .await
            .expect("save def");
        manager.set_policy_definition_store(std::sync::Arc::new(store));

        // A gateway that references the definition (reference-only — no inline Rego).
        let gateway = create_test_gateway(
            "gw-audit",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: String::new(),
                policy_definition_id: Some("gw-def-1".to_string()),
                policy_definition_ids: Vec::new(),
            }),
        );
        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        let decisions = crate::observability::policy_audit::capture_decisions(|| {
            // No compiled engine → fail-CLOSED deny, recorded as missing_engine.
            assert!(
                !manager
                    .evaluate_policy("gw-none", serde_json::json!({}))
                    .unwrap()
            );
            // Compiled policy denies the unauthenticated request.
            assert!(
                !manager
                    .evaluate_policy("gw-audit", serde_json::json!({ "gateway": { "direction": "inbound" } }))
                    .unwrap()
            );
        });

        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].scope, "gateway");
        assert_eq!(decisions[0].decision, "missing_engine");
        assert_eq!(decisions[0].flow, "fabric");
        assert_eq!(decisions[1].decision, "deny");
        assert_eq!(
            decisions[1]
                .policy_definition_id
                .as_deref(),
            Some("gw-def-1")
        );
    }

    #[tokio::test]
    async fn multi_policy_gateway_denies_when_any_member_denies() {
        let manager = GatewayPolicyManager::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::policies::FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        for (id, rego) in [
            ("gw-allow", "package agentstream.policy\ndefault allow = true"),
            (
                "gw-need-sub",
                "package agentstream.policy\ndefault allow = false\nallow if { input.source_auth.claims.sub }",
            ),
        ] {
            store
                .save(crate::policies::policy_definitions::PolicyDefinition {
                    id: id.to_string(),
                    name: id.to_string(),
                    description: String::new(),
                    policy_type: crate::policies::policy_definitions::PolicyType::Appliance,
                    policy: rego.to_string(),
                    enabled: true,
                    created_at: "2026-06-07T00:00:00Z".to_string(),
                    updated_at: None,
                    version: None,
                    content_hash: None,
                    sample_input: None,
                    tenant_id: None,
                })
                .await
                .expect("save def");
        }
        manager.set_policy_definition_store(std::sync::Arc::new(store));

        let config = GatewayOpaPolicyConfig {
            enabled: true,
            policy: String::new(),
            policy_definition_id: Some("gw-allow".to_string()),
            policy_definition_ids: vec!["gw-need-sub".to_string()],
        };
        assert_eq!(
            config.all_policy_definition_ids(),
            vec!["gw-allow".to_string(), "gw-need-sub".to_string()],
            "legacy single id first, then the extra set, deduped"
        );

        let gateway = create_test_gateway("gw-multi", GatewayType::SelfGateway, Some(config));
        manager
            .update_gateway_policy(&gateway)
            .await
            .unwrap();

        // Unauthenticated → the second policy denies (deny-overrides).
        assert!(
            !manager
                .evaluate_policy("gw-multi", serde_json::json!({ "gateway": { "direction": "inbound" } }))
                .unwrap(),
            "any member deny blocks the request"
        );
        // Authenticated → both members allow.
        assert!(
            manager
                .evaluate_policy(
                    "gw-multi",
                    serde_json::json!({
                        "gateway": { "direction": "inbound" },
                        "source_auth": { "claims": { "sub": "user-1" } }
                    })
                )
                .unwrap(),
            "all members allow → request passes"
        );
    }

    #[tokio::test]
    async fn gateway_missing_referenced_definition_fails_closed() {
        let manager = GatewayPolicyManager::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let store = crate::policies::FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        manager.set_policy_definition_store(std::sync::Arc::new(store));

        let gateway = create_test_gateway(
            "gw-missing",
            GatewayType::SelfGateway,
            Some(GatewayOpaPolicyConfig {
                enabled: true,
                policy: String::new(),
                policy_definition_id: Some("nope".to_string()),
                policy_definition_ids: Vec::new(),
            }),
        );
        // A referenced-but-missing definition is a compile error…
        assert!(
            manager
                .update_gateway_policy(&gateway)
                .await
                .is_err()
        );
        // …but the gateway stays enforced, so evaluation denies (fail-closed).
        assert!(manager.is_enforced("gw-missing"));
        assert!(
            !manager
                .evaluate_policy("gw-missing", serde_json::json!({}))
                .unwrap()
        );
    }
}
