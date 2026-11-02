//! Pipe-level inbound OPA (Rego) policy enforcement.
//!
//! Mirrors [`crate::policies::surface_manager::SurfacePolicyManager`] but is
//! scoped to LLM pipes and limited to inbound Rego evaluation. Each pipe's
//! policy is compiled once into an [`OpaEngine`] template and cloned per
//! evaluation (a cheap `Arc` bump), so the request-path holds no write lock.

use crate::observability::policy_audit::{self, PolicyFlow, PolicyOutcome, PolicyScope};
use crate::pipes::PipeConfig;
use crate::pipes::config::PipeType;
use crate::policies::OpaEngine;
use crate::policies::policy_definitions::FileSystemPolicyDefinitionStore;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

/// Rego query path for an LLM Surface policy (`package llm.policy`).
const LLM_POLICY_QUERY: &str = "data.llm.policy.allow";

/// Rego query path for an IDE Surface policy (`package ide.policy`).
const IDE_POLICY_QUERY: &str = "data.ide.policy.allow";

/// Select the Rego query path a surface's OPA policy is evaluated against.
///
/// An IDE Surface (`PipeType::IDECatalog`) authors `package ide.policy`; every
/// other surface type (LLM Surface, Webhook) authors
/// `package llm.policy`. The query path is stored alongside the compiled engine
/// at compile time, so evaluation never needs to know the surface type.
fn policy_query_for(pipe_type: &PipeType) -> &'static str {
    match pipe_type {
        PipeType::IDECatalog { .. } => IDE_POLICY_QUERY,
        _ => LLM_POLICY_QUERY,
    }
}

/// A compiled pipe/variant OPA engine plus the Rego query path it is evaluated
/// against (derived from the owning surface's `pipe_type`).
struct CompiledPolicy {
    engine: OpaEngine,
    query: &'static str,
    /// When true, `evaluate` logs the full input JSON handed to Rego and the
    /// resulting allow/deny — a debugging aid for policy authoring, opt-in
    /// per pipe via `PipeOpaConfig.log_decisions`.
    log_decisions: bool,
    /// Stored policy-definition record id this engine was compiled from — for
    /// audit evidence (`policy_definition_id`).
    policy_definition_id: Option<String>,
    /// Policy-definition version — the monotonic revision number in force, so
    /// audit evidence can prove which revision was enforced.
    policy_version: Option<String>,
    /// Content hash (`sha256:<hex>`) of the enforced revision — makes the
    /// decision reproducible against exact Rego bytes.
    policy_content_hash: Option<String>,
    /// Operator-assigned policy-definition name, for the audit record.
    policy_name: Option<String>,
}

/// Compiled-policy evidence surfaced to governance capture so a denial record
/// can name the exact policy definition, version, and content hash enforced.
#[derive(Debug, Clone, Default)]
pub struct PolicyEvidence {
    pub definition_id: Option<String>,
    /// The policy definition's name, else the Rego query it was evaluated with.
    pub name: Option<String>,
    pub version: Option<String>,
    pub content_hash: Option<String>,
}

impl From<&CompiledPolicy> for PolicyEvidence {
    fn from(c: &CompiledPolicy) -> Self {
        Self {
            definition_id: c.policy_definition_id.clone(),
            name: Some(
                c.policy_name
                    .clone()
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| c.query.to_string()),
            ),
            version: c.policy_version.clone(),
            content_hash: c.policy_content_hash.clone(),
        }
    }
}

/// A globally-enforced compiled policy plus its monitor-only flag.
struct GlobalCompiledPolicy {
    policy: CompiledPolicy,
    /// When true, a deny is recorded but not enforced (the request proceeds).
    monitor_only: bool,
}

/// The compiled appliance-wide policy set for one surface type.
struct GlobalSet {
    policies: Vec<GlobalCompiledPolicy>,
    /// True when an ENFORCED (non-monitor) global policy could not be resolved
    /// or compiled — the whole type then denies (fail closed).
    broken: bool,
}

/// The Rego query path for a global policy of the given surface type. IDE
/// surfaces author `package ide.policy`; the appliance (gateway/fabric) type
/// authors `package agentstream.policy`; every other type authors
/// `package llm.policy`.
fn query_for_policy_type(policy_type: &str) -> &'static str {
    match policy_type {
        "ide" => IDE_POLICY_QUERY,
        "appliance" => crate::policies::AGENTSTREAM_POLICY_QUERY,
        _ => LLM_POLICY_QUERY,
    }
}

/// The policy-type string (`llm` / `ide`) for a pipe, used to look up its
/// appliance-wide global policy set.
pub fn pipe_policy_type(pipe_type: &PipeType) -> &'static str {
    match pipe_type {
        PipeType::IDECatalog { .. } => "ide",
        _ => "llm",
    }
}

/// Select the audit [`PolicyScope`] for a compiled-engine key / query. IDE
/// per-member Model Policies and IDE-surface (`data.ide.policy`) evaluations
/// are `Ide`; everything else is `Pipe`.
fn pipe_scope(
    key: &str,
    query: Option<&str>,
) -> PolicyScope {
    if key.contains("#ide-member:") {
        return PolicyScope::Ide;
    }
    match query {
        Some(q) if q == IDE_POLICY_QUERY => PolicyScope::Ide,
        _ => PolicyScope::Pipe,
    }
}

lazy_static::lazy_static! {
    /// Process-global pipe policy manager. Boot compiles every pipe's policy
    /// into it; the admin pipe CRUD handlers and config reload refresh it; the
    /// pipe HTTP handler evaluates against it.
    pub static ref PIPE_POLICY_MANAGER: Arc<PipePolicyManager> = Arc::new(PipePolicyManager::new());
}

/// Inbound OPA policy manager for LLM pipes.
pub struct PipePolicyManager {
    /// Pre-compiled OPA engine sets per pipe (keyed by pipe id / variant / IDE
    /// member key). Each key maps to an ordered set of policies evaluated under
    /// deny-overrides; each carries the Rego query path for its surface type.
    opa_engines: RwLock<HashMap<String, Vec<CompiledPolicy>>>,

    /// Compiled appliance-wide (global) policy sets, keyed by policy type
    /// (`llm` / `ide`). Enforced on every surface of the type under
    /// deny-overrides, in addition to the surface's own policies.
    global_engines: RwLock<HashMap<String, GlobalSet>>,

    /// Policy-definition store used to resolve a pipe's `policy_definition_id`
    /// to Rego text at compile time.
    policy_definition_store: RwLock<Option<Arc<FileSystemPolicyDefinitionStore>>>,
}

impl PipePolicyManager {
    pub fn new() -> Self {
        Self {
            opa_engines: RwLock::new(HashMap::new()),
            global_engines: RwLock::new(HashMap::new()),
            policy_definition_store: RwLock::new(None),
        }
    }

    /// Set (or replace) the policy-definition store used to resolve policies.
    pub fn set_policy_definition_store(
        &self,
        store: Arc<FileSystemPolicyDefinitionStore>,
    ) {
        *self
            .policy_definition_store
            .write()
            .expect("pipe policy_definition_store lock poisoned") = Some(store);
    }

    /// Returns true when a compiled OPA engine exists for the given pipe.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn has_policy(
        &self,
        pipe_id: &str,
    ) -> bool {
        self.opa_engines
            .read()
            .expect("pipe opa_engines lock poisoned")
            .contains_key(pipe_id)
    }

    /// Evidence for the engine [`Self::evaluate`] would select for this
    /// pipe/variant (same key fallback: variant engine if present, else base),
    /// for attaching to a governance denial record. `None` when no engine is
    /// compiled.
    pub fn policy_evidence(
        &self,
        pipe_id: &str,
        variant_alias: Option<&str>,
    ) -> Option<PolicyEvidence> {
        let engines = self
            .opa_engines
            .read()
            .expect("pipe opa_engines lock poisoned");
        let key = match variant_alias {
            Some(alias) => {
                let vk = variant_key(pipe_id, alias);
                if engines.contains_key(&vk) {
                    vk
                } else {
                    pipe_id.to_string()
                }
            }
            None => pipe_id.to_string(),
        };
        engines
            .get(&key)
            .and_then(|set| set.first())
            .map(PolicyEvidence::from)
    }

    /// Recompile the appliance-wide (global) policy sets from `assignments`.
    /// Called at boot and whenever the assignments (or a referenced definition)
    /// change. An enforced global that cannot be resolved/compiled marks its
    /// type broken (fail closed); a monitor-only one is skipped.
    pub async fn refresh_global(
        &self,
        assignments: &crate::policies::GlobalPolicyAssignments,
    ) -> Result<(), String> {
        let store = self
            .policy_definition_store
            .read()
            .expect("pipe policy_definition_store lock poisoned")
            .clone();
        let mut new_global: HashMap<String, GlobalSet> = HashMap::new();
        for (policy_type, list) in &assignments.assignments {
            let query = query_for_policy_type(policy_type);
            let mut set = GlobalSet {
                policies: Vec::new(),
                broken: false,
            };
            for assignment in list {
                let def = match &store {
                    Some(s) => {
                        s.get(&assignment.policy_id)
                            .await
                    }
                    None => None,
                };
                match def {
                    Some(def) if def.enabled && !def.policy.is_empty() => {
                        let engine = OpaEngine::new();
                        if let Err(e) = engine.load_policy(&format!("global:{policy_type}"), &def.policy) {
                            warn!(policy_type = %policy_type, def_id = %assignment.policy_id, error = %e, "Global policy failed to compile");
                            if !assignment.monitor_only {
                                set.broken = true;
                            }
                            continue;
                        }
                        set.policies
                            .push(GlobalCompiledPolicy {
                                policy: CompiledPolicy {
                                    engine,
                                    query,
                                    log_decisions: false,
                                    policy_definition_id: Some(def.id.clone()),
                                    policy_version: def
                                        .version
                                        .map(|v| v.to_string()),
                                    policy_content_hash: def.content_hash.clone(),
                                    policy_name: Some(def.name.clone()),
                                },
                                monitor_only: assignment.monitor_only,
                            });
                    }
                    _ => {
                        warn!(policy_type = %policy_type, def_id = %assignment.policy_id, "Global policy definition missing/disabled/empty");
                        if !assignment.monitor_only {
                            set.broken = true;
                        }
                    }
                }
            }
            if set.broken || !set.policies.is_empty() {
                new_global.insert(policy_type.clone(), set);
            }
        }
        let count: usize = new_global
            .values()
            .map(|s| s.policies.len())
            .sum();
        *self
            .global_engines
            .write()
            .expect("global_engines lock poisoned") = new_global;
        info!(compiled = count, "Refreshed appliance-wide (global) policy sets");
        Ok(())
    }

    /// Whether any appliance-wide global policy applies to `policy_type`.
    pub fn has_global(
        &self,
        policy_type: &str,
    ) -> bool {
        self.global_engines
            .read()
            .expect("global_engines lock poisoned")
            .contains_key(policy_type)
    }

    /// Whether the appliance-wide set for `policy_type` could not be resolved
    /// or compiled, so it denies everything.
    #[cfg(test)]
    pub(crate) fn global_is_broken(
        &self,
        policy_type: &str,
    ) -> bool {
        self.global_engines
            .read()
            .expect("global_engines lock poisoned")
            .get(policy_type)
            .is_some_and(|set| set.broken)
    }

    /// Evaluate the appliance-wide global policy set for `policy_type` under
    /// deny-overrides. A monitor-only member records its (would-be) decision but
    /// never blocks. Returns the decision plus the deciding policy's evidence.
    pub fn evaluate_global(
        &self,
        policy_type: &str,
        input: serde_json::Value,
    ) -> (Result<bool, String>, Option<PolicyEvidence>) {
        let engines = self
            .global_engines
            .read()
            .expect("global_engines lock poisoned");
        let input_ctx = policy_audit::extract_input_context(&input);
        let policy_key = format!("global:{policy_type}");
        // The appliance (gateway/fabric) global is a Gateway-scoped decision on
        // the Fabric flow; llm/ide globals are surface access-point decisions.
        let (scope, flow) = match policy_type {
            "ide" => (PolicyScope::Ide, PolicyFlow::AccessPoint),
            "appliance" => (PolicyScope::Gateway, PolicyFlow::Fabric),
            _ => (PolicyScope::Pipe, PolicyFlow::AccessPoint),
        };
        let Some(set) = engines.get(policy_type) else {
            return (Ok(true), None);
        };
        if set.broken {
            let reason = "An enforced appliance-wide policy is unavailable; denied (fail-closed)";
            policy_audit::record_decision(
                scope,
                flow,
                PolicyOutcome::MissingEngine,
                Some(reason),
                "",
                None,
                None,
                None,
                None,
                input_ctx
                    .surface_id
                    .as_deref(),
                Some(&policy_key),
                &input_ctx,
            );
            return (Ok(false), None);
        }
        for gp in &set.policies {
            match gp
                .policy
                .engine
                .evaluate_query(gp.policy.query, input.clone())
            {
                Ok(decision) => {
                    policy_audit::record_decision(
                        scope,
                        flow,
                        if decision.allow {
                            PolicyOutcome::Allow
                        } else {
                            PolicyOutcome::Deny
                        },
                        decision.reason.as_deref(),
                        gp.policy.query,
                        gp.policy
                            .policy_definition_id
                            .as_deref(),
                        gp.policy
                            .policy_version
                            .as_deref(),
                        gp.policy
                            .policy_content_hash
                            .as_deref(),
                        gp.policy
                            .policy_name
                            .as_deref(),
                        input_ctx
                            .surface_id
                            .as_deref(),
                        Some(&policy_key),
                        &input_ctx,
                    );
                    if !decision.allow {
                        if gp.monitor_only {
                            warn!(policy_type = %policy_type, "Global monitor-only policy would deny (not enforced)");
                            continue;
                        }
                        return (Ok(false), Some(PolicyEvidence::from(&gp.policy)));
                    }
                }
                Err(e) => {
                    let msg = format!("Global policy evaluation error: {e}");
                    policy_audit::record_decision(
                        scope,
                        flow,
                        PolicyOutcome::Error,
                        Some(&msg),
                        gp.policy.query,
                        gp.policy
                            .policy_definition_id
                            .as_deref(),
                        gp.policy
                            .policy_version
                            .as_deref(),
                        gp.policy
                            .policy_content_hash
                            .as_deref(),
                        gp.policy
                            .policy_name
                            .as_deref(),
                        input_ctx
                            .surface_id
                            .as_deref(),
                        Some(&policy_key),
                        &input_ctx,
                    );
                    if gp.monitor_only {
                        continue;
                    }
                    return (Err(msg), Some(PolicyEvidence::from(&gp.policy)));
                }
            }
        }
        (
            Ok(true),
            set.policies
                .last()
                .map(|gp| PolicyEvidence::from(&gp.policy)),
        )
    }

    /// Compile, refresh, or remove every OPA engine owned by a pipe based on
    /// its config — the base pipe plus one engine per `$alias` variant.
    ///
    /// Variants are full snapshots, so each may enable/disable OPA or point at
    /// a different policy definition than the base. We drop all engines owned
    /// by the pipe first (so renamed/removed variants never leave stale
    /// engines), then recompile the base under `pipe_id` and each variant
    /// under the composite key `pipe_id$alias`.
    pub async fn update_pipe_policy(
        &self,
        pipe: &PipeConfig,
    ) -> Result<(), String> {
        // Clear base + all variant engines for this pipe before recompiling.
        self.remove_pipe(&pipe.id);

        self.compile_key(
            &pipe.id,
            pipe.opa_enabled(),
            &pipe.opa_policy_definition_ids(),
            policy_query_for(&pipe.pipe_type),
            pipe.opa_log_decisions(),
        )
        .await?;

        for variant in &pipe.variants {
            match pipe.resolve_variant(Some(&variant.alias)) {
                Ok(resolved) => {
                    let key = variant_key(&pipe.id, &variant.alias);
                    self.compile_key(
                        &key,
                        resolved.opa_enabled(),
                        &resolved.opa_policy_definition_ids(),
                        policy_query_for(&resolved.pipe_type),
                        resolved.opa_log_decisions(),
                    )
                    .await?;
                }
                Err(e) => {
                    warn!(pipe_id = %pipe.id, alias = %variant.alias, error = %e, "Failed to resolve variant for OPA compile; skipping");
                }
            }
        }

        // IDE Surface: compile each catalogue member's optional per-member
        // Model Policy under its own composite key so dispatch can gate a
        // specific model on top of the front-door OPA. Member policies are
        // IDE-scoped (`package ide.policy`) and always "enabled" when a
        // definition id is set (presence is the enablement).
        if let PipeType::IDECatalog { config } = &pipe.pipe_type {
            for member in &config.members {
                if let Some(policy_id) = member.opa_policy_definition_id() {
                    let key = ide_member_policy_key(&pipe.id, &member.model_id());
                    let member_ids = [policy_id.to_string()];
                    self.compile_key(&key, true, &member_ids, IDE_POLICY_QUERY, false)
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Compile (or remove) the OPA engine **set** under `key`, honouring OPA
    /// enablement and the ordered list of policy-definition ids (evaluated under
    /// deny-overrides). Removes any existing set when OPA is disabled or the
    /// list is empty; a referenced-but-missing / empty-body policy evicts the
    /// whole set (fail closed — the enforcement point then denies); a disabled
    /// member is skipped; a compile failure evicts the set and returns Err.
    async fn compile_key(
        &self,
        key: &str,
        opa_enabled: bool,
        def_ids: &[String],
        query: &'static str,
        log_decisions: bool,
    ) -> Result<(), String> {
        if !opa_enabled || def_ids.is_empty() {
            self.remove_key(key);
            return Ok(());
        }

        // Clone the Arc so the std::sync lock is released before awaiting.
        let maybe_store = self
            .policy_definition_store
            .read()
            .expect("pipe policy_definition_store lock poisoned")
            .clone();
        let Some(store) = maybe_store else {
            warn!(key = %key, "Policy definition store unavailable; skipping pipe policy compile");
            self.remove_key(key);
            return Ok(());
        };

        let mut compiled: Vec<CompiledPolicy> = Vec::with_capacity(def_ids.len());
        for def_id in def_ids {
            match store.get(def_id).await {
                Some(def) if def.enabled && !def.policy.is_empty() => {
                    let engine = OpaEngine::new();
                    // Fail closed: a bad compile evicts the whole set rather than
                    // leaving stale/partial logic active for this pipe/variant.
                    if let Err(e) = engine.load_policy(key, &def.policy) {
                        warn!(key = %key, def_id = %def_id, error = %e, "OPA policy failed to compile; removing engine set (fail closed)");
                        self.remove_key(key);
                        return Err(e);
                    }
                    compiled.push(CompiledPolicy {
                        engine,
                        query,
                        log_decisions,
                        policy_definition_id: Some(def.id.clone()),
                        policy_version: def
                            .version
                            .map(|v| v.to_string()),
                        policy_content_hash: def.content_hash.clone(),
                        policy_name: Some(def.name.clone()),
                    });
                }
                Some(def) if !def.enabled => {
                    info!(key = %key, def_id = %def_id, "Policy definition disabled; skipping in set");
                }
                Some(_) => {
                    warn!(key = %key, def_id = %def_id, "Policy definition has empty Rego body; removing engine set (fail closed)");
                    self.remove_key(key);
                    return Ok(());
                }
                None => {
                    warn!(key = %key, def_id = %def_id, "Policy definition not found; removing engine set (fail closed)");
                    self.remove_key(key);
                    return Ok(());
                }
            }
        }

        if compiled.is_empty() {
            // Every referenced policy was disabled — no engine (matches the
            // single-policy disabled behaviour: the enforcement point denies).
            self.remove_key(key);
            return Ok(());
        }

        info!(key = %key, count = compiled.len(), log_decisions, "Compiled OPA policy set for pipe/variant");
        self.opa_engines
            .write()
            .expect("pipe opa_engines lock poisoned")
            .insert(key.to_string(), compiled);
        Ok(())
    }

    /// Remove a single compiled engine by exact key.
    fn remove_key(
        &self,
        key: &str,
    ) {
        if self
            .opa_engines
            .write()
            .expect("pipe opa_engines lock poisoned")
            .remove(key)
            .is_some()
        {
            info!(key = %key, "Removed OPA policy engine");
        }
    }

    /// Remove every compiled engine owned by a pipe — the base (`pipe_id`),
    /// all variant engines (`pipe_id$alias`), and all IDE per-member Model
    /// Policy engines (`pipe_id#…`). Used on delete/disable and before each
    /// recompile.
    pub fn remove_pipe(
        &self,
        pipe_id: &str,
    ) {
        let dollar = format!("{pipe_id}$");
        let hash = format!("{pipe_id}#");
        let mut engines = self
            .opa_engines
            .write()
            .expect("pipe opa_engines lock poisoned");
        let before = engines.len();
        engines.retain(|key, _| key != pipe_id && !key.starts_with(&dollar) && !key.starts_with(&hash));
        if engines.len() != before {
            info!(pipe_id = %pipe_id, "Removed OPA policy engines for pipe");
        }
    }

    /// Evaluate the inbound policy for a pipe (optionally a `$alias` variant).
    ///
    /// Returns `Ok(true)` to allow, `Ok(false)` to deny, or `Err` when policy
    /// evaluation is unavailable or fails. This is only called by the handler
    /// when the resolved pipe/variant declares OPA enabled. When
    /// a variant alias is supplied and a variant-specific engine exists, it is
    /// used; otherwise evaluation falls back to the base engine. If no engine is
    /// compiled the request is **denied** (fail-closed), matching the surface
    /// manager's behaviour.
    pub fn evaluate(
        &self,
        pipe_id: &str,
        variant_alias: Option<&str>,
        input: serde_json::Value,
    ) -> Result<bool, String> {
        self.eval_with_key(&self.resolve_pipe_key(pipe_id, variant_alias), input)
            .0
    }

    /// Like [`Self::evaluate`] but also returns the deciding policy's evidence
    /// (the policy that denied or errored in a deny-overrides set), so a denial
    /// is attributed to the exact policy rather than the first in the set.
    pub fn evaluate_with_evidence(
        &self,
        pipe_id: &str,
        variant_alias: Option<&str>,
        input: serde_json::Value,
    ) -> (Result<bool, String>, Option<PolicyEvidence>) {
        self.eval_with_key(&self.resolve_pipe_key(pipe_id, variant_alias), input)
    }

    /// Resolve the compiled-engine key for a pipe/variant: the variant engine
    /// when one is compiled for the alias, else the base pipe engine.
    fn resolve_pipe_key(
        &self,
        pipe_id: &str,
        variant_alias: Option<&str>,
    ) -> String {
        match variant_alias {
            Some(alias) => {
                let vk = variant_key(pipe_id, alias);
                let has_variant = self
                    .opa_engines
                    .read()
                    .expect("pipe opa_engines lock poisoned")
                    .contains_key(&vk);
                if has_variant {
                    vk
                } else {
                    pipe_id.to_string()
                }
            }
            None => pipe_id.to_string(),
        }
    }

    /// Evaluate an IDE Surface's per-member **Model Policy** for a resolved
    /// catalogue model. Called by the dispatch path only when the resolved
    /// member declares an `opa_policy_id`. Fail-closed like [`Self::evaluate`]:
    /// if the member policy was set but no engine compiled (e.g. the policy was
    /// deleted), the dispatch is **denied**.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn evaluate_ide_member(
        &self,
        ide_id: &str,
        model_id: &str,
        input: serde_json::Value,
    ) -> Result<bool, String> {
        self.eval_with_key(&ide_member_policy_key(ide_id, model_id), input)
            .0
    }

    /// Like [`Self::evaluate_ide_member`] but also returns the deciding policy's
    /// evidence.
    pub fn evaluate_ide_member_with_evidence(
        &self,
        ide_id: &str,
        model_id: &str,
        input: serde_json::Value,
    ) -> (Result<bool, String>, Option<PolicyEvidence>) {
        self.eval_with_key(&ide_member_policy_key(ide_id, model_id), input)
    }

    /// Look up the compiled engine for an exact key and evaluate it, or
    /// fail-closed (deny) when no engine is compiled. Shared by the pipe/variant
    /// [`Self::evaluate`] and the IDE per-member [`Self::evaluate_ide_member`].
    fn eval_with_key(
        &self,
        key: &str,
        input: serde_json::Value,
    ) -> (Result<bool, String>, Option<PolicyEvidence>) {
        let engines = self
            .opa_engines
            .read()
            .expect("pipe opa_engines lock poisoned");

        // Extract the redacted caller/HTTP/workload summary from the policy
        // input before it is consumed by evaluation.
        let input_ctx = policy_audit::extract_input_context(&input);

        if let Some(set) = engines.get(key) {
            // The dashboard Surface Logs viewer filters log lines by the
            // literal message substring `[PIPE:{pipe_id}]`; `key` is `pipe_id`,
            // `pipe_id$alias`, or an IDE per-member key `pipe_id#…`, so the raw
            // pipe id is the part before the first `$` or `#`.
            let pipe_id = key
                .split(['$', '#'])
                .next()
                .unwrap_or(key);
            // Deny-overrides: every policy in the set must allow; the first to
            // deny or error decides the request.
            for engine in set {
                let scope = pipe_scope(key, Some(engine.query));
                if engine.log_decisions {
                    // Serialise the input once so the input log line and the
                    // decision log line refer to the exact same payload.
                    let input_json = serde_json::to_string(&input).unwrap_or_else(|_| "<unserialisable>".to_string());
                    info!(
                        key = %key,
                        query = %engine.query,
                        input = %input_json,
                        "[PIPE:{}] OPA input (query={}): {}",
                        pipe_id,
                        engine.query,
                        input_json,
                    );
                }
                match engine
                    .engine
                    .evaluate_query(engine.query, input.clone())
                {
                    Ok(decision) => {
                        if engine.log_decisions {
                            info!(
                                key = %key,
                                allow = decision.allow,
                                reason = ?decision.reason,
                                "[PIPE:{}] OPA decision: allow={} reason={:?}",
                                pipe_id,
                                decision.allow,
                                decision.reason,
                            );
                        }
                        if !decision.allow {
                            warn!(
                                key = %key,
                                reason = ?decision.reason,
                                "[PIPE:{}] OPA policy denied request: {:?}",
                                pipe_id,
                                decision.reason,
                            );
                        }
                        policy_audit::record_decision(
                            scope,
                            PolicyFlow::AccessPoint,
                            if decision.allow {
                                PolicyOutcome::Allow
                            } else {
                                PolicyOutcome::Deny
                            },
                            decision.reason.as_deref(),
                            engine.query,
                            engine
                                .policy_definition_id
                                .as_deref(),
                            engine
                                .policy_version
                                .as_deref(),
                            engine
                                .policy_content_hash
                                .as_deref(),
                            engine.policy_name.as_deref(),
                            Some(pipe_id),
                            Some(key),
                            &input_ctx,
                        );
                        if !decision.allow {
                            return (Ok(false), Some(PolicyEvidence::from(engine)));
                        }
                    }
                    Err(e) => {
                        let msg = log_evaluate_error(pipe_id, key, engine.query, &e);
                        policy_audit::record_decision(
                            scope,
                            PolicyFlow::AccessPoint,
                            PolicyOutcome::Error,
                            Some(&msg),
                            engine.query,
                            engine
                                .policy_definition_id
                                .as_deref(),
                            engine
                                .policy_version
                                .as_deref(),
                            engine
                                .policy_content_hash
                                .as_deref(),
                            engine.policy_name.as_deref(),
                            Some(pipe_id),
                            Some(key),
                            &input_ctx,
                        );
                        return (Err(msg), Some(PolicyEvidence::from(engine)));
                    }
                }
            }
            // Every policy in the set allowed.
            (Ok(true), None)
        } else {
            let pipe_id = key
                .split(['$', '#'])
                .next()
                .unwrap_or(key);
            let error = format!("No compiled OPA engine for OPA-enabled policy key {key}");
            warn!(
                key = %key,
                "[PIPE:{}] {}; denying request (fail-closed)",
                pipe_id,
                error,
            );
            policy_audit::record_decision(
                pipe_scope(key, None),
                PolicyFlow::AccessPoint,
                PolicyOutcome::MissingEngine,
                Some(&error),
                "",
                None,
                None,
                None,
                None,
                Some(pipe_id),
                Some(key),
                &input_ctx,
            );
            (Err(error), None)
        }
    }
}

/// Returns true when `pipe` references `policy_id` in any OPA slot the
/// [`PipePolicyManager`] compiles: the base front-door policy, any variant's
/// resolved policy, or any IDE catalogue member's Model Policy. This is the
/// reverse index from a mutated reusable policy definition back to the runtime
/// engines that embed its Rego — a match means the pipe must be
/// recompiled via [`PipePolicyManager::update_pipe_policy`].
pub fn pipe_references_policy(
    pipe: &PipeConfig,
    policy_id: &str,
) -> bool {
    if pipe
        .opa_policy_definition_ids()
        .iter()
        .any(|id| id == policy_id)
    {
        return true;
    }
    for variant in &pipe.variants {
        if let Ok(resolved) = pipe.resolve_variant(Some(&variant.alias))
            && resolved
                .opa_policy_definition_ids()
                .iter()
                .any(|id| id == policy_id)
        {
            return true;
        }
    }
    if let PipeType::IDECatalog { config } = &pipe.pipe_type
        && config
            .members
            .iter()
            .any(|m| m.opa_policy_definition_id() == Some(policy_id))
    {
        return true;
    }
    false
}

/// Composite engine key for a pipe variant: `pipe_id$alias`. Mirrors the
/// `$alias` route convention so variant engines never collide with the base.
fn variant_key(
    pipe_id: &str,
    alias: &str,
) -> String {
    format!("{pipe_id}${alias}")
}

/// Composite engine key for an IDE Surface per-member **Model Policy**:
/// `{ide_id}#ide-member:{model_id}`. The `#` separator sits outside the
/// `[A-Za-z0-9_-]` pipe-id charset, so a member key never collides with the
/// base (`ide_id`) engine or a `$alias` variant engine.
pub fn ide_member_policy_key(
    ide_id: &str,
    model_id: &str,
) -> String {
    format!("{ide_id}#ide-member:{model_id}")
}

/// Log a Rego evaluation error against the surface Logs tab and return the
/// error unchanged so `evaluate` can propagate it. The dashboard Logs viewer
/// filters by the literal `[PIPE:{pipe_id}]` substring in the message body,
/// so a broken policy (e.g. an undefined variable that causes Regorus to
/// refuse the query) surfaces to the operator instead of a silent deny.
fn log_evaluate_error(
    pipe_id: &str,
    key: &str,
    query: &str,
    err: &str,
) -> String {
    warn!(
        key = %key,
        query = %query,
        error = %err,
        "[PIPE:{}] OPA evaluation error (query={}): {}",
        pipe_id,
        query,
        err,
    );
    err.to_string()
}

impl Default for PipePolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipes::config::{PipeOpaConfig, PipeType};

    fn pipe_with_opa(
        id: &str,
        enabled: bool,
        def_id: Option<&str>,
    ) -> PipeConfig {
        let mut pipe = PipeConfig::new(
            id.to_string(),
            "Test".to_string(),
            PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        );
        pipe.opa_policy = Some(PipeOpaConfig {
            enabled,
            policy_definition_id: def_id.map(|s| s.to_string()),
            policy_definition_ids: Vec::new(),
            log_decisions: false,
        });
        pipe
    }

    #[test]
    fn variant_key_never_collides_with_base_pipe_key() {
        let pid = "pipe-1";
        // A variant engine keys on `pipe_id$alias`, distinct from the bare pipe id.
        assert_eq!(variant_key(pid, "fast"), "pipe-1$fast");
        assert_ne!(variant_key(pid, "fast"), pid);
        // Distinct aliases key distinctly, and neither collides with the base.
        assert_ne!(variant_key(pid, "fast"), variant_key(pid, "slow"));
        // The IDE per-member `#` key is disjoint from both the base and variant keys.
        let member = ide_member_policy_key(pid, "gpt-4o");
        assert_ne!(member, pid);
        assert_ne!(member, variant_key(pid, "fast"));
        // The `$`/`#` separators sit outside the variant-alias grammar, so no
        // alias value can forge a base or member key. See the grammar assertion
        // in `pipe_variants::tests::alias_grammar_forbids_key_separators`.
        assert!(crate::pipes::pipe_variants::PipeVariant::validate_alias("fast$slow").is_err());
    }

    /// A policy that allows only when `input.http.method == "GET"`.
    const METHOD_GATE_POLICY: &str = r#"
package llm.policy
import rego.v1
default allow := false
allow if input.http.method == "GET"
"#;

    /// A policy that gates on caller context: allow only an api_key caller
    /// whose key is named `trusted`.
    const CALLER_GATE_POLICY: &str = r#"
package llm.policy
import rego.v1
default allow := false
allow if {
    input.source_auth.method == "api_key"
    input.source_auth.key_name == "trusted"
}
"#;

    fn load_engine(
        mgr: &PipePolicyManager,
        pipe_id: &str,
        policy: &str,
    ) {
        load_engine_versioned(mgr, pipe_id, policy, "def-1", "v1");
    }

    /// Like [`load_engine`] but with an explicit definition id + version, so a
    /// test can assert the audit record reflects the compiled revision.
    fn load_engine_versioned(
        mgr: &PipePolicyManager,
        pipe_id: &str,
        policy: &str,
        def_id: &str,
        version: &str,
    ) {
        let engine = OpaEngine::new();
        engine
            .load_policy(pipe_id, policy)
            .expect("policy compiles");
        mgr.opa_engines
            .write()
            .unwrap()
            .insert(
                pipe_id.to_string(),
                vec![CompiledPolicy {
                    engine,
                    query: LLM_POLICY_QUERY,
                    log_decisions: false,
                    policy_definition_id: Some(def_id.to_string()),
                    policy_version: Some(version.to_string()),
                    policy_content_hash: None,
                    policy_name: Some("Test Policy".to_string()),
                }],
            );
    }

    use crate::observability::policy_audit::{self, CapturedDecision};

    /// Run `f` while capturing the `policy_audit` decision events it emits.
    fn with_collector<F: FnOnce()>(f: F) -> Vec<CapturedDecision> {
        policy_audit::capture_decisions(f)
    }

    #[test]
    fn eval_records_allow_and_deny_with_policy_version() {
        let mgr = PipePolicyManager::new();
        load_engine_versioned(&mgr, "p-audit", METHOD_GATE_POLICY, "def-42", "2026-08-01T00:00:00Z");

        let decisions = with_collector(|| {
            let allowed = mgr
                .evaluate(
                    "p-audit",
                    None,
                    serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } }),
                )
                .unwrap();
            assert!(allowed);
            let denied = mgr
                .evaluate(
                    "p-audit",
                    None,
                    serde_json::json!({ "http": { "method": "POST", "path": "/x", "headers": {} } }),
                )
                .unwrap();
            assert!(!denied);
        });

        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].scope, "pipe");
        assert_eq!(decisions[0].decision, "allow");
        assert_eq!(
            decisions[0]
                .policy_definition_id
                .as_deref(),
            Some("def-42")
        );
        assert_eq!(
            decisions[0]
                .policy_version
                .as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
        assert_eq!(
            decisions[0]
                .http_method
                .as_deref(),
            Some("GET")
        );
        assert_eq!(decisions[1].decision, "deny");
        assert!(
            decisions[1]
                .deny_reason
                .is_some()
        );
    }

    #[test]
    fn eval_missing_engine_records_fail_closed_pipe_and_ide() {
        let mgr = PipePolicyManager::new();
        let decisions = with_collector(|| {
            mgr.evaluate("gone", None, serde_json::json!({}))
                .expect_err("missing pipe engine should fail closed with an evaluation error");
            mgr.evaluate_ide_member("ide-x", "model-1", serde_json::json!({}))
                .expect_err("missing IDE member engine should fail closed with an evaluation error");
        });
        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].scope, "pipe");
        assert_eq!(decisions[0].decision, "missing_engine");
        assert_eq!(decisions[1].scope, "ide");
        assert_eq!(decisions[1].decision, "missing_engine");
    }

    #[test]
    fn recompiled_definition_updates_recorded_version_stale_case() {
        let mgr = PipePolicyManager::new();
        // Compile v1, evaluate → records v1.
        load_engine_versioned(&mgr, "p-stale", METHOD_GATE_POLICY, "def-1", "v1");
        let d1 = with_collector(|| {
            let _ = mgr.evaluate("p-stale", None, serde_json::json!({ "http": { "method": "GET" } }));
        });
        assert_eq!(
            d1[0]
                .policy_version
                .as_deref(),
            Some("v1")
        );

        // Definition changes and the pipe is recompiled → the next decision must
        // carry the new version, proving stale definitions don't linger in evidence.
        load_engine_versioned(&mgr, "p-stale", METHOD_GATE_POLICY, "def-1", "v2");
        let d2 = with_collector(|| {
            let _ = mgr.evaluate("p-stale", None, serde_json::json!({ "http": { "method": "GET" } }));
        });
        assert_eq!(
            d2[0]
                .policy_version
                .as_deref(),
            Some("v2")
        );
    }

    #[test]
    fn evaluate_allows_when_policy_passes() {
        let mgr = PipePolicyManager::new();
        load_engine(&mgr, "p1", METHOD_GATE_POLICY);
        let input = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });
        assert_eq!(mgr.evaluate("p1", None, input), Ok(true));
    }

    #[test]
    fn evaluate_denies_when_policy_fails() {
        let mgr = PipePolicyManager::new();
        load_engine(&mgr, "p1", METHOD_GATE_POLICY);
        let input = serde_json::json!({ "http": { "method": "POST", "path": "/x", "headers": {} } });
        assert_eq!(mgr.evaluate("p1", None, input), Ok(false));
    }

    #[test]
    fn evaluate_gates_on_caller_identity() {
        let mgr = PipePolicyManager::new();
        load_engine(&mgr, "p1", CALLER_GATE_POLICY);

        let trusted = serde_json::json!({
            "http": { "method": "POST", "path": "/x", "headers": {} },
            "source_auth": { "method": "api_key", "key_name": "trusted" }
        });
        let untrusted = serde_json::json!({
            "http": { "method": "POST", "path": "/x", "headers": {} },
            "source_auth": { "method": "api_key", "key_name": "other" }
        });
        let anonymous = serde_json::json!({
            "http": { "method": "POST", "path": "/x", "headers": {} }
        });

        assert_eq!(mgr.evaluate("p1", None, trusted), Ok(true));
        assert_eq!(mgr.evaluate("p1", None, untrusted), Ok(false));
        assert_eq!(mgr.evaluate("p1", None, anonymous), Ok(false));
    }

    #[test]
    fn evaluate_fails_closed_with_error_when_no_engine() {
        let mgr = PipePolicyManager::new();
        let input = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });
        let error = mgr
            .evaluate("missing", None, input)
            .expect_err("missing engine should surface a policy evaluation error");
        assert!(error.contains("No compiled OPA engine"), "unexpected error: {error}");
    }

    #[test]
    fn evaluate_surfaces_rego_error_for_broken_policy() {
        // An undefined variable causes Regorus to refuse the query at eval
        // time rather than silently making the rule body false. `evaluate`
        // must propagate the error so the operator sees it in the surface
        // Logs tab via `log_evaluate_error`, instead of the caller mapping
        // a silent deny to a bare 403.
        let mgr = PipePolicyManager::new();
        let engine = OpaEngine::new();
        let broken = r#"
package llm.policy
default allow := false
allow if token_is_acceptable_login
"#;
        engine
            .load_policy("p-broken", broken)
            .expect("compile succeeds — Regorus rejects at eval time");
        mgr.opa_engines
            .write()
            .unwrap()
            .insert(
                "p-broken".to_string(),
                vec![CompiledPolicy {
                    engine,
                    query: LLM_POLICY_QUERY,
                    log_decisions: false,
                    policy_definition_id: None,
                    policy_version: None,
                    policy_content_hash: None,
                    policy_name: None,
                }],
            );
        let input = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });
        let err = mgr
            .evaluate("p-broken", None, input)
            .expect_err("broken policy surfaces error, not silent deny");
        assert!(err.contains("token_is_acceptable_login"), "expected undefined-variable error, got: {err}");
    }

    #[test]
    fn eval_error_records_error_outcome() {
        // A broken policy (undefined variable) surfaces as an `error` outcome in
        // the audit evidence, distinct from a policy-driven deny.
        let mgr = PipePolicyManager::new();
        let engine = OpaEngine::new();
        let broken = "package llm.policy\ndefault allow := false\nallow if token_is_acceptable_login\n";
        engine
            .load_policy("p-broken", broken)
            .expect("compile succeeds — Regorus rejects at eval time");
        mgr.opa_engines
            .write()
            .unwrap()
            .insert(
                "p-broken".to_string(),
                vec![CompiledPolicy {
                    engine,
                    query: LLM_POLICY_QUERY,
                    log_decisions: false,
                    policy_definition_id: Some("def-broken".to_string()),
                    policy_version: Some("v9".to_string()),
                    policy_content_hash: None,
                    policy_name: None,
                }],
            );
        let decisions = with_collector(|| {
            let _ = mgr.evaluate("p-broken", None, serde_json::json!({ "http": { "method": "GET" } }));
        });
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].scope, "pipe");
        assert_eq!(decisions[0].decision, "error");
        assert!(
            decisions[0]
                .deny_reason
                .is_some()
        );
        assert_eq!(
            decisions[0]
                .policy_version
                .as_deref(),
            Some("v9")
        );
    }

    #[tokio::test]
    async fn update_removes_engine_when_disabled() {
        let mgr = PipePolicyManager::new();
        load_engine(&mgr, "p1", METHOD_GATE_POLICY);
        assert!(mgr.has_policy("p1"));

        let pipe = pipe_with_opa("p1", false, Some("def"));
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("update ok");
        assert!(!mgr.has_policy("p1"));
    }

    #[tokio::test]
    async fn update_removes_engine_when_no_definition_id() {
        let mgr = PipePolicyManager::new();
        load_engine(&mgr, "p1", METHOD_GATE_POLICY);
        assert!(mgr.has_policy("p1"));

        let pipe = pipe_with_opa("p1", true, None);
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("update ok");
        assert!(!mgr.has_policy("p1"));
    }

    #[tokio::test]
    async fn update_without_store_skips_compile() {
        let mgr = PipePolicyManager::new();
        let pipe = pipe_with_opa("p1", true, Some("def"));
        // No policy_definition_store set — compile is skipped, engine absent.
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("update ok");
        assert!(!mgr.has_policy("p1"));
    }

    #[test]
    fn remove_pipe_is_idempotent() {
        let mgr = PipePolicyManager::new();
        mgr.remove_pipe("nope");
        load_engine(&mgr, "p1", METHOD_GATE_POLICY);
        mgr.remove_pipe("p1");
        assert!(!mgr.has_policy("p1"));
    }

    #[tokio::test]
    async fn multi_policy_set_denies_when_any_denies() {
        use crate::policies::FileSystemPolicyDefinitionStore;
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        for (id, body) in [("allow", ALLOW_ALL_LLM), ("deny", DENY_ALL_LLM)] {
            store
                .save(PolicyDefinition {
                    id: id.to_string(),
                    name: id.to_string(),
                    description: String::new(),
                    policy_type: PolicyType::Llm,
                    policy: body.to_string(),
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

        let mgr = PipePolicyManager::new();
        mgr.set_policy_definition_store(Arc::new(store));

        // Set [allow, deny] → deny-overrides denies.
        let mut pipe = pipe_with_opa("p1", true, Some("allow"));
        if let Some(opa) = pipe.opa_policy.as_mut() {
            opa.policy_definition_ids = vec!["deny".to_string()];
        }
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("compile set");

        // A single allow policy still allows.
        let allow_only = pipe_with_opa("p2", true, Some("allow"));
        mgr.update_pipe_policy(&allow_only)
            .await
            .expect("compile single");

        let input = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });
        let input2 = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });
        // Evaluate under the capture path so these emissions register the
        // `policy_audit` callsites as observed rather than poisoning the
        // process-global interest cache for concurrent capture-based tests.
        with_collector(|| {
            assert_eq!(mgr.evaluate("p1", None, input), Ok(false), "one deny denies the whole set");
            assert_eq!(mgr.evaluate("p2", None, input2), Ok(true), "single allow policy allows");
            // The denial names the *deciding* policy (the second, which denied),
            // not the first in the set.
            let input3 = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });
            let (decision, evidence) = mgr.evaluate_with_evidence("p1", None, input3);
            assert_eq!(decision, Ok(false));
            let evidence = evidence.expect("deciding evidence");
            assert_eq!(
                evidence
                    .definition_id
                    .as_deref(),
                Some("deny")
            );
            assert_eq!(evidence.name.as_deref(), Some("deny"), "the evidence names the deciding policy");
        });
    }

    #[tokio::test]
    async fn global_policy_deny_overrides_monitor_only_and_fail_closed() {
        use crate::policies::FileSystemPolicyDefinitionStore;
        use crate::policies::GlobalPolicyAssignments;
        use crate::policies::global_policy::GlobalAssignment;
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        for (id, body) in [("allow", ALLOW_ALL_LLM), ("deny", DENY_ALL_LLM)] {
            store
                .save(PolicyDefinition {
                    id: id.to_string(),
                    name: id.to_string(),
                    description: String::new(),
                    policy_type: PolicyType::Llm,
                    policy: body.to_string(),
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
        let mgr = PipePolicyManager::new();
        mgr.set_policy_definition_store(Arc::new(store));

        // No global assignments → nothing enforced.
        assert!(!mgr.has_global("llm"));

        let assign = |policy_id: &str, monitor_only: bool| {
            let mut a = GlobalPolicyAssignments::default();
            a.assignments.insert(
                "llm".to_string(),
                vec![GlobalAssignment {
                    policy_id: policy_id.to_string(),
                    monitor_only,
                }],
            );
            a
        };
        let get_input = || serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });

        // Enforced global deny → has_global + evaluate_global denies.
        mgr.refresh_global(&assign("deny", false))
            .await
            .expect("refresh");
        assert!(mgr.has_global("llm"));
        with_collector(|| {
            assert_eq!(
                mgr.evaluate_global("llm", get_input())
                    .0,
                Ok(false)
            );
        });

        // Monitor-only deny → evaluated + recorded but never blocks.
        mgr.refresh_global(&assign("deny", true))
            .await
            .expect("refresh monitor");
        with_collector(|| {
            assert_eq!(
                mgr.evaluate_global("llm", get_input())
                    .0,
                Ok(true),
                "monitor-only never blocks"
            );
        });

        // A missing enforced global fails closed for the whole type.
        mgr.refresh_global(&assign("nope", false))
            .await
            .expect("refresh broken");
        assert!(mgr.has_global("llm"));
        with_collector(|| {
            assert_eq!(
                mgr.evaluate_global("llm", get_input())
                    .0,
                Ok(false),
                "missing enforced global denies"
            );
        });

        // Clearing assignments removes global enforcement.
        mgr.refresh_global(&GlobalPolicyAssignments::default())
            .await
            .expect("refresh clear");
        assert!(!mgr.has_global("llm"));
    }

    #[tokio::test]
    async fn appliance_global_uses_gateway_query_path() {
        use crate::policies::FileSystemPolicyDefinitionStore;
        use crate::policies::GlobalPolicyAssignments;
        use crate::policies::global_policy::GlobalAssignment;
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        for (id, body) in [
            ("gw-allow", "package agentstream.policy\ndefault allow = true"),
            ("gw-deny", "package agentstream.policy\ndefault allow = false"),
        ] {
            store
                .save(PolicyDefinition {
                    id: id.to_string(),
                    name: id.to_string(),
                    description: String::new(),
                    policy_type: PolicyType::Appliance,
                    policy: body.to_string(),
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
        let mgr = PipePolicyManager::new();
        mgr.set_policy_definition_store(Arc::new(store));

        let assign = |policy_id: &str| {
            let mut a = GlobalPolicyAssignments::default();
            a.assignments.insert(
                "appliance".to_string(),
                vec![GlobalAssignment {
                    policy_id: policy_id.to_string(),
                    monitor_only: false,
                }],
            );
            a
        };
        let get_input = || serde_json::json!({ "gateway": { "direction": "inbound" } });

        // An appliance-wide allow-all resolves via `data.agentstream.policy.allow`
        // (a wrong query path would yield no value → deny), proving the mapping.
        mgr.refresh_global(&assign("gw-allow"))
            .await
            .expect("refresh allow");
        assert!(mgr.has_global("appliance"));
        with_collector(|| {
            assert_eq!(
                mgr.evaluate_global("appliance", get_input())
                    .0,
                Ok(true)
            );
        });

        // And an appliance-wide deny blocks.
        mgr.refresh_global(&assign("gw-deny"))
            .await
            .expect("refresh deny");
        with_collector(|| {
            assert_eq!(
                mgr.evaluate_global("appliance", get_input())
                    .0,
                Ok(false)
            );
        });
    }

    /// An IDE-scoped per-member policy (`package ide.policy`) allowing only GET.
    const IDE_MEMBER_GATE_POLICY: &str = r#"
package ide.policy
import rego.v1
default allow := false
allow if input.http.method == "GET"
"#;

    fn load_member_engine(
        mgr: &PipePolicyManager,
        ide_id: &str,
        model_id: &str,
        policy: &str,
    ) {
        let key = ide_member_policy_key(ide_id, model_id);
        let engine = OpaEngine::new();
        engine
            .load_policy(&key, policy)
            .expect("policy compiles");
        mgr.opa_engines
            .write()
            .unwrap()
            .insert(
                key,
                vec![CompiledPolicy {
                    engine,
                    query: IDE_POLICY_QUERY,
                    log_decisions: false,
                    policy_definition_id: None,
                    policy_version: None,
                    policy_content_hash: None,
                    policy_name: None,
                }],
            );
    }

    #[test]
    fn evaluate_ide_member_gates_on_its_own_engine() {
        let mgr = PipePolicyManager::new();
        load_member_engine(&mgr, "ide1", "fast-coder", IDE_MEMBER_GATE_POLICY);
        let allow = serde_json::json!({ "http": { "method": "GET", "path": "/v1/chat/completions", "headers": {} } });
        let deny = serde_json::json!({ "http": { "method": "POST", "path": "/v1/chat/completions", "headers": {} } });
        assert_eq!(mgr.evaluate_ide_member("ide1", "fast-coder", allow), Ok(true));
        assert_eq!(mgr.evaluate_ide_member("ide1", "fast-coder", deny), Ok(false));
    }

    #[test]
    fn evaluate_ide_member_fails_closed_with_error_when_no_engine() {
        let mgr = PipePolicyManager::new();
        let input = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });
        let error = mgr
            .evaluate_ide_member("ide1", "missing-model", input)
            .expect_err("missing member engine should surface a policy evaluation error");
        assert!(error.contains("No compiled OPA engine"), "unexpected error: {error}");
    }

    #[test]
    fn remove_pipe_drops_ide_member_engines() {
        let mgr = PipePolicyManager::new();
        // Base front-door engine + a per-member engine, both owned by `ide1`.
        load_engine(&mgr, "ide1", METHOD_GATE_POLICY);
        load_member_engine(&mgr, "ide1", "fast-coder", IDE_MEMBER_GATE_POLICY);
        let member_key = ide_member_policy_key("ide1", "fast-coder");
        assert!(mgr.has_policy("ide1"));
        assert!(
            mgr.opa_engines
                .read()
                .unwrap()
                .contains_key(&member_key)
        );

        mgr.remove_pipe("ide1");

        assert!(!mgr.has_policy("ide1"));
        assert!(
            !mgr.opa_engines
                .read()
                .unwrap()
                .contains_key(&member_key),
            "remove_pipe must drop the per-member engine too"
        );
    }

    #[tokio::test]
    async fn update_compiles_from_definition_store_then_evaluates() {
        use crate::policies::FileSystemPolicyDefinitionStore;
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        store
            .save(PolicyDefinition {
                id: "def-method".to_string(),
                name: "Method gate".to_string(),
                description: String::new(),
                policy_type: PolicyType::Llm,
                policy: METHOD_GATE_POLICY.to_string(),
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

        let mgr = PipePolicyManager::new();
        mgr.set_policy_definition_store(Arc::new(store));

        let pipe = pipe_with_opa("p1", true, Some("def-method"));
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("compile");
        assert!(mgr.has_policy("p1"));

        let allow = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });
        let deny = serde_json::json!({ "http": { "method": "POST", "path": "/x", "headers": {} } });
        assert_eq!(mgr.evaluate("p1", None, allow), Ok(true));
        assert_eq!(mgr.evaluate("p1", None, deny), Ok(false));
    }

    #[tokio::test]
    async fn update_compiles_per_variant_policies() {
        use crate::pipes::config::PipeOpaConfig;
        use crate::pipes::pipe_variants::{PipeVariant, PipeVariantOverrides};
        use crate::policies::FileSystemPolicyDefinitionStore;
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        for (id, body) in [("def-method", METHOD_GATE_POLICY), ("def-caller", CALLER_GATE_POLICY)] {
            store
                .save(PolicyDefinition {
                    id: id.to_string(),
                    name: id.to_string(),
                    description: String::new(),
                    policy_type: PolicyType::Llm,
                    policy: body.to_string(),
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

        let mgr = PipePolicyManager::new();
        mgr.set_policy_definition_store(Arc::new(store));

        // Base gates on HTTP method; the `secure` variant swaps in a caller gate.
        let mut pipe = pipe_with_opa("p1", true, Some("def-method"));
        pipe.variants = vec![PipeVariant {
            id: "v1".to_string(),
            alias: "secure".to_string(),
            name: "Secure".to_string(),
            description: String::new(),
            enabled: true,
            overrides: PipeVariantOverrides {
                complete: true,
                opa_policy: Some(PipeOpaConfig {
                    enabled: true,
                    policy_definition_id: Some("def-caller".to_string()),
                    policy_definition_ids: Vec::new(),
                    log_decisions: false,
                }),
                ..Default::default()
            },
        }];

        mgr.update_pipe_policy(&pipe)
            .await
            .expect("compile");

        // Base policy (method gate) is evaluated under the bare pipe id.
        assert!(mgr.has_policy("p1"));
        let get = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });
        let post = serde_json::json!({ "http": { "method": "POST", "path": "/x", "headers": {} } });
        assert_eq!(mgr.evaluate("p1", None, get.clone()), Ok(true));
        assert_eq!(mgr.evaluate("p1", None, post.clone()), Ok(false));

        // Variant policy (caller gate) is evaluated under the `secure` alias and
        // is independent of the base method gate.
        let trusted = serde_json::json!({
            "http": { "method": "POST", "path": "/x", "headers": {} },
            "source_auth": { "method": "api_key", "key_name": "trusted" }
        });
        assert_eq!(mgr.evaluate("p1", Some("secure"), trusted), Ok(true));
        assert_eq!(mgr.evaluate("p1", Some("secure"), post), Ok(false));

        // Removing the pipe drops both the base and variant engines.
        mgr.remove_pipe("p1");
        assert!(!mgr.has_policy("p1"));
        assert!(
            mgr.evaluate("p1", Some("secure"), get)
                .is_err()
        );
    }

    #[tokio::test]
    async fn update_removes_engine_when_definition_missing() {
        use crate::policies::FileSystemPolicyDefinitionStore;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");

        let mgr = PipePolicyManager::new();
        load_engine(&mgr, "p1", METHOD_GATE_POLICY);
        mgr.set_policy_definition_store(Arc::new(store));

        // Pipe references a definition id that does not exist in the store.
        let pipe = pipe_with_opa("p1", true, Some("ghost"));
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("update ok");
        assert!(!mgr.has_policy("p1"));
    }

    #[test]
    fn policy_query_selects_path_by_surface_type() {
        assert_eq!(
            policy_query_for(&PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            }),
            LLM_POLICY_QUERY
        );
        assert_eq!(
            policy_query_for(&PipeType::IDECatalog {
                config: crate::pipes::catalog::IdeCatalogConfig::default(),
            }),
            IDE_POLICY_QUERY
        );
    }

    /// An LLM Surface policy authored as `package ide.policy` must NOT be
    /// honoured — the LLM query path is `data.llm.policy.allow`, so a mismatched
    /// package fails closed (deny), and vice-versa. This pins the split.
    #[tokio::test]
    async fn ide_and_llm_query_paths_are_distinct() {
        use crate::policies::FileSystemPolicyDefinitionStore;
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

        const IDE_ALLOW: &str = r#"
package ide.policy
import rego.v1
default allow := false
allow if input.http.method == "GET"
"#;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        // One IDE policy (package ide.policy) and one LLM policy (package llm.policy).
        store
            .save(PolicyDefinition {
                id: "def-ide".to_string(),
                name: "IDE gate".to_string(),
                description: String::new(),
                policy_type: PolicyType::Ide,
                policy: IDE_ALLOW.to_string(),
                enabled: true,
                created_at: "2026-06-07T00:00:00Z".to_string(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
                tenant_id: None,
            })
            .await
            .expect("save ide def");
        store
            .save(PolicyDefinition {
                id: "def-llm".to_string(),
                name: "LLM gate".to_string(),
                description: String::new(),
                policy_type: PolicyType::Llm,
                policy: METHOD_GATE_POLICY.to_string(),
                enabled: true,
                created_at: "2026-06-07T00:00:00Z".to_string(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
                tenant_id: None,
            })
            .await
            .expect("save llm def");

        let mgr = PipePolicyManager::new();
        mgr.set_policy_definition_store(Arc::new(store));

        let get = serde_json::json!({ "http": { "method": "GET", "path": "/x", "headers": {} } });

        // IDE surface compiled with the ide.policy package evaluates against the
        // ide query path and allows the GET.
        let mut ide_pipe = pipe_with_opa("ide1", true, Some("def-ide"));
        ide_pipe.pipe_type = PipeType::IDECatalog {
            config: crate::pipes::catalog::IdeCatalogConfig::default(),
        };
        mgr.update_pipe_policy(&ide_pipe)
            .await
            .expect("compile ide");
        assert_eq!(mgr.evaluate("ide1", None, get.clone()), Ok(true));

        // The same ide.policy body compiled on an LLM (API) surface never
        // matches the llm.policy query path, so it is never allowed — the
        // handler gates on `matches!(evaluate(..), Ok(true))`, so a mismatched
        // package (undefined query) fails closed (deny).
        let llm_with_ide_body = pipe_with_opa("llm-bad", true, Some("def-ide"));
        mgr.update_pipe_policy(&llm_with_ide_body)
            .await
            .expect("compile llm-bad");
        assert!(!matches!(mgr.evaluate("llm-bad", None, get.clone()), Ok(true)));

        // A correctly-authored llm.policy body on an LLM surface allows the GET.
        let llm_ok = pipe_with_opa("llm-ok", true, Some("def-llm"));
        mgr.update_pipe_policy(&llm_ok)
            .await
            .expect("compile llm-ok");
        assert_eq!(mgr.evaluate("llm-ok", None, get), Ok(true));
    }

    // ── Reusable-definition mutation must reach live engines ──────

    const ALLOW_ALL_LLM: &str = "package llm.policy\nimport rego.v1\ndefault allow := true";
    const DENY_ALL_LLM: &str = "package llm.policy\nimport rego.v1\ndefault allow := false";

    async fn store_with(
        dir: &tempfile::TempDir,
        body: &str,
        enabled: bool,
    ) -> Arc<crate::policies::FileSystemPolicyDefinitionStore> {
        use crate::policies::FileSystemPolicyDefinitionStore;
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        store
            .save(PolicyDefinition {
                id: "def".to_string(),
                name: "def".to_string(),
                description: String::new(),
                policy_type: PolicyType::Llm,
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
            .expect("save def");
        Arc::new(store)
    }

    async fn resave(
        store: &crate::policies::FileSystemPolicyDefinitionStore,
        body: &str,
        enabled: bool,
    ) {
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};
        store
            .save(PolicyDefinition {
                id: "def".to_string(),
                name: "def".to_string(),
                description: String::new(),
                policy_type: PolicyType::Llm,
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
            .expect("resave def");
    }

    /// Core acceptance: changing an allow policy to deny takes effect
    /// immediately for an already-registered pipe, with no pipe edit or restart
    /// — the recompile is the only action (what the CRUD fan-out performs).
    #[tokio::test]
    async fn definition_update_takes_effect_on_registered_pipe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with(&dir, ALLOW_ALL_LLM, true).await;
        let mgr = PipePolicyManager::new();
        mgr.set_policy_definition_store(store.clone());

        let pipe = pipe_with_opa("p1", true, Some("def"));
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("compile");
        let input = serde_json::json!({ "http": { "method": "POST" } });
        assert_eq!(mgr.evaluate("p1", None, input.clone()), Ok(true), "allow-all before update");

        // Operator edits the shared definition to deny-all; recompile the
        // already-registered pipe only (no pipe config change).
        resave(&store, DENY_ALL_LLM, true).await;
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("recompile");
        assert_eq!(mgr.evaluate("p1", None, input), Ok(false), "deny takes effect immediately");
    }

    /// Disabling a definition (enabled=false) evicts the compiled engine, so an
    /// OPA-enabled pipe fails closed (deny) rather than keeping the old allow.
    #[tokio::test]
    async fn disabling_definition_evicts_engine_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with(&dir, ALLOW_ALL_LLM, true).await;
        let mgr = PipePolicyManager::new();
        mgr.set_policy_definition_store(store.clone());

        let pipe = pipe_with_opa("p1", true, Some("def"));
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("compile");
        assert!(mgr.has_policy("p1"));

        resave(&store, ALLOW_ALL_LLM, false).await; // same body, now disabled
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("recompile");
        assert!(!mgr.has_policy("p1"), "disabled definition evicts the engine");
        mgr.evaluate("p1", None, serde_json::json!({}))
            .expect_err("disabled definition should fail closed with an evaluation error");
    }

    /// A recompile that fails to compile (invalid Rego) must not leave the old
    /// permissive engine active — it evicts and fails closed.
    #[tokio::test]
    async fn invalid_rego_recompile_evicts_engine_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with(&dir, ALLOW_ALL_LLM, true).await;
        let mgr = PipePolicyManager::new();
        mgr.set_policy_definition_store(store.clone());

        let pipe = pipe_with_opa("p1", true, Some("def"));
        mgr.update_pipe_policy(&pipe)
            .await
            .expect("compile");
        assert_eq!(mgr.evaluate("p1", None, serde_json::json!({})), Ok(true));

        resave(&store, "package llm.policy\nthis is not valid rego {{{", true).await;
        assert!(
            mgr.update_pipe_policy(&pipe)
                .await
                .is_err(),
            "invalid Rego recompile should error"
        );
        assert!(!mgr.has_policy("p1"), "bad recompile evicts the stale engine");
        mgr.evaluate("p1", None, serde_json::json!({}))
            .expect_err("bad recompile should fail closed with an evaluation error");
    }

    /// The reverse index detects a policy id referenced by the base front-door,
    /// a variant override, or an IDE catalogue member's Model Policy.
    #[test]
    fn pipe_references_policy_detects_all_slots() {
        use crate::pipes::catalog::{IdeCatalogConfig, IdeCatalogMember};
        use crate::pipes::pipe_variants::{PipeVariant, PipeVariantOverrides};

        // Only `pipe_id` is required; every other member field has a serde default.
        let member: IdeCatalogMember =
            serde_json::from_value(serde_json::json!({ "pipe_id": "m1", "opa_policy_id": "def-member" }))
                .expect("member");

        // Base front-door reference.
        let base = pipe_with_opa("p1", true, Some("def-base"));
        assert!(pipe_references_policy(&base, "def-base"));
        assert!(!pipe_references_policy(&base, "nope"));

        // Variant override reference.
        let mut with_variant = pipe_with_opa("p2", true, Some("def-base"));
        with_variant.variants = vec![PipeVariant {
            id: "v1".to_string(),
            alias: "secure".to_string(),
            name: "Secure".to_string(),
            description: String::new(),
            enabled: true,
            overrides: PipeVariantOverrides {
                complete: true,
                opa_policy: Some(PipeOpaConfig {
                    enabled: true,
                    policy_definition_id: Some("def-variant".to_string()),
                    policy_definition_ids: Vec::new(),
                    log_decisions: false,
                }),
                ..Default::default()
            },
        }];
        assert!(pipe_references_policy(&with_variant, "def-variant"));

        // IDE catalogue member Model Policy reference.
        let ide = PipeConfig::new(
            "ide1".to_string(),
            "IDE".to_string(),
            PipeType::IDECatalog {
                config: IdeCatalogConfig {
                    members: vec![member],
                    ..Default::default()
                },
            },
        );
        assert!(pipe_references_policy(&ide, "def-member"));
        assert!(!pipe_references_policy(&ide, "def-base"));
    }
}
