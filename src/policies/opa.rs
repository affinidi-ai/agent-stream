use regorus::Engine;
use regorus::utils::limits::{ExecutionTimerConfig, PolicyLengthConfig};
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing::info;

const MAX_POLICY_BYTES: usize = 128 * 1024;
const MAX_POLICY_LINES: usize = 4_000;
const MAX_POLICY_COLUMNS: u32 = 4_096;
const MAX_POLICY_INPUT_BYTES: usize = 256 * 1024;
const POLICY_EVALUATION_LIMIT: Duration = Duration::from_millis(100);
const POLICY_TIMER_CHECK_INTERVAL: u32 = 128;
const MAX_CONCURRENT_POLICY_COMPILATIONS: usize = 4;
const MAX_CONCURRENT_POLICY_EVALUATIONS: usize = 32;
static ACTIVE_POLICY_COMPILATIONS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_POLICY_EVALUATIONS: AtomicUsize = AtomicUsize::new(0);

struct ResourcePermit<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for ResourcePermit<'_> {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, Ordering::Release);
    }
}

fn try_acquire_resource<'a>(
    counter: &'a AtomicUsize,
    limit: usize,
    resource: &str,
) -> Result<ResourcePermit<'a>, String> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| (active < limit).then_some(active + 1))
        .map(|_| ResourcePermit { counter })
        .map_err(|active| format!("{resource} capacity is exhausted ({active}/{limit})"))
}

fn configured_engine() -> Engine {
    let mut engine = Engine::new();
    engine.set_policy_length_config(PolicyLengthConfig {
        max_col: NonZeroU32::new(MAX_POLICY_COLUMNS).expect("policy column limit must be non-zero"),
        max_file_bytes: NonZeroUsize::new(MAX_POLICY_BYTES).expect("policy byte limit must be non-zero"),
        max_lines: NonZeroUsize::new(MAX_POLICY_LINES).expect("policy line limit must be non-zero"),
    });
    engine.set_execution_timer_config(ExecutionTimerConfig {
        limit: POLICY_EVALUATION_LIMIT,
        check_interval: NonZeroU32::new(POLICY_TIMER_CHECK_INTERVAL).expect("timer interval must be non-zero"),
    });
    engine.set_gather_prints(true);
    engine
}

fn policy_code_without_literals_or_comments(
    policy: &str,
    keep_whitespace: bool,
) -> String {
    let mut code = String::with_capacity(policy.len());
    let chars = policy.chars();
    let mut quoted = false;
    let mut raw = false;
    let mut escaped = false;
    let mut comment = false;

    for ch in chars {
        if comment {
            if ch == '\n' {
                comment = false;
            }
            continue;
        }
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            code.push(' ');
            continue;
        }
        if raw {
            if ch == '`' {
                raw = false;
            }
            code.push(' ');
            continue;
        }
        match ch {
            '#' => comment = true,
            '"' => {
                quoted = true;
                code.push(' ');
            }
            '`' => {
                raw = true;
                code.push(' ');
            }
            _ if ch.is_whitespace() && !keep_whitespace => {}
            _ => code.push(ch),
        }
    }
    code
}

/// Policy input fields that no request ever carries. A rule reading one never
/// matches, so a policy meant to gate on it would silently do nothing.
const UNPOPULATED_INPUTS: &[&str] = &["input.mcp", "input.metadata", "input.resource.tool", "input.resource.route"];

static BRACKET_FIELD: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r#"\[\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\]"#).expect("bracket field pattern compiles")
});

static SPACED_DOT: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\s*\.\s*").expect("dot pattern compiles"));

/// Refuse a policy that reads an input field no request carries
/// ([`UNPOPULATED_INPUTS`]), in dot or bracket form. Run when a policy is
/// saved or checked in the editor, not when a stored policy is loaded, so a
/// policy saved before this check keeps loading as it did.
pub fn validate_policy_inputs(policy: &str) -> Result<(), String> {
    let dotted = BRACKET_FIELD.replace_all(policy, ".$1");
    let code = SPACED_DOT
        .replace_all(&policy_code_without_literals_or_comments(&dotted, true), ".")
        .into_owned();
    for field in UNPOPULATED_INPUTS {
        let reads_field = code
            .match_indices(field)
            .any(|(at, _)| {
                let before = code[..at].chars().next_back();
                let after = code[at + field.len()..]
                    .chars()
                    .next();
                !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.')
                    && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
            });
        if reads_field {
            return Err(format!(
                "policy reads `{field}`, which no request carries, so a rule using it would never match"
            ));
        }
    }
    Ok(())
}

fn validate_policy_source(policy: &str) -> Result<(), String> {
    if policy.len() > MAX_POLICY_BYTES {
        return Err(format!("policy source exceeds the {} byte limit", MAX_POLICY_BYTES));
    }
    if policy.lines().count() > MAX_POLICY_LINES {
        return Err(format!("policy source exceeds the {} line limit", MAX_POLICY_LINES));
    }

    let code = policy_code_without_literals_or_comments(policy, false);
    for (builtin, reason) in [
        ("numbers.range(", "can allocate an attacker-sized collection"),
        ("http.send(", "host network access is not available to policies"),
        ("opa.runtime(", "runtime metadata is not available to policies"),
        ("print(", "policy-authored output is not permitted"),
    ] {
        if code.contains(builtin) {
            return Err(format!("policy builtin `{builtin}` is not permitted: {reason}"));
        }
    }
    Ok(())
}

/// OPA policy engine for evaluating Rego policies.
///
/// ## Performance
///
/// The policy is compiled once via `load_policy()` and stored as a template engine.
/// On each evaluation, the template is **cloned** (cheap with regorus `arc` feature —
/// internal data uses `Arc`) and evaluated on the owned clone. This eliminates all
/// lock contention: concurrent requests evaluate in parallel with zero synchronization.
///
/// Uses `eval_allow_query()` (faster than `eval_query()` for boolean decisions) and
/// `set_input_json()` (avoids intermediate `serde_json::Value` allocation).
pub struct OpaEngine {
    engine: RwLock<Engine>,
}

/// Policy evaluation decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether the request is allowed
    pub allow: bool,

    /// Reason for the decision (if denied)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OpaEngine {
    /// Create a new OPA engine
    pub fn new() -> Self {
        Self {
            engine: RwLock::new(configured_engine()),
        }
    }

    /// Load a Rego policy from a string.
    /// The policy is compiled and stored as a template for fast clone-per-eval.
    pub fn load_policy(
        &self,
        policy_name: &str,
        policy_content: &str,
    ) -> Result<(), String> {
        let mut engine = self
            .engine
            .write()
            .expect("OpaEngine lock poisoned");

        validate_policy_source(policy_content)?;
        let _permit = try_acquire_resource(
            &ACTIVE_POLICY_COMPILATIONS,
            MAX_CONCURRENT_POLICY_COMPILATIONS,
            "Policy compilation",
        )?;

        // Clear previous policies while retaining the configured admission and
        // execution limits on the replacement engine.
        *engine = configured_engine();

        // Add the policy (compiles it)
        engine
            .add_policy(policy_name.to_string(), policy_content.to_string())
            .map_err(|e| format!("Failed to add policy: {}", e))?;

        info!("Loaded OPA policy: {}", policy_name);
        Ok(())
    }

    /// Clone the internal engine template for evaluation.
    /// The read lock is held only long enough to clone (cheap Arc bump).
    fn clone_engine(&self) -> Engine {
        self.engine
            .read()
            .expect("OpaEngine lock poisoned")
            .clone()
    }

    /// Evaluate a surface-scoped policy against input data.
    /// Uses the canonical surface query path [`super::SURFACE_POLICY_QUERY`]
    /// (`data.surface.policy.allow`; renamed from the legacy `channel.policy`).
    /// Clones the template and evaluates on the clone — fully
    /// concurrent, no lock held.
    pub fn evaluate(
        &self,
        input: serde_json::Value,
    ) -> Result<PolicyDecision, String> {
        self.evaluate_query(super::SURFACE_POLICY_QUERY, input)
    }

    /// Evaluate a specific query path against input data.
    /// Clones the template and evaluates on the clone — fully concurrent.
    ///
    /// The engine also reads a companion reason rule from the same policy
    /// package (derived from `query` by replacing the trailing `.allow`
    /// with `.allow_reason` or `.deny_reason`) and surfaces it as
    /// [`PolicyDecision::reason`]. This lets a policy author supply a
    /// human-readable message alongside `allow` — e.g.
    ///
    /// ```rego
    /// package llm.policy
    /// default allow = false
    /// allow if { input.source_auth.claims.role == "admin" }
    /// allow_reason := "Admin bypass" if allow
    /// deny_reason := "Only admin callers may use this surface" if not allow
    /// ```
    ///
    /// The reason flows straight into surface OPA logs and any downstream
    /// observability. On an allow with no `allow_reason` rule defined,
    /// `reason` stays `None`. On a deny with no `deny_reason` rule defined,
    /// the fixed fallback `"Policy denied request"` is used instead.
    pub fn evaluate_query(
        &self,
        query: &str,
        input: serde_json::Value,
    ) -> Result<PolicyDecision, String> {
        let input_json = serde_json::to_string(&input).map_err(|e| format!("Failed to serialize input: {}", e))?;
        if input_json.len() > MAX_POLICY_INPUT_BYTES {
            return Err(format!("Policy input exceeds the {} byte limit", MAX_POLICY_INPUT_BYTES));
        }
        let _permit =
            try_acquire_resource(&ACTIVE_POLICY_EVALUATIONS, MAX_CONCURRENT_POLICY_EVALUATIONS, "Policy evaluation")?;
        let mut engine = self.clone_engine();

        engine
            .set_input_json(&input_json)
            .map_err(|e| format!("Failed to set input: {}", e))?;

        match engine.eval_bool_query(query.to_string(), false) {
            Ok(true) => Ok(PolicyDecision {
                allow: true,
                reason: read_reason(&mut engine, allow_reason_path(query)),
            }),
            Ok(false) => {
                let reason = read_reason(&mut engine, deny_reason_path(query))
                    .unwrap_or_else(|| "Policy denied request".to_string());
                Ok(PolicyDecision {
                    allow: false,
                    reason: Some(reason),
                })
            }
            // Undefined `allow` (the query produced no value): the module does
            // not declare the expected `package`, or omits a `default allow`.
            // That is a policy misconfiguration, not a system error: fail
            // closed with an actionable reason. Keyed on the Regorus
            // "no value" marker (see [`super::REGORUS_QUERY_NO_VALUE_MARKER`]
            // for the version-coupling note).
            Err(e)
                if e.to_string()
                    .contains(super::REGORUS_QUERY_NO_VALUE_MARKER) =>
            {
                Ok(PolicyDecision {
                    allow: false,
                    reason: Some(format!(
                        "Policy produced no `allow` decision for query '{}'; the module must declare the expected package and define `allow` (e.g. `default allow = false`)",
                        query
                    )),
                })
            }
            Err(e) => Err(format!("Failed to evaluate query '{}': {}", query, e)),
        }
    }
}

/// Derive the companion `deny_reason` rule path from an `.allow` query.
///
/// `data.llm.policy.allow` → `Some("data.llm.policy.deny_reason")`.
/// A query that does not end in `.allow` returns `None` so the engine falls
/// back to the fixed generic deny reason.
fn deny_reason_path(query: &str) -> Option<String> {
    query
        .strip_suffix(".allow")
        .map(|base| format!("{base}.deny_reason"))
}

/// Derive the companion `allow_reason` rule path from an `.allow` query.
///
/// `data.llm.policy.allow` → `Some("data.llm.policy.allow_reason")`.
/// A query that does not end in `.allow` returns `None`; on an allow with
/// no derived path (or no rule defined) the decision's `reason` stays
/// `None`.
fn allow_reason_path(query: &str) -> Option<String> {
    query
        .strip_suffix(".allow")
        .map(|base| format!("{base}.allow_reason"))
}

/// Look up a string reason rule at `path` and coerce it to `String`.
/// Returns `None` when the path is absent, the rule is undefined, or the
/// value is not a string.
fn read_reason(
    engine: &mut Engine,
    path: Option<String>,
) -> Option<String> {
    path.and_then(|p| engine.eval_rule(p).ok())
        .and_then(|value| {
            value
                .as_string()
                .ok()
                .map(|s| s.to_string())
        })
}

impl Default for OpaEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_permit_rejects_excess_and_releases_capacity() {
        let active = AtomicUsize::new(0);
        let permit = try_acquire_resource(&active, 1, "test").unwrap();
        assert!(try_acquire_resource(&active, 1, "test").is_err());
        drop(permit);
        assert!(try_acquire_resource(&active, 1, "test").is_ok());
    }

    #[test]
    fn load_policy_rejects_oversized_source() {
        let engine = OpaEngine::new();
        let policy = format!("package llm.policy\ndefault allow = false\n#{}\nallow := true\n", "x".repeat(128 * 1024));

        let error = engine
            .load_policy("oversized", &policy)
            .expect_err("oversized policies must be rejected before compilation");
        assert!(error.contains("policy source exceeds"), "unexpected error: {error}");
    }

    #[test]
    fn load_policy_rejects_unbounded_range_builtin() {
        let engine = OpaEngine::new();
        let policy = r#"
package llm.policy

default allow = false
allow if { count(numbers.range(1, 1000000)) > 0 }
"#;

        let error = engine
            .load_policy("range", policy)
            .expect_err("unbounded allocation builtins must be rejected");
        assert!(error.contains("numbers.range"), "unexpected error: {error}");
    }

    #[test]
    fn load_policy_rejects_builtin_with_comment_before_call() {
        let engine = OpaEngine::new();
        let policy = r#"
package llm.policy

default allow = false
allow if {
    count(numbers.range # comment hides the call from naive substring matching
    (1, 1000000)) > 0
}
"#;

        let error = engine
            .load_policy("commented_range", policy)
            .expect_err("comments must not bypass unsafe builtin admission");
        assert!(error.contains("numbers.range"), "unexpected error: {error}");
    }

    #[test]
    fn load_policy_rejects_host_capability_and_output_builtins() {
        let engine = OpaEngine::new();
        for (name, expression) in [
            ("http", "http.send({\"method\": \"get\", \"url\": \"https://example.test\"})"),
            ("runtime", "opa.runtime()"),
            ("print", "print(input)"),
        ] {
            let policy = format!("package llm.policy\ndefault allow = false\nallow if {{ {expression} }}");
            assert!(
                engine
                    .load_policy(name, &policy)
                    .is_err(),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn unknown_host_io_builtin_fails_closed() {
        let engine = OpaEngine::new();
        let policy = "package llm.policy\ndefault allow = false\nallow if { os.exec(\"id\") }";
        match engine.load_policy("host_io", policy) {
            Err(_) => {}
            Ok(()) => assert!(
                engine
                    .evaluate_query("data.llm.policy.allow", serde_json::json!({}))
                    .is_err()
            ),
        }
    }

    #[test]
    fn builtin_names_inside_comments_and_strings_are_not_rejected() {
        let engine = OpaEngine::new();
        let policy = r#"
package llm.policy
# numbers.range(1, 1000000)
default allow = false
allow if { input.message == "print(http.send(opa.runtime()))" }
"#;
        engine
            .load_policy("literal", policy)
            .expect("comments and strings are not executable builtins");
    }

    #[test]
    fn a_policy_reading_an_input_no_request_carries_is_refused() {
        for (policy, field) in [
            ("deny if input.mcp.tool_name == \"delete_repo\"", "input.mcp"),
            ("deny if { input . mcp . method == \"tools/call\" }", "input.mcp"),
            ("deny if input[\"mcp\"][\"tool_name\"] == \"x\"", "input.mcp"),
            ("deny if input.metadata.team == \"x\"", "input.metadata"),
            ("deny if input.resource.tool == \"x\"", "input.resource.tool"),
            ("deny if input.resource[\"route\"] == \"/admin\"", "input.resource.route"),
            ("deny if { m := input.mcp; m.tool_name == \"x\" }", "input.mcp"),
        ] {
            let err = validate_policy_inputs(&format!("package llm.policy\n{policy}")).unwrap_err();
            assert!(err.contains(&format!("`{field}`")), "{policy}: {err}");
        }
    }

    #[test]
    fn populated_inputs_and_mentions_in_comments_or_strings_are_accepted() {
        let policy = r#"
package llm.policy
# input.mcp is never populated
default allow := false
allow if {
    input.resource.model == "gpt-4o"
    input.resource.server_tools[_] == "web_search"
    input.resource.tools_allowed
    input.mcpx == "input.mcp"
    input.request.metadata_tag == "x"
    x.input.mcp == 1
}
"#;
        validate_policy_inputs(policy).expect("no unpopulated input is read");
    }

    #[test]
    fn a_stored_policy_reading_an_unpopulated_input_still_loads() {
        OpaEngine::new()
            .load_policy("stored", "package llm.policy\ndefault allow := true\ndeny if input.mcp.tool_name == \"x\"")
            .expect("loading is unchanged, so an upgrade does not stop a stored policy loading");
    }

    #[test]
    fn oversized_policy_input_is_rejected_before_evaluation() {
        let engine = OpaEngine::new();
        engine
            .load_policy("input", "package llm.policy\ndefault allow = true")
            .unwrap();
        let error = engine
            .evaluate_query("data.llm.policy.allow", serde_json::json!({"value": "x".repeat(MAX_POLICY_INPUT_BYTES)}))
            .expect_err("oversized input must be rejected");
        assert!(error.contains("input exceeds"), "unexpected error: {error}");
    }

    #[test]
    fn expensive_comprehension_stops_at_execution_deadline() {
        let engine = OpaEngine::new();
        let policy = r#"
package llm.policy

default allow = false
allow if {
    pairs := [[x, y] |
        some x in input.values
        some y in input.values
    ]
    count(pairs) > 0
}
"#;
        engine
            .load_policy("expensive", policy)
            .unwrap();
        let started = std::time::Instant::now();
        let error = engine
            .evaluate_query("data.llm.policy.allow", serde_json::json!({"values": (0..1000).collect::<Vec<_>>() }))
            .expect_err("expensive evaluation must hit its deadline");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            error
                .to_lowercase()
                .contains("time limit"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn recursive_policy_terminates_as_an_error() {
        let engine = OpaEngine::new();
        engine
            .load_policy("recursive", "package llm.policy\ndefault allow = false\nallow if { allow }")
            .unwrap();
        let started = std::time::Instant::now();
        assert!(
            engine
                .evaluate_query("data.llm.policy.allow", serde_json::json!({}))
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_opa_basic_allow() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let input = serde_json::json!({
            "mcp": {
                "method": "tools/call",
                "tool_name": "echo"
            }
        });

        let decision = engine
            .evaluate(input)
            .unwrap();
        assert!(decision.allow);
    }

    #[test]
    fn test_opa_basic_deny() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let input = serde_json::json!({
            "mcp": {
                "method": "tools/call",
                "tool_name": "restricted"
            }
        });

        let decision = engine
            .evaluate(input)
            .unwrap();
        assert!(!decision.allow);
        // A policy that does not define `deny_reason` falls back to the fixed
        // generic string.
        assert_eq!(decision.reason.as_deref(), Some("Policy denied request"));
    }

    #[test]
    fn test_opa_source_auth_claims() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.source_auth.method == "jwt_bearer"
    input.source_auth.claims.role == "admin"
    input.mcp.method == "tools/call"
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let input = serde_json::json!({
            "mcp": {
                "method": "tools/call",
                "tool_name": "restricted_tool"
            },
            "source_auth": {
                "method": "jwt_bearer",
                "subject": "admin-user",
                "claims": { "role": "admin" }
            }
        });

        let decision = engine
            .evaluate(input)
            .unwrap();
        assert!(decision.allow);
    }

    #[test]
    fn test_opa_source_auth_deny_wrong_role() {
        let engine = OpaEngine::new();

        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.source_auth.method == "jwt_bearer"
    input.source_auth.claims.role == "admin"
}
"#;

        engine
            .load_policy("test", policy)
            .unwrap();

        let input = serde_json::json!({
            "source_auth": {
                "method": "jwt_bearer",
                "subject": "user-1",
                "claims": { "role": "viewer" }
            }
        });

        let decision = engine
            .evaluate(input)
            .unwrap();
        assert!(!decision.allow);
    }

    #[test]
    fn test_opa_allow_has_no_reason() {
        let engine = OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.role == "admin"
}
"#;
        engine
            .load_policy("test", policy)
            .unwrap();

        let decision = engine
            .evaluate(serde_json::json!({ "role": "admin" }))
            .unwrap();
        assert!(decision.allow);
        // No `allow_reason` rule defined — `reason` stays `None`.
        assert!(decision.reason.is_none());
    }

    #[test]
    fn test_opa_allow_reason_from_policy() {
        // Mirror of `test_opa_deny_reason_from_policy` — an operator-authored
        // `allow_reason` string rule in the same package as `allow` surfaces
        // through [`PolicyDecision::reason`] on the allow branch, so surface
        // OPA logs can explain *why* a request was allowed (e.g. the IDE
        // discovery bypass in `data.ide.policy`).
        let engine = OpaEngine::new();
        let policy = r#"
package ide.policy

default allow := false

allow if input.request.purpose == "discovery"

allow_reason := "Discovery is allowed" if {
    input.request.purpose == "discovery"
}
"#;
        engine
            .load_policy("test", policy)
            .unwrap();

        let decision = engine
            .evaluate_query("data.ide.policy.allow", serde_json::json!({ "request": { "purpose": "discovery" } }))
            .unwrap();
        assert!(decision.allow);
        assert_eq!(decision.reason.as_deref(), Some("Discovery is allowed"));
    }

    #[test]
    fn test_opa_deny_reason_from_policy() {
        let engine = OpaEngine::new();
        let policy = r#"
package surface.policy

default allow = false

allow if {
    input.role == "admin"
}

deny_reason := sprintf("Role '%s' is not permitted", [input.role]) if {
    not allow
}
"#;
        engine
            .load_policy("test", policy)
            .unwrap();

        let decision = engine
            .evaluate(serde_json::json!({ "role": "viewer" }))
            .unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason.as_deref(), Some("Role 'viewer' is not permitted"));
    }

    #[test]
    fn test_opa_deny_reason_flows_through_per_layer_query() {
        // Each per-layer query path (`data.llm.policy.allow`,
        // `data.ide.policy.allow`, `data.agentstream.policy.allow`) must
        // resolve the sibling `deny_reason` rule from the *same* package,
        // because [`deny_reason_path`] derives the base by stripping
        // `.allow` from the query. Exercise the LLM Surface layer.
        let engine = OpaEngine::new();
        let policy = r#"
package llm.policy

default allow = false

deny_reason := "LLM surface access denied for this caller"
"#;
        engine
            .load_policy("test", policy)
            .unwrap();

        let decision = engine
            .evaluate_query("data.llm.policy.allow", serde_json::json!({}))
            .unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason.as_deref(), Some("LLM surface access denied for this caller"));
    }

    #[test]
    fn test_opa_undefined_allow_fails_closed_with_actionable_reason() {
        // Policy declares the wrong package for the queried layer — Regorus
        // resolves the query to no value and returns an error containing
        // [`super::REGORUS_QUERY_NO_VALUE_MARKER`]. The engine translates
        // that into an actionable fail-closed deny rather than an opaque
        // engine error.
        let engine = OpaEngine::new();
        let policy = r#"
package unrelated.namespace

allow := true
"#;
        engine
            .load_policy("test", policy)
            .unwrap();

        let decision = engine
            .evaluate_query("data.llm.policy.allow", serde_json::json!({}))
            .unwrap();
        assert!(!decision.allow);
        let reason = decision
            .reason
            .expect("expected an actionable reason on undefined allow");
        assert!(reason.contains("data.llm.policy.allow"), "reason should mention the failing query, got: {reason}");
    }

    #[test]
    fn regorus_no_value_marker_matches_live_error() {
        // Canary: the [`super::REGORUS_QUERY_NO_VALUE_MARKER`] constant is
        // coupled to the pinned Regorus version's error wording. If a
        // Regorus upgrade rewords "did not produce any values", this test
        // breaks first and points straight at the constant.
        use regorus::Engine;
        let mut engine = Engine::new();
        engine
            .add_policy("canary".to_string(), "package unrelated.namespace\nallow := true".to_string())
            .unwrap();
        engine
            .set_input_json("{}")
            .unwrap();
        let err = engine
            .eval_bool_query("data.llm.policy.allow".to_string(), false)
            .expect_err("querying an undefined rule should error");
        assert!(
            err.to_string()
                .contains(super::super::REGORUS_QUERY_NO_VALUE_MARKER),
            "Regorus error wording changed; update REGORUS_QUERY_NO_VALUE_MARKER. Got: {err}"
        );
    }

    #[test]
    fn deny_reason_path_derives_sibling_from_allow_query() {
        assert_eq!(super::deny_reason_path("data.llm.policy.allow").as_deref(), Some("data.llm.policy.deny_reason"));
        assert_eq!(super::deny_reason_path("data.ide.policy.allow").as_deref(), Some("data.ide.policy.deny_reason"));
        assert_eq!(
            super::deny_reason_path("data.agentstream.policy.allow").as_deref(),
            Some("data.agentstream.policy.deny_reason")
        );
        assert_eq!(
            super::deny_reason_path("data.channel.policy.allow").as_deref(),
            Some("data.channel.policy.deny_reason")
        );
        // A query that does not end in `.allow` yields no sibling path.
        assert_eq!(super::deny_reason_path("data.llm.policy.something"), None);
    }

    #[test]
    fn allow_reason_path_derives_sibling_from_allow_query() {
        assert_eq!(super::allow_reason_path("data.llm.policy.allow").as_deref(), Some("data.llm.policy.allow_reason"));
        assert_eq!(super::allow_reason_path("data.ide.policy.allow").as_deref(), Some("data.ide.policy.allow_reason"));
        // A query that does not end in `.allow` yields no sibling path.
        assert_eq!(super::allow_reason_path("data.llm.policy.something"), None);
    }
}
