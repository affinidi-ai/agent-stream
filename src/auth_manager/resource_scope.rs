//! Resource-scope patterns for management access tokens (PATs).
//!
//! A scoped PAT's non-empty resource pattern has the canonical form
//! `TENANT:${header}:<resource-kind>:<resource-id-pattern>`. Authorization matches
//! that anchored pattern against a typed target built from the validated tenant
//! header and the managed resource's logical identifier.
//!
//! The pattern may embed `${header-name}` placeholders that are substituted, at
//! request time, with the value of a **required header** the token also declares.
//! Each required header is validated against its own anchored regex on every call
//! the token makes; a missing or invalid header rejects the request. A tenant
//! selector must resolve to one literal value unless the bootstrap configuration
//! declares an authenticated edge that strips and replaces that header.
//!
//! ## Security model
//!
//! - Every compiled regex (header validators and the effective resource pattern)
//!   is **fully anchored** (`\A(?:…)\z`) so a prefix pattern cannot be satisfied
//!   by an identifier that merely contains it.
//! - A caller-supplied header value is **regex-escaped** before substitution, so
//!   even if a lax validator admitted metacharacters they are matched literally —
//!   defence in depth on top of the (operator-authored, strict) validator.
//! - The `regex` crate is a finite automaton (linear-time, no catastrophic
//!   backtracking); source lengths and the compiled program size are additionally
//!   capped to bound work and memory.
//! - Compilation of a stored token's scope that fails (should never happen — it is
//!   validated at write time) makes the token **fail closed** (unusable), never
//!   silently unscoped.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use axum::http::{HeaderMap, HeaderValue};
use dashmap::DashMap;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// Max characters in an operator-authored resource pattern.
pub const MAX_PATTERN_LEN: usize = 512;
/// Max characters in a required-header validation pattern.
pub const MAX_HEADER_PATTERN_LEN: usize = 256;
/// Max characters in a required-header name.
pub const MAX_HEADER_NAME_LEN: usize = 64;
/// Max characters accepted in a presented header value.
pub const MAX_HEADER_VALUE_LEN: usize = 512;
/// Max number of required headers per token.
pub const MAX_REQUIRED_HEADERS: usize = 8;
/// Cap on distinct compiled effective patterns cached per token (bounds memory
/// against a caller that cycles through many distinct valid header values).
const MAX_EFFECTIVE_CACHE: usize = 512;
/// Compiled-program size cap (defensive; the crate is already linear-time).
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// A request header a token requires, plus the regex its value must satisfy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequiredHeader {
    /// Header name (case-insensitive; ASCII letters, digits, and `-`).
    pub name: String,
    /// Validation regex for the header value. Enforced anchored.
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSelector {
    pub header_name: String,
    pub broad: bool,
}

pub fn selector_is_broad(raw_pattern: &str) -> bool {
    use regex_syntax::hir::literal::Extractor;

    if raw_pattern.trim().is_empty() {
        return true;
    }

    let Ok(hir) = regex_syntax::parse(raw_pattern) else {
        return true;
    };
    let sequence = Extractor::new()
        .limit_literal_len(MAX_HEADER_PATTERN_LEN)
        .extract(&hir);
    match sequence.literals() {
        Some([only]) => !only.is_exact() || only.as_bytes().is_empty(),
        _ => true,
    }
}

/// Matches a `${header-name}` placeholder within a resource pattern.
static PLACEHOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Za-z0-9_-]+)\}").expect("valid placeholder regex"));

#[derive(Debug, Clone)]
enum Segment {
    /// Operator-authored regex fragment, used verbatim.
    Literal(String),
    /// A required-header reference (lowercased name); substituted, escaped, at eval.
    Placeholder(String),
}

struct HeaderValidator {
    name_lower: String,
    display_name: String,
    regex: Regex,
}

/// A token's resource scope, compiled once and reused across requests. Holds the
/// anchored header validators, the parsed pattern segments, and a bounded cache of
/// effective compiled patterns keyed by the tuple of presented header values.
pub struct CompiledResourceScope {
    has_pattern: bool,
    segments: Vec<Segment>,
    validators: Vec<HeaderValidator>,
    cache: DashMap<Vec<String>, Arc<Regex>>,
}

pub struct CompiledCanonicalResourceScope {
    scope: CompiledResourceScope,
    tenant_header: Option<String>,
    tenant_selector: Option<TenantSelector>,
}

pub struct CanonicalScopeEvaluation {
    pub pattern: Option<Arc<Regex>>,
    pub tenant_id: Option<String>,
}

/// Why a request failed the resource-scope header gate. All map to `403`.
#[derive(Debug)]
pub enum ScopeRejection {
    /// A required header was absent (or present more than once).
    MissingHeader(String),
    /// A required header value failed its validation regex (or was unreadable).
    InvalidHeader(String),
    /// Effective-pattern compilation failed at request time (fail closed).
    Internal,
}

impl ScopeRejection {
    /// A caller-safe message. Deliberately does not echo the header value.
    pub fn message(&self) -> String {
        match self {
            ScopeRejection::MissingHeader(h) | ScopeRejection::InvalidHeader(h) => {
                format!("required header '{h}' is missing or invalid")
            }
            ScopeRejection::Internal => "resource scope could not be evaluated".to_string(),
        }
    }
}

fn compile_anchored(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(&format!(r"\A(?:{pattern})\z"))
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| e.to_string())
}

fn validate_header_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_HEADER_NAME_LEN {
        return Err(format!("header name '{name}' has an invalid length (1..={MAX_HEADER_NAME_LEN})"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(format!("header name '{name}' has invalid characters (allowed: A-Z a-z 0-9 -)"));
    }
    Ok(())
}

fn parse_segments(template: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut last = 0;
    for caps in PLACEHOLDER_RE.captures_iter(template) {
        let whole = caps
            .get(0)
            .expect("group 0 always present");
        if whole.start() > last {
            segments.push(Segment::Literal(template[last..whole.start()].to_string()));
        }
        let name = caps
            .get(1)
            .expect("group 1 in placeholder regex")
            .as_str()
            .to_ascii_lowercase();
        segments.push(Segment::Placeholder(name));
        last = whole.end();
    }
    if last < template.len() {
        segments.push(Segment::Literal(template[last..].to_string()));
    }
    segments
}

/// Concatenate segments, substituting each placeholder with the regex-escaped
/// value from `values` (missing values contribute nothing — an empty literal).
fn build_effective(
    segments: &[Segment],
    values: &HashMap<String, String>,
) -> String {
    let mut out = String::new();
    for seg in segments {
        match seg {
            Segment::Literal(s) => out.push_str(s),
            Segment::Placeholder(name) => {
                if let Some(v) = values.get(name) {
                    out.push_str(&regex::escape(v));
                }
            }
        }
    }
    out
}

fn split_top_level_alternatives(selector: &str) -> Vec<&str> {
    let mut alternatives = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut in_class = false;
    let mut escaped = false;

    for (index, character) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => depth = depth.saturating_sub(1),
            '|' if !in_class && depth == 0 => {
                alternatives.push(&selector[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    alternatives.push(&selector[start..]);
    alternatives
}

fn outer_noncapturing_group(selector: &str) -> Option<&str> {
    if !selector.starts_with("(?:") {
        return None;
    }
    let mut depth = 0usize;
    let mut in_class = false;
    let mut escaped = false;

    for (index, character) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return (index + character.len_utf8() == selector.len()).then_some(&selector[3..index]);
                }
            }
            _ => {}
        }
    }
    None
}

fn branch_has_known_resource_kind(branch: &str) -> bool {
    let Some((kind, _resource_pattern)) = branch.split_once(':') else {
        return false;
    };
    crate::tenancy::ResourceKind::from_path_family(kind).is_some_and(|parsed| parsed.as_str() == kind)
}

fn canonical_tenant_header(segments: &[Segment]) -> Result<String, String> {
    let (tenant_header, selector) = match segments {
        [Segment::Literal(prefix), Segment::Placeholder(header), Segment::Literal(suffix)]
            if prefix == "TENANT:" && suffix.starts_with(':') =>
        {
            (header.clone(), &suffix[1..])
        }
        _ => {
            return Err("non-empty resource pattern must use TENANT:${header}:<resource-kind>:<resource-id-pattern>"
                .to_string());
        }
    };
    if selector.is_empty() {
        return Err("resource pattern must include a bounded resource selector".to_string());
    }

    let alternatives = if let Some(body) = outer_noncapturing_group(selector) {
        split_top_level_alternatives(body)
    } else {
        let alternatives = split_top_level_alternatives(selector);
        if alternatives.len() != 1 {
            return Err("multiple resource selectors must be wrapped in a single noncapturing group".to_string());
        }
        alternatives
    };
    if alternatives
        .iter()
        .any(|branch| branch.is_empty() || !branch_has_known_resource_kind(branch))
    {
        return Err("every resource selector must start with a known resource kind followed by ':'".to_string());
    }
    Ok(tenant_header)
}

/// Compile a token's resource-scope spec. Returns an error string suitable for a
/// `400` at write time; the same routine builds the runtime scope so a stored
/// token that cannot compile fails closed.
pub fn compile(
    pattern: Option<&str>,
    headers: &[RequiredHeader],
) -> Result<CompiledResourceScope, String> {
    if headers.len() > MAX_REQUIRED_HEADERS {
        return Err(format!("too many required headers (max {MAX_REQUIRED_HEADERS})"));
    }

    let mut validators = Vec::with_capacity(headers.len());
    let mut seen: HashSet<String> = HashSet::new();
    for h in headers {
        let name = h.name.trim();
        validate_header_name(name)?;
        let name_lower = name.to_ascii_lowercase();
        if !seen.insert(name_lower.clone()) {
            return Err(format!("duplicate required header '{name}'"));
        }
        if h.pattern.is_empty() {
            return Err(format!("required header '{name}' must declare a validation pattern"));
        }
        if h.pattern.len() > MAX_HEADER_PATTERN_LEN {
            return Err(format!("required header '{name}' pattern is too long (max {MAX_HEADER_PATTERN_LEN})"));
        }
        let regex = compile_anchored(&h.pattern)
            .map_err(|e| format!("required header '{name}' has an invalid pattern: {e}"))?;
        validators.push(HeaderValidator {
            name_lower,
            display_name: name.to_string(),
            regex,
        });
    }

    let (has_pattern, segments) = match pattern.map(str::trim) {
        Some(p) if !p.is_empty() => {
            if p.len() > MAX_PATTERN_LEN {
                return Err(format!("resource pattern is too long (max {MAX_PATTERN_LEN})"));
            }
            let segments = parse_segments(p);
            for seg in &segments {
                if let Segment::Placeholder(name_lower) = seg
                    && !validators
                        .iter()
                        .any(|v| &v.name_lower == name_lower)
                {
                    return Err(format!("resource pattern references undeclared header '${{{name_lower}}}'"));
                }
            }
            // Confirm the surrounding regex compiles once placeholders are replaced
            // by a benign literal (the real value is likewise escaped to a literal).
            let sample: HashMap<String, String> = validators
                .iter()
                .map(|v| (v.name_lower.clone(), "x".to_string()))
                .collect();
            compile_anchored(&build_effective(&segments, &sample))
                .map_err(|e| format!("invalid resource pattern: {e}"))?;
            (true, segments)
        }
        _ => (false, Vec::new()),
    };

    Ok(CompiledResourceScope {
        has_pattern,
        segments,
        validators,
        cache: DashMap::new(),
    })
}

pub fn compile_canonical(
    pattern: Option<&str>,
    headers: &[RequiredHeader],
) -> Result<CompiledCanonicalResourceScope, String> {
    let scope = compile(pattern, headers)?;
    let tenant_header = match pattern.map(str::trim) {
        Some(pattern) if !pattern.is_empty() => Some(canonical_tenant_header(&parse_segments(pattern))?),
        _ => None,
    };
    let tenant_selector = tenant_header
        .as_ref()
        .map(|header_name| {
            headers
                .iter()
                .find(|header| {
                    header
                        .name
                        .eq_ignore_ascii_case(header_name)
                })
                .map(|header| TenantSelector {
                    header_name: header.name.clone(),
                    broad: selector_is_broad(&header.pattern),
                })
                .ok_or_else(|| format!("tenant selector references undeclared header '${{{header_name}}}'"))
        })
        .transpose()?;
    Ok(CompiledCanonicalResourceScope {
        scope,
        tenant_header,
        tenant_selector,
    })
}

/// Validate a spec without retaining the compiled result (for write-time checks).
pub fn validate(
    pattern: Option<&str>,
    headers: &[RequiredHeader],
) -> Result<(), String> {
    compile(pattern, headers).map(|_| ())
}

pub fn validate_canonical(
    pattern: Option<&str>,
    headers: &[RequiredHeader],
) -> Result<(), String> {
    compile_canonical(pattern, headers).map(|_| ())
}

/// Patterns that compile fine but confine nothing, so a required header
/// declaring one enforces no useful request gate.
const DISALLOWED_HEADER_PATTERNS: &[&str] = &[".*", ".+", "^.*$", "^.+$", r"\A.*\z", r"\A.+\z"];

/// Reject a required-header pattern too permissive to provide a useful request
/// gate (e.g. `.*`). Tenant selectors that admit multiple values are subject to
/// the separate trusted-edge provenance check at write and authentication time.
pub fn assert_min_strictness(headers: &[RequiredHeader]) -> Result<(), String> {
    for h in headers {
        let normalized = h.pattern.trim();
        if DISALLOWED_HEADER_PATTERNS.contains(&normalized) || normalized.len() < 2 {
            return Err(format!(
                "required header '{}' pattern is too permissive for tenant isolation; use a strict format (e.g. \\d{{12}})",
                h.name
            ));
        }
    }
    Ok(())
}

impl CompiledResourceScope {
    /// Run the header gate and, if a pattern is present, resolve the effective
    /// anchored regex for this request. `Ok(None)` means "headers valid, no ID
    /// pattern to enforce".
    pub fn evaluate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<Arc<Regex>>, ScopeRejection> {
        // Validate every required header (the gate applies to every call). When a
        // pattern is present, collect the values in validator order to key the cache.
        let mut key: Vec<String> = Vec::with_capacity(self.validators.len());
        for v in &self.validators {
            let mut present = headers
                .get_all(v.name_lower.as_str())
                .iter();
            let first: Option<&HeaderValue> = present.next();
            let Some(raw) = first else {
                return Err(ScopeRejection::MissingHeader(v.display_name.clone()));
            };
            if present.next().is_some() {
                // Ambiguous: the same header supplied more than once.
                return Err(ScopeRejection::InvalidHeader(v.display_name.clone()));
            }
            let value = raw
                .to_str()
                .map_err(|_| ScopeRejection::InvalidHeader(v.display_name.clone()))?;
            if value.len() > MAX_HEADER_VALUE_LEN || !v.regex.is_match(value) {
                return Err(ScopeRejection::InvalidHeader(v.display_name.clone()));
            }
            if self.has_pattern {
                key.push(value.to_string());
            }
        }

        if !self.has_pattern {
            return Ok(None);
        }

        // Hot path: a warm account hits the cache and skips both the name→value
        // map allocation and the regex compilation below.
        if let Some(existing) = self.cache.get(&key) {
            return Ok(Some(existing.clone()));
        }
        let values: HashMap<String, String> = self
            .validators
            .iter()
            .map(|v| v.name_lower.clone())
            .zip(key.iter().cloned())
            .collect();
        let effective = build_effective(&self.segments, &values);
        let regex = compile_anchored(&effective).map_err(|_| ScopeRejection::Internal)?;
        let arc = Arc::new(regex);
        if self.cache.len() < MAX_EFFECTIVE_CACHE {
            self.cache
                .insert(key, arc.clone());
        }
        Ok(Some(arc))
    }
}

impl CompiledCanonicalResourceScope {
    pub fn tenant_selector(&self) -> Option<&TenantSelector> {
        self.tenant_selector.as_ref()
    }

    pub fn evaluate(
        &self,
        headers: &HeaderMap,
    ) -> Result<CanonicalScopeEvaluation, ScopeRejection> {
        let pattern = self.scope.evaluate(headers)?;
        let tenant_id = self
            .tenant_header
            .as_ref()
            .map(|header| {
                let tenant_id = headers
                    .get(header)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
                    .ok_or_else(|| ScopeRejection::InvalidHeader(header.clone()))?;
                crate::tenancy::validate_tenant_id(&tenant_id)
                    .map_err(|_| ScopeRejection::InvalidHeader(header.clone()))?;
                Ok(tenant_id)
            })
            .transpose()?;
        Ok(CanonicalScopeEvaluation { pattern, tenant_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn header(
        name: &str,
        pattern: &str,
    ) -> RequiredHeader {
        RequiredHeader {
            name: name.into(),
            pattern: pattern.into(),
        }
    }

    #[test]
    fn static_pattern_is_anchored() {
        let scope = compile(Some("TENANT:.*"), &[]).unwrap();
        let re = scope
            .evaluate(&HeaderMap::new())
            .unwrap()
            .unwrap();
        assert!(re.is_match("TENANT:abc"));
        assert!(!re.is_match("EVIL:TENANT:abc"), "prefix must not be satisfied by a containing string");
        assert!(!re.is_match("TENANT:abc\nx"), "trailing content must not match");
    }

    #[test]
    fn header_interpolation_scopes_per_value() {
        let scope =
            compile(Some("TENANT:${x-external-account}:.*"), &[header("x-external-account", r"\d{12}")]).unwrap();
        let re = scope
            .evaluate(&headers(&[("x-external-account", "123456789012")]))
            .unwrap()
            .unwrap();
        assert!(re.is_match("TENANT:123456789012:db-password"));
        assert!(!re.is_match("TENANT:999999999999:db-password"), "another account's namespace must not match");
    }

    #[test]
    fn missing_or_invalid_header_is_rejected() {
        let scope =
            compile(Some("TENANT:${x-external-account}:.*"), &[header("x-external-account", r"\d{12}")]).unwrap();
        assert!(matches!(scope.evaluate(&HeaderMap::new()), Err(ScopeRejection::MissingHeader(_))));
        assert!(matches!(
            scope.evaluate(&headers(&[("x-external-account", "abc")])),
            Err(ScopeRejection::InvalidHeader(_))
        ));
        assert!(
            matches!(
                scope.evaluate(&headers(&[("x-external-account", "1234567890123")])),
                Err(ScopeRejection::InvalidHeader(_))
            ),
            "13 digits must fail the anchored \\d{{12}} validator"
        );
    }

    #[test]
    fn header_value_is_escaped_against_injection() {
        // A permissive validator that would admit regex metacharacters; escaping
        // must neutralise them so the value matches only literally.
        let scope = compile(Some("TENANT:${acct}:.*"), &[header("acct", r".+")]).unwrap();
        let re = scope
            .evaluate(&headers(&[("acct", ".*")]))
            .unwrap()
            .unwrap();
        assert!(re.is_match("TENANT:.*:x"), "the literal value '.*' is matched literally");
        assert!(!re.is_match("TENANT:anything:x"), "escaped '.*' must not act as a wildcard");
    }

    #[test]
    fn ambiguous_repeated_header_is_rejected() {
        let scope = compile(Some("TENANT:${acct}:.*"), &[header("acct", r"\d+")]).unwrap();
        assert!(matches!(
            scope.evaluate(&headers(&[("acct", "1"), ("acct", "2")])),
            Err(ScopeRejection::InvalidHeader(_))
        ));
    }

    #[test]
    fn header_gate_without_pattern_still_validates() {
        let scope = compile(None, &[header("x-external-account", r"\d{12}")]).unwrap();
        assert!(
            scope
                .evaluate(&headers(&[("x-external-account", "123456789012")]))
                .unwrap()
                .is_none()
        );
        assert!(
            scope
                .evaluate(&HeaderMap::new())
                .is_err()
        );
    }

    #[test]
    fn placeholder_without_declared_header_is_a_config_error() {
        let err = compile(Some("TENANT:${x-external-account}:.*"), &[])
            .err()
            .unwrap();
        assert!(err.contains("undeclared header"), "got: {err}");
    }

    #[test]
    fn malformed_regex_is_rejected() {
        assert!(compile(Some("TENANT:(:.*"), &[]).is_err());
        assert!(compile(None, &[header("h", "(")]).is_err());
    }

    #[test]
    fn duplicate_and_bad_header_names_rejected() {
        assert!(compile(None, &[header("h", r"\d"), header("H", r"\d")]).is_err(), "case-insensitive duplicate");
        assert!(compile(None, &[header("bad name", r"\d")]).is_err(), "space is not allowed");
    }

    #[test]
    fn case_insensitive_header_lookup() {
        let scope = compile(Some("T:${X-External-Account}"), &[header("X-External-Account", r"\d{2}")]).unwrap();
        let re = scope
            .evaluate(&headers(&[("x-external-account", "42")]))
            .unwrap()
            .unwrap();
        assert!(re.is_match("T:42"));
    }

    #[test]
    fn min_strictness_rejects_wildcard_patterns() {
        for weak in [".*", ".+", "^.*$", "^.+$", r"\A.*\z", r"\A.+\z", "x"] {
            assert!(
                assert_min_strictness(&[header("acct", weak)]).is_err(),
                "expected '{weak}' to be rejected as too permissive"
            );
        }
    }

    #[test]
    fn min_strictness_allows_strict_patterns() {
        assert!(assert_min_strictness(&[header("acct", r"\d{12}")]).is_ok());
        assert!(assert_min_strictness(&[]).is_ok(), "no required headers is trivially fine");
    }

    #[test]
    fn min_strictness_is_independent_of_compile() {
        // Compilation handles syntax; write-time and authentication-time
        // posture checks decide whether a compiled selector may be trusted.
        assert!(compile(Some("TENANT:${acct}:.*"), &[header("acct", r".+")]).is_ok());
    }

    #[test]
    fn tenant_selector_classifies_exact_and_broad_patterns() {
        assert!(!selector_is_broad("tenant-a"));
        assert!(!selector_is_broad(r"tenant\.a"));
        assert!(selector_is_broad(r"\d{12}"));
        assert!(selector_is_broad("[a-z0-9-]+"));
        assert!(selector_is_broad("tenant-a|tenant-b"));

        let exact = compile_canonical(Some("TENANT:${account}:pipes:.*"), &[header("account", "tenant-a")]).unwrap();
        assert_eq!(
            exact.tenant_selector(),
            Some(&TenantSelector {
                header_name: "account".into(),
                broad: false,
            })
        );
    }

    #[test]
    fn canonical_scope_infers_tenant_and_matches_typed_resource_target() {
        let scope = compile_canonical(
            Some("TENANT:${account}:(?:pipes:prod-.*|secrets:.*)"),
            &[header("account", r"[a-z0-9-]+")],
        )
        .unwrap();
        let evaluated = scope
            .evaluate(&headers(&[("account", "tenant-a")]))
            .unwrap();
        assert_eq!(evaluated.tenant_id.as_deref(), Some("tenant-a"));
        let pattern = evaluated.pattern.unwrap();
        assert!(pattern.is_match("TENANT:tenant-a:pipes:prod-chat"));
        assert!(pattern.is_match("TENANT:tenant-a:secrets:key"));
        assert!(!pattern.is_match("TENANT:tenant-b:pipes:prod-chat"));
    }

    #[test]
    fn canonical_scope_rejects_invalid_tenant_identifier() {
        let scope = compile_canonical(Some("TENANT:${account}:pipes:.*"), &[header("account", r".+")]).unwrap();

        assert!(matches!(
            scope.evaluate(&headers(&[("account", "tenant/escape")])),
            Err(ScopeRejection::InvalidHeader(_))
        ));
    }

    #[test]
    fn canonical_scope_rejects_legacy_and_unbounded_patterns() {
        let headers = [header("account", r"[a-z0-9-]+")];
        assert!(compile_canonical(None, &[]).is_ok());
        for pattern in [
            ".*",
            "TENANT:.*",
            "TENANT:${account}:.*",
            "TENANT:${account}:unknown-kind:.*",
            "TENANT:${account}:pipes:.*|secrets:.*",
            "TENANT:${account}:${account}:pipes:.*",
        ] {
            assert!(compile_canonical(Some(pattern), &headers).is_err(), "pattern should be rejected: {pattern}");
        }
    }
}
