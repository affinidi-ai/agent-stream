use serde::Serialize;
use std::collections::HashMap;

/// Version of the [`PolicyInput`] contract handed to Rego. Bump when the input
/// shape changes in a way a policy or tool may need to detect. Set by
/// [`PolicyInput::new`] on every enforcement point so a policy sees a
/// consistent, versioned input regardless of which surface produced it.
pub const POLICY_INPUT_SCHEMA_VERSION: u32 = 1;

// ── PolicyInput ────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct PolicyInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<SurfaceRoutingContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<SourceAuthContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_identity: Option<ExtensionIdentityContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_binding: Option<IdentityBindingContext>,

    /// The normalized target of the request (model / tool / route / surface
    /// type), for resource-scoped policies such as "only model X".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceContext>,

    /// The normalized action verb (`dispatch`, `discovery`), consistent across
    /// surface types. Supersedes the IDE-only `request.purpose`, which is kept
    /// as a compatibility alias.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    /// Evaluation-environment attributes (currently the request time), for
    /// time-window policies. Always present.
    pub environment: EnvironmentContext,

    /// Version of this policy-input contract (see [`POLICY_INPUT_SCHEMA_VERSION`]).
    pub schema_version: u32,
}

impl PolicyInput {
    /// Build a `PolicyInput` with HTTP, gateway, and channel context pre-populated.
    ///
    /// Callers set remaining optional fields (`source_auth`, `agent`, `mcp`,
    /// `extension_identity`, `payment`) on the returned value.
    pub fn new(
        method: &str,
        path: &str,
        filtered_headers: HashMap<String, String>,
        direction: &str,
        source_id: Option<String>,
        target_id: Option<String>,
        config_id: Option<String>,
        channel_name: &str,
    ) -> Self {
        Self {
            http: Some(HttpContext {
                method: method.to_string(),
                path: path.to_string(),
                headers: filtered_headers,
            }),
            gateway: Some(GatewayContext {
                direction: direction.to_string(),
                source_id,
                target_id,
            }),
            channel: Some(SurfaceRoutingContext {
                config_id,
                name: Some(channel_name.to_string()),
                variant_alias: None,
            }),
            schema_version: POLICY_INPUT_SCHEMA_VERSION,
            environment: EnvironmentContext {
                now: chrono::Utc::now().to_rfc3339(),
            },
            ..Default::default()
        }
    }
}

/// Header-name substrings that mark a credential. `api-key` and `apikey`
/// cover provider keys a caller may send (`x-api-key`, which the Anthropic
/// ingress takes as the caller's own provider key, `x-goog-api-key`, Azure's
/// `api-key`) and API-key front doors (`x-boris-api-key`).
const SENSITIVE_HEADER_SUBSTRINGS: &[&str] = &["authorization", "cookie", "token", "api-key", "apikey"];

/// Returns `true` if the lowercased header name is sensitive and should be stripped.
fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADER_SUBSTRINGS
        .iter()
        .any(|s| name.contains(s))
}

/// Filter sensitive headers (authorization, cookie, token) from an axum `HeaderMap`.
pub fn filter_sensitive_headers(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(k, _)| !is_sensitive_header(&k.as_str().to_lowercase()))
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.as_str().to_string(), val.to_string()))
        })
        .collect()
}

/// Filter sensitive headers from a JSON header map (used by connection-point message processing).
pub fn filter_sensitive_json_headers(
    headers: Option<&serde_json::Map<String, serde_json::Value>>
) -> HashMap<String, String> {
    headers
        .map(|h| {
            h.iter()
                .filter(|(k, _)| !is_sensitive_header(&k.to_lowercase()))
                .filter_map(|(k, v)| {
                    v.as_str()
                        .map(|val| (k.clone(), val.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── Context types (moved from opa.rs) ──────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct HttpContext {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
}

/// Why the front door is evaluating policy for this request, injected as
/// `input.request.purpose` into Rego. It lets an IDE Surface policy allow
/// unauthenticated **discovery** of the model menu (`GET /v1/models`) while
/// still requiring an authenticated caller for **dispatch**
/// (`POST /v1/chat/completions`) — the client learns how to sign in from the
/// public `.well-known/agent-stream` bootstrap, then signs in on first dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestPurpose {
    /// Reading the surface's published model catalogue (`GET /v1/models`), or
    /// a public discovery document over the fabric (`GET {path}/agent.json`).
    Discovery,
    /// Invoking a model through the surface (`POST /v1/chat/completions`).
    Dispatch,
}

/// Request-intent context injected as `input.request` into Rego.
#[derive(Debug, Clone, Serialize)]
pub struct RequestContext {
    pub purpose: RequestPurpose,

    /// Whether the caller supplied a distinct upstream credential
    /// (`X-Agent-Stream-Upstream-Authorization`) alongside the front-door token.
    /// Exposed as `input.request.forwarded_upstream_auth` so an IDE Surface
    /// policy can require a separate upstream token for certain models without
    /// inspecting the token itself. Defaults to `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forwarded_upstream_auth: bool,
}

/// Resolved agent context injected as `input.agent` into Rego.
/// `trust_verification` is `Some(true)` when all trust registry recognition queries pass,
/// `Some(false)` when any query returns false, and `None` when TR data is unavailable.
#[derive(Debug, Clone, Serialize)]
pub struct AgentContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_verification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_dna: Option<crate::identity::uai::types::AgentDna>,
}

// ── Context types (moved from gateway_manager.rs) ──────────

/// Gateway-level policy context added to `input.gateway` in Rego
#[derive(Debug, Clone, Serialize)]
pub struct GatewayContext {
    /// Traffic direction: "inbound" (self gateway) or "outbound" (remote gateway)
    pub direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
}

/// Channel routing context added to `input.channel` in Rego
#[derive(Debug, Clone, Serialize)]
pub struct SurfaceRoutingContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Surface variant alias selected by the request URL (`/route$alias/...`).
    /// `None` when the request targets the default variant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_alias: Option<String>,
}

// ── New context types ──────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum SourceAuthContext {
    JwtBearer {
        subject: String,
        claims: serde_json::Value,
    },
    ApiKey {
        key_name: String,
    },
    Mtls {
        principal: String,
        fingerprint: String,
        subject_dn: String,
        issuer_dn: String,
        sans: crate::source_auth::models::MtlsSans,
    },
}

impl From<&crate::source_auth::AuthenticatedIdentity> for SourceAuthContext {
    fn from(identity: &crate::source_auth::AuthenticatedIdentity) -> Self {
        use crate::source_auth::AuthenticatedIdentity;
        match identity {
            AuthenticatedIdentity::JwtBearer { subject, claims } => SourceAuthContext::JwtBearer {
                subject: subject.clone(),
                claims: claims.clone(),
            },
            AuthenticatedIdentity::ApiKey { key_name } => SourceAuthContext::ApiKey { key_name: key_name.clone() },
            AuthenticatedIdentity::Mtls {
                principal,
                fingerprint,
                subject_dn,
                issuer_dn,
                sans,
                source: _,
            } => SourceAuthContext::Mtls {
                principal: principal.clone(),
                fingerprint: fingerprint.clone(),
                subject_dn: subject_dn.clone(),
                issuer_dn: issuer_dn.clone(),
                sans: sans.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtensionIdentityContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_hash: Option<String>,
}

/// Verified identity binding from an upstream gateway's request-path VP.
/// Available as `input.identity_binding` in Rego policies.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityBindingContext {
    /// Whether the VP signature was cryptographically verified
    pub verified: bool,
    /// The agent DID (VP holder / subject)
    pub agent_did: String,
    /// The gateway DID that signed the VP (issuer), on the fabric path.
    pub gateway_did: String,
    /// The credential issuer DID, for "known issuer" policy checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    /// The identity fields from the VC inside the VP
    pub identity_fields: HashMap<String, serde_json::Value>,
}

/// Normalized request target injected as `input.resource` into Rego, so a
/// policy can gate on the concrete resource (e.g. a specific model)
/// rather than parsing the request body.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ResourceContext {
    /// Surface type the request targets (`llm`, `ide`, `api`, `mcp`, `webhook`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_type: Option<String>,
    /// Requested model id, when the request names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Requested reasoning effort (`minimal`/`low`/`medium`/`high`) when the
    /// caller asked for reasoning, so a policy can gate expensive reasoning per
    /// caller. `None` when reasoning was not requested (or was disabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    /// Requested reasoning token budget (explicit, or derived from the effort),
    /// after any surface governor cap. `None` when reasoning was not requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_max_tokens: Option<u64>,
    /// Per-request routing preference: the models the caller asked to route
    /// among (`models: [...]`). `None` when not requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_models: Option<Vec<String>>,
    /// Per-request routing preference: the provider types the caller steered
    /// toward (`provider.only`, else `provider.order`). `None` when not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_providers: Option<Vec<String>>,
    /// Governed server tools active on this surface (`web_search`, `web_fetch`),
    /// so a policy can gate Agent Stream-executed tool use per caller. `None` when
    /// none are active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tools: Option<Vec<String>>,
    /// Context transforms the caller requested (`transforms: [...]`, e.g.
    /// `middle-out`), so a policy can gate context compression. `None` when the
    /// request named none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_transforms: Option<Vec<String>>,
    /// Document types attached inline to the request (`text`, `markdown`,
    /// `csv`, `json`, `docx`, `pdf`), so a policy can gate document ingestion
    /// per caller. `None` when the request carries no documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_types: Option<Vec<String>>,
    /// Audio formats attached inline to the request (`wav`, `mp3`, …), so a
    /// policy can gate audio input per caller. `None` when the request carries
    /// no audio.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_formats: Option<Vec<String>>,
    /// Image formats attached inline to the request (`png`, `jpeg`, …, or
    /// `remote` for a URL the gateway cannot inspect), so a policy can gate
    /// image input per caller. `None` when the request carries no images.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_formats: Option<Vec<String>>,
    /// High-level modality of the request when it is not a plain text chat —
    /// e.g. `audio_realtime` for a Mode C realtime voice session — so a policy
    /// can gate the realtime front door distinctly. `None` for a normal request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modality: Option<String>,
}

/// Evaluation-environment attributes injected as `input.environment` into Rego.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EnvironmentContext {
    /// RFC 3339 timestamp at which the request is being evaluated.
    pub now: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn filter_sensitive_headers_strips_authorization() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer secret"
                .parse()
                .unwrap(),
        );
        headers.insert(
            "content-type",
            "application/json"
                .parse()
                .unwrap(),
        );

        let result = filter_sensitive_headers(&headers);

        assert!(!result.contains_key("authorization"));
        assert_eq!(
            result
                .get("content-type")
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn filter_sensitive_headers_strips_cookie_and_token() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "session=abc".parse().unwrap());
        headers.insert("x-csrf-token", "tok123".parse().unwrap());
        headers.insert("x-request-id", "req-1".parse().unwrap());

        let result = filter_sensitive_headers(&headers);

        assert!(!result.contains_key("cookie"));
        assert!(!result.contains_key("x-csrf-token"));
        assert_eq!(
            result
                .get("x-request-id")
                .unwrap(),
            "req-1"
        );
    }

    #[test]
    fn filter_sensitive_headers_strips_api_keys() {
        let mut headers = HeaderMap::new();
        for name in ["x-api-key", "x-boris-api-key", "x-goog-api-key", "api-key", "x-apikey"] {
            headers.insert(name, "sk-secret".parse().unwrap());
        }
        headers.insert("x-request-id", "req-1".parse().unwrap());

        let result = filter_sensitive_headers(&headers);

        assert_eq!(
            result
                .keys()
                .collect::<Vec<_>>(),
            vec!["x-request-id"]
        );

        let json: serde_json::Map<String, serde_json::Value> = [("X-Api-Key".to_string(), "sk-secret".into())]
            .into_iter()
            .collect();
        assert!(filter_sensitive_json_headers(Some(&json)).is_empty());
    }

    #[test]
    fn filter_sensitive_headers_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            "Bearer secret"
                .parse()
                .unwrap(),
        );
        headers.insert("accept", "text/html".parse().unwrap());

        let result = filter_sensitive_headers(&headers);

        assert!(!result.contains_key("authorization"));
        assert_eq!(result.get("accept").unwrap(), "text/html");
    }

    #[test]
    fn filter_sensitive_headers_empty_map() {
        let headers = HeaderMap::new();
        let result = filter_sensitive_headers(&headers);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_sensitive_headers_keeps_all_non_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        headers.insert("accept", "*/*".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());

        let result = filter_sensitive_headers(&headers);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn filter_sensitive_json_headers_strips_sensitive() {
        let mut map = serde_json::Map::new();
        map.insert("authorization".into(), serde_json::Value::String("Bearer secret".into()));
        map.insert("cookie".into(), serde_json::Value::String("sess=1".into()));
        map.insert("x-token".into(), serde_json::Value::String("t".into()));
        map.insert("content-type".into(), serde_json::Value::String("application/json".into()));

        let result = filter_sensitive_json_headers(Some(&map));

        assert!(!result.contains_key("authorization"));
        assert!(!result.contains_key("cookie"));
        assert!(!result.contains_key("x-token"));
        assert_eq!(
            result
                .get("content-type")
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn filter_sensitive_json_headers_case_insensitive() {
        let mut map = serde_json::Map::new();
        map.insert("Authorization".into(), serde_json::Value::String("secret".into()));
        map.insert("X-Request-Id".into(), serde_json::Value::String("123".into()));

        let result = filter_sensitive_json_headers(Some(&map));

        assert!(!result.contains_key("Authorization"));
        assert_eq!(
            result
                .get("X-Request-Id")
                .unwrap(),
            "123"
        );
    }

    #[test]
    fn filter_sensitive_json_headers_none_returns_empty() {
        let result = filter_sensitive_json_headers(None);
        assert!(result.is_empty());
    }

    #[test]
    fn new_sets_schema_version_and_environment() {
        let input = PolicyInput::new(
            "POST",
            "/v1/chat/completions",
            HashMap::new(),
            "inbound",
            None,
            None,
            Some("surf-1".to_string()),
            "Surface One",
        );
        assert_eq!(input.schema_version, POLICY_INPUT_SCHEMA_VERSION);
        assert!(
            !input
                .environment
                .now
                .is_empty(),
            "environment.now must be set"
        );
        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["schema_version"], POLICY_INPUT_SCHEMA_VERSION);
        assert!(json["environment"]["now"].is_string());
    }

    #[test]
    fn filter_sensitive_json_headers_skips_non_string_values() {
        let mut map = serde_json::Map::new();
        map.insert("x-count".into(), serde_json::json!(42));
        map.insert("x-request-id".into(), serde_json::Value::String("abc".into()));

        let result = filter_sensitive_json_headers(Some(&map));

        assert!(!result.contains_key("x-count"));
        assert_eq!(
            result
                .get("x-request-id")
                .unwrap(),
            "abc"
        );
    }

    #[test]
    fn request_purpose_serializes_snake_case() {
        assert_eq!(serde_json::to_value(RequestPurpose::Discovery).unwrap(), serde_json::json!("discovery"));
        assert_eq!(serde_json::to_value(RequestPurpose::Dispatch).unwrap(), serde_json::json!("dispatch"));
    }

    #[test]
    fn policy_input_exposes_request_purpose() {
        let mut input = PolicyInput::new(
            "GET",
            "/v1/models",
            HashMap::new(),
            "inbound",
            None,
            None,
            Some("ide-1".into()),
            "IDE Surface",
        );
        input.request = Some(RequestContext {
            purpose: RequestPurpose::Discovery,
            forwarded_upstream_auth: false,
        });

        let value = serde_json::to_value(&input).unwrap();
        assert_eq!(value["request"]["purpose"], serde_json::json!("discovery"));
    }

    #[test]
    fn policy_input_omits_request_when_unset() {
        let input = PolicyInput::new(
            "POST",
            "/v1/chat/completions",
            HashMap::new(),
            "inbound",
            None,
            None,
            Some("ide-1".into()),
            "IDE Surface",
        );
        let value = serde_json::to_value(&input).unwrap();
        assert!(value.get("request").is_none());
    }

    #[test]
    fn policy_input_serializes_identity_binding() {
        let mut fields = HashMap::new();
        fields.insert("role".to_string(), serde_json::json!("admin"));
        let mut input = PolicyInput::new(
            "POST",
            "/v1/chat/completions",
            HashMap::new(),
            "inbound",
            None,
            None,
            Some("surf-1".into()),
            "Fabric Surface",
        );
        input.identity_binding = Some(IdentityBindingContext {
            verified: true,
            agent_did: "did:key:holder".into(),
            gateway_did: "did:peer:gw".into(),
            issuer_did: Some("did:web:issuer.example".into()),
            identity_fields: fields,
        });

        let value = serde_json::to_value(&input).unwrap();
        let binding = &value["identity_binding"];
        assert_eq!(binding["verified"], serde_json::json!(true));
        assert_eq!(binding["agent_did"], serde_json::json!("did:key:holder"));
        assert_eq!(binding["gateway_did"], serde_json::json!("did:peer:gw"));
        assert_eq!(binding["issuer_did"], serde_json::json!("did:web:issuer.example"));
        assert_eq!(binding["identity_fields"]["role"], serde_json::json!("admin"));
    }

    #[test]
    fn policy_input_omits_identity_binding_when_unset() {
        let input = PolicyInput::new(
            "POST",
            "/v1/chat/completions",
            HashMap::new(),
            "inbound",
            None,
            None,
            Some("surf-1".into()),
            "Fabric Surface",
        );
        let value = serde_json::to_value(&input).unwrap();
        assert!(
            value
                .get("identity_binding")
                .is_none()
        );
    }
}
