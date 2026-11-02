//! Types for pipe templates.
//!
//! A [`PipeTemplate`] is a portable snapshot of a whole pipe under
//! [`PipeTemplate::pipe`]. The dashboard applies one by seeding the
//! pipe canvas wholesale, substituting any placeholder tokens
//! (`$SURFACE_NAME`, `$SURFACE_ENDPOINT`, `$SURFACE_ROUTE`) at apply time. The
//! gateway treats `pipe` as opaque JSON — only the dashboard knows its
//! schema and placeholder vocabulary.

use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

fn default_sort_priority() -> i32 {
    i32::MAX
}

/// Scope tag attached to every pipe template item, telling the placement
/// engine where on the pipe canvas to anchor the item.
///
/// Kept as a string-typed enum with `#[serde(rename_all = "snake_case")]`
/// so JSON files stay readable. Unknown future scopes deserialize via
/// [`PipeScope::Other`] so old gateways can still load newer templates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PipeScope {
    Known(KnownPipeScope),
    /// Forward-compat catch-all for scopes added in future template
    /// versions. The placement engine on older clients can skip these
    /// instead of failing the import.
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnownPipeScope {
    /// Pipe root (`pipe-body` anchor — name, description, top-level fields).
    Pipe,
    /// The inbound listener (`pipe-source` anchor).
    Source,
    /// The outbound upstream (`pipe-upstream` anchor — provider/model/endpoint).
    Upstream,
    /// A middleware enhancement node appended to the pipe chain
    /// (rate limit, cost tracking, override policy, prompt guard,
    /// judge, jury).
    Middleware,
}

/// A single item in a partial pipe template. `kind` matches an element
/// kind in the frontend pipe registry (e.g. `pipe-rate-limit`,
/// `pipe-prompt-guard`); `config` is a partial JSON payload merged onto
/// the placed element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeTemplateItem {
    pub scope: PipeScope,
    pub kind: String,
    /// Optional address detail used when `scope` needs more than the tag
    /// alone. Unused by the current pipe scopes but reserved for
    /// forward-compat with edge-bound items.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Partial configuration applied to the placed element. The
    /// placement engine deep-merges this onto the default config; empty
    /// fields stay empty so the marching-ants validator can flag them.
    #[serde(default)]
    pub config: serde_json::Value,
}

/// Template kind discriminator.
///
/// * `Partial` (default) — bundle of incremental [`PipeTemplateItem`]s
///   the placement engine drops onto an existing pipe canvas.
/// * `Full` — verbatim pipe snapshot under [`PipeTemplate::pipe`]
///   (including any `canvas` and `variants`). The dashboard applies these
///   by replacing the current pipe wholesale. The gateway treats `pipe`
///   as opaque JSON.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TemplateKind {
    #[default]
    Partial,
    Full,
}

/// A reusable, portable snapshot of a pipe configuration.
///
/// Persisted one file per id. LLM pipe templates are stored under the
/// `surface_templates` storage path; all other pipe types under
/// `pipe_templates`. `builtin: true` files are seeded from the matching
/// `config/<dir>/` at first boot and are read-only via the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeTemplate {
    /// Optional JSON schema URI for forward compatibility.
    #[serde(default, rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Stable identifier. Server-minted on create — clients submit
    /// templates through [`CreatePipeTemplate`] (no `id` field) and
    /// receive the assigned id on the response.
    pub id: String,
    pub name: String,
    /// Partial (default) or full. Old files without this field continue
    /// to parse as partial.
    #[serde(default)]
    pub kind: TemplateKind,
    /// Short one-liner shown in the template list.
    #[serde(default)]
    pub description: String,
    /// Long-form explanation shown when the template row is expanded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Body text for the welcome callout shown on the canvas the first
    /// time the user lands on a pipe created from this template. The
    /// dashboard renders it inside its own frame (title + dismiss are
    /// added automatically) so this field is just the contextual hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starter_hint: Option<String>,
    /// FontAwesome icon name (without the `fa-` prefix, e.g. `bolt`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// Free-form tags used for filtering. Templates tagged `starter`
    /// appear in the "start a new pipe" picker.
    #[serde(default)]
    pub tags: Vec<String>,
    /// `"system"` for builtins, otherwise the author DID / user id.
    #[serde(default)]
    pub author: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Server-set. Builtins are immutable through the REST API.
    #[serde(default)]
    pub builtin: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Optional UX hint controlling display order. Lower values sort
    /// first; ties fall back to alphabetical by name. Defaults to
    /// `i32::MAX` so templates without an explicit priority sink to the
    /// bottom of any sorted list.
    #[serde(default = "default_sort_priority")]
    pub sort_priority: i32,
    /// Items for `kind: Partial` templates. Empty for full templates.
    #[serde(default)]
    pub items: Vec<PipeTemplateItem>,
    /// Opaque pipe snapshot. Same shape the pipe REST API accepts
    /// (`PipeConfig`-equivalent payload, including any `canvas` and
    /// `variants`). May contain placeholder tokens (`$SURFACE_NAME`,
    /// `$SURFACE_ENDPOINT`, `$SURFACE_ROUTE`) that the dashboard substitutes at
    /// apply time. The gateway never inspects this — it's a passthrough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipe: Option<serde_json::Value>,
}

impl StorableEntity for PipeTemplate {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Request body for `POST /v1/pipe-templates`.
///
/// Mirrors the editable subset of [`PipeTemplate`]. The `id` field is
/// deliberately absent (and rejected via `deny_unknown_fields`) so the
/// frontend cannot influence template ids — the server mints a
/// `user-<uuid>` id on every create. Other server-managed fields
/// (`author`, `created_at`, `updated_at`, `builtin`) are also rejected.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePipeTemplate {
    #[serde(default, rename = "$schema")]
    pub schema: Option<String>,
    pub name: String,
    #[serde(default)]
    pub kind: TemplateKind,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub starter_hint: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default = "default_sort_priority")]
    pub sort_priority: i32,
    #[serde(default)]
    pub items: Vec<PipeTemplateItem>,
    #[serde(default)]
    pub pipe: Option<serde_json::Value>,
}

impl CreatePipeTemplate {
    /// Build a fully-populated [`PipeTemplate`] from this request,
    /// minting a server-side id and stamping `created_at` / `updated_at`.
    pub fn into_template(
        self,
        id: String,
        now: String,
    ) -> PipeTemplate {
        PipeTemplate {
            schema: self.schema,
            id,
            name: self.name,
            kind: self.kind,
            description: self.description,
            details: self.details,
            starter_hint: self.starter_hint,
            icon: self.icon,
            tags: self.tags,
            author: String::new(),
            created_at: Some(now.clone()),
            updated_at: Some(now),
            builtin: false,
            tenant_id: self.tenant_id,
            sort_priority: self.sort_priority,
            items: self.items,
            pipe: self.pipe,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_roundtrip_preserves_builtin_flag() {
        let tpl = PipeTemplate {
            schema: Some("https://example.com/v1".to_string()),
            id: "builtin-openai-llm".to_string(),
            name: "OpenAI LLM".to_string(),
            kind: TemplateKind::Full,
            description: "test".to_string(),
            details: None,
            starter_hint: None,
            icon: Some("bolt".to_string()),
            tags: vec!["starter".to_string()],
            author: "system".to_string(),
            created_at: None,
            updated_at: None,
            builtin: true,
            tenant_id: None,
            sort_priority: i32::MAX,
            items: vec![],
            pipe: Some(serde_json::json!({ "name": "$SURFACE_NAME", "pipe_type": "LLM" })),
        };
        let json = serde_json::to_string(&tpl).unwrap();
        let back: PipeTemplate = serde_json::from_str(&json).unwrap();
        assert!(back.builtin);
        assert_eq!(back.tags, vec!["starter".to_string()]);
        assert_eq!(back.kind, TemplateKind::Full);
        assert_eq!(back.pipe.unwrap()["name"], "$SURFACE_NAME");
    }

    #[test]
    fn missing_sort_priority_defaults_to_i32_max() {
        let json = r#"{ "id": "x", "name": "X" }"#;
        let tpl: PipeTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.sort_priority, i32::MAX);
    }

    #[test]
    fn explicit_sort_priority_is_preserved_through_roundtrip() {
        let json = r#"{ "id": "x", "name": "X", "sort_priority": 42 }"#;
        let tpl: PipeTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.sort_priority, 42);
        let back: PipeTemplate = serde_json::from_str(&serde_json::to_string(&tpl).unwrap()).unwrap();
        assert_eq!(back.sort_priority, 42);
    }

    #[test]
    fn carries_opaque_pipe_blob() {
        let json = r#"{
            "id": "builtin-webhook-relay",
            "name": "Webhook Relay",
            "pipe": {
                "name": "$SURFACE_NAME",
                "pipe_type": "Webhook",
                "endpoint_url": "$SURFACE_ENDPOINT"
            }
        }"#;
        let tpl: PipeTemplate = serde_json::from_str(json).unwrap();
        let pipe = tpl
            .pipe
            .clone()
            .expect("pipe snapshot must round-trip");
        assert_eq!(pipe["endpoint_url"], "$SURFACE_ENDPOINT");
        let reserialized = serde_json::to_string(&tpl).unwrap();
        let back: PipeTemplate = serde_json::from_str(&reserialized).unwrap();
        assert_eq!(back.pipe.unwrap()["name"], "$SURFACE_NAME");
    }

    #[test]
    fn create_request_rejects_id_field() {
        let json = r#"{ "id": "evil", "name": "X" }"#;
        let parsed: Result<CreatePipeTemplate, _> = serde_json::from_str(json);
        assert!(parsed.is_err(), "id must be rejected by deny_unknown_fields");
    }

    #[test]
    fn into_template_mints_server_fields() {
        let req = CreatePipeTemplate {
            schema: None,
            name: "My Pipe".to_string(),
            kind: TemplateKind::Partial,
            description: String::new(),
            details: None,
            starter_hint: None,
            icon: None,
            tags: vec![],
            tenant_id: None,
            sort_priority: i32::MAX,
            items: vec![],
            pipe: Some(serde_json::json!({})),
        };
        let tpl = req.into_template("user-123".to_string(), "2026-01-01T00:00:00Z".to_string());
        assert_eq!(tpl.id, "user-123");
        assert!(!tpl.builtin);
        assert_eq!(tpl.author, "");
        assert_eq!(tpl.created_at.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(tpl.updated_at.as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn missing_kind_defaults_to_partial() {
        let json = r#"{ "id": "x", "name": "X" }"#;
        let tpl: PipeTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.kind, TemplateKind::Partial);
        assert!(tpl.items.is_empty());
    }

    #[test]
    fn full_template_carries_canvas_and_variants() {
        let json = r#"{
            "id": "builtin-full-llm",
            "name": "Full LLM",
            "kind": "full",
            "pipe": {
                "name": "$SURFACE_NAME",
                "canvas": { "nodes": [] },
                "variants": [{ "id": "v1", "alias": "fast", "name": "Fast" }]
            }
        }"#;
        let tpl: PipeTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.kind, TemplateKind::Full);
        let pipe = tpl
            .pipe
            .clone()
            .expect("pipe blob");
        assert!(pipe["canvas"].is_object());
        assert_eq!(pipe["variants"][0]["alias"], "fast");
        let back: PipeTemplate = serde_json::from_str(&serde_json::to_string(&tpl).unwrap()).unwrap();
        assert_eq!(back.pipe.unwrap()["variants"][0]["alias"], "fast");
    }

    #[test]
    fn partial_template_items_roundtrip() {
        let item = PipeTemplateItem {
            scope: PipeScope::Known(KnownPipeScope::Middleware),
            kind: "pipe-rate-limit".to_string(),
            address: None,
            config: serde_json::json!({ "requests_per_minute": 60 }),
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: PipeTemplateItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scope, PipeScope::Known(KnownPipeScope::Middleware));
        assert_eq!(back.kind, "pipe-rate-limit");
        assert_eq!(back.config["requests_per_minute"], 60);
    }

    #[test]
    fn unknown_pipe_scope_deserializes_to_other() {
        let json = r#"{ "scope": "future_anchor", "kind": "x" }"#;
        let item: PipeTemplateItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.scope, PipeScope::Other("future_anchor".to_string()));
    }
}
