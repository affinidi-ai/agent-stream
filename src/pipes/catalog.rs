//! IDE Surface — contract types.
//!
//! An IDE Surface (`PipeType::IDECatalog`; shown to users simply as an **"IDE"**
//! surface) aggregates other surfaces (LLM pipes and their `$variant` aliases)
//! into a single, governed, per-caller-filtered **model menu** for IDE AI
//! clients. It is a **dispatching front door**, not just a list:
//!
//! - `GET {route}/v1/models` returns the caller's filtered model list.
//! - `POST {route}/v1/chat/completions` (and other suffixes) dispatches by the
//!   request's `model` field (`{pipe_id}[$alias]`) to the chosen member surface,
//!   re-running that member's full governance under the same caller identity.
//!
//! This one-URL + `model`-string shape is the lowest common denominator every
//! IDE AI client speaks (VS Code's `LanguageModelChatProvider`, JetBrains
//! ProxyAI / AI Assistant, Eclipse AssistAI, and the cross-IDE Continue plugin
//! all take a single OpenAI-compatible base URL + a model id), so a single IDE
//! Surface serves them all. VS Code additionally reads the per-entry
//! `agent_stream` extension for a live, curated picker.
//!
//! This module owns the **contract** plus the pure entry builder: the stored
//! configuration types (`IdeCatalogConfig`, `IdeCatalogMember`,
//! `IdeCatalogModelMetadata`), the published wire/response schema
//! (`IdeModelsResponse`, `IdeModelEntry`, `IdeModelEntryExt`, an OpenAI
//! model-list envelope carrying an `agent_stream` extension), and
//! `IdeModelEntry::from_member` (pure member → published-entry mapping). The
//! discovery handler consumes these types to publish the caller's filtered
//! list; per-caller filtering, dispatch, and the admin API are wired
//! separately. Keeping the contract standalone lets it be unit-tested in
//! isolation from the async request path.

use serde::{Deserialize, Serialize};

fn is_false(b: &bool) -> bool {
    !*b
}

fn default_true() -> bool {
    true
}

/// Stored configuration for an IDE Surface: an ordered set of member
/// surfaces (pipes / variants) to publish as discoverable models.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct IdeCatalogConfig {
    /// The surfaces exposed by this catalog. Order here is a fallback; each
    /// member's explicit `order` takes precedence when the list is rendered.
    #[serde(default)]
    pub members: Vec<IdeCatalogMember>,

    /// Optional central client sign-in bootstrap. When set, the IDE Surface
    /// publishes these (public, non-secret) identity-provider identifiers at its
    /// unauthenticated bootstrap endpoint so an IDE client only needs the Access
    /// Point URL — it pulls tenant/client/scopes from here to acquire a token,
    /// then discovers models. Central management: change it once here and every
    /// client picks it up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth: Option<IdeClientAuth>,
}

fn default_client_auth_provider() -> String {
    "entra".to_string()
}

/// Central sign-in bootstrap for IDE clients. All fields are **public OAuth
/// identifiers** (tenant, public-client app id, requested scopes) — never
/// secrets — so they are safe to serve unauthenticated. Authored once on the
/// IDE Surface and pulled by every client, so a fleet is managed centrally.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdeClientAuth {
    /// Identity provider the client signs in with. Currently only `entra`
    /// (Microsoft Entra ID / Azure AD).
    #[serde(default = "default_client_auth_provider")]
    pub provider: String,

    /// Directory (tenant) the client targets, e.g. an Entra tenant GUID or
    /// verified domain.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tenant_id: String,

    /// Public client app registration the editor uses to request the token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,

    /// API scopes the client requests (e.g. `api://<api-app-id>/access_as_user`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,

    /// Optional reference to an **OAuth Identifier** profile (`src/oauth_identifiers`).
    /// When set, the profile's public identifiers (authority/tenant, client id,
    /// scopes) are resolved and overlaid onto this block when the bootstrap is
    /// published — so the identifiers are managed once in the Credentials store
    /// and every referencing surface follows. Inline fields above act as a
    /// fallback when the reference is unset or unresolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_identifier_id: Option<String>,
}

impl IdeClientAuth {
    /// Whether this block references an OAuth Identifier profile (non-blank id).
    fn has_reference(&self) -> bool {
        self.oauth_identifier_id
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty())
    }

    /// Validate the bootstrap: a non-blank provider, and — for the `entra`
    /// provider **without** a profile reference — a tenant, a client id, and at
    /// least one non-blank scope, so a client that pulls it can actually sign in.
    /// When a profile reference is set, the profile supplies those fields, so the
    /// inline fields may be blank.
    pub fn validate(&self) -> Result<(), String> {
        let provider = self.provider.trim();
        if provider.is_empty() {
            return Err("client_auth provider must not be empty".to_string());
        }
        if self.has_reference() {
            return Ok(());
        }
        if provider.eq_ignore_ascii_case("entra") {
            if self
                .tenant_id
                .trim()
                .is_empty()
            {
                return Err("client_auth requires a tenant_id for the entra provider".to_string());
            }
            if self
                .client_id
                .trim()
                .is_empty()
            {
                return Err("client_auth requires a client_id for the entra provider".to_string());
            }
            if !self
                .scopes
                .iter()
                .any(|s| !s.trim().is_empty())
            {
                return Err("client_auth requires at least one scope for the entra provider".to_string());
            }
        }
        Ok(())
    }
}

/// A single **upstream** sign-in slot published in the surface bootstrap: how an
/// IDE client acquires a token to forward to a member surface's upstream
/// provider, independent of the front-door token. All fields are public OAuth
/// identifiers (never secrets). Slots are **synthesized** at publish time from a
/// member's `upstream_oauth_identifier_id` (never authored directly); the client
/// keys its per-upstream token cache on the slot `id` and attaches the token in
/// `X-Agent-Stream-Upstream-Authorization`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdeUpstreamAuth {
    /// Stable slot id a published model entry references (`upstream_auth_id`) and
    /// the client keys its per-upstream token cache on.
    pub id: String,

    /// Identity provider the client signs in with. Currently only `entra`.
    #[serde(default = "default_client_auth_provider")]
    pub provider: String,

    /// Directory (tenant) the upstream token targets.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tenant_id: String,

    /// Public client app registration the editor uses to request the token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,

    /// API scopes the upstream token requests (e.g. the Graph scopes Copilot
    /// requires).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,

    /// The **OAuth Identifier** profile this synthesized slot resolves from. The
    /// profile's public identifiers are overlaid onto the slot when the bootstrap
    /// is published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_identifier_id: Option<String>,
}

/// A single entry in an IDE Surface — a reference to an LLM Surface (pipe),
/// optionally pinned to one of its `$variant` aliases, plus presentation and
/// curation metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdeCatalogMember {
    /// The referenced LLM Surface (pipe) id.
    pub pipe_id: String,

    /// Variant alias to expose (`{pipe_id}${alias}`). `None` exposes the base
    /// surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_alias: Option<String>,

    /// Operator-chosen mnemonic that becomes this entry's client-facing model
    /// id (the string the IDE client sends back in the request `model`). When
    /// set and non-blank it overrides the derived `{pipe_id}[$alias]`; when
    /// absent the canonical id is used. Uniqueness is enforced across every
    /// member via `model_id()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,

    /// Display name shown in the client model picker. Defaults to the mnemonic /
    /// surface / model name when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Optional curation group (e.g. "Coding", "Writing", "Secure").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Sort order within the catalog (lower renders first).
    #[serde(default)]
    pub order: i32,

    /// Marks this entry as the client's default selection.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,

    /// When `false`, the entry is withheld from the published list without
    /// deleting it from the catalog.
    #[serde(default = "default_true")]
    pub expose: bool,

    /// Optional capability/metadata overrides surfaced to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<IdeCatalogModelMetadata>,

    /// Optional per-member upstream sign-in via an **OAuth Identifier** profile
    /// reference (`src/oauth_identifiers`). Gives a member its own upstream token
    /// (e.g. a Graph-audience token for Microsoft 365 Copilot) distinct from the
    /// front-door token. At publish time the surface synthesizes a deterministic
    /// upstream slot (`oauth:{profile_id}`) from this reference, resolves it to
    /// the profile's public identifiers, and publishes the member's model-entry
    /// `upstream_auth_id` pointing at it. `None` ⇒ the caller's front-door token
    /// is forwarded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_oauth_identifier_id: Option<String>,

    /// Optional per-member **Model Policy** — the id of an IDE-type policy
    /// definition (`PolicyType::Ide`, `package ide.policy`) evaluated on this
    /// specific model *after* the front-door gates pass and the member is
    /// resolved, under the caller's front-door identity. Lets a catalogue expose
    /// a model only to a subset of callers (e.g. a premium model gated to one
    /// Entra group) without touching the member LLM Surface's own policy. A
    /// `false` result denies the dispatch with HTTP 403; a set-but-uncompiled
    /// policy fails closed. `None` ⇒ no extra per-model gate (the front-door and
    /// the member surface's own governance still apply).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opa_policy_id: Option<String>,

    /// Stable, opaque **canvas node identity** minted once by the dashboard IDE
    /// editor and preserved across saves. The backend never reads it — it is a
    /// UI-only handle that lets the editor bind per-member canvas state (node
    /// position, docked gate chips) to *this* member regardless of the member's
    /// position in the array. Without it the editor derived a member's canvas id
    /// from its array index, so reordering the catalogue (which re-sorts the
    /// persisted array) silently remapped every member's saved canvas state onto
    /// its neighbour. `None` on legacy configs authored before this field; the
    /// editor mints one on first save.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

/// The synthesized upstream slot id derived from a member's
/// `upstream_oauth_identifier_id`. Kept stable so the published model-entry
/// `upstream_auth_id` and the synthesized `upstreams[]` slot id always match.
fn synthesized_upstream_slot_id(profile_id: &str) -> String {
    format!("oauth:{}", profile_id.trim())
}

impl IdeCatalogMember {
    /// The upstream sign-in slot id this member publishes to clients — the
    /// deterministic synthesized slot id (`oauth:{profile_id}`) when the member
    /// references an OAuth Identifier profile for its upstream, else `None`
    /// (forward the caller's front-door token).
    pub fn published_upstream_auth_id(&self) -> Option<String> {
        self.upstream_oauth_identifier_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(synthesized_upstream_slot_id)
    }

    /// The trimmed, non-blank per-member Model Policy definition id, or `None`
    /// when no per-model gate is configured.
    pub fn opa_policy_definition_id(&self) -> Option<&str> {
        self.opa_policy_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// The unique client-facing model id for this entry. Prefers the
    /// operator-chosen `mnemonic` (trimmed, non-blank); otherwise falls back to
    /// the canonical `{pipe_id}` or `{pipe_id}${alias}`. Stable across restarts
    /// and unique even when two surfaces expose the same upstream model name.
    pub fn model_id(&self) -> String {
        if let Some(m) = self
            .mnemonic
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            return m.to_string();
        }
        match &self.variant_alias {
            Some(alias) if !alias.is_empty() => format!("{}${}", self.pipe_id, alias),
            _ => self.pipe_id.clone(),
        }
    }
}

/// Optional per-entry capability/presentation metadata, authored once on the
/// catalog and surfaced to every client (context window, modalities, sunset).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct IdeCatalogModelMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_tokens: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,

    /// Capability hints (e.g. `["tools", "vision", "json"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Deprecation / sunset timestamp to surface in the picker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sunset_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl IdeCatalogConfig {
    /// Validate the catalog: every member must name a non-blank surface, and
    /// each member's `model_id()` (the mnemonic when set, else the derived
    /// `{pipe_id}[$alias]`) must be unique so client model ids don't collide.
    /// (Existence of the referenced surfaces is checked at the admin-API
    /// boundary, not here.)
    pub fn validate(&self) -> Result<(), String> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for member in &self.members {
            if member
                .pipe_id
                .trim()
                .is_empty()
            {
                return Err("catalog member has an empty pipe_id".to_string());
            }
            let key = member.model_id();
            if !seen.insert(key.clone()) {
                return Err(format!("catalog has duplicate entry: {}", key));
            }
        }
        if let Some(client_auth) = &self.client_auth {
            client_auth.validate()?;
        }
        Ok(())
    }

    /// The upstream sign-in slots to publish: one **synthesized** slot per
    /// distinct member `upstream_oauth_identifier_id` (`oauth:{profile_id}`,
    /// carrying the profile reference so a later `resolve_upstreams` overlays its
    /// public identifiers), deduped by slot id. Members that share a profile
    /// yield a single slot. This keeps the published bootstrap wire shape (a flat
    /// `upstreams[]`) while the operator configures the upstream token per
    /// catalogue member.
    pub fn synthesized_upstreams(&self) -> Vec<IdeUpstreamAuth> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut out: Vec<IdeUpstreamAuth> = Vec::new();
        for member in &self.members {
            if let Some(profile_id) = member
                .upstream_oauth_identifier_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let slot_id = synthesized_upstream_slot_id(profile_id);
                if seen.insert(slot_id.clone()) {
                    out.push(IdeUpstreamAuth {
                        id: slot_id,
                        provider: default_client_auth_provider(),
                        tenant_id: String::new(),
                        client_id: String::new(),
                        scopes: Vec::new(),
                        oauth_identifier_id: Some(profile_id.to_string()),
                    });
                }
            }
        }
        out
    }
}

/// Resolve the public identifiers of a referenced OAuth Identifier profile into
/// the `(provider, tenant_id, client_id, scopes)` an IDE sign-in block
/// publishes. Non-Entra shapes leave `tenant_id` blank (the current IDE client
/// is Entra-only). Returns `None` when the store is unregistered or the id does
/// not resolve, so callers keep their inline fallback values.
async fn resolve_profile_fields(id: &str) -> Option<(String, String, String, Vec<String>)> {
    let store = crate::oauth_identifiers::global_oauth_identifier_store()?;
    let profile = store
        .get(id)
        .await
        .ok()
        .flatten()?;
    let (provider, tenant_id) = match &profile.shape {
        crate::oauth_identifiers::models::OAuthIdentifierShape::Entra { tenant_id } => {
            ("entra".to_string(), tenant_id.clone())
        }
        crate::oauth_identifiers::models::OAuthIdentifierShape::Okta { .. } => ("okta".to_string(), String::new()),
        crate::oauth_identifiers::models::OAuthIdentifierShape::Oidc { .. } => ("oidc".to_string(), String::new()),
    };
    Some((provider, tenant_id, profile.client_id, profile.scopes))
}

/// Resolve any OAuth Identifier reference on a client sign-in block, overlaying
/// the profile's public identifiers. Inline values are kept when the reference
/// is unset or unresolvable (back-compat). The internal reference id is never
/// published to clients.
pub async fn resolve_client_auth(mut auth: IdeClientAuth) -> IdeClientAuth {
    if let Some(id) = auth
        .oauth_identifier_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        && let Some((provider, tenant_id, client_id, scopes)) = resolve_profile_fields(id.trim()).await
    {
        auth.provider = provider;
        auth.tenant_id = tenant_id;
        auth.client_id = client_id;
        auth.scopes = scopes;
    }
    auth.oauth_identifier_id = None;
    auth
}

/// Resolve any OAuth Identifier references on the upstream sign-in slots,
/// overlaying each resolved profile's public identifiers. Inline values are kept
/// when a reference is unset or unresolvable; reference ids are never published.
pub async fn resolve_upstreams(upstreams: Vec<IdeUpstreamAuth>) -> Vec<IdeUpstreamAuth> {
    let mut out = Vec::with_capacity(upstreams.len());
    for mut slot in upstreams {
        if let Some(id) = slot
            .oauth_identifier_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            && let Some((provider, tenant_id, client_id, scopes)) = resolve_profile_fields(id.trim()).await
        {
            slot.provider = provider;
            slot.tenant_id = tenant_id;
            slot.client_id = client_id;
            slot.scopes = scopes;
        }
        slot.oauth_identifier_id = None;
        out.push(slot);
    }
    out
}

/// The published, **unauthenticated** bootstrap document an IDE Surface serves
/// at `{route}/.well-known/agent-stream`. It hands an IDE client everything it
/// needs to sign in and discover models from only the Access Point URL: the
/// (public) sign-in identifiers plus the discovery/dispatch paths.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdeBootstrapResponse {
    /// Central sign-in identifiers the client uses to acquire a token.
    pub auth: IdeClientAuth,

    /// Upstream sign-in slots the client uses to acquire *additional*, distinct
    /// tokens to forward per model (public identifiers only). Empty when the
    /// surface forwards only the front-door token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<IdeUpstreamAuth>,

    /// Model-discovery path relative to the Access Point (`GET`).
    pub models_path: String,

    /// Chat-completions dispatch path relative to the Access Point (`POST`).
    pub chat_path: String,
}

impl IdeBootstrapResponse {
    /// Build the bootstrap document from a surface's stored client sign-in
    /// config plus its upstream sign-in slots, stamping the fixed
    /// discovery/dispatch paths the gateway serves.
    pub fn for_client_and_upstreams(
        auth: IdeClientAuth,
        upstreams: Vec<IdeUpstreamAuth>,
    ) -> Self {
        Self {
            auth,
            upstreams,
            models_path: "/v1/models".to_string(),
            chat_path: "/v1/chat/completions".to_string(),
        }
    }
}

/// The published `/v1/models` response — an OpenAI model-list envelope whose
/// entries carry an `agent_stream` extension object (routing + presentation).
/// Generic OpenAI clients read `data[].id`/`object` and ignore the extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdeModelsResponse {
    #[serde(rename = "object")]
    pub object: String,

    pub data: Vec<IdeModelEntry>,

    /// Opaque version token (content hash) so clients — and the live-push
    /// signal — can cheaply detect whether the resolved list changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_version: Option<String>,
}

impl IdeModelsResponse {
    /// Build a list envelope from resolved entries, stamping a stable version
    /// token derived from the entries' ids + display names.
    pub fn list(data: Vec<IdeModelEntry>) -> Self {
        let version = Self::version_of(&data);
        Self {
            object: "list".to_string(),
            data,
            catalog_version: Some(version),
        }
    }

    fn version_of(data: &[IdeModelEntry]) -> String {
        // Cheap, order-sensitive fingerprint of the resolved list. Not a
        // cryptographic hash — only used to detect "did the menu change".
        let mut acc: u64 = 1469598103934665603; // FNV-1a offset basis
        for entry in data {
            for byte in entry
                .id
                .as_bytes()
                .iter()
                .chain(
                    entry
                        .agent_stream
                        .display_name
                        .as_bytes(),
                )
                .chain(
                    entry
                        .agent_stream
                        .route
                        .as_bytes(),
                )
            {
                acc ^= *byte as u64;
                acc = acc.wrapping_mul(1099511628211); // FNV prime
            }
        }
        format!("{:016x}", acc)
    }
}

/// A single published model entry: OpenAI base fields + the `agent_stream`
/// routing/presentation extension.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdeModelEntry {
    /// Client-facing model id (`{pipe_id}` or `{pipe_id}${alias}`).
    pub id: String,

    #[serde(rename = "object")]
    pub object: String,

    pub created: i64,

    pub owned_by: String,

    /// Agent Stream routing + presentation extension (ignored by generic
    /// OpenAI clients).
    pub agent_stream: IdeModelEntryExt,
}

/// Routing + presentation extension attached to each published model entry.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct IdeModelEntryExt {
    /// Chat-completions route to POST to for this model. The universal path is
    /// the IDE Surface's own route with the model id in the body (works for
    /// every OpenAI-compatible client); this field lets a client that supports
    /// per-model base URLs (e.g. the VS Code extension) target the entry
    /// directly.
    pub route: String,

    /// Underlying surface (pipe) id this entry resolves to.
    pub surface_id: String,

    /// Variant alias, when the entry targets a specific `$variant`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_alias: Option<String>,

    /// Human display name for the picker.
    pub display_name: String,

    /// Optional curation group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Sort order within the catalog.
    #[serde(default)]
    pub order: i32,

    /// Whether this is the catalog's default selection.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,

    /// The OpenAI `model` string sent upstream, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Provider type (`openai`, `anthropic`, …), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_tokens: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sunset_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Upstream sign-in slot id whose token the client should forward for this
    /// model. `None` ⇒ forward the front-door token (today's behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_auth_id: Option<String>,
}

impl IdeModelEntry {
    /// Build a published entry for a resolved member surface. `route` is the
    /// chat-completions route a client POSTs to for this model (the IDE
    /// Surface's own front-door route in v1); `model`/`provider` come from the
    /// resolved member pipe's upstream; `created` is the response timestamp.
    ///
    /// The display name falls back through the member's explicit name, the
    /// upstream model string, then the canonical model id, so an entry always
    /// carries a human-readable label. Curation metadata (context window,
    /// capabilities, sunset) is copied from the member when present.
    pub fn from_member(
        member: &IdeCatalogMember,
        route: String,
        model: Option<String>,
        provider: Option<String>,
        created: i64,
    ) -> Self {
        let display_name = member
            .display_name
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                member
                    .mnemonic
                    .as_ref()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| model.clone())
            .unwrap_or_else(|| member.model_id());
        let meta = member
            .metadata
            .clone()
            .unwrap_or_default();
        IdeModelEntry {
            id: member.model_id(),
            object: "model".to_string(),
            created,
            owned_by: provider
                .clone()
                .unwrap_or_else(|| "agent-stream".to_string()),
            agent_stream: IdeModelEntryExt {
                route,
                surface_id: member.pipe_id.clone(),
                variant_alias: member.variant_alias.clone(),
                display_name,
                group: member.group.clone(),
                order: member.order,
                default: member.default,
                model,
                provider,
                max_input_tokens: meta.max_input_tokens,
                max_output_tokens: meta.max_output_tokens,
                capabilities: meta.capabilities,
                description: meta.description,
                sunset_at: meta.sunset_at,
                upstream_auth_id: member.published_upstream_auth_id(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal exposed catalogue member for tests.
    fn member_lit(
        pipe_id: &str,
        variant_alias: Option<&str>,
    ) -> IdeCatalogMember {
        IdeCatalogMember {
            pipe_id: pipe_id.into(),
            variant_alias: variant_alias.map(str::to_string),
            mnemonic: None,
            display_name: None,
            group: None,
            order: 0,
            default: false,
            expose: true,
            metadata: None,
            upstream_oauth_identifier_id: None,
            opa_policy_id: None,
            node_id: None,
        }
    }

    #[test]
    fn model_id_uses_variant_suffix() {
        let base = IdeCatalogMember {
            pipe_id: "gpt4o".into(),
            variant_alias: None,
            mnemonic: None,
            display_name: None,
            group: None,
            order: 0,
            default: false,
            expose: true,
            metadata: None,
            upstream_oauth_identifier_id: None,
            opa_policy_id: None,
            node_id: None,
        };
        assert_eq!(base.model_id(), "gpt4o");

        let variant = IdeCatalogMember {
            variant_alias: Some("secure".into()),
            ..base.clone()
        };
        assert_eq!(variant.model_id(), "gpt4o$secure");
    }

    #[test]
    fn model_id_prefers_mnemonic_over_derived_id() {
        let base = IdeCatalogMember {
            pipe_id: "gpt4o".into(),
            variant_alias: Some("secure".into()),
            mnemonic: Some("  fast-coder  ".into()),
            display_name: None,
            group: None,
            order: 0,
            default: false,
            expose: true,
            metadata: None,
            upstream_oauth_identifier_id: None,
            opa_policy_id: None,
            node_id: None,
        };
        // A trimmed, non-blank mnemonic becomes the model id.
        assert_eq!(base.model_id(), "fast-coder");

        // A blank/whitespace mnemonic falls back to the derived id.
        let blank = IdeCatalogMember {
            mnemonic: Some("   ".into()),
            ..base.clone()
        };
        assert_eq!(blank.model_id(), "gpt4o$secure");
    }

    #[test]
    fn validate_rejects_duplicate_mnemonics() {
        let cfg = IdeCatalogConfig {
            members: vec![
                IdeCatalogMember {
                    pipe_id: "gpt4o".into(),
                    variant_alias: None,
                    mnemonic: Some("coder".into()),
                    display_name: None,
                    group: None,
                    order: 0,
                    default: false,
                    expose: true,
                    metadata: None,
                    upstream_oauth_identifier_id: None,
                    opa_policy_id: None,
                    node_id: None,
                },
                IdeCatalogMember {
                    pipe_id: "claude".into(),
                    variant_alias: Some("fast".into()),
                    mnemonic: Some("coder".into()),
                    display_name: None,
                    group: None,
                    order: 1,
                    default: false,
                    expose: true,
                    metadata: None,
                    upstream_oauth_identifier_id: None,
                    opa_policy_id: None,
                    node_id: None,
                },
            ],
            client_auth: None,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("duplicate entry"), "got: {err}");
        assert!(err.contains("coder"), "got: {err}");
    }

    #[test]
    fn validate_rejects_blank_and_duplicate_members() {
        let dup = IdeCatalogConfig {
            members: vec![
                IdeCatalogMember {
                    pipe_id: "gpt4o".into(),
                    variant_alias: Some("secure".into()),
                    mnemonic: None,
                    display_name: None,
                    group: None,
                    order: 0,
                    default: false,
                    expose: true,
                    metadata: None,
                    upstream_oauth_identifier_id: None,
                    opa_policy_id: None,
                    node_id: None,
                },
                IdeCatalogMember {
                    pipe_id: "gpt4o".into(),
                    variant_alias: Some("secure".into()),
                    mnemonic: None,
                    display_name: None,
                    group: None,
                    order: 1,
                    default: false,
                    expose: true,
                    metadata: None,
                    upstream_oauth_identifier_id: None,
                    opa_policy_id: None,
                    node_id: None,
                },
            ],
            client_auth: None,
        };
        let err = dup.validate().unwrap_err();
        assert!(err.contains("duplicate entry"), "got: {err}");

        let blank = IdeCatalogConfig {
            members: vec![IdeCatalogMember {
                pipe_id: "  ".into(),
                variant_alias: None,
                mnemonic: None,
                display_name: None,
                group: None,
                order: 0,
                default: false,
                expose: true,
                metadata: None,
                upstream_oauth_identifier_id: None,
                opa_policy_id: None,
                node_id: None,
            }],
            client_auth: None,
        };
        assert!(
            blank
                .validate()
                .unwrap_err()
                .contains("empty pipe_id")
        );
    }

    #[test]
    fn validate_accepts_distinct_members() {
        let cfg = IdeCatalogConfig {
            members: vec![
                IdeCatalogMember {
                    pipe_id: "gpt4o".into(),
                    variant_alias: None,
                    mnemonic: None,
                    display_name: Some("GPT-4o".into()),
                    group: Some("General".into()),
                    order: 0,
                    default: true,
                    expose: true,
                    metadata: None,
                    upstream_oauth_identifier_id: None,
                    opa_policy_id: None,
                    node_id: None,
                },
                IdeCatalogMember {
                    pipe_id: "gpt4o".into(),
                    variant_alias: Some("secure".into()),
                    mnemonic: None,
                    display_name: Some("GPT-4o (Secure)".into()),
                    group: Some("Secure".into()),
                    order: 1,
                    default: false,
                    expose: true,
                    metadata: None,
                    upstream_oauth_identifier_id: None,
                    opa_policy_id: None,
                    node_id: None,
                },
            ],
            client_auth: None,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_round_trips_through_json() {
        let cfg = IdeCatalogConfig {
            members: vec![IdeCatalogMember {
                pipe_id: "claude".into(),
                variant_alias: Some("reasoning".into()),
                mnemonic: None,
                display_name: Some("Claude (Reasoning)".into()),
                group: Some("Secure".into()),
                order: 3,
                default: true,
                expose: true,
                metadata: Some(IdeCatalogModelMetadata {
                    description: Some("High-reasoning, PII-masked".into()),
                    max_input_tokens: Some(200_000),
                    max_output_tokens: Some(8_192),
                    capabilities: vec!["tools".into(), "vision".into()],
                    sunset_at: None,
                }),
                upstream_oauth_identifier_id: None,
                opa_policy_id: None,
                node_id: None,
            }],
            client_auth: None,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: IdeCatalogConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn client_auth_validate_accepts_full_entra_config() {
        let auth = IdeClientAuth {
            provider: "entra".into(),
            tenant_id: "11111111-1111-1111-1111-111111111111".into(),
            client_id: "22222222-2222-2222-2222-222222222222".into(),
            scopes: vec!["api://agent-stream/.default".into()],
            oauth_identifier_id: None,
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn client_auth_validate_rejects_missing_entra_fields() {
        let base = IdeClientAuth {
            provider: "entra".into(),
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            scopes: vec!["scope".into()],
            oauth_identifier_id: None,
        };

        let no_tenant = IdeClientAuth {
            tenant_id: "  ".into(),
            ..base.clone()
        };
        assert!(
            no_tenant
                .validate()
                .unwrap_err()
                .contains("tenant_id"),
            "expected tenant_id error"
        );

        let no_client = IdeClientAuth {
            client_id: String::new(),
            ..base.clone()
        };
        assert!(
            no_client
                .validate()
                .unwrap_err()
                .contains("client_id"),
            "expected client_id error"
        );

        let no_scopes = IdeClientAuth {
            scopes: vec!["   ".into()],
            ..base.clone()
        };
        assert!(
            no_scopes
                .validate()
                .unwrap_err()
                .contains("scope"),
            "expected scope error"
        );
    }

    #[test]
    fn client_auth_validate_rejects_blank_provider() {
        let auth = IdeClientAuth {
            provider: "  ".into(),
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            scopes: vec!["scope".into()],
            oauth_identifier_id: None,
        };
        assert!(
            auth.validate()
                .unwrap_err()
                .contains("provider"),
            "expected provider error"
        );
    }

    #[test]
    fn config_validate_propagates_client_auth_error() {
        let cfg = IdeCatalogConfig {
            members: vec![member_lit("gpt4o", None)],
            client_auth: Some(IdeClientAuth {
                provider: "entra".into(),
                tenant_id: String::new(),
                client_id: "client".into(),
                scopes: vec!["scope".into()],
                oauth_identifier_id: None,
            }),
        };
        assert!(
            cfg.validate()
                .unwrap_err()
                .contains("tenant_id"),
            "config validate should surface client_auth error"
        );
    }

    #[test]
    fn bootstrap_response_stamps_fixed_paths() {
        let auth = IdeClientAuth {
            provider: "entra".into(),
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            scopes: vec!["api://agent-stream/.default".into()],
            oauth_identifier_id: None,
        };
        let resp = IdeBootstrapResponse::for_client_and_upstreams(auth.clone(), Vec::new());
        assert_eq!(resp.auth, auth);
        assert_eq!(resp.models_path, "/v1/models");
        assert_eq!(resp.chat_path, "/v1/chat/completions");

        let value = serde_json::to_value(&resp).unwrap();
        assert_eq!(value["models_path"], "/v1/models");
        assert_eq!(value["chat_path"], "/v1/chat/completions");
        assert_eq!(value["auth"]["provider"], "entra");
        assert_eq!(value["auth"]["tenant_id"], "tenant");
        assert_eq!(value["auth"]["client_id"], "client");
        assert_eq!(value["auth"]["scopes"][0], "api://agent-stream/.default");
    }

    #[test]
    fn config_round_trips_with_client_auth() {
        let cfg = IdeCatalogConfig {
            members: vec![member_lit("gpt4o", None)],
            client_auth: Some(IdeClientAuth {
                provider: "entra".into(),
                tenant_id: "tenant".into(),
                client_id: "client".into(),
                scopes: vec!["api://agent-stream/.default".into()],
                oauth_identifier_id: None,
            }),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("client_auth"), "json was: {json}");
        let back: IdeCatalogConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn response_stamps_version_and_serializes_openai_shape() {
        let entry = IdeModelEntry {
            id: "gpt4o$secure".into(),
            object: "model".into(),
            created: 1_700_000_000,
            owned_by: "openai".into(),
            agent_stream: IdeModelEntryExt {
                route: "https://gw.example.com/llm/gpt4o$secure/v1/chat/completions".into(),
                surface_id: "gpt4o".into(),
                variant_alias: Some("secure".into()),
                display_name: "GPT-4o (Secure)".into(),
                group: Some("Secure".into()),
                order: 1,
                default: false,
                model: Some("gpt-4o".into()),
                provider: Some("openai".into()),
                max_input_tokens: Some(128_000),
                max_output_tokens: Some(8_192),
                capabilities: vec!["tools".into()],
                description: None,
                sunset_at: None,
                upstream_auth_id: None,
            },
        };
        let resp = IdeModelsResponse::list(vec![entry]);
        assert_eq!(resp.object, "list");
        assert_eq!(resp.data.len(), 1);
        assert!(resp.catalog_version.is_some());

        let value = serde_json::to_value(&resp).unwrap();
        assert_eq!(value["object"], "list");
        assert_eq!(value["data"][0]["id"], "gpt4o$secure");
        assert_eq!(value["data"][0]["object"], "model");
        assert_eq!(value["data"][0]["agent_stream"]["display_name"], "GPT-4o (Secure)");
        assert_eq!(
            value["data"][0]["agent_stream"]["route"],
            "https://gw.example.com/llm/gpt4o$secure/v1/chat/completions"
        );
    }

    #[test]
    fn version_changes_when_list_changes() {
        let make = |id: &str| IdeModelEntry {
            id: id.into(),
            object: "model".into(),
            created: 0,
            owned_by: "openai".into(),
            agent_stream: IdeModelEntryExt {
                route: format!("https://gw/{id}/v1/chat/completions"),
                surface_id: id.into(),
                display_name: id.into(),
                ..Default::default()
            },
        };
        let a = IdeModelsResponse::list(vec![make("gpt4o")]);
        let b = IdeModelsResponse::list(vec![make("gpt4o"), make("claude")]);
        assert_ne!(a.catalog_version, b.catalog_version);

        let a2 = IdeModelsResponse::list(vec![make("gpt4o")]);
        assert_eq!(a.catalog_version, a2.catalog_version, "same list = same version");
    }

    #[test]
    fn from_member_copies_metadata_and_resolves_display_name() {
        let member = IdeCatalogMember {
            pipe_id: "claude".into(),
            variant_alias: Some("reasoning".into()),
            mnemonic: None,
            display_name: Some("Claude (Reasoning)".into()),
            group: Some("Secure".into()),
            order: 5,
            default: true,
            expose: true,
            metadata: Some(IdeCatalogModelMetadata {
                description: Some("High-reasoning, PII-masked".into()),
                max_input_tokens: Some(200_000),
                max_output_tokens: Some(8_192),
                capabilities: vec!["tools".into(), "vision".into()],
                sunset_at: None,
            }),
            upstream_oauth_identifier_id: None,
            opa_policy_id: None,
            node_id: None,
        };
        let entry = IdeModelEntry::from_member(
            &member,
            "/ide/team".into(),
            Some("claude-3-5-sonnet".into()),
            Some("anthropic".into()),
            1_700_000_000,
        );

        assert_eq!(entry.id, "claude$reasoning");
        assert_eq!(entry.object, "model");
        assert_eq!(entry.created, 1_700_000_000);
        assert_eq!(entry.owned_by, "anthropic");
        let ext = &entry.agent_stream;
        assert_eq!(ext.route, "/ide/team");
        assert_eq!(ext.surface_id, "claude");
        assert_eq!(ext.variant_alias.as_deref(), Some("reasoning"));
        assert_eq!(ext.display_name, "Claude (Reasoning)");
        assert_eq!(ext.group.as_deref(), Some("Secure"));
        assert_eq!(ext.order, 5);
        assert!(ext.default);
        assert_eq!(ext.model.as_deref(), Some("claude-3-5-sonnet"));
        assert_eq!(ext.provider.as_deref(), Some("anthropic"));
        assert_eq!(ext.max_input_tokens, Some(200_000));
        assert_eq!(ext.max_output_tokens, Some(8_192));
        assert_eq!(ext.capabilities, vec!["tools".to_string(), "vision".to_string()]);
        assert_eq!(ext.description.as_deref(), Some("High-reasoning, PII-masked"));
    }

    #[test]
    fn from_member_falls_back_to_model_then_id_for_display_name() {
        // No explicit display name → falls back to the upstream model string.
        let mut member = IdeCatalogMember {
            pipe_id: "gpt4o".into(),
            variant_alias: None,
            mnemonic: None,
            display_name: None,
            group: None,
            order: 0,
            default: false,
            expose: true,
            metadata: None,
            upstream_oauth_identifier_id: None,
            opa_policy_id: None,
            node_id: None,
        };
        let by_model =
            IdeModelEntry::from_member(&member, "/ide".into(), Some("gpt-4o".into()), Some("openai".into()), 0);
        assert_eq!(
            by_model
                .agent_stream
                .display_name,
            "gpt-4o"
        );
        assert_eq!(by_model.owned_by, "openai");

        // No display name and no model → falls back to the canonical model id,
        // and an unknown provider surfaces as the sentinel owner.
        member.variant_alias = Some("fast".into());
        let by_id = IdeModelEntry::from_member(&member, "/ide".into(), None, None, 0);
        assert_eq!(
            by_id
                .agent_stream
                .display_name,
            "gpt4o$fast"
        );
        assert_eq!(by_id.owned_by, "agent-stream");
    }

    #[test]
    fn bootstrap_publishes_upstream_slots() {
        let auth = IdeClientAuth {
            provider: "entra".into(),
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            scopes: vec!["api://agent-stream/.default".into()],
            oauth_identifier_id: None,
        };
        let upstreams = vec![IdeUpstreamAuth {
            id: "copilot".into(),
            provider: "entra".into(),
            tenant_id: "tenant".into(),
            client_id: "graph-client".into(),
            scopes: vec!["https://graph.microsoft.com/Sites.Read.All".into()],
            oauth_identifier_id: None,
        }];
        let resp = IdeBootstrapResponse::for_client_and_upstreams(auth, upstreams);
        let value = serde_json::to_value(&resp).unwrap();
        assert_eq!(value["upstreams"][0]["id"], "copilot");
        assert_eq!(value["upstreams"][0]["client_id"], "graph-client");
        assert_eq!(value["models_path"], "/v1/models");

        // for_client_and_upstreams with no slots omits upstreams entirely (empty vec skipped).
        let bare = IdeBootstrapResponse::for_client_and_upstreams(
            IdeClientAuth {
                provider: "entra".into(),
                tenant_id: "t".into(),
                client_id: "c".into(),
                scopes: vec!["s".into()],
                oauth_identifier_id: None,
            },
            Vec::new(),
        );
        let bare_value = serde_json::to_value(&bare).unwrap();
        assert!(
            bare_value
                .get("upstreams")
                .is_none(),
            "empty upstreams should be skipped"
        );
    }

    #[test]
    fn from_member_publishes_upstream_auth_id() {
        let mut member = member_lit("gpt4o", None);
        member.upstream_oauth_identifier_id = Some("  copilot  ".into());
        let entry = IdeModelEntry::from_member(&member, "/ide".into(), Some("gpt-4o".into()), Some("openai".into()), 0);
        assert_eq!(
            entry
                .agent_stream
                .upstream_auth_id
                .as_deref(),
            Some("oauth:copilot"),
            "the synthesized slot id should be published"
        );
    }

    #[tokio::test]
    async fn resolve_client_auth_keeps_inline_when_reference_unresolvable() {
        // With no OAuth Identifier store registered (or an unknown id), the
        // inline values are kept and the internal reference id is never
        // published.
        let auth = IdeClientAuth {
            provider: "entra".into(),
            tenant_id: "inline-tenant".into(),
            client_id: "inline-client".into(),
            scopes: vec!["inline-scope".into()],
            oauth_identifier_id: Some("does-not-exist".into()),
        };
        let resolved = resolve_client_auth(auth).await;
        assert_eq!(resolved.tenant_id, "inline-tenant");
        assert_eq!(resolved.client_id, "inline-client");
        assert_eq!(resolved.scopes, vec!["inline-scope".to_string()]);
        assert!(
            resolved
                .oauth_identifier_id
                .is_none(),
            "reference id must never be published"
        );
    }

    #[tokio::test]
    async fn resolve_client_auth_reference_can_relax_validation() {
        // A reference-only block (blank inline entra fields) validates because
        // the profile is expected to supply them at publish time.
        let auth = IdeClientAuth {
            provider: "entra".into(),
            tenant_id: String::new(),
            client_id: String::new(),
            scopes: vec![],
            oauth_identifier_id: Some("some-profile".into()),
        };
        assert!(auth.validate().is_ok(), "reference-only client_auth should validate");
    }

    #[tokio::test]
    async fn resolve_upstreams_strips_reference_ids() {
        let slots = vec![IdeUpstreamAuth {
            id: "copilot".into(),
            provider: "entra".into(),
            tenant_id: "inline".into(),
            client_id: "inline".into(),
            scopes: vec!["inline".into()],
            oauth_identifier_id: Some("does-not-exist".into()),
        }];
        let resolved = resolve_upstreams(slots).await;
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].tenant_id, "inline");
        assert!(
            resolved[0]
                .oauth_identifier_id
                .is_none()
        );
    }

    #[test]
    fn member_upstream_profile_synthesizes_slot_and_publishes_id() {
        let mut member = member_lit("copilot-surface", None);
        member.upstream_oauth_identifier_id = Some("  prof-123  ".into());
        // The published model entry points at the deterministic synthesized slot.
        assert_eq!(
            member
                .published_upstream_auth_id()
                .as_deref(),
            Some("oauth:prof-123")
        );

        let cfg = IdeCatalogConfig {
            members: vec![member],
            client_auth: None,
        };
        let slots = cfg.synthesized_upstreams();
        assert_eq!(slots.len(), 1, "one synthesized slot from the member profile");
        assert_eq!(slots[0].id, "oauth:prof-123");
        assert_eq!(
            slots[0]
                .oauth_identifier_id
                .as_deref(),
            Some("prof-123")
        );
    }

    #[test]
    fn synthesized_upstreams_dedupes_shared_member_profiles() {
        let mut a = member_lit("a", None);
        a.upstream_oauth_identifier_id = Some("shared".into());
        let mut b = member_lit("b", None);
        b.upstream_oauth_identifier_id = Some("shared".into());
        let cfg = IdeCatalogConfig {
            members: vec![a, b],
            client_auth: None,
        };
        let slots = cfg.synthesized_upstreams();
        assert_eq!(slots.len(), 1, "two members sharing a profile yield one slot");
        assert_eq!(slots[0].id, "oauth:shared");
    }
}
