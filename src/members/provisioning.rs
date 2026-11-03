//! On-the-fly member auto-provisioning.
//!
//! When a surface opts in (`team_attribution.auto_provision`) and a **verified**
//! caller (JWT / mTLS / API key) presents an identity that maps to no existing
//! [`crate::members::Member`], the appliance can mint a member on first sight
//! and assign it to teams — driven by an appliance-level, admin-owned
//! [`MemberProvisioningConfig`] rather than per-surface rules.
//!
//! ## Trust boundary
//!
//! Provisioning reads identifiers **only** from the authenticated identity
//! ([`ProvisioningSource`] extracts from JWT claims / the JWT subject / mTLS
//! certificate fields / the API-key name — never from a caller-controlled header
//! or request body). This is enforced structurally: there is no `Header` or
//! `BodyJsonPath` provisioning source. A surface that locates the caller from a
//! spoofable header can still *attribute* usage, but it can never *create* a
//! member.
//!
//! ## Concurrency
//!
//! First-sight provisioning is rare (once per identity, then the member is in
//! the store and every later request resolves it directly). The whole
//! resolve-or-create-and-assign critical section runs under a single async
//! mutex, so concurrent first-sight requests for the same *or different*
//! identities can never double-create a member or race a team's membership
//! list. The cost is negligible because the mutex is only reached on the
//! first-sight path.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use crate::members::store::FileSystemMemberStore;
use crate::members::types::{Member, MemberIdentifier, is_plausible_email, normalize_identifier};
use crate::source_auth::AuthenticatedIdentity;
use crate::teams::store::FileSystemTeamStore;
use crate::teams::types::Team;

/// Trailing window for the per-minute creation guard.
const CREATION_WINDOW_SECS: i64 = 60;

/// Filename of the member auto-provisioning config within its storage directory.
const PROVISIONING_CONFIG_FILENAME: &str = "member_provisioning.json";

/// Process-wide member provisioner, registered at startup so the data-plane team
/// gate can auto-provision a caller without threading it through every handler.
static GLOBAL_MEMBER_PROVISIONER: OnceLock<Arc<MemberProvisioner>> = OnceLock::new();

/// Register the process-wide member provisioner. First write wins.
pub fn set_global_member_provisioner(provisioner: Arc<MemberProvisioner>) {
    let _ = GLOBAL_MEMBER_PROVISIONER.set(provisioner);
}

/// Access the process-wide member provisioner, if one has been registered.
pub fn global_member_provisioner() -> Option<Arc<MemberProvisioner>> {
    GLOBAL_MEMBER_PROVISIONER
        .get()
        .cloned()
}

/// A verified place to read a caller identifier from for provisioning. Unlike
/// [`crate::teams::caller_identity::CallerIdentitySource`], this cannot read a
/// caller-controlled header or request body — every variant reads a credential
/// the appliance itself verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProvisioningSource {
    /// A claim on the verified JWT bearer token (e.g. `oid`, `email`, `sub`).
    JwtClaim { claim: String },
    /// The JWT `sub` claim.
    JwtSubject,
    /// The `CN=` of the verified mTLS client-certificate subject DN.
    MtlsSubjectCn,
    /// The first `email` SAN of the verified mTLS client certificate.
    MtlsEmailSan,
    /// The validated API key's name.
    ApiKeyName,
}

/// Which [`MemberIdentifier`] variant a derived value is stored as.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierKind {
    Email,
    Subject,
    ApiKey,
    Custom,
}

impl ProvisioningSource {
    /// The default identifier kind for this source when a rule doesn't override
    /// it. Chosen conservatively — a claim of unknown shape becomes `Custom`
    /// (which never fails email validation).
    fn default_kind(&self) -> IdentifierKind {
        match self {
            ProvisioningSource::JwtClaim { .. } => IdentifierKind::Custom,
            ProvisioningSource::JwtSubject => IdentifierKind::Subject,
            ProvisioningSource::MtlsSubjectCn => IdentifierKind::Custom,
            ProvisioningSource::MtlsEmailSan => IdentifierKind::Email,
            ProvisioningSource::ApiKeyName => IdentifierKind::ApiKey,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if let ProvisioningSource::JwtClaim { claim } = self
            && claim.trim().is_empty()
        {
            return Err("provisioning JWT claim must not be empty".to_string());
        }
        Ok(())
    }
}

/// One rule deriving a member identifier from the verified caller identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProvisioningIdentifierRule {
    pub source: ProvisioningSource,
    /// Store the derived value as this identifier kind. Omitted ⇒ the source's
    /// natural default kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_kind: Option<IdentifierKind>,
}

/// Defaults stamped on a freshly auto-provisioned member.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemberDefaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_budget_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_token_cap: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_per_minute: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
}

/// Team-level caps stamped on a team that a rule ensures into existence.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TeamDefaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_budget_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_token_cap: Option<u64>,
}

/// A predicate over the caller's verified JWT claims. Non-JWT identities never
/// match a claim predicate (the rule is simply skipped for them).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TeamRuleMatch {
    /// The claim equals `equals` (string comparison, case-insensitive).
    #[serde(rename = "claim_equals")]
    Equals { claim: String, equals: String },
    /// The claim is (or contains, for an array claim) `contains`.
    #[serde(rename = "claim_contains")]
    Contains { claim: String, contains: String },
    /// The claim is present and non-null.
    #[serde(rename = "claim_present")]
    Present { claim: String },
}

impl TeamRuleMatch {
    fn claim(&self) -> &str {
        match self {
            TeamRuleMatch::Equals { claim, .. }
            | TeamRuleMatch::Contains { claim, .. }
            | TeamRuleMatch::Present { claim } => claim,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.claim().trim().is_empty() {
            return Err("team rule claim must not be empty".to_string());
        }
        Ok(())
    }

    /// Evaluate the predicate against the caller's JWT claims (if any).
    fn matches(
        &self,
        claims: Option<&serde_json::Value>,
    ) -> bool {
        let Some(claims) = claims else {
            return false;
        };
        match self {
            TeamRuleMatch::Equals { claim, equals } => claims
                .get(claim)
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case(equals))
                .unwrap_or(false),
            TeamRuleMatch::Contains { claim, contains } => match claims.get(claim) {
                Some(serde_json::Value::Array(items)) => items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .any(|s| s.eq_ignore_ascii_case(contains)),
                Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case(contains),
                _ => false,
            },
            TeamRuleMatch::Present { claim } => claims
                .get(claim)
                .map(|v| !v.is_null())
                .unwrap_or(false),
        }
    }
}

/// A team-assignment rule. When `when` matches (or is absent = always), the
/// member is added to the resolved team.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TeamAssignmentRule {
    /// Predicate over the caller's claims; `None` = always applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<TeamRuleMatch>,
    /// A fixed team id to add the member to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// A team id derived from claim values, e.g. `tenant-{{claim.tid}}`. The
    /// result is slug-sanitised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id_template: Option<String>,
    /// When set, create the resolved team if it doesn't exist. When clear, a
    /// rule referencing a non-existent team is skipped.
    #[serde(default)]
    pub ensure_team: bool,
    /// Display name for a team created via `ensure_team`. Supports `{{claim.X}}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_name_template: Option<String>,
    /// Caps for a team created via `ensure_team`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_defaults: Option<TeamDefaults>,
}

impl TeamAssignmentRule {
    fn validate(&self) -> Result<(), String> {
        if let Some(when) = &self.when {
            when.validate()?;
        }
        let has_fixed = self
            .team_id
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());
        let has_template = self
            .team_id_template
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());
        if !has_fixed && !has_template {
            return Err("a team rule must set team_id or team_id_template".to_string());
        }
        Ok(())
    }
}

/// Appliance-level auto-provisioning configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemberProvisioningConfig {
    /// Master switch. When clear, no caller is ever auto-provisioned regardless
    /// of a surface's `auto_provision` opt-in.
    #[serde(default)]
    pub enabled: bool,
    /// Ordered identifier-derivation rules. A provisioned member carries every
    /// identifier that resolves (deduped), so the same caller resolves under any
    /// of them next time. At least one is required when enabled.
    #[serde(default)]
    pub identifier_rules: Vec<ProvisioningIdentifierRule>,
    /// JWT claim to use as the member's display name (e.g. `name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_claim: Option<String>,
    /// Defaults stamped on each new member.
    #[serde(default)]
    pub member_defaults: MemberDefaults,
    /// Team-assignment rules, evaluated top-down; a member may match several.
    #[serde(default)]
    pub team_rules: Vec<TeamAssignmentRule>,
    /// Hard ceiling on how many auto-provisioned members may exist. Once
    /// reached, no further members are minted (a safety net against a hostile
    /// token issuer filling the disk). `None` = unbounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_auto_provisioned_members: Option<usize>,
    /// Max member creations per minute across the appliance. `None` = unbounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creations_per_minute: Option<u32>,
}

impl MemberProvisioningConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self
            .identifier_rules
            .is_empty()
        {
            return Err("auto-provisioning requires at least one identifier rule".to_string());
        }
        for rule in &self.identifier_rules {
            rule.source.validate()?;
        }
        for rule in &self.team_rules {
            rule.validate()?;
        }
        if let Some(0) = self.max_auto_provisioned_members {
            return Err("max_auto_provisioned_members must be greater than zero".to_string());
        }
        if let Some(0) = self.creations_per_minute {
            return Err("creations_per_minute must be greater than zero".to_string());
        }
        Ok(())
    }
}

/// A team that a rule resolved to, before it is created/looked up.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedTeamRule {
    pub team_id: String,
    pub ensure: bool,
    pub name: String,
    pub defaults: Option<TeamDefaults>,
}

/// The outcome of a provisioning attempt.
#[derive(Debug, Clone)]
pub struct ProvisionOutcome {
    /// The resolved member (freshly created, or an existing one found under the
    /// lock when a concurrent request won the race).
    pub member: Member,
    /// Every team the member now belongs to that this call resolved.
    pub teams: Vec<Team>,
    /// `true` when this call actually created the member.
    pub created: bool,
}

/// A read-only preview of what provisioning *would* do for a given identity,
/// without writing anything. Backs the admin dry-run endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct ProvisionPreview {
    /// Whether provisioning is enabled and would run for this identity.
    pub would_provision: bool,
    /// The identifiers that would be minted (as `{kind, value}`).
    pub identifiers: Vec<PreviewIdentifier>,
    /// The display name that would be assigned.
    pub name: Option<String>,
    /// The teams the member would be assigned to.
    pub teams: Vec<PreviewTeam>,
    /// Human-readable reason when `would_provision` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewIdentifier {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreviewTeam {
    pub team_id: String,
    pub name: String,
    /// `true` when the team would be created by this rule (`ensure_team`).
    pub would_create: bool,
}

/// Pull the `CN=` component out of an RFC 4514 subject DN.
fn cn_from_subject_dn(subject_dn: &str) -> Option<String> {
    subject_dn
        .split(',')
        .map(str::trim)
        .find_map(|rdn| {
            rdn.strip_prefix("CN=")
                .or_else(|| rdn.strip_prefix("cn="))
        })
        .map(|s| s.to_string())
}

/// The caller's verified JWT claims, if the identity is a JWT bearer.
fn identity_claims(identity: &AuthenticatedIdentity) -> Option<&serde_json::Value> {
    match identity {
        AuthenticatedIdentity::JwtBearer { claims, .. } => Some(claims),
        _ => None,
    }
}

/// Extract a raw value for `source` from the verified identity.
fn extract_source_value(
    source: &ProvisioningSource,
    identity: &AuthenticatedIdentity,
) -> Option<String> {
    let raw = match source {
        ProvisioningSource::JwtClaim { claim } => identity_claims(identity)
            .and_then(|c| c.get(claim))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        ProvisioningSource::JwtSubject => match identity {
            AuthenticatedIdentity::JwtBearer { subject, .. } => Some(subject.clone()),
            _ => None,
        },
        ProvisioningSource::MtlsSubjectCn => match identity {
            AuthenticatedIdentity::Mtls { subject_dn, .. } => cn_from_subject_dn(subject_dn),
            _ => None,
        },
        ProvisioningSource::MtlsEmailSan => match identity {
            AuthenticatedIdentity::Mtls { sans, .. } => sans.email.first().cloned(),
            _ => None,
        },
        ProvisioningSource::ApiKeyName => match identity {
            AuthenticatedIdentity::ApiKey { key_name } => Some(key_name.clone()),
            _ => None,
        },
    };
    raw.map(|s| normalize_identifier(&s))
        .filter(|s| !s.is_empty())
}

/// Build a [`MemberIdentifier`] of the given kind from a value, downgrading an
/// implausible email to `Custom` so a non-email claim never fails validation.
fn to_identifier(
    kind: IdentifierKind,
    value: String,
) -> MemberIdentifier {
    match kind {
        IdentifierKind::Email if is_plausible_email(&value) => MemberIdentifier::Email { email: value },
        IdentifierKind::Email => MemberIdentifier::Custom { value },
        IdentifierKind::Subject => MemberIdentifier::Subject { subject: value },
        IdentifierKind::ApiKey => MemberIdentifier::ApiKey { key_name: value },
        IdentifierKind::Custom => MemberIdentifier::Custom { value },
    }
}

/// Derive the member identifier list from the config and identity (deduped by
/// normalised value, order-preserving). Pure — shared by provisioning and
/// preview.
fn derive_identifiers(
    config: &MemberProvisioningConfig,
    identity: &AuthenticatedIdentity,
) -> Vec<MemberIdentifier> {
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<MemberIdentifier> = Vec::new();
    for rule in &config.identifier_rules {
        let Some(value) = extract_source_value(&rule.source, identity) else {
            continue;
        };
        if seen.contains(&value) {
            continue;
        }
        let kind = rule
            .as_kind
            .unwrap_or_else(|| rule.source.default_kind());
        let identifier = to_identifier(kind, value.clone());
        if identifier.validate().is_ok() {
            seen.push(value);
            out.push(identifier);
        }
    }
    out
}

/// Slug-sanitise a resolved team id so it is safe as a storage filename and a
/// telemetry-key segment (`[a-z0-9_-]`, non-empty).
fn sanitize_team_id(raw: &str) -> Option<String> {
    let slug: String = raw
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Substitute `{{claim.X}}` (from JWT claims) and `{{identifier}}` (the caller's
/// primary derived value) placeholders in `template`.
fn render_template(
    template: &str,
    claims: Option<&serde_json::Value>,
    primary_identifier: &str,
) -> String {
    let mut out = template.to_string();
    out = out.replace("{{identifier}}", primary_identifier);
    // Replace each {{claim.NAME}} occurrence.
    while let Some(start) = out.find("{{claim.") {
        let Some(end_rel) = out[start..].find("}}") else {
            break;
        };
        let end = start + end_rel;
        let token = &out[start + "{{claim.".len()..end];
        let value = claims
            .and_then(|c| c.get(token))
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        out.replace_range(start..end + 2, &value);
    }
    out
}

/// Resolve the team rules that apply to this identity into concrete team ids.
/// Pure — shared by provisioning and preview.
fn resolve_team_rules(
    config: &MemberProvisioningConfig,
    identity: &AuthenticatedIdentity,
    primary_identifier: &str,
) -> Vec<ResolvedTeamRule> {
    let claims = identity_claims(identity);
    let mut out: Vec<ResolvedTeamRule> = Vec::new();
    for rule in &config.team_rules {
        if let Some(when) = &rule.when
            && !when.matches(claims)
        {
            continue;
        }
        let raw_id = if let Some(fixed) = rule
            .team_id
            .as_ref()
            .filter(|s| !s.trim().is_empty())
        {
            fixed.clone()
        } else if let Some(template) = &rule.team_id_template {
            render_template(template, claims, primary_identifier)
        } else {
            continue;
        };
        let Some(team_id) = sanitize_team_id(&raw_id) else {
            continue;
        };
        let name = rule
            .team_name_template
            .as_ref()
            .map(|t| render_template(t, claims, primary_identifier))
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| team_id.clone());
        if out
            .iter()
            .any(|r| r.team_id == team_id)
        {
            continue;
        }
        out.push(ResolvedTeamRule {
            team_id,
            ensure: rule.ensure_team,
            name,
            defaults: rule.team_defaults.clone(),
        });
    }
    out
}

/// The member provisioner: owns the config, the member/team stores, and the
/// single first-sight critical-section mutex + creation-rate window.
pub struct MemberProvisioner {
    config: RwLock<MemberProvisioningConfig>,
    storage_path: PathBuf,
    member_store: Arc<FileSystemMemberStore>,
    team_store: Arc<FileSystemTeamStore>,
    /// Serialises the resolve-or-create-and-assign critical section.
    provision_lock: Mutex<()>,
    /// Trailing timestamps of member creations for the per-minute guard.
    creation_window: Mutex<VecDeque<i64>>,
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for MemberProvisioner {
    /// Re-read the provisioning config another instance saved. A missing or
    /// invalid file keeps the current config; a storage error is returned so
    /// the reload is retried.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        if let Some(config) = Self::load_from_disk(&self.storage_path).await? {
            *self.config.write().await = config;
        }
        Ok(())
    }
}

impl MemberProvisioner {
    /// Construct a provisioner, loading the config from the `storage_dir`
    /// directory (the config is stored as `member_provisioning.json` inside it)
    /// when present, else starting disabled.
    pub async fn new(
        storage_dir: impl Into<PathBuf>,
        member_store: Arc<FileSystemMemberStore>,
        team_store: Arc<FileSystemTeamStore>,
    ) -> Self {
        let storage_path = storage_dir
            .into()
            .join(PROVISIONING_CONFIG_FILENAME);
        let config = Self::load_from_disk(&storage_path)
            .await
            .unwrap_or_else(|e| {
                warn!("Failed to read member provisioning config {}: {e}", storage_path.display());
                None
            })
            .unwrap_or_default();
        Self {
            config: RwLock::new(config),
            storage_path,
            member_store,
            team_store,
            provision_lock: Mutex::new(()),
            creation_window: Mutex::new(VecDeque::new()),
        }
    }

    /// The stored config, or `None` when the file is missing or invalid.
    async fn load_from_disk(path: &PathBuf) -> std::io::Result<Option<MemberProvisioningConfig>> {
        let bytes = match tokio::fs::read(path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        match serde_json::from_slice::<MemberProvisioningConfig>(&bytes) {
            Ok(config) => Ok(Some(config)),
            Err(e) => {
                warn!("Failed to parse member provisioning config {}: {e}", path.display());
                Ok(None)
            }
        }
    }

    /// A clone of the current config (for the admin read endpoint).
    pub async fn config(&self) -> MemberProvisioningConfig {
        self.config
            .read()
            .await
            .clone()
    }

    /// Replace the config after validation, persisting it atomically to disk.
    pub async fn update_config(
        &self,
        new_config: MemberProvisioningConfig,
    ) -> Result<(), String> {
        new_config.validate()?;
        if let Some(parent) = self.storage_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let bytes = serde_json::to_vec_pretty(&new_config).map_err(|e| e.to_string())?;
        let tmp = self
            .storage_path
            .with_extension("json.tmp");
        tokio::fs::write(&tmp, &bytes)
            .await
            .map_err(|e| e.to_string())?;
        tokio::fs::rename(&tmp, &self.storage_path)
            .await
            .map_err(|e| e.to_string())?;
        *self.config.write().await = new_config;
        Ok(())
    }

    /// Whether the per-minute creation guard currently allows another creation.
    /// Prunes expired entries; does **not** record (call [`Self::note_creation`]
    /// on an actual creation).
    async fn creation_allowed(
        &self,
        limit: u32,
    ) -> bool {
        let now = Utc::now().timestamp();
        let cutoff = now - CREATION_WINDOW_SECS;
        let mut window = self
            .creation_window
            .lock()
            .await;
        while window
            .front()
            .is_some_and(|ts| *ts < cutoff)
        {
            window.pop_front();
        }
        (window.len() as u32) < limit
    }

    async fn note_creation(&self) {
        self.creation_window
            .lock()
            .await
            .push_back(Utc::now().timestamp());
    }

    /// Preview what provisioning would do for `identity` using the stored
    /// config, without writing.
    pub async fn preview(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> ProvisionPreview {
        let config = self.config().await;
        self.preview_with_config(&config, identity)
            .await
    }

    /// Preview what provisioning would do for `identity` against an
    /// explicitly-supplied `config` (e.g. an operator's unsaved editor state),
    /// without writing. Team existence is still checked against the live team
    /// store so `would_create` stays accurate.
    pub async fn preview_with_config(
        &self,
        config: &MemberProvisioningConfig,
        identity: &AuthenticatedIdentity,
    ) -> ProvisionPreview {
        if !config.enabled {
            return ProvisionPreview {
                would_provision: false,
                identifiers: Vec::new(),
                name: None,
                teams: Vec::new(),
                reason: Some("auto-provisioning is disabled".to_string()),
            };
        }
        let identifiers = derive_identifiers(config, identity);
        if identifiers.is_empty() {
            return ProvisionPreview {
                would_provision: false,
                identifiers: Vec::new(),
                name: None,
                teams: Vec::new(),
                reason: Some("no identifier could be derived from this identity".to_string()),
            };
        }
        let primary = identifiers[0].match_value();
        let resolved = resolve_team_rules(config, identity, &primary);
        let mut teams = Vec::new();
        for rule in resolved {
            // Prefer the live team's real name for an existing team so the
            // preview shows e.g. "Engineering" rather than an opaque id.
            let existing = self
                .team_store
                .get(&rule.team_id)
                .await
                .filter(|t| !t.status.is_deleted());
            let (name, exists) = match existing {
                Some(team) => (team.name, true),
                None => (rule.name, false),
            };
            teams.push(PreviewTeam {
                team_id: rule.team_id,
                name,
                would_create: !exists && rule.ensure,
            });
        }
        let name = config
            .name_claim
            .as_ref()
            .and_then(|claim| identity_claims(identity).and_then(|c| c.get(claim)))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        ProvisionPreview {
            would_provision: true,
            identifiers: identifiers
                .iter()
                .map(preview_identifier)
                .collect(),
            name,
            teams,
            reason: None,
        }
    }

    /// Resolve-or-create the member for `identity` and assign teams. Returns
    /// `None` when provisioning is disabled, no identifier can be derived, or a
    /// guardrail (cap / rate limit) blocks creation. Runs the whole critical
    /// section under the provisioning mutex so it is race-free.
    pub async fn provision(
        &self,
        identity: &AuthenticatedIdentity,
    ) -> Option<ProvisionOutcome> {
        let config = self.config().await;
        if !config.enabled {
            return None;
        }
        let identifiers = derive_identifiers(&config, identity);
        if identifiers.is_empty() {
            return None;
        }

        let _guard = self
            .provision_lock
            .lock()
            .await;

        // Under the lock, re-check: a concurrent request may have created the
        // member, or it may already exist under any derived identifier.
        for identifier in &identifiers {
            if let Some(existing) = self
                .member_store
                .find_for_gate(&identifier.match_value())
                .await
            {
                let teams = self
                    .team_store
                    .teams_for_member(&existing.id)
                    .await;
                return Some(ProvisionOutcome {
                    member: existing,
                    teams,
                    created: false,
                });
            }
        }

        // Guardrails: hard population cap and per-minute creation rate.
        if let Some(max) = config.max_auto_provisioned_members {
            let count = self
                .member_store
                .list()
                .await
                .into_iter()
                .filter(|m| m.auto_provisioned && !m.status.is_deleted())
                .count();
            if count >= max {
                warn!("Auto-provisioning refused: reached max_auto_provisioned_members ({max})");
                return None;
            }
        }
        if let Some(limit) = config.creations_per_minute
            && !self
                .creation_allowed(limit)
                .await
        {
            warn!("Auto-provisioning refused: creations_per_minute ({limit}) exceeded");
            return None;
        }

        let primary = identifiers[0].match_value();
        let name = config
            .name_claim
            .as_ref()
            .and_then(|claim| identity_claims(identity).and_then(|c| c.get(claim)))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let now = Utc::now();
        let member = Member {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description: Some("Auto-provisioned on first sight from a verified caller identity.".to_string()),
            status: crate::entity_status::EntityStatus::Enabled,
            system: false,
            tenant_id: None,
            test_fixture: false,
            auto_provisioned: true,
            identifiers,
            monthly_budget_usd: config
                .member_defaults
                .monthly_budget_usd,
            monthly_token_cap: config
                .member_defaults
                .monthly_token_cap,
            budget_period_anchor: None,
            requests_per_minute: config
                .member_defaults
                .requests_per_minute,
            tokens_per_minute: config
                .member_defaults
                .tokens_per_minute,
            allowed_models: config
                .member_defaults
                .allowed_models
                .clone(),
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = member.validate() {
            warn!("Auto-provisioning produced an invalid member: {e}");
            return None;
        }
        if let Err(e) = self
            .member_store
            .save(member.clone())
            .await
        {
            warn!("Auto-provisioning failed to save member: {e}");
            return None;
        }
        self.note_creation().await;

        // Assign teams per the rules. Each ensure/lookup + membership update runs
        // under the same lock, so team membership can't race.
        let resolved = resolve_team_rules(&config, identity, &primary);
        let mut teams: Vec<Team> = Vec::new();
        for rule in resolved {
            let team = match self
                .team_store
                .get(&rule.team_id)
                .await
            {
                Some(mut team) => {
                    if team.status.is_deleted() {
                        continue;
                    }
                    if !team.has_member(&member.id) {
                        team.members
                            .push(member.id.clone());
                        if let Err(e) = self
                            .team_store
                            .save(team.clone())
                            .await
                        {
                            warn!("Auto-provisioning failed to update team '{}': {e}", rule.team_id);
                            continue;
                        }
                    }
                    team
                }
                None if rule.ensure => {
                    let defaults = rule
                        .defaults
                        .unwrap_or_default();
                    let team = Team {
                        id: rule.team_id.clone(),
                        name: rule.name.clone(),
                        description: Some("Auto-created by member provisioning.".to_string()),
                        status: crate::entity_status::EntityStatus::Enabled,
                        system: false,
                        tenant_id: None,
                        test_fixture: false,
                        monthly_budget_usd: defaults.monthly_budget_usd,
                        monthly_token_cap: defaults.monthly_token_cap,
                        members: vec![member.id.clone()],
                        created_at: now,
                        updated_at: now,
                    };
                    if let Err(e) = self
                        .team_store
                        .save(team.clone())
                        .await
                    {
                        warn!("Auto-provisioning failed to create team '{}': {e}", rule.team_id);
                        continue;
                    }
                    team
                }
                None => {
                    warn!(
                        "Auto-provisioning rule references non-existent team '{}' (ensure_team not set) — skipping",
                        rule.team_id
                    );
                    continue;
                }
            };
            teams.push(team);
        }

        info!(
            member_id = %member.id,
            identifier = %primary,
            teams = teams.len(),
            "Auto-provisioned member from verified caller identity"
        );
        Some(ProvisionOutcome { member, teams, created: true })
    }
}

fn preview_identifier(identifier: &MemberIdentifier) -> PreviewIdentifier {
    let (kind, value) = match identifier {
        MemberIdentifier::Email { email } => ("email", email.clone()),
        MemberIdentifier::Subject { subject } => ("subject", subject.clone()),
        MemberIdentifier::ApiKey { key_name } => ("api_key", key_name.clone()),
        MemberIdentifier::Custom { value } => ("custom", value.clone()),
    };
    PreviewIdentifier { kind: kind.to_string(), value }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(claims: serde_json::Value) -> AuthenticatedIdentity {
        AuthenticatedIdentity::JwtBearer {
            subject: "sub-abc".to_string(),
            claims,
        }
    }

    fn base_config() -> MemberProvisioningConfig {
        MemberProvisioningConfig {
            enabled: true,
            identifier_rules: vec![
                ProvisioningIdentifierRule {
                    source: ProvisioningSource::JwtClaim { claim: "oid".to_string() },
                    as_kind: Some(IdentifierKind::Subject),
                },
                ProvisioningIdentifierRule {
                    source: ProvisioningSource::JwtClaim { claim: "email".to_string() },
                    as_kind: Some(IdentifierKind::Email),
                },
            ],
            name_claim: Some("name".to_string()),
            member_defaults: MemberDefaults {
                monthly_budget_usd: Some(10.0),
                ..Default::default()
            },
            team_rules: vec![
                TeamAssignmentRule {
                    when: None,
                    team_id: Some("auto-provisioned".to_string()),
                    team_id_template: None,
                    ensure_team: true,
                    team_name_template: Some("Auto-provisioned".to_string()),
                    team_defaults: None,
                },
                TeamAssignmentRule {
                    when: Some(TeamRuleMatch::Contains {
                        claim: "groups".to_string(),
                        contains: "engineering".to_string(),
                    }),
                    team_id: Some("engineering".to_string()),
                    team_id_template: None,
                    ensure_team: false,
                    team_name_template: None,
                    team_defaults: None,
                },
                TeamAssignmentRule {
                    when: Some(TeamRuleMatch::Present { claim: "tid".to_string() }),
                    team_id: None,
                    team_id_template: Some("tenant-{{claim.tid}}".to_string()),
                    ensure_team: true,
                    team_name_template: Some("Tenant {{claim.tid}}".to_string()),
                    team_defaults: Some(TeamDefaults {
                        monthly_budget_usd: Some(500.0),
                        monthly_token_cap: None,
                    }),
                },
            ],
            max_auto_provisioned_members: Some(100),
            creations_per_minute: Some(60),
        }
    }

    #[test]
    fn validate_requires_identifier_rule_when_enabled() {
        let mut c = base_config();
        c.identifier_rules.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_team_rule_without_target() {
        let mut c = base_config();
        c.team_rules = vec![TeamAssignmentRule {
            when: None,
            team_id: None,
            team_id_template: None,
            ensure_team: false,
            team_name_template: None,
            team_defaults: None,
        }];
        assert!(c.validate().is_err());
    }

    #[test]
    fn derive_identifiers_picks_all_matching_rules() {
        let identity = jwt(serde_json::json!({ "oid": "OID-1", "email": "Dev@Team.io" }));
        let ids = derive_identifiers(&base_config(), &identity);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].match_value(), "oid-1");
        assert_eq!(ids[1].match_value(), "dev@team.io");
        assert!(matches!(ids[1], MemberIdentifier::Email { .. }));
    }

    #[test]
    fn derive_identifiers_downgrades_non_email_to_custom() {
        let mut config = base_config();
        config.identifier_rules = vec![ProvisioningIdentifierRule {
            source: ProvisioningSource::JwtClaim { claim: "oid".to_string() },
            as_kind: Some(IdentifierKind::Email),
        }];
        let identity = jwt(serde_json::json!({ "oid": "not-an-email" }));
        let ids = derive_identifiers(&config, &identity);
        assert_eq!(ids.len(), 1);
        assert!(matches!(ids[0], MemberIdentifier::Custom { .. }));
    }

    #[test]
    fn team_rules_match_group_and_tenant() {
        let identity = jwt(serde_json::json!({
            "oid": "oid-1",
            "email": "dev@team.io",
            "groups": ["engineering", "all"],
            "tid": "acme"
        }));
        let resolved = resolve_team_rules(&base_config(), &identity, "oid-1");
        let ids: Vec<&str> = resolved
            .iter()
            .map(|r| r.team_id.as_str())
            .collect();
        assert_eq!(ids, vec!["auto-provisioned", "engineering", "tenant-acme"]);
        // The tenant team is templated + ensured.
        let tenant = resolved
            .iter()
            .find(|r| r.team_id == "tenant-acme")
            .unwrap();
        assert!(tenant.ensure);
        assert_eq!(tenant.name, "Tenant acme");
    }

    #[test]
    fn team_rules_skip_unmatched_group() {
        let identity = jwt(serde_json::json!({ "oid": "oid-1", "groups": ["marketing"] }));
        let resolved = resolve_team_rules(&base_config(), &identity, "oid-1");
        let ids: Vec<&str> = resolved
            .iter()
            .map(|r| r.team_id.as_str())
            .collect();
        // Only the unconditional rule applies (no groups match, no tid present).
        assert_eq!(ids, vec!["auto-provisioned"]);
    }

    #[test]
    fn render_template_substitutes_claim_and_identifier() {
        let claims = serde_json::json!({ "tid": "acme" });
        assert_eq!(render_template("tenant-{{claim.tid}}", Some(&claims), "id"), "tenant-acme");
        assert_eq!(render_template("m-{{identifier}}", Some(&claims), "user-1"), "m-user-1");
    }

    #[test]
    fn sanitize_team_id_slugifies() {
        assert_eq!(sanitize_team_id("Tenant ACME!"), Some("tenant-acme".to_string()));
        assert_eq!(sanitize_team_id("  --  "), None);
    }

    async fn stores() -> (Arc<FileSystemMemberStore>, Arc<FileSystemTeamStore>) {
        let mdir = std::env::temp_dir().join(format!("prov_m_{}", uuid::Uuid::new_v4()));
        let tdir = std::env::temp_dir().join(format!("prov_t_{}", uuid::Uuid::new_v4()));
        let m = Arc::new(
            FileSystemMemberStore::new(
                mdir.to_string_lossy()
                    .to_string(),
            )
            .await
            .unwrap(),
        );
        let t = Arc::new(
            FileSystemTeamStore::new(
                tdir.to_string_lossy()
                    .to_string(),
            )
            .await
            .unwrap(),
        );
        (m, t)
    }

    async fn provisioner(config: MemberProvisioningConfig) -> MemberProvisioner {
        let (m, t) = stores().await;
        let dir = std::env::temp_dir().join(format!("prov_cfg_{}", uuid::Uuid::new_v4()));
        let p = MemberProvisioner::new(dir, m, t).await;
        p.update_config(config)
            .await
            .unwrap();
        p
    }

    #[tokio::test]
    async fn reload_picks_up_the_config_another_instance_saved() {
        use crate::server::mode::ReloadOnPromotion;

        let dir = std::env::temp_dir().join(format!("prov_shared_{}", uuid::Uuid::new_v4()));
        let (m, t) = stores().await;
        let standby = MemberProvisioner::new(dir.clone(), m.clone(), t.clone()).await;
        let active = MemberProvisioner::new(dir.clone(), m, t).await;
        active
            .update_config(base_config())
            .await
            .unwrap();
        assert!(!standby.config().await.enabled);

        standby
            .reload_from_storage()
            .await
            .unwrap();
        assert_eq!(standby.config().await, base_config());

        tokio::fs::write(dir.join(PROVISIONING_CONFIG_FILENAME), "not json")
            .await
            .unwrap();
        standby
            .reload_from_storage()
            .await
            .unwrap();
        assert_eq!(standby.config().await, base_config(), "an invalid file keeps the current config");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn reload_from_unreadable_storage_fails_and_keeps_the_config() {
        use crate::server::mode::ReloadOnPromotion;

        let dir = std::env::temp_dir().join(format!("prov_unreadable_{}", uuid::Uuid::new_v4()));
        let (m, t) = stores().await;
        let provisioner = MemberProvisioner::new(dir.clone(), m, t).await;
        provisioner
            .update_config(base_config())
            .await
            .unwrap();
        let config_path = dir.join(PROVISIONING_CONFIG_FILENAME);
        tokio::fs::remove_file(&config_path)
            .await
            .unwrap();
        tokio::fs::create_dir(&config_path)
            .await
            .unwrap();

        assert!(
            provisioner
                .reload_from_storage()
                .await
                .is_err(),
            "a read error is retried, not read as a missing config"
        );
        assert_eq!(provisioner.config().await, base_config());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn provision_creates_member_and_teams() {
        let p = provisioner(base_config()).await;
        let identity = jwt(serde_json::json!({
            "oid": "oid-1", "email": "dev@team.io", "name": "Dev One",
            "groups": ["engineering"], "tid": "acme"
        }));
        let outcome = p
            .provision(&identity)
            .await
            .expect("provisioned");
        assert!(outcome.created);
        assert!(
            outcome
                .member
                .auto_provisioned
        );
        assert_eq!(outcome.member.name.as_deref(), Some("Dev One"));
        assert_eq!(
            outcome
                .member
                .monthly_budget_usd,
            Some(10.0)
        );
        // auto-provisioned team + tenant team ensured (engineering doesn't exist
        // and isn't ensured, so it's skipped).
        let team_ids: Vec<&str> = outcome
            .teams
            .iter()
            .map(|t| t.id.as_str())
            .collect();
        assert!(team_ids.contains(&"auto-provisioned"));
        assert!(team_ids.contains(&"tenant-acme"));
        assert!(!team_ids.contains(&"engineering"));
    }

    #[tokio::test]
    async fn provision_is_idempotent_for_same_identity() {
        let p = provisioner(base_config()).await;
        let identity = jwt(serde_json::json!({ "oid": "oid-1", "email": "dev@team.io" }));
        let first = p
            .provision(&identity)
            .await
            .expect("first");
        assert!(first.created);
        let second = p
            .provision(&identity)
            .await
            .expect("second");
        assert!(!second.created);
        assert_eq!(first.member.id, second.member.id);
        // Only one member exists.
        let count = first.member.id;
        assert_eq!(
            p.member_store
                .list()
                .await
                .len(),
            1,
            "member {count} not duplicated"
        );
    }

    #[tokio::test]
    async fn provision_respects_population_cap() {
        let mut config = base_config();
        config.max_auto_provisioned_members = Some(1);
        let p = provisioner(config).await;
        let a = jwt(serde_json::json!({ "oid": "oid-a" }));
        let b = jwt(serde_json::json!({ "oid": "oid-b" }));
        assert!(
            p.provision(&a)
                .await
                .is_some()
        );
        assert!(
            p.provision(&b)
                .await
                .is_none(),
            "second creation blocked by cap"
        );
    }

    #[tokio::test]
    async fn provision_disabled_returns_none() {
        let mut config = base_config();
        config.enabled = false;
        let p = provisioner(MemberProvisioningConfig {
            enabled: false,
            ..MemberProvisioningConfig::default()
        })
        .await;
        let _ = config;
        let identity = jwt(serde_json::json!({ "oid": "oid-1" }));
        assert!(
            p.provision(&identity)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn preview_reports_would_create() {
        let p = provisioner(base_config()).await;
        let identity = jwt(serde_json::json!({
            "oid": "oid-1", "email": "dev@team.io", "name": "Dev", "tid": "acme"
        }));
        let preview = p.preview(&identity).await;
        assert!(preview.would_provision);
        assert_eq!(preview.identifiers.len(), 2);
        assert_eq!(preview.name.as_deref(), Some("Dev"));
        let tenant = preview
            .teams
            .iter()
            .find(|t| t.team_id == "tenant-acme")
            .unwrap();
        assert!(tenant.would_create);
        // Nothing was actually written.
        assert_eq!(
            p.member_store
                .list()
                .await
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn preview_with_config_reflects_supplied_config() {
        // Stored config is disabled, so the stored-config preview declines.
        let p = provisioner(MemberProvisioningConfig {
            enabled: false,
            ..MemberProvisioningConfig::default()
        })
        .await;
        let identity = jwt(serde_json::json!({
            "oid": "oid-1", "email": "dev@team.io", "name": "Dev", "tid": "acme"
        }));
        assert!(
            !p.preview(&identity)
                .await
                .would_provision
        );

        // An unsaved, enabled config supplied inline is honoured instead.
        let preview = p
            .preview_with_config(&base_config(), &identity)
            .await;
        assert!(preview.would_provision);
        assert_eq!(preview.name.as_deref(), Some("Dev"));
        // Still non-destructive.
        assert_eq!(
            p.member_store
                .list()
                .await
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn preview_shows_existing_team_real_name() {
        let config = MemberProvisioningConfig {
            enabled: true,
            identifier_rules: vec![ProvisioningIdentifierRule {
                source: ProvisioningSource::JwtClaim { claim: "oid".to_string() },
                as_kind: Some(IdentifierKind::Subject),
            }],
            name_claim: None,
            member_defaults: MemberDefaults::default(),
            team_rules: vec![TeamAssignmentRule {
                when: None,
                team_id: Some("eng-uuid".to_string()),
                team_id_template: None,
                ensure_team: false,
                team_name_template: None,
                team_defaults: None,
            }],
            max_auto_provisioned_members: None,
            creations_per_minute: None,
        };
        let p = provisioner(config).await;
        // Seed the existing team the fixed rule points at.
        let now = Utc::now();
        p.team_store
            .save(Team {
                id: "eng-uuid".to_string(),
                name: "Engineering".to_string(),
                description: None,
                status: crate::entity_status::EntityStatus::Enabled,
                system: false,
                tenant_id: None,
                test_fixture: false,
                monthly_budget_usd: None,
                monthly_token_cap: None,
                members: Vec::new(),
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
        let identity = jwt(serde_json::json!({ "oid": "oid-9" }));
        let preview = p.preview(&identity).await;
        let team = preview
            .teams
            .iter()
            .find(|t| t.team_id == "eng-uuid")
            .expect("existing team resolved");
        // The preview shows the team's real name, not its id, and won't recreate.
        assert_eq!(team.name, "Engineering");
        assert!(!team.would_create);
    }
}
