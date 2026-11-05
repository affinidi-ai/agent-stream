//! Policy Definition storage and types
//!
//! Defines reusable OPA policy definitions that can be referenced at the
//! appliance level or by LLM / IDE surfaces. Uses RwLockFilesystemStorage for
//! async-friendly cached storage (write-through pattern).

use crate::policies::{
    AGENTSTREAM_POLICY_PACKAGE, IDE_POLICY_PACKAGE, LEGACY_SURFACE_POLICY_PACKAGE, LLM_POLICY_PACKAGE,
    SURFACE_POLICY_PACKAGE,
};
use crate::storage::filesystem::{StorableEntity, StorageBackend, rwlock_storage};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::path::PathBuf;
use tracing::info;

/// The type of entity a policy applies to
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    /// Appliance-wide policy (evaluated before any surface-level policy)
    Appliance,
    /// LLM Surface policy
    Llm,
    /// IDE Surface (front-door catalogue) policy
    Ide,
}

impl std::fmt::Display for PolicyType {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            PolicyType::Appliance => write!(f, "appliance"),
            PolicyType::Llm => write!(f, "llm"),
            PolicyType::Ide => write!(f, "ide"),
        }
    }
}

impl PolicyType {
    /// The Rego `package` a definition of this type must declare so that its
    /// compiled engine is reachable at the runtime query path for its layer.
    /// A mismatch fails closed at eval time (the query resolves to no value),
    /// so write-time validation ([`validate_policy_scope`]) rejects it up front.
    pub fn expected_package(&self) -> &'static str {
        match self {
            // `appliance` is the "Agent Stream" (gateway/instance-wide) type; its
            // Rego seeds the gateway's inline policy. It is NOT the surface layer.
            PolicyType::Appliance => AGENTSTREAM_POLICY_PACKAGE,
            PolicyType::Llm => LLM_POLICY_PACKAGE,
            PolicyType::Ide => IDE_POLICY_PACKAGE,
        }
    }
}

/// Return the `package` name declared by a Rego module, if any.
///
/// The declaration is the first non-blank, non-comment line and must start
/// with the `package` keyword. Returns the package path (e.g. `surface.policy`)
/// with surrounding whitespace trimmed, or `None` when no leading `package`
/// line is present. This is the single-sourced parser reused by
/// [`migrate_legacy_surface_package`] and [`validate_policy_scope`].
pub fn declared_package(rego: &str) -> Option<&str> {
    for line in rego.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return trimmed
            .strip_prefix("package")
            .and_then(|rest| {
                // Require whitespace after the keyword so `packagexyz` is not matched.
                if rest.starts_with(char::is_whitespace) {
                    Some(rest.trim())
                } else {
                    None
                }
            });
    }
    None
}

/// Rewrite a leading `package channel.policy` declaration to the canonical
/// `package surface.policy`. Only the package path is rewritten;
/// the rest of the module — comments, rules, whitespace — is preserved byte
/// for byte. Returns a borrowed `Cow` (no allocation) when the module already
/// declares the canonical package or declares some unrelated package.
pub fn migrate_legacy_surface_package(rego: &str) -> Cow<'_, str> {
    match declared_package(rego) {
        Some(pkg) if pkg == LEGACY_SURFACE_POLICY_PACKAGE => {
            Cow::Owned(rego.replacen(LEGACY_SURFACE_POLICY_PACKAGE, SURFACE_POLICY_PACKAGE, 1))
        }
        _ => Cow::Borrowed(rego),
    }
}

/// Validate that a definition's Rego declares the package expected for its
/// [`PolicyType`] — `appliance`→`agentstream.policy`, `llm`→`llm.policy`,
/// `ide`→`ide.policy`. An empty body is accepted (the runtime managers treat it
/// as "no engine" = fail-closed deny). Any mismatch (cross-scope package, a
/// legacy `channel.policy`, or no `package` line) is rejected with an actionable
/// message. Note the surface / fabric layer (`surface.policy`) is not one of the
/// creatable reusable types, so it is not validated here.
pub fn validate_policy_scope(policy: &PolicyDefinition) -> Result<(), String> {
    if policy
        .policy
        .trim()
        .is_empty()
    {
        return Ok(());
    }
    let expected = policy
        .policy_type
        .expected_package();
    match declared_package(&policy.policy) {
        Some(pkg) if pkg == expected => Ok(()),
        Some(pkg) => Err(format!(
            "{} policy must declare `package {}`, but the Rego declares `package {}`",
            policy.policy_type, expected, pkg
        )),
        None => {
            Err(format!("{} policy must declare `package {}` as its first statement", policy.policy_type, expected))
        }
    }
}

/// A reusable OPA policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefinition {
    /// Unique identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this policy does
    #[serde(default)]
    pub description: String,
    /// What type of entity this policy can be applied to
    pub policy_type: PolicyType,
    /// The Rego policy content
    pub policy: String,
    /// Whether this policy is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// ISO 8601 creation timestamp
    pub created_at: String,
    /// ISO 8601 last-updated timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Resolved version number of the enforced revision (projection of the
    /// document's `current_version`). Output-only; ignored on write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Content hash (`sha256:<hex>`) of the enforced revision. Output-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// Saved sample input for the policy dry-run (Test panel), retained with the
    /// policy so an operator's last test fixture persists across edits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_input: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

fn default_true() -> bool {
    true
}

/// SHA-256 content hash (`sha256:<hex>`) binding a policy's scope to its Rego
/// body — the attestation primitive audit and governance records carry so a
/// verifier can prove which bytes were enforced. The policy type is mixed in
/// (with a unit separator) so identical Rego under a different scope hashes
/// differently.
pub fn content_hash(
    policy_type: &PolicyType,
    rego: &str,
) -> String {
    content_hash_from_parts(&policy_type.to_string(), rego)
}

fn content_hash_from_parts(
    policy_type: &str,
    rego: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy_type.as_bytes());
    hasher.update([0x1e]); // ASCII record separator
    hasher.update(rego.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// One immutable revision of a policy's Rego body. Versions are append-only and
/// never mutated after creation — the sole exception is the one-time legacy
/// package normalization in [`FileSystemPolicyDefinitionStore::migrate_legacy_packages`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyVersion {
    /// Monotonic, 1-based revision number (per appliance; single-instance).
    pub version: u32,
    /// The Rego policy content for this revision — immutable.
    pub policy: String,
    /// `sha256:<hex>` content hash binding scope + body (see [`content_hash`]).
    pub content_hash: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Authoring admin principal, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Optional operator change note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Policy name as it stood for this revision. Bindings resolve a policy by
    /// id, so a rename never breaks enforcement — each revision keeps its own
    /// name for the history view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Policy description as it stood for this revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A versioned, immutable OPA policy document. Persisted one file per id; the
/// runtime enforces `current_version` and can resolve any historical version
/// for attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    /// Stable identifier — the policy identity referenced by bindings + audits.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what this policy does.
    #[serde(default)]
    pub description: String,
    /// What type of entity this policy applies to.
    pub policy_type: PolicyType,
    /// Document-level active flag.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Version number currently enforced at runtime.
    pub current_version: u32,
    /// ISO 8601 creation timestamp (of the document).
    pub created_at: String,
    /// ISO 8601 last-updated timestamp (document metadata or new version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Append-only revision history (never mutated post-creation).
    pub versions: Vec<PolicyVersion>,
    /// Saved sample input for the policy dry-run (document-level; not versioned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_input: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl StorableEntity for PolicyDocument {
    fn id(&self) -> &str {
        &self.id
    }

    /// Convert a legacy flat `PolicyDefinition` file into a single-version
    /// document on load. Idempotent: an already-versioned document (has
    /// `versions`) is left untouched.
    fn migrate_raw_json(value: &mut serde_json::Value) -> Result<bool> {
        let Some(obj) = value.as_object_mut() else {
            return Ok(false);
        };
        if obj.contains_key("versions") {
            return Ok(false);
        }
        let policy = obj
            .get("policy")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let policy_type = obj
            .get("policy_type")
            .and_then(|v| v.as_str())
            .unwrap_or("appliance")
            .to_string();
        let created_at = obj
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let hash = content_hash_from_parts(&policy_type, &policy);
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let description = obj
            .get("description")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let version = serde_json::json!({
            "version": 1,
            "policy": policy,
            "content_hash": hash,
            "created_at": created_at,
            "note": "migrated",
            "name": name,
            "description": description,
        });
        obj.remove("policy");
        obj.insert("current_version".to_string(), serde_json::json!(1));
        obj.insert("versions".to_string(), serde_json::json!([version]));
        Ok(true)
    }
}

impl PolicyDocument {
    /// The currently enforced version entry.
    pub fn current(&self) -> Option<&PolicyVersion> {
        self.versions
            .iter()
            .find(|v| v.version == self.current_version)
    }

    /// Resolve a specific historical version.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn version(
        &self,
        version: u32,
    ) -> Option<&PolicyVersion> {
        self.versions
            .iter()
            .find(|v| v.version == version)
    }

    /// Project to the flat [`PolicyDefinition`] view of the current version —
    /// what existing API consumers and runtime managers read.
    pub fn to_definition(&self) -> PolicyDefinition {
        let current = self.current();
        PolicyDefinition {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            policy_type: self.policy_type.clone(),
            policy: current
                .map(|v| v.policy.clone())
                .unwrap_or_default(),
            enabled: self.enabled,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            version: current.map(|v| v.version),
            content_hash: current.map(|v| v.content_hash.clone()),
            sample_input: self.sample_input.clone(),
            tenant_id: self.tenant_id.clone(),
        }
    }
}

/// File-based storage for versioned, immutable policy documents.
pub struct FileSystemPolicyDefinitionStore {
    storage: Box<dyn StorageBackend<PolicyDocument>>,
}

impl FileSystemPolicyDefinitionStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage_path = PathBuf::from(storage_dir);
        let storage = rwlock_storage(storage_path, "policy_definition").await?;
        Ok(Self { storage })
    }

    /// Re-read every policy document from disk.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }

    /// Get the flat (current-version) view of a policy by ID.
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<PolicyDefinition> {
        self.get_document(id)
            .await
            .map(|d| d.to_definition())
    }

    /// Get the full versioned document by ID.
    pub async fn get_document(
        &self,
        id: &str,
    ) -> Option<PolicyDocument> {
        self.storage
            .get(id)
            .await
            .ok()
            .flatten()
    }

    /// Resolve a specific historical version — the primitive that makes an
    /// attestation referencing `policy_id@version` reproducible.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn get_version(
        &self,
        id: &str,
        version: u32,
    ) -> Option<PolicyVersion> {
        self.get_document(id)
            .await
            .and_then(|d| d.version(version).cloned())
    }

    /// List all policies as flat current-version views.
    pub async fn list(&self) -> Vec<PolicyDefinition> {
        self.list_documents()
            .await
            .iter()
            .map(PolicyDocument::to_definition)
            .collect()
    }

    /// List all versioned documents.
    pub async fn list_documents(&self) -> Vec<PolicyDocument> {
        self.storage
            .list_all()
            .await
            .unwrap_or_default()
    }

    /// List policy definitions filtered by type
    #[expect(dead_code)]
    pub async fn list_by_type(
        &self,
        policy_type: &PolicyType,
    ) -> Vec<PolicyDefinition> {
        self.list()
            .await
            .into_iter()
            .filter(|p| &p.policy_type == policy_type)
            .collect()
    }

    /// Save a policy (create or update). A change to the Rego body appends a new
    /// immutable version; metadata-only changes (name/description/enabled) update
    /// the document without a new version. Provenance is unattributed — use
    /// [`save_authored`](Self::save_authored) to record the author. Production
    /// callers thread the principal via `save_authored`; this stays for tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn save(
        &self,
        policy: PolicyDefinition,
    ) -> Result<()> {
        self.save_authored(policy, None, None)
            .await
    }

    /// Save a policy, recording the authoring principal and an optional change
    /// note on any newly appended version.
    pub async fn save_authored(
        &self,
        policy: PolicyDefinition,
        author: Option<String>,
        note: Option<String>,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let hash = content_hash(&policy.policy_type, &policy.policy);

        let doc = match self
            .get_document(&policy.id)
            .await
        {
            Some(mut existing) => {
                let name = policy.name;
                let description = policy.description;
                existing.name = name.clone();
                existing.description = description.clone();
                existing.policy_type = policy.policy_type;
                existing.enabled = policy.enabled;
                existing.sample_input = policy.sample_input;
                existing.updated_at = Some(now.clone());
                let unchanged = existing
                    .current()
                    .is_some_and(|v| v.content_hash == hash);
                if unchanged {
                    // Metadata-only edit: keep the current revision's name /
                    // description snapshot in sync; older revisions stay frozen.
                    if let Some(cur) = existing
                        .versions
                        .iter_mut()
                        .find(|v| v.version == existing.current_version)
                    {
                        cur.name = Some(name);
                        cur.description = Some(description);
                    }
                } else {
                    let next = existing.current_version + 1;
                    existing
                        .versions
                        .push(PolicyVersion {
                            version: next,
                            policy: policy.policy,
                            content_hash: hash,
                            created_at: now,
                            created_by: author,
                            note,
                            name: Some(name),
                            description: Some(description),
                        });
                    existing.current_version = next;
                }
                existing
            }
            None => {
                let created_at = if policy.created_at.is_empty() {
                    now.clone()
                } else {
                    policy.created_at
                };
                let name = policy.name;
                let description = policy.description;
                PolicyDocument {
                    id: policy.id,
                    name: name.clone(),
                    description: description.clone(),
                    policy_type: policy.policy_type,
                    enabled: policy.enabled,
                    current_version: 1,
                    created_at,
                    updated_at: Some(now.clone()),
                    versions: vec![PolicyVersion {
                        version: 1,
                        policy: policy.policy,
                        content_hash: hash,
                        created_at: now,
                        created_by: author,
                        note,
                        name: Some(name),
                        description: Some(description),
                    }],
                    sample_input: policy.sample_input,
                    tenant_id: policy.tenant_id,
                }
            }
        };

        self.storage.save(&doc).await
    }

    pub async fn set_tenant_id(
        &self,
        id: &str,
        tenant_id: Option<String>,
    ) -> Result<()> {
        let mut document = self
            .get_document(id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Policy definition not found: {}", id))?;
        document.tenant_id = tenant_id;
        document.updated_at = Some(chrono::Utc::now().to_rfc3339());
        self.storage
            .save(&document)
            .await
    }

    /// Delete a policy definition
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }

    /// Test helper: read the current-version Rego body for a definition.
    #[cfg(test)]
    pub async fn get_policy_text(
        &self,
        id: &str,
    ) -> Option<String> {
        self.get_document(id)
            .await
            .and_then(|d| {
                d.current()
                    .map(|v| v.policy.clone())
            })
    }

    /// Check if a policy definition exists
    pub async fn exists(
        &self,
        id: &str,
    ) -> bool {
        self.storage
            .exists(id)
            .await
            .unwrap_or(false)
    }

    /// One-time, idempotent migration of stored surface / fabric policy
    /// definitions from the legacy `package channel.policy` to the canonical
    /// `package surface.policy`. Selection is **body-based** — any
    /// definition whose Rego declares `package channel.policy` is rewritten,
    /// regardless of `policy_type` — because the surface layer is not one of the
    /// creatable reusable types (`appliance`/`llm`/`ide`) and legacy defs may
    /// carry any stored type. Runs at startup and on config reload, before
    /// surfaces are (re)compiled, so the runtime only ever evaluates
    /// `data.surface.policy.allow`. Returns the number of definitions rewritten.
    pub async fn migrate_legacy_packages(&self) -> Result<usize> {
        let mut migrated = 0usize;
        for mut doc in self.list_documents().await {
            let cv = doc.current_version;
            let current_policy = match doc
                .versions
                .iter()
                .find(|v| v.version == cv)
            {
                Some(v) => v.policy.clone(),
                None => continue,
            };
            if let Cow::Owned(rewritten) = migrate_legacy_surface_package(&current_policy) {
                info!(
                    policy_id = %doc.id,
                    "Migrating surface policy definition from `{}` to `{}`",
                    LEGACY_SURFACE_POLICY_PACKAGE, SURFACE_POLICY_PACKAGE
                );
                let new_hash = content_hash(&doc.policy_type, &rewritten);
                if let Some(entry) = doc
                    .versions
                    .iter_mut()
                    .find(|v| v.version == cv)
                {
                    entry.policy = rewritten;
                    entry.content_hash = new_hash;
                }
                doc.updated_at = Some(chrono::Utc::now().to_rfc3339());
                self.storage
                    .save(&doc)
                    .await?;
                migrated += 1;
            }
        }
        Ok(migrated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(
        policy_type: PolicyType,
        policy: &str,
    ) -> PolicyDefinition {
        PolicyDefinition {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: String::new(),
            policy_type,
            policy: policy.to_string(),
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
            tenant_id: None,
        }
    }

    #[tokio::test]
    async fn sample_input_and_tenant_round_trip_while_metadata_edits_preserve_ownership() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            tmp.path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .expect("store");
        let mut d = def(PolicyType::Llm, "package llm.policy\ndefault allow = true");
        d.sample_input = Some("{\"a\":1}".to_string());
        d.tenant_id = Some("tenant-a".into());
        store
            .save(d)
            .await
            .expect("save");
        assert_eq!(
            store
                .get("p1")
                .await
                .expect("get")
                .sample_input
                .as_deref(),
            Some("{\"a\":1}")
        );
        assert_eq!(
            store
                .get("p1")
                .await
                .expect("get tenant")
                .tenant_id
                .as_deref(),
            Some("tenant-a")
        );

        // A metadata-only edit (unchanged Rego) still updates the saved input.
        let mut d2 = def(PolicyType::Llm, "package llm.policy\ndefault allow = true");
        d2.sample_input = Some("{\"b\":2}".to_string());
        d2.tenant_id = Some("tenant-b".into());
        store
            .save(d2)
            .await
            .expect("save2");
        assert_eq!(
            store
                .get("p1")
                .await
                .expect("get2")
                .sample_input
                .as_deref(),
            Some("{\"b\":2}")
        );
        assert_eq!(
            store
                .get("p1")
                .await
                .expect("get preserved tenant")
                .tenant_id
                .as_deref(),
            Some("tenant-a")
        );
    }

    #[test]
    fn declared_package_skips_blanks_and_comments() {
        assert_eq!(declared_package("\n# a comment\n\npackage llm.policy\nallow := true"), Some("llm.policy"));
        assert_eq!(declared_package("package surface.policy"), Some("surface.policy"));
        // No leading package line.
        assert_eq!(declared_package("allow := true"), None);
        // `packagexyz` must not match — requires whitespace after the keyword.
        assert_eq!(declared_package("packagexyz.policy"), None);
    }

    #[test]
    fn migrate_rewrites_only_legacy_channel_package() {
        let migrated = migrate_legacy_surface_package("package channel.policy\n\ndefault allow = false");
        assert!(matches!(migrated, Cow::Owned(_)));
        assert!(migrated.starts_with("package surface.policy"));
        assert!(migrated.contains("default allow = false"));
        // Already canonical → borrowed, unchanged.
        assert!(matches!(migrate_legacy_surface_package("package surface.policy\nallow := true"), Cow::Borrowed(_)));
        // Unrelated package → borrowed, unchanged.
        assert!(matches!(migrate_legacy_surface_package("package llm.policy"), Cow::Borrowed(_)));
    }

    #[test]
    fn validate_accepts_matching_and_empty() {
        // Empty body is allowed (managers treat it as fail-closed "no engine").
        assert!(validate_policy_scope(&def(PolicyType::Llm, "   ")).is_ok());
        // Canonical packages per creatable type.
        assert!(validate_policy_scope(&def(PolicyType::Llm, "package llm.policy\nallow := true")).is_ok());
        assert!(validate_policy_scope(&def(PolicyType::Ide, "package ide.policy\nallow := true")).is_ok());
        // `appliance` is the "Agent Stream" type → agentstream.policy.
        assert!(
            validate_policy_scope(&def(PolicyType::Appliance, "package agentstream.policy\nallow := true")).is_ok()
        );
    }

    #[test]
    fn validate_rejects_cross_scope_and_missing_package() {
        // Cross-scope: llm-typed body declaring the ide package.
        let err = validate_policy_scope(&def(PolicyType::Llm, "package ide.policy\nallow := true")).unwrap_err();
        assert!(err.contains("llm.policy"), "got: {err}");
        // Missing package line entirely.
        let err = validate_policy_scope(&def(PolicyType::Ide, "allow := true")).unwrap_err();
        assert!(err.contains("ide.policy"), "got: {err}");
        // `appliance` must declare agentstream.policy — surface.policy is rejected.
        let err =
            validate_policy_scope(&def(PolicyType::Appliance, "package surface.policy\nallow := true")).unwrap_err();
        assert!(err.contains("agentstream.policy"), "got: {err}");
        // The surface layer's channel.policy is not a valid body for any creatable type.
        assert!(validate_policy_scope(&def(PolicyType::Appliance, "package channel.policy\nallow := true")).is_err());
        assert!(validate_policy_scope(&def(PolicyType::Llm, "package channel.policy\nallow := true")).is_err());
    }

    #[tokio::test]
    async fn migrate_legacy_packages_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");

        // A legacy surface-layer definition declaring channel.policy. Selection
        // is body-based (type-agnostic), so the stored policy_type is irrelevant.
        let mut legacy = def(PolicyType::Llm, "package channel.policy\n\ndefault allow = false");
        legacy.id = "surf-def".to_string();
        store
            .save(legacy)
            .await
            .expect("save");
        // A definition that does not declare channel.policy is left untouched.
        let mut llm = def(PolicyType::Llm, "package llm.policy\nallow := true");
        llm.id = "llm-def".to_string();
        store
            .save(llm)
            .await
            .expect("save llm");

        // First run rewrites exactly the one channel.policy definition.
        assert_eq!(
            store
                .migrate_legacy_packages()
                .await
                .expect("migrate"),
            1
        );
        assert!(
            store
                .get_policy_text("surf-def")
                .await
                .unwrap()
                .starts_with("package surface.policy")
        );
        // Second run is a no-op.
        assert_eq!(
            store
                .migrate_legacy_packages()
                .await
                .expect("migrate2"),
            0
        );
        // The llm definition is never rewritten.
        assert!(
            store
                .get_policy_text("llm-def")
                .await
                .unwrap()
                .starts_with("package llm.policy")
        );
    }

    #[test]
    fn content_hash_binds_scope_and_body() {
        let a = content_hash(&PolicyType::Llm, "package llm.policy\nallow := true");
        let b = content_hash(&PolicyType::Llm, "package llm.policy\nallow := true");
        let c = content_hash(&PolicyType::Llm, "package llm.policy\nallow := false");
        // Same scope + body → stable; different body → different hash.
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("sha256:"));
        // Same body under a different scope hashes differently.
        let ide = content_hash(&PolicyType::Ide, "package llm.policy\nallow := true");
        assert_ne!(a, ide);
    }

    #[test]
    fn migrate_raw_json_converts_flat_definition_and_is_idempotent() {
        let mut v = serde_json::json!({
            "id": "p1",
            "name": "n",
            "description": "",
            "policy_type": "llm",
            "policy": "package llm.policy\nallow := true",
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z",
        });
        assert!(PolicyDocument::migrate_raw_json(&mut v).expect("migrate"));
        let doc: PolicyDocument = serde_json::from_value(v).expect("deserialize");
        assert_eq!(doc.current_version, 1);
        assert_eq!(doc.versions.len(), 1);
        assert!(
            doc.versions[0]
                .content_hash
                .starts_with("sha256:")
        );
        assert!(doc.current().is_some());
        // A versioned document is not re-migrated.
        let mut again = serde_json::to_value(&doc).expect("serialize");
        assert!(!PolicyDocument::migrate_raw_json(&mut again).expect("migrate2"));
    }

    #[tokio::test]
    async fn editing_rego_appends_immutable_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");

        let mut d = def(PolicyType::Llm, "package llm.policy\nallow := true");
        d.id = "v".to_string();
        store
            .save(d.clone())
            .await
            .expect("save v1");
        let doc = store
            .get_document("v")
            .await
            .expect("doc v1");
        assert_eq!(doc.current_version, 1);
        let h1 = doc.versions[0]
            .content_hash
            .clone();

        // Metadata-only change → no new version.
        let mut meta = d.clone();
        meta.name = "renamed".to_string();
        store
            .save(meta)
            .await
            .expect("save meta");
        let doc = store
            .get_document("v")
            .await
            .expect("doc meta");
        assert_eq!(doc.current_version, 1);
        assert_eq!(doc.versions.len(), 1);
        assert_eq!(doc.name, "renamed");

        // Rego change → append v2; v1 retained + immutable.
        let mut edit = d.clone();
        edit.policy = "package llm.policy\nallow := false".to_string();
        store
            .save_authored(edit, Some("admin@example".to_string()), Some("tighten".to_string()))
            .await
            .expect("save v2");
        let doc = store
            .get_document("v")
            .await
            .expect("doc v2");
        assert_eq!(doc.current_version, 2);
        assert_eq!(doc.versions.len(), 2);
        assert_eq!(doc.versions[0].content_hash, h1, "v1 must be immutable");
        assert_ne!(doc.versions[1].content_hash, h1);
        assert_eq!(
            doc.versions[1]
                .created_by
                .as_deref(),
            Some("admin@example")
        );

        // Historical resolution stays exact.
        assert!(
            store
                .get_version("v", 1)
                .await
                .unwrap()
                .policy
                .contains("allow := true")
        );
        assert!(
            store
                .get_version("v", 2)
                .await
                .unwrap()
                .policy
                .contains("allow := false")
        );
        // Flat view projects the current version + its hash.
        let flat = store
            .get("v")
            .await
            .expect("flat");
        assert_eq!(flat.version, Some(2));
        assert_eq!(
            flat.content_hash,
            Some(
                doc.versions[1]
                    .content_hash
                    .clone()
            )
        );
    }
}
