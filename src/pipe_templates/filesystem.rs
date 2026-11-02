//! Filesystem-backed storage for pipe templates with builtin seeding.
//!
//! On first start the templates dir is created and every `*.json` file
//! discovered under the optional seed source directory (typically
//! `<config_dir>/pipe_templates/`) is parsed, stamped with
//! `builtin: true`, and written to the storage dir. On subsequent
//! restarts a builtin file is overwritten in place when its on-disk
//! content differs from the source AND the file still has
//! `builtin: true` — this lets us ship corrected builtins without
//! leaving stale copies on every dev box. Admins who want to hand-edit
//! a builtin must flip `builtin: false` (which also takes the file out
//! of REST-API immutability), at which point the seeder leaves it alone.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use super::types::PipeTemplate;
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// Only `*.json` files in the seed dir are considered; anything else is
/// ignored so the folder can also hold READMEs and other docs.
const SEED_FILE_EXTENSION: &str = "json";

/// Public store API. Keeping a trait makes the handler layer testable
/// with a memory store later; for now the only implementation is the
/// filesystem one.
#[async_trait]
pub trait PipeTemplateStore: Send + Sync {
    async fn list_all(&self) -> Result<Vec<PipeTemplate>>;
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<PipeTemplate>>;
    async fn save(
        &self,
        template: &PipeTemplate,
    ) -> Result<()>;
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
}

/// Filesystem-based pipe template store with in-memory cache.
pub struct FileSystemPipeTemplateStore {
    storage: Box<dyn StorageBackend<PipeTemplate>>,
}

impl FileSystemPipeTemplateStore {
    /// Create a new store.
    ///
    /// * `storage_dir` — runtime persistence directory (one file per
    ///   template id).
    /// * `seed_source_dir` — optional directory scanned for `*.json`
    ///   files at boot. Each discovered file is parsed and seeded as a
    ///   builtin. Pass `None` to skip seeding.
    pub async fn new(
        storage_dir: PathBuf,
        seed_source_dir: Option<PathBuf>,
    ) -> Result<Self> {
        info!("Loading pipe templates from: {}", storage_dir.display());
        tokio::fs::create_dir_all(&storage_dir)
            .await
            .with_context(|| format!("creating pipe_templates dir {}", storage_dir.display()))?;

        if let Some(seed_dir) = seed_source_dir {
            Self::seed_builtins(&storage_dir, &seed_dir).await?;
        } else {
            info!("No seed source directory provided; skipping builtin pipe template seeding");
        }

        let storage = cached_storage(storage_dir, "pipe_template").await?;
        let count = storage
            .list_all()
            .await?
            .len();
        info!("Loaded {} pipe template(s)", count);
        Ok(Self { storage })
    }

    /// Scan `seed_source_dir` for `*.json` files and write each one to
    /// the runtime storage dir as a builtin. Files whose on-disk copy
    /// matches the source byte-for-byte are skipped; files that differ
    /// are overwritten only when the on-disk copy still has
    /// `builtin: true`.
    async fn seed_builtins(
        storage_dir: &Path,
        seed_source_dir: &Path,
    ) -> Result<()> {
        if !seed_source_dir.exists() {
            info!(
                "Seed source dir {} does not exist; skipping builtin pipe template seeding",
                seed_source_dir.display()
            );
            return Ok(());
        }

        let mut entries = tokio::fs::read_dir(seed_source_dir)
            .await
            .with_context(|| format!("reading seed source dir {}", seed_source_dir.display()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("iterating seed source dir {}", seed_source_dir.display()))?
        {
            let source_path = entry.path();
            if !source_path.is_file() {
                continue;
            }
            if source_path
                .extension()
                .and_then(|s| s.to_str())
                != Some(SEED_FILE_EXTENSION)
            {
                continue;
            }

            if let Err(e) = Self::seed_one(storage_dir, &source_path).await {
                warn!("Failed to seed builtin pipe template from {}: {:#}", source_path.display(), e);
            }
        }

        Ok(())
    }

    async fn seed_one(
        storage_dir: &Path,
        source_path: &Path,
    ) -> Result<()> {
        let body = tokio::fs::read_to_string(source_path)
            .await
            .with_context(|| format!("reading {}", source_path.display()))?;

        let mut tpl: PipeTemplate = serde_json::from_str(&body)
            .with_context(|| format!("parsing pipe template at {}", source_path.display()))?;

        if tpl.id.is_empty() {
            anyhow::bail!("seed template {} has an empty `id` field", source_path.display());
        }
        // The id names the file written below, so it gets the same check as a
        // store save: one file name inside `storage_dir`.
        crate::storage::filesystem::ensure_storable_id(storage_dir, "seed pipe template", &tpl.id)?;
        tpl.builtin = true;
        if tpl.author.is_empty() {
            tpl.author = "system".to_string();
        }

        let pretty =
            serde_json::to_string_pretty(&tpl).with_context(|| format!("serializing seed template '{}'", tpl.id))?;

        let target_path = storage_dir.join(format!("{}.json", tpl.id));

        if target_path.exists() {
            let on_disk = tokio::fs::read_to_string(&target_path)
                .await
                .with_context(|| format!("reading existing builtin {}", target_path.display()))?;
            if on_disk == pretty {
                return Ok(());
            }
            match serde_json::from_str::<PipeTemplate>(&on_disk) {
                Ok(existing) if !existing.builtin => {
                    info!("Builtin '{}' has been adopted (builtin: false); leaving on-disk copy", tpl.id);
                    return Ok(());
                }
                Ok(_) => {
                    info!("Re-seeding stale builtin pipe template: {}", tpl.id);
                }
                Err(e) => {
                    warn!("Existing builtin '{}' could not be parsed ({}); overwriting with seed source", tpl.id, e);
                }
            }
        } else {
            info!("Seeded builtin pipe template: {} (from {})", tpl.id, source_path.display());
        }

        tokio::fs::write(&target_path, pretty)
            .await
            .with_context(|| format!("writing builtin template to {}", target_path.display()))?;
        Ok(())
    }
}

#[async_trait]
impl PipeTemplateStore for FileSystemPipeTemplateStore {
    async fn list_all(&self) -> Result<Vec<PipeTemplate>> {
        self.storage.list_all().await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<PipeTemplate>> {
        self.storage.get(id).await
    }

    async fn save(
        &self,
        template: &PipeTemplate,
    ) -> Result<()> {
        if template.id.is_empty() {
            warn!("Refusing to save pipe template with empty id");
            return Err(anyhow::anyhow!("pipe template id must not be empty"));
        }
        self.storage
            .save(template)
            .await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn write_seed_files(
        seed_dir: &Path,
        count: usize,
    ) -> Vec<String> {
        tokio::fs::create_dir_all(seed_dir)
            .await
            .unwrap();
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let id = format!("builtin-seed-{}", i);
            let body = serde_json::json!({
                "id": id,
                "name": format!("Seed {}", i),
                "description": "",
                "tags": ["starter"],
                "author": "system",
                "builtin": true,
                "pipe": { "name": "$SURFACE_NAME" }
            });
            let path = seed_dir.join(format!("seed_{}.json", i));
            tokio::fs::write(&path, serde_json::to_string_pretty(&body).unwrap())
                .await
                .unwrap();
            ids.push(id);
        }
        ids
    }

    #[tokio::test]
    async fn seeds_all_json_files_on_first_start() {
        let storage = TempDir::new().unwrap();
        let seed = TempDir::new().unwrap();
        let ids = write_seed_files(seed.path(), 3).await;

        let store = FileSystemPipeTemplateStore::new(storage.path().to_path_buf(), Some(seed.path().to_path_buf()))
            .await
            .expect("store init");

        let templates = store
            .list_all()
            .await
            .unwrap();
        assert_eq!(templates.len(), ids.len(), "all seed files should be seeded on first start");
        for id in &ids {
            let found = templates
                .iter()
                .find(|t| &t.id == id)
                .unwrap_or_else(|| panic!("missing seeded builtin: {}", id));
            assert!(found.builtin, "{} should be flagged builtin", id);
            assert_eq!(found.author, "system");
        }
    }

    #[tokio::test]
    async fn missing_seed_dir_is_not_an_error() {
        let storage = TempDir::new().unwrap();
        let missing_seed = storage
            .path()
            .join("does-not-exist");

        let store = FileSystemPipeTemplateStore::new(storage.path().to_path_buf(), Some(missing_seed))
            .await
            .expect("missing seed dir should be tolerated");

        let templates = store
            .list_all()
            .await
            .unwrap();
        assert!(templates.is_empty());
    }

    #[tokio::test]
    async fn preserves_admin_owned_builtin_when_builtin_flag_cleared() {
        let storage = TempDir::new().unwrap();
        let seed = TempDir::new().unwrap();
        let ids = write_seed_files(seed.path(), 1).await;
        let id = &ids[0];

        FileSystemPipeTemplateStore::new(storage.path().to_path_buf(), Some(seed.path().to_path_buf()))
            .await
            .unwrap();

        let path = storage
            .path()
            .join(format!("{}.json", id));
        let mut tpl: PipeTemplate = serde_json::from_str(
            &tokio::fs::read_to_string(&path)
                .await
                .unwrap(),
        )
        .unwrap();
        tpl.name = "Edited Name".to_string();
        tpl.builtin = false;
        tokio::fs::write(&path, serde_json::to_string_pretty(&tpl).unwrap())
            .await
            .unwrap();

        let store = FileSystemPipeTemplateStore::new(storage.path().to_path_buf(), Some(seed.path().to_path_buf()))
            .await
            .unwrap();
        let reloaded = store
            .get(id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.name, "Edited Name");
        assert!(!reloaded.builtin);
    }

    #[tokio::test]
    async fn save_get_delete_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemPipeTemplateStore::new(dir.path().to_path_buf(), None)
            .await
            .unwrap();
        let tpl = PipeTemplate {
            schema: None,
            id: "user-abc".to_string(),
            name: "User Pipe".to_string(),
            kind: crate::pipe_templates::types::TemplateKind::Partial,
            description: String::new(),
            details: None,
            starter_hint: None,
            icon: None,
            tags: vec![],
            author: String::new(),
            created_at: None,
            updated_at: None,
            builtin: false,
            tenant_id: None,
            sort_priority: i32::MAX,
            items: vec![],
            pipe: Some(serde_json::json!({ "name": "x" })),
        };
        store
            .save(&tpl)
            .await
            .unwrap();
        let got = store
            .get("user-abc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.name, "User Pipe");
        store
            .delete("user-abc")
            .await
            .unwrap();
        assert!(
            store
                .get("user-abc")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn save_rejects_empty_id() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemPipeTemplateStore::new(dir.path().to_path_buf(), None)
            .await
            .unwrap();
        let bad = PipeTemplate {
            schema: None,
            id: String::new(),
            name: "X".to_string(),
            kind: crate::pipe_templates::types::TemplateKind::Partial,
            description: String::new(),
            details: None,
            starter_hint: None,
            icon: None,
            tags: vec![],
            author: String::new(),
            created_at: None,
            updated_at: None,
            builtin: false,
            tenant_id: None,
            sort_priority: i32::MAX,
            items: vec![],
            pipe: None,
        };
        assert!(
            store
                .save(&bad)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_seed_with_an_unsafe_id_is_skipped_and_the_others_still_seed() {
        let root = TempDir::new().unwrap();
        let storage = root
            .path()
            .join("surface_templates");
        let seed = root.path().join("seed");
        let ids = write_seed_files(&seed, 2).await;
        let outside = root.path().join("escaped");
        let unsafe_ids = [
            outside
                .to_string_lossy()
                .into_owned(),
            "../escaped".to_string(),
            "..".to_string(),
            "nested/escaped".to_string(),
            "back\\slash".to_string(),
            "nul\u{0}byte".to_string(),
        ];
        for (i, id) in unsafe_ids.iter().enumerate() {
            let body = serde_json::json!({
                "id": id,
                "name": "Unsafe",
                "description": "",
                "tags": [],
                "author": "",
                "builtin": true,
                "pipe": { "name": "$SURFACE_NAME" }
            });
            tokio::fs::write(seed.join(format!("unsafe_{i}.json")), serde_json::to_string(&body).unwrap())
                .await
                .unwrap();
        }

        let store = FileSystemPipeTemplateStore::new(storage.clone(), Some(seed))
            .await
            .expect("store init");

        let mut seeded: Vec<String> = store
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.id)
            .collect();
        seeded.sort();
        assert_eq!(seeded, ids);
        assert!(
            !root
                .path()
                .join("escaped.json")
                .exists(),
            "nothing is written beside the store"
        );
        assert!(
            !outside
                .with_extension("json")
                .exists()
        );
        let mut written: Vec<String> = std::fs::read_dir(&storage)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        written.sort();
        assert_eq!(written, ["builtin-seed-0.json", "builtin-seed-1.json"]);
    }
}
