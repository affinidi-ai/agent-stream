//! Read/verify API for signed governance records. Administrator-gated
//! (`governance.view`) because records carry the raw prompts and completions of
//! recorded interactions. Data is served from the process-wide governance store
//! via a global accessor, so no state threading is needed.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::scoped_id::{authorize_surface_scope, res_scope, tenant_ctx};
use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::governance::{
    ChainAnchor, ChainProblem, RecordOrder, RecordOutcome, RecordQuery, StoredRecord, TenantFilter,
    archived_surface_id, chain_problem,
};
use crate::identity::state::IdentityApiState;
use crate::pipes::FileSystemPipeStore;
use crate::rbac::{Feature, RbacConfig};
use crate::tenancy::PatTenantContext;

use super::authz::require_feature as require;

type ApiResult<T> = Result<T, (StatusCode, String)>;

/// The installed governance store, or a 503 when recording is not configured.
fn store() -> ApiResult<&'static crate::governance::GovernanceStore> {
    crate::governance::store().ok_or((StatusCode::SERVICE_UNAVAILABLE, "Governance store not configured".to_string()))
}

/// Reject surface ids that could escape the governance root (path traversal) or
/// inject a series key. Mirrors the pipe-id rules (the surface id *is* a pipe id),
/// and also admits the name of a deleted surface's archived log
/// (`<id>.deleted-<UTC time>`), which no pipe can take.
fn validate_surface_id(id: &str) -> ApiResult<()> {
    let ok = (!id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        || archived_surface_id(id).is_some();
    if ok {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, "Invalid surface id".to_string()))
    }
}

/// A governance surface for the picker: its id plus the human-readable name
/// resolved from the surface's latest record (self-contained, so it survives
/// deletion of the live surface).
#[derive(Serialize)]
pub struct SurfaceSummary {
    pub surface_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_name: Option<String>,
}

/// `GET /v1/governance/surfaces` - surfaces that have a governance log, each with
/// its id and (best-effort) human-readable name from the latest record. A
/// tenant-bound or resource-scoped caller sees only the surfaces it may read
/// (the rule the records route applies to each one).
pub async fn surfaces(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Vec<SurfaceSummary>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::GovernanceView).await?;
    let summaries =
        visible_surfaces(store()?, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope)).await?;
    Ok(Json(summaries))
}

/// The surfaces with a governance log that the caller may read. A surface the
/// caller may not read is skipped before its log is touched.
async fn visible_surfaces(
    store: &crate::governance::GovernanceStore,
    pipe_store: Option<&FileSystemPipeStore>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> ApiResult<Vec<SurfaceSummary>> {
    let ids = store
        .list_surfaces()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list surfaces: {e}")))?;
    let mut summaries = Vec::new();
    for surface_id in ids {
        if authorize_surface_scope(&surface_id, pipe_store, context, scope)
            .await
            .is_err()
        {
            continue;
        }
        let surface_name = store
            .latest_record(&surface_id)
            .ok()
            .flatten()
            .and_then(|stored| stored.record.surface_name);
        summaries.push(SurfaceSummary { surface_id, surface_name });
    }
    Ok(summaries)
}

/// One LLM surface's export coverage, for `GET /v1/governance/coverage`.
#[derive(Serialize)]
pub struct SurfaceCoverage {
    pub surface_id: String,
    pub surface_name: String,
    /// Governance recording is on (the surface's own block or the appliance default).
    pub governance_recording: bool,
    /// Recorded interactions are exported beyond the local store.
    pub governance_export: bool,
    /// At least one integration is mapped to the surface's `pipe` events.
    pub pipe_events: bool,
}

/// Query for the coverage endpoint.
#[derive(Deserialize)]
pub struct CoverageQuery {
    /// Return only surfaces whose recording or export is off.
    #[serde(default)]
    pub gaps_only: bool,
}

/// `GET /v1/governance/coverage?gaps_only=true` — every LLM surface with whether its
/// governance recording and export are on, counting the appliance-wide defaults
/// (`[surface_defaults]`). A surface with recording or export off is invisible to
/// an observer such as Agent Watch, which cannot tell "no traffic" from "not exported".
pub async fn coverage(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Query(q): Query<CoverageQuery>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Vec<SurfaceCoverage>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::GovernanceView).await?;
    let Some(pipe_store) = state.pipe_store.as_deref() else {
        return Ok(Json(Vec::new()));
    };
    let mut out = Vec::new();
    for pipe in pipe_store.list().await {
        if !matches!(pipe.pipe_type, crate::pipes::PipeType::LLM { .. }) {
            continue;
        }
        if authorize_surface_scope(&pipe.id, Some(pipe_store), tenant_ctx(&context), res_scope(&scope))
            .await
            .is_err()
        {
            continue;
        }
        let coverage = pipe.export_coverage();
        if q.gaps_only && !coverage.has_gap() {
            continue;
        }
        out.push(SurfaceCoverage {
            surface_id: pipe.id.clone(),
            surface_name: pipe.name.clone(),
            governance_recording: coverage.governance_recording,
            governance_export: coverage.governance_export,
            pipe_events: coverage.pipe_events,
        });
    }
    Ok(Json(out))
}

/// Query naming the surface, for the verify and single-record endpoints.
#[derive(Deserialize)]
pub struct SurfaceQuery {
    pub surface_id: String,
}

/// Query parameters for the records endpoint. Each filter is optional.
#[derive(Deserialize)]
pub struct RecordsQuery {
    pub surface_id: String,
    /// Most records answered. Oldest-first without a cursor, the most recent
    /// `limit` (as before filters existed).
    #[serde(default)]
    pub limit: Option<usize>,
    /// `asc` (oldest first, the default) or `desc` (newest first).
    #[serde(default)]
    pub order: Option<String>,
    /// Comma-separated outcomes to keep: `ok`, `blocked`, `failed`.
    #[serde(default)]
    pub outcome: Option<String>,
    /// Comma-separated labels of the stage that blocked or failed the
    /// interaction (`judge`, `jury`, `policy`, ...).
    #[serde(default)]
    pub stage: Option<String>,
    /// Records at or after this time: RFC 3339, or unix seconds.
    #[serde(default)]
    pub since: Option<String>,
    /// Records before this time: RFC 3339, or unix seconds.
    #[serde(default)]
    pub until: Option<String>,
    /// A record's `seq`: `desc` continues before it, `asc` after it.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Response header naming the cursor of the next page, present only when
/// another matching record exists beyond this one.
pub const NEXT_CURSOR_HEADER: &str = "x-next-cursor";

fn bad_request(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.into())
}

/// Comma-separated values, blanks dropped.
fn list_of(value: Option<&str>) -> Vec<&str> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect()
}

/// A time bound as unix milliseconds: RFC 3339, or whole unix seconds.
fn time_bound(
    name: &str,
    value: Option<&str>,
) -> ApiResult<Option<i64>> {
    let Some(value) = value
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };
    if let Ok(seconds) = value.parse::<i64>() {
        return seconds
            .checked_mul(1000)
            .map(Some)
            .ok_or_else(|| bad_request(format!("{name} is out of range")));
    }
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|t| Some(t.timestamp_millis()))
        .map_err(|_| bad_request(format!("{name} must be an RFC 3339 time or unix seconds")))
}

impl RecordsQuery {
    /// The store query these parameters ask for, or a 400 naming the first
    /// parameter that does not parse.
    fn to_query(&self) -> ApiResult<RecordQuery> {
        let order = match self
            .order
            .as_deref()
            .map(str::trim)
        {
            None | Some("") | Some("asc") => RecordOrder::Asc,
            Some("desc") => RecordOrder::Desc,
            Some(_) => return Err(bad_request("order must be asc or desc")),
        };
        let outcomes = list_of(self.outcome.as_deref())
            .into_iter()
            .map(|o| RecordOutcome::parse(o).ok_or_else(|| bad_request("outcome must be ok, blocked or failed")))
            .collect::<ApiResult<Vec<_>>>()?;
        let stages = list_of(self.stage.as_deref())
            .into_iter()
            .map(str::to_string)
            .collect();
        let cursor = self
            .cursor
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(|c| {
                c.parse::<u64>()
                    .map_err(|_| bad_request("cursor must be a record seq"))
            })
            .transpose()?;
        Ok(RecordQuery {
            order,
            outcomes,
            stages,
            since_ms: time_bound("since", self.since.as_deref())?,
            until_ms: time_bound("until", self.until.as_deref())?,
            cursor,
            limit: self.limit,
            tenant: None,
        })
    }
}

/// What a tenant-bound caller may read of `surface_id`'s records: those that
/// name its tenant, and those that name none written since the surface was
/// created (a record names its tenant once attribution is recorded). `None`
/// for an appliance caller.
async fn tenant_filter(
    surface_id: &str,
    pipe_store: Option<&FileSystemPipeStore>,
    context: Option<&PatTenantContext>,
) -> Option<TenantFilter> {
    let context = context?;
    let created = match pipe_store {
        Some(pipes) => pipes
            .get(surface_id)
            .await
            .and_then(|pipe| chrono::DateTime::parse_from_rfc3339(&pipe.created_at).ok())
            .map(|created| created.timestamp_millis()),
        None => None,
    };
    Some(TenantFilter {
        tenant_id: context.tenant_id.clone(),
        unattributed_since_ms: created,
    })
}

/// `GET /v1/governance/records?surface_id=...` - a surface's signed records,
/// each with its chain position `seq`. Oldest first by default, where `limit`
/// keeps the most recent N; `order=desc`, `outcome`, `stage`, `since`, `until`
/// and `cursor` filter and page the read (see [`RecordsQuery`]), and the
/// `x-next-cursor` header carries the next page's cursor when there is one.
/// Only the records answered are read from the encrypted log.
pub async fn records(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Query(q): Query<RecordsQuery>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Response> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::GovernanceView).await?;
    validate_surface_id(&q.surface_id)?;
    let mut query = q.to_query()?;
    authorize_surface_scope(&q.surface_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
        .await?;
    query.tenant = tenant_filter(&q.surface_id, state.pipe_store.as_deref(), tenant_ctx(&context)).await;
    let page = store()?
        .query(&q.surface_id, query)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read records: {e}")))?;
    let mut response = Json(page.records).into_response();
    if let Some(cursor) = page.next_cursor {
        response
            .headers_mut()
            .insert(HeaderName::from_static(NEXT_CURSOR_HEADER), HeaderValue::from(cursor));
    }
    Ok(response)
}

/// Reject record ids that are not the characters a record id is written in.
fn validate_record_id(id: &str) -> ApiResult<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(bad_request("Invalid record id"))
    }
}

/// `GET /v1/governance/records/{id}?surface_id=...` - one signed record of the
/// surface, with its `seq`; `404` when the surface holds no record with that id.
pub async fn record(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Path(record_id): Path<String>,
    Query(q): Query<SurfaceQuery>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<StoredRecord>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::GovernanceView).await?;
    validate_surface_id(&q.surface_id)?;
    validate_record_id(&record_id)?;
    authorize_surface_scope(&q.surface_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
        .await?;
    let tenant = tenant_filter(&q.surface_id, state.pipe_store.as_deref(), tenant_ctx(&context)).await;
    store()?
        .get(&q.surface_id, &record_id, tenant)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read record: {e}")))?
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "Record not found".to_string()))
}

/// The result of verifying a surface's chain.
#[derive(Serialize)]
pub struct ChainVerdict {
    pub surface_id: String,
    /// Whether every record's content hash recomputed, its signed credential
    /// states it and its proof verifies with an appliance key, the chain links
    /// hold (from genesis, or from a retention anchor whose proof verifies),
    /// the index describes the log and the log reaches its chain head.
    pub valid: bool,
    /// Number of records verified (0 when invalid or empty).
    pub count: usize,
    /// The first integrity failure, when `valid` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What kind of failure `error` is, when the chain could be read: `broken`
    /// (a record, link, proof or the anchor does not hold), `unknown_key` (a
    /// proof names a key this appliance has no record of), `truncated` (the
    /// newest records are missing) or `index_mismatch` (the record index
    /// disagreed with the log; it has been rebuilt).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<ChainProblem>,
    /// Records whose proof verified with a key the appliance signed with
    /// before its current one.
    #[serde(skip_serializing_if = "is_zero")]
    pub previous_key_records: u64,
    /// `seq` of the first record kept, when the chain verified and holds records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seq: Option<u64>,
    /// `seq` of the last record, when the chain verified and holds records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seq: Option<u64>,
    /// The retention anchor the chain was verified from, once records have been
    /// pruned: the `seq` and `content_hash` of the last pruned record, its
    /// `timestamp`, `pruned_at` and the `retention_days` in force.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<ChainAnchor>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// `GET /v1/governance/verify?surface_id=...` - verify the surface's chain
/// (content hashes recompute, every record's proof verifies,
/// `prev_record_hash` links hold from genesis or from the signed retention
/// anchor, the index describes the log and the log reaches its chain head).
pub async fn verify(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Query(q): Query<SurfaceQuery>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<ChainVerdict>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::GovernanceView).await?;
    validate_surface_id(&q.surface_id)?;
    authorize_surface_scope(&q.surface_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
        .await?;
    let verdict = match store()?
        .verify_chain(&q.surface_id)
        .await
    {
        Ok(summary) => ChainVerdict {
            surface_id: q.surface_id,
            valid: true,
            count: summary.count as usize,
            error: None,
            problem: None,
            previous_key_records: summary.previous_key_records,
            first_seq: summary.first_seq,
            last_seq: summary.last_seq,
            anchor: summary.anchor,
        },
        Err(e) => ChainVerdict {
            surface_id: q.surface_id,
            valid: false,
            count: 0,
            problem: chain_problem(&e),
            error: Some(e.to_string()),
            previous_key_records: 0,
            first_seq: None,
            last_seq: None,
            anchor: None,
        },
    };
    Ok(Json(verdict))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{GovernanceSigner, GovernanceStore};
    use crate::pipes::{PipeConfig, PipeType};
    use async_trait::async_trait;

    #[test]
    fn surface_id_validation() {
        assert!(validate_surface_id("pipe-abc_123").is_ok());
        assert!(validate_surface_id("").is_err());
        assert!(validate_surface_id("../etc/passwd").is_err());
        assert!(validate_surface_id("a/b").is_err());
        assert!(validate_surface_id(&"x".repeat(129)).is_err());
        assert!(validate_surface_id("pipe-abc.deleted-20261005T101112345Z").is_ok(), "an archived log");
        assert!(validate_surface_id("pipe-abc.deleted-../x").is_err());
        assert!(validate_surface_id("pipe-abc.json").is_err());
    }

    #[test]
    fn record_id_validation() {
        assert!(validate_record_id("0d1a4f6b-9a3e-2b8c-4d5e-6f707f2c1e60").is_ok());
        assert!(validate_record_id("").is_err());
        assert!(validate_record_id("../x").is_err());
        assert!(validate_record_id(&"a".repeat(65)).is_err());
    }

    fn records_query(pairs: &[(&str, &str)]) -> Result<RecordQuery, (StatusCode, String)> {
        let mut params: Vec<(&str, &str)> = vec![("surface_id", "s")];
        params.extend_from_slice(pairs);
        let encoded = serde_urlencoded::to_string(&params).unwrap();
        let q: RecordsQuery = serde_urlencoded::from_str(&encoded).unwrap();
        q.to_query()
    }

    #[test]
    fn todays_parameters_read_as_before() {
        let q = records_query(&[("limit", "300")]).unwrap();
        assert_eq!(q.order, RecordOrder::Asc);
        assert_eq!(q.limit, Some(300));
        assert!(q.outcomes.is_empty() && q.stages.is_empty() && q.cursor.is_none());
        assert!(q.since_ms.is_none() && q.until_ms.is_none());
    }

    #[test]
    fn filters_and_paging_parse() {
        let q = records_query(&[
            ("order", "desc"),
            ("outcome", "blocked, failed"),
            ("stage", "judge,jury"),
            ("since", "1786492800"),
            ("until", "2026-08-12T01:00:00Z"),
            ("cursor", "42"),
            ("limit", "20"),
        ])
        .unwrap();
        assert_eq!(q.order, RecordOrder::Desc);
        assert_eq!(q.outcomes, [RecordOutcome::Blocked, RecordOutcome::Failed]);
        assert_eq!(q.stages, ["judge", "jury"]);
        assert_eq!(q.since_ms, Some(1_786_492_800_000), "unix seconds");
        assert_eq!(q.until_ms, Some(1_786_496_400_000), "RFC 3339");
        assert_eq!((q.cursor, q.limit), (Some(42), Some(20)));
    }

    #[test]
    fn malformed_filters_are_refused_by_name() {
        for (key, value, says) in [
            ("order", "newest", "order"),
            ("outcome", "blocked,denied", "outcome"),
            ("since", "yesterday", "since"),
            ("until", "2026-13-01", "until"),
            ("cursor", "-1", "cursor"),
            ("since", "99999999999999999", "since"),
        ] {
            let (status, message) = records_query(&[(key, value)]).expect_err(key);
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(message.contains(says), "{key}={value}: {message}");
        }
    }

    struct StubSigner;

    #[async_trait]
    impl crate::identity::ssi::vc_issuer::VcSigner for StubSigner {
        async fn sign(
            &self,
            payload: serde_json::Value,
        ) -> anyhow::Result<serde_json::Value> {
            Ok(payload)
        }
    }

    /// Governance logs for one surface of each of two tenants, an
    /// appliance-wide surface and a surface whose configuration was deleted,
    /// with the pipes behind the first three.
    async fn two_tenants(dir: &std::path::Path) -> (GovernanceStore, FileSystemPipeStore) {
        let pipes = FileSystemPipeStore::new(
            dir.join("pipes")
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("pipe store");
        for (id, tenant) in [
            ("owned-mine-stream", Some("tenant-a")),
            ("owned-theirs-stream", Some("tenant-b")),
            ("appliance-wide", None),
        ] {
            let mut pipe = PipeConfig::new(
                id.into(),
                id.into(),
                PipeType::Webhook {
                    endpoint: "https://example.test".into(),
                },
            );
            pipe.tenant_id = tenant.map(str::to_string);
            pipes
                .save(pipe)
                .await
                .expect("save pipe");
        }
        let store = GovernanceStore::new(
            dir.join("governance"),
            GovernanceSigner::new("did:web:example.com".to_string(), Arc::new(StubSigner)),
            None,
        );
        for surface in ["owned-mine-stream", "owned-theirs-stream", "appliance-wide", "deleted-surface"] {
            let draft = serde_json::from_value(serde_json::json!({
                "record_id": format!("rec-{surface}"),
                "surface_id": surface,
                "surface_name": format!("Name of {surface}"),
                "timestamp": "2026-08-12T00:00:00Z",
                "prev_record_hash": crate::governance::GENESIS_HASH,
            }))
            .expect("record draft");
            store
                .record(draft, 0)
                .await
                .expect("record");
        }
        (store, pipes)
    }

    fn tenant(id: &str) -> PatTenantContext {
        PatTenantContext {
            token_id: format!("tok-{id}"),
            tenant_id: id.into(),
        }
    }

    async fn listed(
        store: &GovernanceStore,
        pipes: &FileSystemPipeStore,
        context: Option<&PatTenantContext>,
        scope: Option<&PatResourceScope>,
    ) -> Vec<String> {
        visible_surfaces(store, Some(pipes), context, scope)
            .await
            .expect("surfaces")
            .into_iter()
            .map(|s| s.surface_id)
            .collect()
    }

    #[tokio::test]
    async fn a_tenant_token_lists_only_its_own_tenants_surfaces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pipes) = two_tenants(dir.path()).await;

        let appliance = listed(&store, &pipes, None, None).await;
        assert_eq!(
            appliance,
            ["appliance-wide", "deleted-surface", "owned-mine-stream", "owned-theirs-stream"],
            "an appliance caller sees every log, a deleted surface's included"
        );

        let a = tenant("tenant-a");
        assert_eq!(listed(&store, &pipes, Some(&a), None).await, ["owned-mine-stream"]);
        let b = tenant("tenant-b");
        assert_eq!(listed(&store, &pipes, Some(&b), None).await, ["owned-theirs-stream"]);

        let summaries = visible_surfaces(&store, Some(&pipes), Some(&a), None)
            .await
            .unwrap();
        assert_eq!(
            summaries[0]
                .surface_name
                .as_deref(),
            Some("Name of owned-mine-stream")
        );
    }

    #[tokio::test]
    async fn a_resource_scoped_token_lists_only_surfaces_its_pattern_admits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pipes) = two_tenants(dir.path()).await;
        let a = tenant("tenant-a");
        let admits_mine =
            PatResourceScope(Arc::new(regex::Regex::new("^TENANT:tenant-a:pipes:owned-mine-.*$").expect("pattern")));
        assert_eq!(listed(&store, &pipes, Some(&a), Some(&admits_mine)).await, ["owned-mine-stream"]);
        let admits_nothing =
            PatResourceScope(Arc::new(regex::Regex::new("^TENANT:tenant-a:pipes:other-.*$").expect("pattern")));
        assert!(
            listed(&store, &pipes, Some(&a), Some(&admits_nothing))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_tenant_caller_reads_only_its_tenants_records_since_its_surface_was_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_store, pipes) = two_tenants(dir.path()).await;
        let created = pipes
            .get("owned-mine-stream")
            .await
            .unwrap()
            .created_at;
        let a = tenant("tenant-a");
        assert_eq!(
            tenant_filter("owned-mine-stream", Some(&pipes), Some(&a)).await,
            Some(TenantFilter {
                tenant_id: "tenant-a".to_string(),
                unattributed_since_ms: chrono::DateTime::parse_from_rfc3339(&created)
                    .ok()
                    .map(|t| t.timestamp_millis()),
            })
        );
        assert!(
            tenant_filter("owned-mine-stream", Some(&pipes), Some(&a))
                .await
                .unwrap()
                .unattributed_since_ms
                .is_some()
        );
        assert_eq!(
            tenant_filter("owned-mine-stream", Some(&pipes), None).await,
            None,
            "an appliance caller reads every record"
        );
        assert_eq!(
            tenant_filter("deleted-surface", Some(&pipes), Some(&a))
                .await
                .and_then(|f| f.unattributed_since_ms),
            None,
            "without a surface, records that name no tenant are not the caller's"
        );
    }

    #[tokio::test]
    async fn a_tenant_caller_without_a_pipe_store_lists_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, _pipes) = two_tenants(dir.path()).await;
        let a = tenant("tenant-a");
        assert!(
            visible_surfaces(&store, None, Some(&a), None)
                .await
                .unwrap()
                .is_empty(),
            "ownership cannot be checked, so nothing is shown"
        );
    }
}
