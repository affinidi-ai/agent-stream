//! Read API for LLM drift dimension time-series. Administrator-gated
//! (`drift.view`). Reads **only** the `drift:*` namespace from the dedicated
//! drift store, so this endpoint can never expose usage or attributed series —
//! those live in a different store behind a different endpoint. This namespace
//! isolation is what keeps drift graphs confined to the LLM Drift page.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use axum::extract::{Path, Query, State};
use axum::{Extension, Json, http::StatusCode};
use serde::{Deserialize, Serialize};

use super::scoped_id::{authorize_surface_scope, res_scope, tenant_ctx};
use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::drift::dimension::surface_dimension_key;
use crate::drift::run::RunHandle;
use crate::drift::{
    DimensionVerdict, DriftBaseline, DriftDimension, DriftRun, DriftSeriesResponse, DriftStatus, DriftThresholds,
    EvalTask, RecordedSession, RunTrigger, all_running_views, cancel_run, drift_eval_runtime, evaluate_dimension,
    global_drift_baseline_store, global_drift_run_store, global_drift_session_store, global_drift_store,
    overall_status, register_run, resolve_run_cost_ceiling, run_eval_task, running_run_view, running_runs_for_surface,
    window_mean,
};
use crate::identity::IdentityApiState;
use crate::rbac::{Feature, RbacConfig};
use crate::tenancy::PatTenantContext;

use super::authz::require_feature as require;

type ApiResult<T> = Result<T, (StatusCode, String)>;

/// Cap on series keys per request (the dimension set × a handful of surfaces).
const MAX_KEYS: usize = 64;

fn default_max_points() -> usize {
    500
}

/// Query parameters for `GET /v1/drift/series`.
#[derive(Debug, Deserialize)]
pub struct DriftSeriesQuery {
    /// Comma-separated `drift:surface:{id}:{dimension}` keys.
    pub keys: String,
    /// Window start (unix seconds, inclusive).
    pub from: i64,
    /// Window end (unix seconds, inclusive).
    pub to: i64,
    /// Maximum points per series; the store picks the finest tier that fits.
    #[serde(default = "default_max_points")]
    pub max_points: usize,
    /// Optional explicit resolution tier label; `auto`/empty ⇒ auto-select.
    #[serde(default)]
    pub resolution: Option<String>,
}

fn parse_keys(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Accept only well-formed `drift:surface:{id}:{dimension}` keys — the id must
/// satisfy the pipe-id charset and the dimension must be a known one. This both
/// prevents key injection and confines the endpoint to the drift namespace.
fn is_valid_drift_key(key: &str) -> bool {
    let Some(rest) = key.strip_prefix("drift:surface:") else {
        return false;
    };
    let mut parts = rest.splitn(2, ':');
    let (Some(id), Some(dim)) = (parts.next(), parts.next()) else {
        return false;
    };
    let id_ok = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    let dim_ok = DriftDimension::ALL
        .iter()
        .any(|d| d.as_str() == dim);
    id_ok && dim_ok
}

/// The surface a `drift:surface:{id}:{dimension}` key reads from.
///
/// Every drift series key names the surface it belongs to, which is what makes
/// a key authorizable at all: the caller may read it only if they own that
/// surface. Returns `None` for anything not of that shape — and a `None` is a
/// refusal, never a pass, at the one call site.
fn surface_id_from_drift_key(key: &str) -> Option<&str> {
    key.strip_prefix("drift:surface:")?
        .split(':')
        .next()
        .filter(|id| !id.is_empty())
}

/// Authorize every surface a batch of keys touches, resolving each one once.
///
/// A chart asks for nine dimensions of one surface, so the distinct-surface set
/// is almost always a single entry while the key list is not. Without the memo
/// this would be nine pipe-store reads to answer one question nine times.
async fn authorize_drift_keys(
    keys: &[String],
    pipe_store: Option<&crate::pipes::FileSystemPipeStore>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), (StatusCode, String)> {
    // An appliance caller owns everything; skip the work entirely.
    if context.is_none() && scope.is_none() {
        return Ok(());
    }
    let mut seen: Vec<&str> = Vec::new();
    for key in keys {
        // A key whose surface cannot be read is refused rather than allowed:
        // `is_valid_drift_key` has already run, so reaching here means the
        // shape changed and nobody updated this.
        let Some(surface_id) = surface_id_from_drift_key(key) else {
            return Err((StatusCode::NOT_FOUND, "Not found".to_string()));
        };
        if seen.contains(&surface_id) {
            continue;
        }
        authorize_surface_scope(surface_id, pipe_store, context, scope).await?;
        seen.push(surface_id);
    }
    Ok(())
}

/// `GET /v1/drift/series` — drift dimension means over time for one or more
/// `drift:surface:{id}:{dimension}` keys. Backs the LLM Drift page charts.
pub async fn series(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<DriftSeriesQuery>,
) -> ApiResult<Json<Vec<DriftSeriesResponse>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftView).await?;
    if q.to < q.from {
        return Err((StatusCode::BAD_REQUEST, "`to` must be >= `from`".to_string()));
    }
    let keys = parse_keys(&q.keys);
    if keys.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "no series keys supplied".to_string()));
    }
    if keys.len() > MAX_KEYS {
        return Err((StatusCode::BAD_REQUEST, format!("Too many keys (max {MAX_KEYS})")));
    }
    if let Some(bad) = keys
        .iter()
        .find(|k| !is_valid_drift_key(k))
    {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid drift series key: {bad}")));
    }
    // Shape alone was never authorization: a well-formed key naming somebody
    // else's surface used to return their numbers.
    authorize_drift_keys(&keys, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope)).await?;
    let store =
        global_drift_store().ok_or((StatusCode::SERVICE_UNAVAILABLE, "Drift store not configured".to_string()))?;
    let max_points = q.max_points.clamp(1, 5000);
    let force_tier = q
        .resolution
        .as_deref()
        .filter(|r| !r.is_empty() && *r != "auto");

    let out = store
        .range_many(&keys, q.from, q.to, max_points, force_tier)
        .await;
    Ok(Json(out))
}

/// Metadata for one drift dimension, so the LLM Drift page can render a chart
/// per dimension (title, axis unit, whether to fix the axis to `[0,1]`) without
/// hardcoding the dimension set.
#[derive(Serialize)]
pub struct DimensionInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub unit: &'static str,
    pub is_rate: bool,
    /// What produces this dimension's observations, shown when its chart is
    /// empty so "not applicable here" is distinguishable from "broken".
    pub source_hint: &'static str,
}

/// `GET /v1/drift/dimensions` — the drift dimensions and their display metadata.
pub async fn dimensions(
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Vec<DimensionInfo>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftView).await?;
    let out = DriftDimension::ALL
        .iter()
        .map(|d| DimensionInfo {
            id: d.as_str(),
            label: d.label(),
            unit: d.unit(),
            is_rate: d.is_rate(),
            source_hint: d.source_hint(),
        })
        .collect();
    Ok(Json(out))
}

/// Reject surface ids that could escape a store root or inject a series key
/// (the surface id is a pipe id, and here also a series-key fragment).
fn validate_surface_id(id: &str) -> ApiResult<()> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, "Invalid surface id".to_string()))
    }
}

/// Fetch each dimension's count-weighted window mean for `surface_id` over
/// `[from, to]`, keyed by dimension id (absent dimensions have no samples).
async fn dimension_means(
    surface_id: &str,
    from: i64,
    to: i64,
) -> HashMap<String, (f64, u64)> {
    let Some(store) = global_drift_store() else {
        return HashMap::new();
    };
    let keys: Vec<String> = DriftDimension::ALL
        .iter()
        .map(|d| surface_dimension_key(surface_id, *d))
        .collect();
    let series = store
        .range_many(&keys, from, to, 500, None)
        .await;
    let by_key: HashMap<&str, &DriftSeriesResponse> = series
        .iter()
        .map(|s| (s.key.as_str(), s))
        .collect();
    let mut out = HashMap::new();
    for dim in DriftDimension::ALL {
        let key = surface_dimension_key(surface_id, dim);
        if let Some(m) = by_key
            .get(key.as_str())
            .and_then(|s| window_mean(&s.points))
        {
            out.insert(dim.as_str().to_string(), m);
        }
    }
    out
}

/// Query for the verdict endpoint: which surface + the window to judge.
#[derive(Debug, Deserialize)]
pub struct VerdictQuery {
    pub surface_id: String,
    pub from: i64,
    pub to: i64,
}

/// A surface's drift verdict: the overall status plus a per-dimension breakdown.
#[derive(Serialize)]
pub struct SurfaceVerdict {
    pub surface_id: String,
    pub status: DriftStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_captured_at: Option<String>,
    pub dimensions: Vec<DimensionVerdict>,
}

/// Resolve a surface's drift verdict thresholds — the surface's operator
/// overrides when set, else the built-in defaults. A missing pipe store or an
/// unknown surface resolves to the defaults.
async fn surface_thresholds(
    state: &IdentityApiState,
    surface_id: &str,
) -> DriftThresholds {
    let Some(store) = state.pipe_store.as_ref() else {
        return DriftThresholds::default();
    };
    store
        .get(surface_id)
        .await
        .and_then(|p| {
            p.drift
                .map(|d| d.thresholds())
        })
        .unwrap_or_default()
}

/// `GET /v1/drift/verdict?surface_id=&from=&to=` — the surface's drift verdict
/// over the window, comparing each dimension's current mean to its baseline.
pub async fn verdict(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<VerdictQuery>,
) -> ApiResult<Json<SurfaceVerdict>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftView).await?;
    validate_surface_id(&q.surface_id)?;
    authorize_surface_scope(&q.surface_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
        .await?;
    if q.to < q.from {
        return Err((StatusCode::BAD_REQUEST, "`to` must be >= `from`".to_string()));
    }
    let baseline = match global_drift_baseline_store() {
        Some(s) => s.get(&q.surface_id).await,
        None => None,
    };
    let means = dimension_means(&q.surface_id, q.from, q.to).await;
    let thresholds = surface_thresholds(&state, &q.surface_id).await;
    let dimensions: Vec<DimensionVerdict> = DriftDimension::ALL
        .iter()
        .map(|dim| {
            let base = baseline
                .as_ref()
                .and_then(|b| {
                    b.dimensions
                        .get(dim.as_str())
                        .copied()
                });
            evaluate_dimension(
                *dim,
                base,
                means
                    .get(dim.as_str())
                    .copied(),
                &thresholds,
            )
        })
        .collect();
    let status = overall_status(&dimensions);
    Ok(Json(SurfaceVerdict {
        surface_id: q.surface_id,
        status,
        baseline_captured_at: baseline.map(|b| b.captured_at),
        dimensions,
    }))
}

/// Query carrying just a surface id.
#[derive(Debug, Deserialize)]
pub struct SurfaceIdQuery {
    pub surface_id: String,
}

/// Query for the run-history list: an optional surface filter and a cap on the
/// cross-surface view.
#[derive(Debug, Deserialize)]
pub struct RunsQuery {
    pub surface_id: Option<String>,
    pub limit: Option<usize>,
}

/// `GET /v1/drift/baseline?surface_id=` — the surface's pinned baseline, if any.
pub async fn baseline(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<SurfaceIdQuery>,
) -> ApiResult<Json<Option<DriftBaseline>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftView).await?;
    validate_surface_id(&q.surface_id)?;
    authorize_surface_scope(&q.surface_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
        .await?;
    let store = global_drift_baseline_store()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Drift baseline store not configured".to_string()))?;
    Ok(Json(store.get(&q.surface_id).await))
}

fn default_baseline_window_secs() -> i64 {
    86_400
}

/// Query for baseline capture: surface + the window to average.
#[derive(Debug, Deserialize)]
pub struct BaselineCaptureQuery {
    pub surface_id: String,
    #[serde(default = "default_baseline_window_secs")]
    pub window_secs: i64,
}

/// `POST /v1/drift/baseline?surface_id=&window_secs=` — pin the surface's current
/// behaviour (each dimension's mean over the window) as its baseline.
pub async fn capture_baseline(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<BaselineCaptureQuery>,
) -> ApiResult<Json<DriftBaseline>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftManage).await?;
    validate_surface_id(&q.surface_id)?;
    authorize_surface_scope(&q.surface_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
        .await?;
    let window = q
        .window_secs
        .clamp(300, 30 * 86_400);
    let store = global_drift_baseline_store()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Drift baseline store not configured".to_string()))?;
    let to = chrono::Utc::now().timestamp();
    let means = dimension_means(&q.surface_id, to - window, to).await;
    if means.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No drift data in the window to baseline".to_string()));
    }
    let baseline = DriftBaseline {
        surface_id: q.surface_id.clone(),
        captured_at: chrono::Utc::now().to_rfc3339(),
        window_secs: window,
        dimensions: means
            .into_iter()
            .map(|(k, (m, _))| (k, m))
            .collect(),
    };
    store
        .save(&baseline)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save baseline: {e}")))?;
    Ok(Json(baseline))
}

/// `GET /v1/drift/sessions?surface_id=` — the surface's captured "indicative"
/// sessions (the prompt/response pairs a replay evaluation re-runs), newest
/// first.
pub async fn list_sessions(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<SurfaceIdQuery>,
) -> ApiResult<Json<Vec<RecordedSession>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftView).await?;
    validate_surface_id(&q.surface_id)?;
    authorize_surface_scope(&q.surface_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
        .await?;
    let store = global_drift_session_store()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Drift session store not configured".to_string()))?;
    Ok(Json(
        store
            .list_for_surface(&q.surface_id)
            .await,
    ))
}

/// Query for `POST /v1/drift/eval/run`. The **source** surface owns the captured
/// sessions + the eval config + the baseline comparison; the **target** provides
/// the executor (a different surface or variant lets an operator test a change
/// without disturbing the source's baseline). Both default to `surface_id`.
#[derive(Debug, Deserialize)]
pub struct EvalRunQuery {
    /// Source surface (whose captured sessions + eval config + baseline).
    pub surface_id: String,
    /// Target surface to run the sessions through (defaults to the source).
    #[serde(default)]
    pub target_surface_id: Option<String>,
    /// Variant alias to resolve on the target (an experiment).
    #[serde(default)]
    pub variant: Option<String>,
}

/// `POST /v1/drift/eval/run?surface_id=&target_surface_id=&variant=` — replay the
/// **source** surface's captured sessions through the **target** surface/variant
/// (both default to the source), comparing each new answer to the
/// originally-captured one. Only a plain self-run (same surface, no variant)
/// folds into the source's drift dimensions; an experiment is inspect-only.
///
/// **Async:** the replay can take minutes (a judge/jury surface replays many
/// slow upstream calls per session), so this registers the run and returns its
/// **running** record immediately; poll `GET /v1/drift/runs/{id}` for progress
/// and `POST /v1/drift/eval/cancel?run_id=` to stop it.
pub async fn run_eval(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<EvalRunQuery>,
) -> ApiResult<Json<DriftRun>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftManage).await?;
    let source_id = q.surface_id.clone();
    validate_surface_id(&source_id)?;
    let target_id = q
        .target_surface_id
        .clone()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| source_id.clone());
    validate_surface_id(&target_id)?;
    // Both the source (its captured sessions/baseline) and the target (its
    // executor) must be surfaces the caller owns — a run reads/replays both.
    authorize_surface_scope(&source_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope)).await?;
    authorize_surface_scope(&target_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope)).await?;
    let variant = q
        .variant
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    if let Some(v) = variant.as_deref() {
        // A variant alias shares the surface-id charset (`[A-Za-z0-9_-]`); the
        // target's variant set is enforced by `prepare_pipe_execution`.
        validate_surface_id(v)?;
    }

    // Prepare the TARGET's executor (resolving the variant), so the sessions run
    // through the surface/variant being evaluated.
    let (target_config, executor, default_path) =
        crate::pipes::api::prepare_pipe_execution(&state, &target_id, variant.as_deref()).await?;
    // The SOURCE surface's eval config + name define the comparison (its data +
    // baseline). Reuse the resolved target config when it's the same surface.
    let (source_eval, source_name, source_tenant_id) = if source_id == target_id {
        (
            target_config
                .drift
                .as_ref()
                .and_then(|d| d.eval.clone())
                .unwrap_or_default(),
            target_config.name.clone(),
            target_config
                .tenant_id
                .clone(),
        )
    } else {
        let src = state
            .pipe_store
            .as_ref()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Pipe store not initialized".to_string()))?
            .get(&source_id)
            .await
            .ok_or((StatusCode::NOT_FOUND, format!("Source surface not found: {source_id}")))?;
        (
            src.drift
                .as_ref()
                .and_then(|d| d.eval.clone())
                .unwrap_or_default(),
            src.name.clone(),
            src.tenant_id.clone(),
        )
    };
    let model = match &target_config.pipe_type {
        crate::pipes::config::PipeType::LLM { provider, .. } => provider
            .model_name()
            .to_string(),
        _ => String::new(),
    };
    // Fold into the baseline series only for the plain self-run.
    let fold = target_id == source_id && variant.is_none();

    let (target_warn, target_drift) = target_config
        .drift
        .as_ref()
        .map(|d| (d.warn_threshold, d.drift_threshold))
        .unwrap_or((None, None));

    // Register the in-flight run + spawn the replay so the request returns a run
    // id immediately. A manual run always executes — even a suspended surface —
    // so an operator can retry a fix; a successful run clears the suspension.
    let runtime = drift_eval_runtime();
    let run_id = uuid::Uuid::new_v4().to_string();
    let handle = register_run(
        &run_id,
        RunHandle {
            surface_id: source_id.clone(),
            surface_name: source_name.clone(),
            target_surface_id: (target_id != source_id).then(|| target_id.clone()),
            variant: variant.clone(),
            trigger: RunTrigger::Manual,
            started_at: chrono::Utc::now().to_rfc3339(),
            total: AtomicUsize::new(0),
            progress: AtomicUsize::new(0),
            cancelled: AtomicBool::new(false),
        },
    );
    let view =
        running_run_view(&run_id).ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Failed to register run".to_string()))?;
    let task = EvalTask {
        executor,
        default_path,
        model,
        source_surface_id: source_id,
        source_surface_name: source_name,
        source_tenant_id,
        target_surface_id: target_id,
        variant,
        fold_into_series: fold,
        max_run_cost_usd: resolve_run_cost_ceiling(source_eval.max_run_cost_usd, runtime.max_run_cost_usd),
        eval: source_eval,
        target_config,
        trigger: RunTrigger::Manual,
        run_id,
        handle,
        session_timeout: runtime.session_timeout,
        max_failures: runtime.max_failures,
        target_warn_threshold: target_warn,
        target_drift_threshold: target_drift,
    };
    tokio::spawn(async move {
        run_eval_task(task).await;
    });
    Ok(Json(view))
}

/// Query for `POST /v1/drift/eval/cancel`.
#[derive(Debug, Deserialize)]
pub struct CancelRunQuery {
    pub run_id: String,
}

/// `POST /v1/drift/eval/cancel?run_id=` — request cancellation of an in-flight
/// replay evaluation. It stops cleanly between sessions and is recorded as
/// `cancelled`. 404 when no in-flight run has that id (already finished/unknown).
pub async fn cancel_eval(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<CancelRunQuery>,
) -> ApiResult<StatusCode> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftManage).await?;
    // The run id is a generated UUID; validate the charset so it can't be used to
    // probe the store or registry with arbitrary input.
    validate_surface_id(&q.run_id)?;
    cancel_run_in_scope(&q.run_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope)).await?;
    Ok(StatusCode::ACCEPTED)
}

/// Cancel the in-flight run `run_id` when the caller may act on its surface.
///
/// The run is resolved *before* cancelling so the surface it belongs to can be
/// authorized: a run id is a UUID nobody can guess, but `GET /v1/drift/runs`
/// hands them out. An unknown, finished or foreign run is the same 404.
async fn cancel_run_in_scope(
    run_id: &str,
    pipe_store: Option<&crate::pipes::FileSystemPipeStore>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> ApiResult<()> {
    let not_found = || (StatusCode::NOT_FOUND, "No in-flight run with that id".to_string());
    let run = running_run_view(run_id).ok_or_else(not_found)?;
    authorize_surface_scope(&run.surface_id, pipe_store, context, scope)
        .await
        .map_err(|_| not_found())?;
    if cancel_run(run_id) {
        Ok(())
    } else {
        Err(not_found())
    }
}

/// `GET /v1/drift/runs?surface_id=&limit=` — evaluation run history, newest
/// first. With `surface_id` it returns that surface's full history; without it,
/// the most recent `limit` runs (default 25) across **all** surfaces.
pub async fn list_runs(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<RunsQuery>,
) -> ApiResult<Json<Vec<DriftRun>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftView).await?;
    let store = global_drift_run_store()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Drift run store not configured".to_string()))?;
    match q
        .surface_id
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        // One surface: in-flight (live) first, then its persisted history.
        Some(surface_id) => {
            validate_surface_id(surface_id)?;
            authorize_surface_scope(surface_id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
                .await?;
            let mut runs = running_runs_for_surface(surface_id);
            runs.extend(
                store
                    .list_for_surface(surface_id)
                    .await,
            );
            Ok(Json(runs))
        }
        // All surfaces: every in-flight run + the most recent `limit`, merged.
        //
        // The merge is done before the filter, and the `limit` applied after, so
        // a scoped caller asking for 25 gets 25 of *theirs* rather than whatever
        // survives of the appliance's newest 25.
        None => {
            let limit = q
                .limit
                .unwrap_or(25)
                .clamp(1, 200);
            let mut runs = all_running_views();
            runs.extend(store.list_recent(limit).await);
            runs = retain_authorized_runs(runs, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
                .await;
            runs.sort_by(|a, b| b.ran_at.cmp(&a.ran_at));
            runs.truncate(limit);
            Ok(Json(runs))
        }
    }
}

/// Drop the runs a scoped caller does not own.
///
/// This listing takes no surface id, so there is nothing to authorize up front
/// — it used to answer with the appliance's most recent runs across every
/// tenant, handing out other tenants' surface ids and the run ids that made
/// `cancel` reachable.
///
/// Resolved once per distinct surface: a page of runs is usually a handful of
/// surfaces, and without the memo this is a pipe-store read per row.
async fn retain_authorized_runs(
    runs: Vec<DriftRun>,
    pipe_store: Option<&crate::pipes::FileSystemPipeStore>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Vec<DriftRun> {
    // An appliance caller owns everything; the cross-tenant view is the point.
    if context.is_none() && scope.is_none() {
        return runs;
    }
    let mut verdict: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    let mut kept = Vec::with_capacity(runs.len());
    for run in runs {
        let allowed = match verdict.get(&run.surface_id) {
            Some(known) => *known,
            None => {
                let ok = authorize_surface_scope(&run.surface_id, pipe_store, context, scope)
                    .await
                    .is_ok();
                verdict.insert(run.surface_id.clone(), ok);
                ok
            }
        };
        if allowed {
            kept.push(run);
        }
    }
    kept
}

/// `GET /v1/drift/runs/{id}` — one persisted run, with its per-sample outcomes.
pub async fn get_run(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Path(id): Path<String>,
) -> ApiResult<Json<DriftRun>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::DriftView).await?;
    validate_surface_id(&id)?;
    find_run_in_scope(&id, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope))
        .await
        .map(Json)
}

/// The run `id` when the caller may read its surface. An in-flight run is
/// served live from the registry (progress); a finished one from the persisted
/// store.
///
/// A run id is a UUID nobody can namespace, so the only thing that can be
/// authorized is the surface it belongs to. Checked *after* the lookup and
/// answered as 404 either way, so this cannot be used to probe which run ids
/// exist on the appliance.
async fn find_run_in_scope(
    id: &str,
    pipe_store: Option<&crate::pipes::FileSystemPipeStore>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> ApiResult<DriftRun> {
    let run = match running_run_view(id) {
        Some(view) => view,
        None => {
            let store = global_drift_run_store()
                .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Drift run store not configured".to_string()))?;
            store
                .get(id)
                .await
                .ok_or((StatusCode::NOT_FOUND, "Run not found".to_string()))?
        }
    };
    authorize_surface_scope(&run.surface_id, pipe_store, context, scope)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Run not found".to_string()))?;
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_drift_namespace_keys_are_valid() {
        assert!(is_valid_drift_key("drift:surface:pipe-1:latency_ms"));
        assert!(is_valid_drift_key("drift:surface:abc_123:refusal_rate"));
        // Wrong namespace / attributed usage keys are rejected.
        assert!(!is_valid_drift_key("surface:pipe-1"));
        assert!(!is_valid_drift_key("member:abc:surface:pipe-1"));
        assert!(!is_valid_drift_key("drift:surface:pipe-1")); // no dimension
        assert!(!is_valid_drift_key("drift:surface:pipe-1:not_a_dim"));
        assert!(!is_valid_drift_key("drift:surface:../etc:latency_ms"));
    }

    #[test]
    fn parse_keys_trims_and_drops_blanks() {
        assert_eq!(
            parse_keys("drift:surface:p:latency_ms, , drift:surface:p:refusal_rate "),
            vec!["drift:surface:p:latency_ms", "drift:surface:p:refusal_rate"]
        );
    }

    use crate::pipes::{FileSystemPipeStore, PipeConfig, PipeType};
    use crate::tenancy::PatTenantContext;
    use std::sync::Arc;

    /// The tenant a resource-scoped token acts for, and the pattern it carries.
    ///
    /// Shaped like a control plane's provisioning token: one tenant, and a
    /// prefix its own surfaces are named with.
    fn tenant_scope() -> (PatTenantContext, PatResourceScope) {
        let context = PatTenantContext {
            token_id: "tok-1".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(Arc::new(
            regex::Regex::new("^TENANT:tenant-a:(?:pipes:owned-.*|secrets:owned-.*)$").expect("pattern"),
        ));
        (context, scope)
    }

    /// Two surfaces on one appliance, owned by different tenants — the
    /// situation every guard below exists for.
    async fn store_with_two_tenants(dir: &std::path::Path) -> FileSystemPipeStore {
        let store = FileSystemPipeStore::new(
            dir.to_str()
                .expect("utf-8 tempdir")
                .to_string(),
        )
        .await
        .expect("pipe store");
        for (id, tenant) in [("owned-mine-stream", "tenant-a"), ("owned-theirs-stream", "tenant-b")] {
            let mut pipe = PipeConfig::new(
                id.into(),
                id.into(),
                PipeType::Webhook {
                    endpoint: "https://example.test".into(),
                },
            );
            pipe.tenant_id = Some(tenant.into());
            store
                .save(pipe)
                .await
                .expect("save pipe");
        }
        store
    }

    /// Built through serde rather than a literal, so this fixture does not have
    /// to be revisited every time `DriftRun` grows a field it does not care
    /// about — only the ones without a `serde(default)` are named.
    fn run_on(surface_id: &str) -> DriftRun {
        serde_json::from_value(serde_json::json!({
            "id": format!("run-for-{surface_id}"),
            "suite_id": surface_id,
            "suite_name": surface_id,
            "surface_id": surface_id,
            "ran_at": "2026-09-24T00:00:00Z",
            "trigger": "manual",
            "total": 0,
            "passed": 0,
            "errors": 0,
            "quality": 0.0,
            "samples": [],
        }))
        .expect("drift run fixture")
    }

    #[test]
    fn a_drift_key_names_the_surface_it_reads() {
        assert_eq!(surface_id_from_drift_key("drift:surface:pipe-1:latency_ms"), Some("pipe-1"));
        // Not a drift key, or no surface in it — both must refuse rather than
        // resolve to something the caller then gets authorized for.
        assert_eq!(surface_id_from_drift_key("surface:pipe-1"), None);
        assert_eq!(surface_id_from_drift_key("drift:surface::latency_ms"), None);
        assert_eq!(surface_id_from_drift_key("drift:surface:"), None);
    }

    /// The leak this closes: a well-formed key naming somebody else's surface
    /// used to return their numbers, because shape was the only check.
    #[tokio::test]
    async fn drift_series_keys_are_refused_across_tenants() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with_two_tenants(dir.path()).await;
        let (context, scope) = tenant_scope();

        let mine = vec!["drift:surface:owned-mine-stream:latency_ms".to_string()];
        assert!(
            authorize_drift_keys(&mine, Some(&store), Some(&context), Some(&scope))
                .await
                .is_ok(),
            "a caller must still read their own surface"
        );

        let theirs = vec!["drift:surface:owned-theirs-stream:latency_ms".to_string()];
        assert!(
            authorize_drift_keys(&theirs, Some(&store), Some(&context), Some(&scope))
                .await
                .is_err(),
            "another tenant's surface must be refused"
        );

        // The mixed batch is the one that matters: one bad key must fail the
        // whole request rather than being quietly dropped from the results.
        let mixed = vec![
            "drift:surface:owned-mine-stream:latency_ms".to_string(),
            "drift:surface:owned-theirs-stream:cost".to_string(),
        ];
        assert!(
            authorize_drift_keys(&mixed, Some(&store), Some(&context), Some(&scope))
                .await
                .is_err(),
            "a batch is only as authorized as its least authorized key"
        );
    }

    /// An appliance-wide caller (no tenant context, no pattern) is unrestricted
    /// — that is what the admin token is for, and the check must not cost it a
    /// store read per key either.
    #[tokio::test]
    async fn an_appliance_caller_reads_every_surface() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with_two_tenants(dir.path()).await;
        let keys = vec!["drift:surface:owned-theirs-stream:latency_ms".to_string()];
        assert!(
            authorize_drift_keys(&keys, Some(&store), None, None)
                .await
                .is_ok()
        );
    }

    /// `GET /v1/drift/runs` with no surface id used to answer with the
    /// appliance's most recent runs across every tenant — handing out other
    /// tenants' surface ids, and the run ids that made `cancel` reachable.
    #[tokio::test]
    async fn the_cross_surface_run_listing_keeps_only_the_callers_own() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with_two_tenants(dir.path()).await;
        let (context, scope) = tenant_scope();
        let runs = vec![run_on("owned-mine-stream"), run_on("owned-theirs-stream"), run_on("owned-mine-stream")];

        let kept = retain_authorized_runs(runs.clone(), Some(&store), Some(&context), Some(&scope)).await;
        assert_eq!(kept.len(), 2, "only the caller's own runs survive");
        assert!(
            kept.iter()
                .all(|r| r.surface_id == "owned-mine-stream"),
            "no other tenant's run may appear: {:?}",
            kept.iter()
                .map(|r| &r.surface_id)
                .collect::<Vec<_>>()
        );

        // The appliance-wide view is the point of the unfiltered listing.
        assert_eq!(
            retain_authorized_runs(runs, Some(&store), None, None)
                .await
                .len(),
            3
        );
    }

    /// A surface the store has never heard of is refused, not passed through.
    /// Fail-closed matters most here: a run record naming a deleted surface
    /// must not become readable by everyone.
    #[tokio::test]
    async fn an_unknown_surface_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with_two_tenants(dir.path()).await;
        let (context, scope) = tenant_scope();
        let kept =
            retain_authorized_runs(vec![run_on("owned-vanished-stream")], Some(&store), Some(&context), Some(&scope))
                .await;
        assert!(kept.is_empty());
    }

    #[test]
    fn surface_id_validation_blocks_traversal() {
        assert!(validate_surface_id("pipe-1").is_ok());
        assert!(validate_surface_id("abc_123").is_ok());
        assert!(validate_surface_id("").is_err());
        assert!(validate_surface_id("../etc").is_err());
        assert!(validate_surface_id("a/b").is_err());
        assert!(validate_surface_id(&"x".repeat(129)).is_err());
    }

    /// Register an in-flight run on `surface_id`; deregistered when dropped.
    struct InFlight(String);

    impl InFlight {
        fn on(surface_id: &str) -> (Self, Arc<RunHandle>) {
            let run_id = uuid::Uuid::new_v4().to_string();
            let handle = register_run(
                &run_id,
                RunHandle {
                    surface_id: surface_id.to_string(),
                    surface_name: surface_id.to_string(),
                    target_surface_id: None,
                    variant: None,
                    trigger: RunTrigger::Manual,
                    started_at: "2026-10-20T00:00:00Z".to_string(),
                    total: AtomicUsize::new(3),
                    progress: AtomicUsize::new(1),
                    cancelled: AtomicBool::new(false),
                },
            );
            (Self(run_id), handle)
        }
    }

    impl Drop for InFlight {
        fn drop(&mut self) {
            crate::drift::run::deregister_run(&self.0);
        }
    }

    #[tokio::test]
    async fn a_scoped_caller_cannot_cancel_another_tenants_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with_two_tenants(dir.path()).await;
        let (context, scope) = tenant_scope();
        let (theirs, their_handle) = InFlight::on("owned-theirs-stream");
        let (mine, my_handle) = InFlight::on("owned-mine-stream");

        let refused = cancel_run_in_scope(&theirs.0, Some(&store), Some(&context), Some(&scope))
            .await
            .expect_err("a foreign run is not cancelled");
        assert_eq!(refused.0, StatusCode::NOT_FOUND, "answered like an unknown run");
        assert!(
            !their_handle
                .cancelled
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        assert!(
            cancel_run_in_scope(&mine.0, Some(&store), Some(&context), Some(&scope))
                .await
                .is_ok()
        );
        assert!(
            my_handle
                .cancelled
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        let unknown = cancel_run_in_scope("no-such-run", Some(&store), Some(&context), Some(&scope))
            .await
            .expect_err("an unknown run is not cancelled");
        assert_eq!(unknown, refused, "foreign and unknown runs look the same");

        assert!(
            cancel_run_in_scope(&theirs.0, Some(&store), None, None)
                .await
                .is_ok(),
            "an appliance caller cancels any run"
        );
        assert!(
            their_handle
                .cancelled
                .load(std::sync::atomic::Ordering::Relaxed)
        );
    }

    #[tokio::test]
    async fn a_scoped_caller_cannot_read_another_tenants_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store_with_two_tenants(dir.path()).await;
        let (context, scope) = tenant_scope();
        let (theirs, _) = InFlight::on("owned-theirs-stream");
        let (mine, _) = InFlight::on("owned-mine-stream");

        let refused = find_run_in_scope(&theirs.0, Some(&store), Some(&context), Some(&scope))
            .await
            .expect_err("a foreign run is not returned");
        assert_eq!(refused, (StatusCode::NOT_FOUND, "Run not found".to_string()));

        let own = find_run_in_scope(&mine.0, Some(&store), Some(&context), Some(&scope))
            .await
            .expect("the caller's own run is returned");
        assert_eq!(own.surface_id, "owned-mine-stream");
        assert_eq!(own.id, mine.0);
        assert_eq!(
            find_run_in_scope(&theirs.0, Some(&store), None, None)
                .await
                .map(|run| run.surface_id),
            Ok("owned-theirs-stream".to_string()),
            "an appliance caller reads any run"
        );
    }
}
