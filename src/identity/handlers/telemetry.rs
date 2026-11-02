//! Read-only time-series telemetry endpoint backing the dashboard usage graphs.
//!
//! Returns spend / token / request counts over a requested window at the finest
//! resolution that fits, for one or more series keys at once (so per-member line
//! charts can be fetched in a single round trip). Data is served from the
//! process-wide [`crate::telemetry::TelemetryStore`]; access is gated on the
//! `metrics.view` RBAC feature, mirroring the rest of the metrics surface.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use super::scoped_id::{authorize_series_key, res_scope, tenant_ctx};
use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::identity::state::IdentityApiState;
use crate::metrics::ops_telemetry::{OpsSeriesResponse, global_ops_store};
use crate::rbac::{Feature, RbacConfig};
use crate::telemetry::{SeriesResponse, global_telemetry_store};
use crate::tenancy::PatTenantContext;

use super::authz::require_feature as require;

type ApiResult<T> = Result<T, (StatusCode, String)>;

/// Default number of points returned per series when the caller omits a cap.
fn default_max_points() -> usize {
    500
}

/// Upper bound on the number of series keys one request may fetch. A large
/// team's per-member chart legitimately needs many keys, so the cap is generous,
/// but it bounds the per-request lock-taking `range` calls an authenticated
/// caller can trigger.
const MAX_KEYS: usize = 256;

/// Split and clean a comma-separated `keys` parameter into distinct series keys.
fn parse_keys(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string)
        .collect()
}

/// Whether a series key is attributed to an individual member or team (as
/// opposed to appliance-wide, surface, or stage scope). Reading per-member or
/// per-team usage/rejection breakdowns is more sensitive than aggregate or
/// surface figures, so it requires the stricter `metrics.view_attributed`
/// feature in addition to `metrics.view`.
fn is_attributed_key(key: &str) -> bool {
    key.starts_with("member:")
        || key.starts_with("team:")
        || key.starts_with("rejection:member:")
        || key.starts_with("rejection:team:")
}

/// Normalise the optional `resolution` parameter into a forced-tier label,
/// treating empty / `auto` as "auto-pick".
fn force_tier_from(resolution: &Option<String>) -> Option<&str> {
    resolution
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty() && !r.eq_ignore_ascii_case("auto"))
}

/// Query parameters for `GET /v1/telemetry/series`.
#[derive(Debug, Deserialize)]
pub struct SeriesQuery {
    /// Comma-separated list of series keys (e.g. `team:abc,member:def`).
    pub keys: String,
    /// Window start (unix seconds, inclusive).
    pub from: i64,
    /// Window end (unix seconds, inclusive).
    pub to: i64,
    /// Maximum points per series; the store picks the finest tier that fits.
    #[serde(default = "default_max_points")]
    pub max_points: usize,
    /// Optional explicit resolution tier label (e.g. `5m`, `1h`). When set to a
    /// known tier the store serves that exact resolution regardless of the
    /// window; omitted or unknown ⇒ the store auto-picks. `auto` is treated as
    /// omitted.
    #[serde(default)]
    pub resolution: Option<String>,
}

/// `GET /v1/telemetry/series` — usage over time for one or more series keys.
pub async fn series(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<SeriesQuery>,
) -> ApiResult<Json<Vec<SeriesResponse>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MetricsView).await?;
    if q.to < q.from {
        return Err((StatusCode::BAD_REQUEST, "`to` must be >= `from`".to_string()));
    }
    let keys = parse_keys(&q.keys);
    if keys.len() > MAX_KEYS {
        return Err((StatusCode::BAD_REQUEST, format!("Too many keys (max {MAX_KEYS})")));
    }
    // Tenant confinement: a tenant/resource-scoped caller may read only series
    // for surfaces it owns; attributed/appliance-wide keys 404 (fail closed).
    for key in &keys {
        authorize_series_key(key, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope)).await?;
    }
    if keys
        .iter()
        .any(|k| is_attributed_key(k))
    {
        require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MetricsViewAttributed).await?;
    }
    let store = global_telemetry_store()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Telemetry store not configured".to_string()))?;
    let max_points = q.max_points.clamp(1, 5000);
    let force_tier = force_tier_from(&q.resolution);

    let out = store
        .range_many(&keys, q.from, q.to, max_points, force_tier)
        .await;
    Ok(Json(out))
}

/// `GET /v1/dashboard/ops-series` — operational metrics (connections, throughput,
/// tokens, latency) over time for one or more `ops:*` series keys. Backs the
/// dashboard's shared drag-rail charts. RBAC-gated on `metrics.view`, served from
/// the process-wide [`crate::metrics::ops_telemetry::OpsMetricsStore`] via the
/// swappable [`crate::timeseries::TimeSeriesBackend`] port.
pub async fn ops_series(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<SeriesQuery>,
) -> ApiResult<Json<Vec<OpsSeriesResponse>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MetricsView).await?;
    if q.to < q.from {
        return Err((StatusCode::BAD_REQUEST, "`to` must be >= `from`".to_string()));
    }
    let keys = parse_keys(&q.keys);
    if keys.len() > MAX_KEYS {
        return Err((StatusCode::BAD_REQUEST, format!("Too many keys (max {MAX_KEYS})")));
    }
    // `ops:*` keys are appliance-wide operational metrics with no surface
    // dimension, so a tenant/resource-scoped caller is denied all of them here.
    for key in &keys {
        authorize_series_key(key, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&scope)).await?;
    }
    let store = global_ops_store()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Operational metrics store not configured".to_string()))?;
    let max_points = q.max_points.clamp(1, 5000);
    let force_tier = force_tier_from(&q.resolution);

    let out = store
        .range_many(&keys, q.from, q.to, max_points, force_tier)
        .await;
    Ok(Json(out))
}

/// Validate a `rejection:*` scope for the rejections endpoint. Accepts only the
/// well-formed scopes the dashboard builds — `rejection:all`, a surface
/// (optionally with a `:stage:{stage}` suffix), a team, or a member — so a
/// malformed or already-category-suffixed key (e.g. `rejection:all:hate`) is
/// rejected with a 400 rather than silently returning all-zero counts.
fn is_valid_rejection_scope(scope: &str) -> bool {
    if scope == "rejection:all" {
        return true;
    }
    ["rejection:surface:", "rejection:team:", "rejection:member:"]
        .iter()
        .filter_map(|prefix| scope.strip_prefix(prefix))
        .any(|rest| !rest.is_empty() && !rest.ends_with(':'))
}

/// Query parameters for `GET /v1/telemetry/rejections`.
#[derive(Debug, Deserialize)]
pub struct RejectionsQuery {
    /// The rejection series key prefix to break down, e.g. `rejection:all`,
    /// `rejection:surface:{pipe}`, `rejection:surface:{pipe}:stage:{stage}`,
    /// `rejection:team:{team}`, or `rejection:member:{member}`. The per-category
    /// series queried are `{scope}:{category}`.
    pub scope: String,
    /// Window start (unix seconds, inclusive).
    pub from: i64,
    /// Window end (unix seconds, inclusive).
    pub to: i64,
    /// Optional explicit resolution tier label; omitted/unknown/`auto` ⇒ auto.
    #[serde(default)]
    pub resolution: Option<String>,
}

/// Per-category rejection count over the requested window.
#[derive(Debug, serde::Serialize)]
pub struct RejectionCategoryCount {
    pub category: String,
    pub label: String,
    pub count: u64,
}

/// `GET /v1/telemetry/rejections` response: the total rejection count plus the
/// per-category breakdown for a scope over a window.
#[derive(Debug, serde::Serialize)]
pub struct RejectionsResponse {
    pub scope: String,
    pub from: i64,
    pub to: i64,
    pub total: u64,
    pub categories: Vec<RejectionCategoryCount>,
}

/// `GET /v1/telemetry/rejections` — per-category rejection counts for a scope.
///
/// Enumerates the taxonomy's canonical categories, queries each
/// `{scope}:{category}` series' `requests` counter summed over the window, and
/// returns the non-zero categories plus the reserved `_total` count. RBAC-gated
/// on `metrics.view`, served from the process-wide telemetry store.
pub async fn rejections(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    pat_scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<RejectionsQuery>,
) -> ApiResult<Json<RejectionsResponse>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MetricsView).await?;
    if q.to < q.from {
        return Err((StatusCode::BAD_REQUEST, "`to` must be >= `from`".to_string()));
    }
    let scope = q.scope.trim();
    if !is_valid_rejection_scope(scope) {
        return Err((
            StatusCode::BAD_REQUEST,
            "`scope` must be rejection:all, rejection:surface:{id}[:stage:{stage}], rejection:team:{id}, or rejection:member:{id}".to_string(),
        ));
    }
    // Tenant confinement: only `rejection:surface:{id}` for an owned surface is
    // permitted for a tenant/resource-scoped caller; `rejection:all`/team/member
    // 404 (fail closed).
    authorize_series_key(scope, state.pipe_store.as_deref(), tenant_ctx(&context), res_scope(&pat_scope)).await?;
    if is_attributed_key(scope) {
        require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MetricsViewAttributed).await?;
    }
    let store = global_telemetry_store()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Telemetry store not configured".to_string()))?;
    let force_tier = force_tier_from(&q.resolution);

    // Query every category series plus the reserved total in one batched call so
    // the per-request fan-out takes the store read lock once. `defs` order is
    // preserved, with the total last.
    let defs = crate::rejection_taxonomy::global_categories();
    let keys: Vec<String> = defs
        .iter()
        .map(|c| format!("{scope}:{}", c.id))
        .chain(std::iter::once(format!("{scope}:{}", crate::telemetry::REJECTION_TOTAL_CATEGORY)))
        .collect();
    let counts: Vec<u64> = store
        .range_many(&keys, q.from, q.to, 5000, force_tier)
        .await
        .iter()
        .map(|r| {
            r.points
                .iter()
                .map(|p| p.requests)
                .sum::<u64>()
        })
        .collect();

    let total = counts
        .last()
        .copied()
        .unwrap_or(0);
    let categories = defs
        .into_iter()
        .zip(counts.iter().copied())
        .filter(|(_, count)| *count > 0)
        .map(|(c, count)| RejectionCategoryCount {
            category: c.id,
            label: c.label,
            count,
        })
        .collect();

    Ok(Json(RejectionsResponse {
        scope: scope.to_string(),
        from: q.from,
        to: q.to,
        total,
        categories,
    }))
}

/// `GET /v1/cache/stats` — response-cache effectiveness (hits, misses, hit
/// rate, avoided spend, live entries). RBAC-gated on `metrics.view`; reads the
/// process-wide response cache via its global accessor.
pub async fn cache_stats(
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<crate::pipes::response_cache::CacheStats>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MetricsView).await?;
    let cache = crate::pipes::response_cache::global_response_cache()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Response cache not configured".to_string()))?;
    Ok(Json(cache.stats()))
}

/// `GET /v1/prompt-guard/detector-stats` — model-backed PII detector health
/// (successful vs failed calls, error rate) since process start. RBAC-gated on
/// `metrics.view`; reads the process-wide detector counters.
pub async fn detector_stats(
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<crate::pipes::prompt_guard::detector_stats::DetectorStatsSnapshot>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MetricsView).await?;
    Ok(Json(crate::pipes::prompt_guard::detector_stats::global().snapshot()))
}

/// Request for `POST /v1/prompt-guard/detector-test`.
#[derive(Deserialize)]
pub struct DetectorTestRequest {
    /// The model-PII detector config to exercise (as edited in the surface).
    pub config: crate::pipes::prompt_guard::LlmPiiConfig,
    /// The saved surface the detector belongs to. Required to test with a
    /// stored API key, which is only sent to the endpoint saved with it.
    #[serde(default)]
    pub surface_id: Option<String>,
    /// Sample text to run the detector over.
    pub text: String,
}

/// A detected entity, echoed back for the test result.
#[derive(Serialize)]
pub struct DetectorTestEntity {
    pub entity_type: String,
    pub text: String,
    pub group: Option<String>,
}

/// Result of `POST /v1/prompt-guard/detector-test`.
#[derive(Serialize)]
pub struct DetectorTestResponse {
    pub ok: bool,
    pub entities: Vec<DetectorTestEntity>,
    pub error: Option<String>,
}

/// `POST /v1/prompt-guard/detector-test` — run a model-PII detector config
/// against sample text so an operator can confirm it works before enabling it.
/// Gated on `pipes.edit` at the router (same as editing the surface). A test
/// with a stored key uses only a key and endpoint saved together on the
/// caller's surface, a pairing only `secrets.view` may choose
/// (`pipe_secret_bindings`): a key reference or endpoint from the request body
/// never decides where a stored key is sent. The test
/// returns the endpoint's reply, so the endpoint must pass the strict egress
/// check. Caching is forced off so the test always makes a live call.
pub async fn detector_test(
    Extension(secrets_store): Extension<Option<Arc<dyn crate::secrets::SecretsStore>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    State(state): State<crate::identity::state::IdentityApiState>,
    Json(request): Json<DetectorTestRequest>,
) -> ApiResult<Json<DetectorTestResponse>> {
    let mut config = request.config;

    let api_key = match config
        .api_key_secret
        .as_deref()
        .map(str::trim)
        .filter(|reference| !reference.is_empty())
    {
        Some(_) => {
            let surface_id = request
                .surface_id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, SAVE_BEFORE_KEYED_TEST.to_string()))?;
            let (_, surface) =
                super::pipes::load_pipe_or_404(&state, surface_id, tenant_ctx(&context), res_scope(&scope)).await?;
            let saved =
                saved_detector(&surface, &config)?.ok_or((StatusCode::CONFLICT, SAVE_BEFORE_KEYED_TEST.to_string()))?;
            let secret_ref = saved
                .api_key_secret
                .clone()
                .unwrap_or_default();
            // Send only to the endpoint saved with the key.
            config.provider_type = saved.provider_type;
            config.endpoint_url = saved.endpoint_url;
            Some(
                resolve_detector_api_key(
                    &secrets_store,
                    surface.tenant_id.as_deref(),
                    tenant_ctx(&context),
                    res_scope(&scope),
                    &secret_ref,
                )
                .await?,
            )
        }
        None => None,
    };

    run_detector_test(config, api_key.as_deref(), &request.text)
        .await
        .map(Json)
}

/// Run one live detector call for the test. The test shows the endpoint's
/// reply to the caller, so it may not reach private, link-local, loopback or
/// cloud-metadata addresses: the URL is checked up front, and the call uses
/// the strict client (no redirects, every DNS answer re-checked) so neither a
/// redirect nor a rebinding host can reach one afterwards. Live traffic keeps
/// the service-endpoint rules, so a self-hosted detector still works.
async fn run_detector_test(
    mut config: crate::pipes::prompt_guard::LlmPiiConfig,
    api_key: Option<&str>,
    text: &str,
) -> ApiResult<DetectorTestResponse> {
    config.timeout_secs = bounded_detector_test_timeout_secs(config.timeout_secs);
    config.cache_detection = false;
    crate::url_validation::validate_strict_service_endpoint_url(&config.resolved_endpoint_url())
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "Detection endpoint rejected: a detector test cannot reach private, link-local, loopback or \
                     cloud-metadata addresses ({e})"
                ),
            )
        })?;

    let client =
        crate::http_client::with_strict_validating_resolver(std::time::Duration::from_secs(config.timeout_secs))
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create HTTP client: {e}")))?;
    let body = serde_json::json!({ "messages": [{ "role": "user", "content": text }] });
    Ok(match crate::pipes::prompt_guard::llm_pii::detect(&client, &config, api_key, &body).await {
        Ok(entities) => DetectorTestResponse {
            ok: true,
            entities: entities
                .into_iter()
                .map(|e| DetectorTestEntity {
                    entity_type: e.entity_type,
                    text: e.text,
                    group: e.group,
                })
                .collect(),
            error: None,
        },
        Err(e) => DetectorTestResponse {
            ok: false,
            entities: Vec::new(),
            error: Some(e),
        },
    })
}

/// Longest a detector test may wait for the endpoint. The request's
/// `timeout_secs` is otherwise unbounded, so a stalling endpoint could hold the
/// test open indefinitely. The detector call sets its own per-request timeout
/// from `timeout_secs`, which overrides the client's, so the bound is applied
/// to the config itself.
const MAX_DETECTOR_TEST_TIMEOUT_SECS: u64 = 30;

fn bounded_detector_test_timeout_secs(timeout_secs: u64) -> u64 {
    timeout_secs.clamp(1, MAX_DETECTOR_TEST_TIMEOUT_SECS)
}

/// Refusal for a keyed test whose key and endpoint are not saved on the surface.
const SAVE_BEFORE_KEYED_TEST: &str =
    "Save the surface before testing with a stored API key: the test only sends a key to the endpoint saved with it";

/// The detector saved on `surface` (base or any variant) whose provider,
/// endpoint, model and API key match the one under test, so a keyed test sends
/// the key only where the surface already sends it, and spends it only on the
/// saved model rather than any model the caller names. A variant that cannot be
/// resolved is an error, not "no saved detector".
fn saved_detector(
    surface: &crate::pipes::PipeConfig,
    tested: &crate::pipes::prompt_guard::LlmPiiConfig,
) -> Result<Option<crate::pipes::prompt_guard::LlmPiiConfig>, super::pipes::AppError> {
    let key_of = |detector: &crate::pipes::prompt_guard::LlmPiiConfig| {
        detector
            .api_key_secret
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .to_string()
    };
    let tested_key = key_of(tested);
    let tested_endpoint = tested.resolved_endpoint_url();
    Ok(super::pipe_tenancy::resolved_views(surface)?
        .into_iter()
        .filter_map(|view| view.prompt_guard)
        .flat_map(|prompt_guard| prompt_guard.llm_pii)
        .find(|saved| {
            !tested_key.is_empty()
                && key_of(saved) == tested_key
                && saved.provider_type == tested.provider_type
                && saved.resolved_endpoint_url() == tested_endpoint
                && saved.model == tested.model
        }))
}

/// Resolve a saved detector's API key for the caller, owned by the surface's
/// tenant and admitted by the caller's token scope, as a surface save checks
/// it. An unknown, foreign-tenant or out-of-scope reference gets one generic
/// refusal, so the endpoint does not reveal which secrets exist.
async fn resolve_detector_api_key(
    store: &Option<Arc<dyn crate::secrets::SecretsStore>>,
    owner_tenant_id: Option<&str>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
    secret_ref: &str,
) -> ApiResult<String> {
    let Some(store) = store else {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Secrets store not configured".to_string()));
    };
    super::pipe_tenancy::resolve_authorized_secret(store.as_ref(), owner_tenant_id, context, scope, secret_ref)
        .await
        .map(|secret| secret.value)
        .map_err(|_| (StatusCode::FORBIDDEN, "Secret reference is not accessible".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector_secrets() -> Option<Arc<dyn crate::secrets::SecretsStore>> {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        Some(Arc::new(MemorySecretsStore::with(vec![
            secret("uuid-shared", "shared-key", "SHARED", None),
            secret("uuid-a", "acct-key", "A-VALUE", Some("tenant-a")),
            secret("uuid-a-other", "other-key", "A-OTHER", Some("tenant-a")),
            secret("uuid-b", "b-key", "B-VALUE", Some("tenant-b")),
        ])))
    }

    fn tenant(id: &str) -> PatTenantContext {
        PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: id.into(),
        }
    }

    #[tokio::test]
    async fn detector_key_resolves_a_secret_the_caller_may_use() {
        let store = detector_secrets();
        let session = resolve_detector_api_key(&store, None, None, None, "shared-key").await;
        assert_eq!(session.unwrap(), "SHARED");

        let context = tenant("tenant-a");
        let own = resolve_detector_api_key(&store, Some("tenant-a"), Some(&context), None, "acct-key").await;
        assert_eq!(own.unwrap(), "A-VALUE");
    }

    #[tokio::test]
    async fn detector_key_refuses_another_tenants_secret() {
        let store = detector_secrets();
        let context = tenant("tenant-a");
        for reference in ["b-key", "uuid-b"] {
            let refused = resolve_detector_api_key(&store, Some("tenant-a"), Some(&context), None, reference).await;
            assert_eq!(refused.unwrap_err().0, StatusCode::FORBIDDEN, "{reference} reached another tenant's secret");
        }
    }

    #[tokio::test]
    async fn detector_key_refuses_a_tenant_secret_on_an_appliance_surface() {
        let store = detector_secrets();
        let refused = resolve_detector_api_key(&store, None, None, None, "acct-key").await;
        assert_eq!(refused.unwrap_err().0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn detector_key_refuses_a_secret_outside_the_token_scope() {
        let store = detector_secrets();
        let context = tenant("tenant-a");
        let scope = PatResourceScope(Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:secrets:acct-[^:]*\z").unwrap()));
        let allowed =
            resolve_detector_api_key(&store, Some("tenant-a"), Some(&context), Some(&scope), "acct-key").await;
        assert_eq!(allowed.unwrap(), "A-VALUE", "precondition: in-scope secret is allowed");

        let refused =
            resolve_detector_api_key(&store, Some("tenant-a"), Some(&context), Some(&scope), "other-key").await;
        assert_eq!(refused.unwrap_err().0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn detector_key_refusal_does_not_reveal_whether_the_secret_exists() {
        let store = detector_secrets();
        let context = tenant("tenant-a");
        let unknown = resolve_detector_api_key(&store, Some("tenant-a"), Some(&context), None, "no-such-key").await;
        let foreign = resolve_detector_api_key(&store, Some("tenant-a"), Some(&context), None, "b-key").await;
        assert_eq!(unknown.unwrap_err(), foreign.unwrap_err());
    }

    fn pii_detector(
        endpoint_url: &str,
        key: Option<&str>,
    ) -> crate::pipes::prompt_guard::LlmPiiConfig {
        serde_json::from_value(serde_json::json!({
            "provider_type": "",
            "endpoint_url": endpoint_url,
            "model": "detector",
            "api_key_secret": key,
        }))
        .unwrap()
    }

    fn surface_with_detector(detector: Option<crate::pipes::prompt_guard::LlmPiiConfig>) -> crate::pipes::PipeConfig {
        let mut surface = crate::pipes::PipeConfig::new(
            "surface-1".into(),
            "Surface".into(),
            crate::pipes::PipeType::Webhook {
                endpoint: "https://example.com".into(),
            },
        );
        surface.prompt_guard =
            detector.map(|detector| serde_json::from_value(serde_json::json!({ "llm_pii": [detector] })).unwrap());
        surface
    }

    #[test]
    fn saved_detector_matches_the_saved_key_and_endpoint() {
        let saved = pii_detector("https://detector.example/v1/chat/completions", Some("detector-key"));
        let surface = surface_with_detector(Some(saved.clone()));
        let found = saved_detector(&surface, &saved)
            .unwrap()
            .expect("the saved detector matches itself");
        assert_eq!(found.endpoint_url, "https://detector.example/v1/chat/completions");
    }

    #[test]
    fn saved_detector_refuses_the_saved_key_with_another_endpoint() {
        let surface = surface_with_detector(Some(pii_detector(
            "https://detector.example/v1/chat/completions",
            Some("detector-key"),
        )));
        let redirected = pii_detector("https://collector.example/v1/chat/completions", Some("detector-key"));
        assert!(
            saved_detector(&surface, &redirected)
                .unwrap()
                .is_none(),
            "a saved key was matched to an unsaved endpoint"
        );
    }

    #[test]
    fn saved_detector_refuses_the_saved_key_with_another_model() {
        let surface = surface_with_detector(Some(pii_detector(
            "https://detector.example/v1/chat/completions",
            Some("detector-key"),
        )));
        let mut other_model = pii_detector("https://detector.example/v1/chat/completions", Some("detector-key"));
        other_model.model = "expensive-model".into();
        assert!(
            saved_detector(&surface, &other_model)
                .unwrap()
                .is_none(),
            "a saved key was matched to an unsaved model"
        );
    }

    #[test]
    fn detector_test_timeout_is_bounded() {
        assert_eq!(bounded_detector_test_timeout_secs(u64::MAX), MAX_DETECTOR_TEST_TIMEOUT_SECS);
        assert_eq!(bounded_detector_test_timeout_secs(0), 1);
        assert_eq!(bounded_detector_test_timeout_secs(5), 5);
    }

    #[tokio::test]
    async fn detector_test_gives_up_on_a_stalling_endpoint_at_the_configured_timeout() {
        use crate::pipes::test_upstreams::CaptureUpstream;
        let stalling = CaptureUpstream::stalling().await;
        let _allowed = crate::url_validation::test_service_endpoints::allow(std::slice::from_ref(&stalling.url));
        let mut config = pii_detector(&stalling.url, None);
        config.timeout_secs = 1;

        let started = std::time::Instant::now();
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(10), run_detector_test(config, None, "Alice"))
                .await
                .expect("the detector test outlived its timeout")
                .expect("a timeout is reported as a failed test");
        assert!(!response.ok, "a stalling endpoint was reported as a working detector");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(stalling.requests(), 1);
    }

    #[test]
    fn saved_detector_refuses_a_key_the_surface_does_not_use() {
        let surface = surface_with_detector(Some(pii_detector(
            "https://detector.example/v1/chat/completions",
            Some("detector-key"),
        )));
        let other_key = pii_detector("https://detector.example/v1/chat/completions", Some("operator-key"));
        assert!(
            saved_detector(&surface, &other_key)
                .unwrap()
                .is_none(),
            "a key the surface does not use was matched"
        );
    }

    #[test]
    fn saved_detector_refuses_a_surface_without_a_detector() {
        let tested = pii_detector("https://detector.example/v1/chat/completions", Some("detector-key"));
        assert!(
            saved_detector(&surface_with_detector(None), &tested)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn detector_test_calls_an_allowed_endpoint() {
        use crate::pipes::test_upstreams::CaptureUpstream;
        let detector = CaptureUpstream::answering("[]").await;
        let _allowed = crate::url_validation::test_service_endpoints::allow(std::slice::from_ref(&detector.url));

        run_detector_test(pii_detector(&detector.url, None), None, "Alice")
            .await
            .expect("an allowed endpoint is called");
        assert_eq!(detector.requests(), 1);
    }

    #[tokio::test]
    async fn detector_test_is_never_answered_from_the_detection_cache() {
        use crate::pipes::test_upstreams::CaptureUpstream;
        let working = CaptureUpstream::answering(r#"[{"type":"person","text":"Bob Cached"}]"#).await;
        let stalling = CaptureUpstream::stalling().await;
        let _allowed =
            crate::url_validation::test_service_endpoints::allow(&[working.url.clone(), stalling.url.clone()]);
        let text = "Bob Cached is the only caller of this test";

        let warmed = run_detector_test(pii_detector(&working.url, None), None, text)
            .await
            .expect("the working endpoint answers");
        assert!(warmed.ok, "precondition: the working detector passes");

        let mut broken = pii_detector(&stalling.url, None);
        broken.timeout_secs = 1;
        let retested = run_detector_test(broken, None, text)
            .await
            .expect("a timeout is reported as a failed test");
        assert!(!retested.ok, "an earlier result for the same model and text passed a stalling endpoint");
        assert_eq!(stalling.requests(), 1);
    }

    #[tokio::test]
    async fn detector_test_refuses_an_internal_endpoint() {
        use crate::pipes::test_upstreams::CaptureUpstream;
        let internal = CaptureUpstream::answering("[]").await;

        let refused = run_detector_test(pii_detector(&internal.url, None), None, "Alice").await;
        let (status, _) = refused
            .err()
            .expect("an internal endpoint is refused");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(internal.requests(), 0, "an internal endpoint was called");
    }

    #[tokio::test]
    async fn detector_test_does_not_follow_a_redirect() {
        use crate::pipes::test_upstreams::CaptureUpstream;
        let internal = CaptureUpstream::answering("[]").await;
        let redirecting = CaptureUpstream::redirecting_to(&internal.url).await;
        let _allowed = crate::url_validation::test_service_endpoints::allow(std::slice::from_ref(&redirecting.url));

        let response = run_detector_test(pii_detector(&redirecting.url, None), None, "Alice")
            .await
            .expect("the redirect is reported as a failed test");
        assert!(!response.ok, "a redirect was reported as a working detector");
        assert_eq!(redirecting.requests(), 1);
        assert_eq!(internal.requests(), 0, "the redirect to an internal endpoint was followed");
    }

    #[test]
    fn parse_keys_trims_and_drops_blanks() {
        let keys = parse_keys("team:a, member:b ,, ,surface:c");
        assert_eq!(keys, vec!["team:a", "member:b", "surface:c"]);
    }

    #[test]
    fn parse_keys_empty_yields_nothing() {
        assert!(parse_keys(" , , ").is_empty());
    }

    #[test]
    fn key_cap_is_generous_but_bounded() {
        // A 256-member team chart fits; a thousand-key flood would be rejected.
        let many = (0..300)
            .map(|i| format!("member:{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_keys(&many).len() > MAX_KEYS);
    }

    #[test]
    fn valid_rejection_scopes_accepted() {
        assert!(is_valid_rejection_scope("rejection:all"));
        assert!(is_valid_rejection_scope("rejection:surface:pipe-1"));
        assert!(is_valid_rejection_scope("rejection:surface:pipe-1:stage:llm"));
        assert!(is_valid_rejection_scope("rejection:team:t1"));
        assert!(is_valid_rejection_scope("rejection:member:m1"));
    }

    #[test]
    fn malformed_rejection_scopes_rejected() {
        // Already category-suffixed, bare prefix, empty id, trailing colon,
        // unknown namespace, and non-rejection scopes are all rejected.
        assert!(!is_valid_rejection_scope("rejection:all:hate"));
        assert!(!is_valid_rejection_scope("rejection:"));
        assert!(!is_valid_rejection_scope("rejection:surface:"));
        assert!(!is_valid_rejection_scope("rejection:member:m1:"));
        assert!(!is_valid_rejection_scope("rejection:bogus:x"));
        assert!(!is_valid_rejection_scope("surface:pipe-1"));
        assert!(!is_valid_rejection_scope(""));
    }

    #[test]
    fn attributed_keys_require_stricter_feature() {
        // Member/team usage and rejection breakdowns are attributed.
        assert!(is_attributed_key("member:abc"));
        assert!(is_attributed_key("member:abc:surface:pipe-1"));
        assert!(is_attributed_key("team:xyz"));
        assert!(is_attributed_key("rejection:member:abc"));
        assert!(is_attributed_key("rejection:team:xyz"));
        // Appliance-wide, surface, stage, and ops scopes stay at metrics.view.
        assert!(!is_attributed_key("surfaces:all"));
        assert!(!is_attributed_key("surface:pipe-1"));
        assert!(!is_attributed_key("surface:pipe-1:stage:llm"));
        assert!(!is_attributed_key("rejection:all"));
        assert!(!is_attributed_key("rejection:surface:pipe-1"));
        assert!(!is_attributed_key("ops:all"));
    }

    #[test]
    fn force_tier_normalises_auto_and_blank() {
        assert_eq!(force_tier_from(&None), None);
        assert_eq!(force_tier_from(&Some("  ".to_string())), None);
        assert_eq!(force_tier_from(&Some("auto".to_string())), None);
        assert_eq!(force_tier_from(&Some("AUTO".to_string())), None);
        assert_eq!(force_tier_from(&Some(" 1h ".to_string())), Some("1h"));
    }
}
