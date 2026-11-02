//! Spend-report / chargeback export endpoint.
//!
//! Aggregates spend, tokens, and request counts over an **arbitrary date range**
//! (multi-month capable, unlike the current-month [`crate::teams::TeamUsageTracker`])
//! by team, member, and/or surface, for FinOps chargeback and reporting. Data is
//! summed from the process-wide [`crate::telemetry::TelemetryStore`] time-series
//! (the same source the usage dashboards draw from), so the numbers reconcile
//! with the charts.
//!
//! `GET /v1/spend-report?from={unix}&to={unix}&scope={all|team|member|surface}&format={json|csv}`
//!
//! Because it exposes per-team and per-member attributed spend, it is gated on
//! the `metrics.view_attributed` RBAC feature (default **administrator**),
//! matching the attributed telemetry read endpoints.

use std::sync::Arc;

use axum::{
    Extension,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::scoped_id::{res_scope, tenant_ctx};
use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::identity::state::IdentityApiState;
use crate::pipes::key_source::KeySourceCounts;
use crate::rbac::{Feature, RbacConfig};
use crate::telemetry::{global_telemetry_store, member_key, surface_key, team_key};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};

use super::authz::require_feature as require;

type ApiResult<T> = Result<T, (StatusCode, String)>;

/// Cap on the number of series keys summed in one report, bounding the work an
/// authenticated caller can trigger. A large estate (teams + members + surfaces)
/// still fits comfortably.
const MAX_REPORT_KEYS: usize = 2000;

/// Which dimensions to include in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportScope {
    All,
    Team,
    Member,
    Surface,
}

impl ReportScope {
    fn parse(raw: &str) -> Option<Self> {
        match raw
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "all" => Some(Self::All),
            "team" | "teams" => Some(Self::Team),
            "member" | "members" => Some(Self::Member),
            "surface" | "surfaces" => Some(Self::Surface),
            _ => None,
        }
    }

    fn includes_team(self) -> bool {
        matches!(self, Self::All | Self::Team)
    }

    fn includes_member(self) -> bool {
        matches!(self, Self::All | Self::Member)
    }

    fn includes_surface(self) -> bool {
        matches!(self, Self::All | Self::Surface)
    }
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportFormat {
    Json,
    Csv,
}

impl ReportFormat {
    fn parse(raw: &str) -> Option<Self> {
        match raw
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SpendReportQuery {
    pub from: i64,
    pub to: i64,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
}

/// One row of the report — a single entity's totals over the window.
#[derive(Debug, Clone, Serialize)]
pub struct SpendRow {
    /// `team` | `member` | `surface`.
    pub dimension: &'static str,
    /// Stable identifier (team UUID / member UUID / surface id).
    pub id: String,
    /// Human-readable label (team/surface name, member display label).
    pub label: String,
    /// Spend at the priced (catalog) rate, whoever's key served it. The same
    /// figure as `catalog_cost_usd`.
    pub cost_usd: f64,
    pub catalog_cost_usd: f64,
    /// The part of the spend billed to the account: calls served on platform
    /// keys. Calls on the caller's or the customer's own key bill nothing.
    pub billed_cost_usd: f64,
    pub tokens: u64,
    pub requests: u64,
    /// Requests by the source of the key that served their main call
    /// (`client`, `customer`, `platform`). Requests recorded before key sources
    /// were counted carry none, so these can sum to less than `requests`.
    pub requests_by_key_source: KeySourceCounts,
}

/// The JSON report envelope.
#[derive(Debug, Clone, Serialize)]
pub struct SpendReport {
    pub from: i64,
    pub to: i64,
    pub scope: &'static str,
    pub currency: &'static str,
    pub generated_at: String,
    pub total_cost_usd: f64,
    pub total_catalog_cost_usd: f64,
    pub total_billed_cost_usd: f64,
    pub total_tokens: u64,
    pub total_requests: u64,
    pub total_requests_by_key_source: KeySourceCounts,
    pub rows: Vec<SpendRow>,
}

fn scope_label(scope: ReportScope) -> &'static str {
    match scope {
        ReportScope::All => "all",
        ReportScope::Team => "team",
        ReportScope::Member => "member",
        ReportScope::Surface => "surface",
    }
}

/// One entity to sum: its series key plus how to label the resulting row.
struct Entity {
    dimension: &'static str,
    id: String,
    label: String,
    key: String,
}

/// `GET /v1/spend-report` — chargeback / spend export over an arbitrary window.
///
/// Sums the telemetry series for every non-deleted team, member, and/or surface
/// (per `scope`) between `from` and `to` (unix seconds) and returns totals as
/// JSON (default) or CSV (`format=csv`, downloadable). RBAC-gated on
/// `metrics.view_attributed`.
pub async fn spend_report(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    pat_scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Query(q): Query<SpendReportQuery>,
) -> ApiResult<Response> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MetricsViewAttributed).await?;
    // A tenant/resource-scoped caller must not receive cross-tenant chargeback
    // rows. Team/member dimensions are not tenant-scopable resources here, so a
    // tenant caller is confined to surface rows it owns.
    let tenant_scoped = tenant_ctx(&context).is_some() || res_scope(&pat_scope).is_some();

    if q.to < q.from {
        return Err((StatusCode::BAD_REQUEST, "`to` must be >= `from`".to_string()));
    }
    let scope = ReportScope::parse(
        q.scope
            .as_deref()
            .unwrap_or_default(),
    )
    .ok_or((StatusCode::BAD_REQUEST, "`scope` must be one of: all, team, member, surface".to_string()))?;
    let format = ReportFormat::parse(
        q.format
            .as_deref()
            .unwrap_or_default(),
    )
    .ok_or((StatusCode::BAD_REQUEST, "`format` must be one of: json, csv".to_string()))?;

    let store = global_telemetry_store()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Telemetry store not configured".to_string()))?;

    // Build the entity list (id + label + series key) for the requested scope,
    // skipping soft-deleted records.
    let mut entities: Vec<Entity> = Vec::new();

    // Team and member dimensions are appliance-wide aggregates (not
    // tenant-owned resources), so a tenant-scoped caller gets neither.
    if scope.includes_team()
        && !tenant_scoped
        && let Some(team_store) = state.team_store.clone()
    {
        for team in team_store
            .list()
            .await
            .into_iter()
            .filter(|t| !t.status.is_deleted())
        {
            entities.push(Entity {
                dimension: "team",
                key: team_key(&team.id),
                label: team.name,
                id: team.id,
            });
        }
    }
    if scope.includes_member()
        && !tenant_scoped
        && let Some(member_store) = state.member_store.clone()
    {
        for member in member_store
            .list()
            .await
            .into_iter()
            .filter(|m| !m.status.is_deleted())
        {
            entities.push(Entity {
                dimension: "member",
                key: member_key(&member.id),
                label: member.display_label(),
                id: member.id,
            });
        }
    }
    if scope.includes_surface()
        && let Some(pipe_store) = state.pipe_store.clone()
    {
        for pipe in pipe_store
            .list()
            .await
            .into_iter()
            .filter(|p| !p.status.is_deleted())
            // Confine surface rows to those the caller may access (tenant +
            // token id-namespace). An appliance caller keeps every surface.
            .filter(|p| {
                can_access(p.tenant_id.as_deref(), tenant_ctx(&context))
                    && scope_allows_resource(res_scope(&pat_scope), tenant_ctx(&context), ResourceKind::Pipes, &p.id)
            })
        {
            entities.push(Entity {
                dimension: "surface",
                key: surface_key(&pipe.id),
                label: pipe.name,
                id: pipe.id,
            });
        }
    }

    if entities.len() > MAX_REPORT_KEYS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Report spans too many entities (max {MAX_REPORT_KEYS}); narrow the scope"),
        ));
    }

    // Sum each entity's series over the window in one batched read. `max_points`
    // is set to the tier retention cap so a wide window isn't down-sampled into
    // fewer buckets than actually recorded (which would under-count the totals).
    let keys: Vec<String> = entities
        .iter()
        .map(|e| e.key.clone())
        .collect();
    let series = store
        .range_many(&keys, q.from, q.to, 5000, None)
        .await;

    let mut rows: Vec<SpendRow> = entities
        .into_iter()
        .zip(series)
        .map(|(entity, s)| {
            let mut cost = 0.0f64;
            let mut billed = 0.0f64;
            let mut tokens = 0u64;
            let mut requests = 0u64;
            let mut by_key_source = KeySourceCounts::default();
            for p in &s.points {
                cost += p.cost;
                billed += p.billed_cost;
                tokens = tokens.saturating_add(p.tokens);
                requests = requests.saturating_add(p.requests);
                by_key_source.add(p.requests_by_key_source);
            }
            SpendRow {
                dimension: entity.dimension,
                id: entity.id,
                label: entity.label,
                cost_usd: cost,
                catalog_cost_usd: cost,
                billed_cost_usd: billed,
                tokens,
                requests,
                requests_by_key_source: by_key_source,
            }
        })
        .filter(|r| r.requests > 0 || r.cost_usd > 0.0 || r.tokens > 0)
        .collect();

    // Highest spend first, then by tokens, for a readable report.
    rows.sort_by(|a, b| {
        b.cost_usd
            .partial_cmp(&a.cost_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.tokens.cmp(&a.tokens))
    });

    let total_cost_usd: f64 = rows
        .iter()
        .map(|r| r.cost_usd)
        .sum();
    let total_tokens: u64 = rows
        .iter()
        .fold(0u64, |acc, r| acc.saturating_add(r.tokens));
    let total_requests: u64 = rows
        .iter()
        .fold(0u64, |acc, r| acc.saturating_add(r.requests));
    let total_billed_cost_usd: f64 = rows
        .iter()
        .map(|r| r.billed_cost_usd)
        .sum();
    let total_requests_by_key_source = rows
        .iter()
        .fold(KeySourceCounts::default(), |mut acc, r| {
            acc.add(r.requests_by_key_source);
            acc
        });

    match format {
        ReportFormat::Json => {
            let report = SpendReport {
                from: q.from,
                to: q.to,
                scope: scope_label(scope),
                currency: "USD",
                generated_at: chrono::Utc::now().to_rfc3339(),
                total_cost_usd,
                total_catalog_cost_usd: total_cost_usd,
                total_billed_cost_usd,
                total_tokens,
                total_requests,
                total_requests_by_key_source,
                rows,
            };
            Ok(axum::Json(report).into_response())
        }
        ReportFormat::Csv => {
            let body = render_csv(&rows);
            let filename = format!("spend-report_{}_{}-{}.csv", scope_label(scope), q.from, q.to);
            let headers = [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
            ];
            Ok((headers, body).into_response())
        }
    }
}

/// Escape a field for RFC 4180 CSV: wrap in quotes and double any inner quotes
/// when it contains a comma, quote, CR, or LF.
fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Render the rows as a CSV document (header + one line per row).
fn render_csv(rows: &[SpendRow]) -> String {
    let mut out = String::from(
        "dimension,id,label,cost_usd,tokens,requests,billed_cost_usd,requests_client,requests_customer,requests_platform\r\n",
    );
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{:.6},{},{},{:.6},{},{},{}\r\n",
            r.dimension,
            csv_escape(&r.id),
            csv_escape(&r.label),
            r.cost_usd,
            r.tokens,
            r.requests,
            r.billed_cost_usd,
            r.requests_by_key_source
                .client,
            r.requests_by_key_source
                .customer,
            r.requests_by_key_source
                .platform,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_parse_accepts_aliases_and_rejects_junk() {
        assert_eq!(ReportScope::parse(""), Some(ReportScope::All));
        assert_eq!(ReportScope::parse("ALL"), Some(ReportScope::All));
        assert_eq!(ReportScope::parse("teams"), Some(ReportScope::Team));
        assert_eq!(ReportScope::parse(" Member "), Some(ReportScope::Member));
        assert_eq!(ReportScope::parse("surfaces"), Some(ReportScope::Surface));
        assert_eq!(ReportScope::parse("bogus"), None);
    }

    #[test]
    fn scope_inclusion_flags() {
        assert!(ReportScope::All.includes_team());
        assert!(ReportScope::All.includes_member());
        assert!(ReportScope::All.includes_surface());
        assert!(ReportScope::Team.includes_team());
        assert!(!ReportScope::Team.includes_member());
        assert!(!ReportScope::Member.includes_surface());
        assert!(ReportScope::Surface.includes_surface());
    }

    #[test]
    fn format_parse_accepts_json_csv_and_rejects_junk() {
        assert_eq!(ReportFormat::parse(""), Some(ReportFormat::Json));
        assert_eq!(ReportFormat::parse("JSON"), Some(ReportFormat::Json));
        assert_eq!(ReportFormat::parse("csv"), Some(ReportFormat::Csv));
        assert_eq!(ReportFormat::parse("xml"), None);
    }

    #[test]
    fn csv_escape_quotes_special_chars() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("she said \"hi\""), "\"she said \"\"hi\"\"\"");
        assert_eq!(csv_escape("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn render_csv_has_header_and_escaped_rows() {
        let rows = vec![
            SpendRow {
                dimension: "team",
                id: "t1".to_string(),
                label: "Platform, Inc".to_string(),
                cost_usd: 12.5,
                catalog_cost_usd: 12.5,
                billed_cost_usd: 2.5,
                tokens: 1000,
                requests: 3,
                requests_by_key_source: KeySourceCounts {
                    client: 1,
                    customer: 1,
                    platform: 1,
                },
            },
            SpendRow {
                dimension: "member",
                id: "m1".to_string(),
                label: "ada@example.com".to_string(),
                cost_usd: 0.0,
                catalog_cost_usd: 0.0,
                billed_cost_usd: 0.0,
                tokens: 0,
                requests: 1,
                requests_by_key_source: KeySourceCounts::default(),
            },
        ];
        let csv = render_csv(&rows);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "dimension,id,label,cost_usd,tokens,requests,billed_cost_usd,requests_client,requests_customer,requests_platform"
        );
        assert_eq!(lines[1], "team,t1,\"Platform, Inc\",12.500000,1000,3,2.500000,1,1,1");
        assert_eq!(lines[2], "member,m1,ada@example.com,0.000000,0,1,0.000000,0,0,0");
    }
}
