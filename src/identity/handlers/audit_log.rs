//! Unified audit read API (`GET /api/v1/audit`).
//!
//! Serves the shared audit log — **all** categories, including the
//! policy-decision evidence recorded by [`crate::observability::policy_audit`]
//! *and* credential-delegation events. With no query params it returns every
//! category (`exclude_vp_audit: false`); callers narrow the view with the
//! `category` / `flow` / `scope` / `decision` filters, and `category_counts`
//! reports the per-category totals so the UI can drive its category chips.
//!
//! This is the inverse of the credential-delegation endpoint
//! (`/api/v1/delegation-audit`), which filters policy-decision evidence *out*
//! (`exclude_vp_audit: true`) to stay a clean delegation-only view.
//!
//! Endpoint: `GET /api/v1/audit`.
//!
//! Gated by `Feature::AuditView` (administrator-only in the default RBAC config)
//! — the same least-privilege guard as the delegation audit view.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::identity::state::IdentityApiState;

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default = "default_page")]
    pub page: usize,
    /// Case-insensitive substring match on the raw JSON line.
    pub filter: Option<String>,
    /// OR set of action-type categories (comma-separated).
    pub category: Option<String>,
    /// Restrict to policy decisions with this flow (`access_point` | `transit_point` | `fabric`).
    pub flow: Option<String>,
    /// Restrict to policy decisions with this scope (`pipe` | `ide` | `gateway` | `surface`).
    pub scope: Option<String>,
    /// Restrict to policy decisions with this decision (`allow` | `deny` | `error` | `missing_engine`).
    pub decision: Option<String>,
}

fn default_limit() -> usize {
    100
}
fn default_page() -> usize {
    1
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub events: Vec<crate::delegation_vault::audit::DelegationAuditEvent>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    /// Per-category event counts across the text/refinement-filtered set (before
    /// the category filter), so the UI can show each category's count.
    pub category_counts: std::collections::BTreeMap<String, usize>,
}

/// GET /api/v1/audit — unified audit evidence view.
pub async fn get_audit_log(
    State(_state): State<IdentityApiState>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, String)> {
    let limit = query.limit.clamp(1, 500);
    let page = query.page.max(1);

    let result = crate::delegation_vault::audit::read_audit_log(
        page,
        limit,
        crate::delegation_vault::audit::AuditLogFilter {
            text: query.filter.as_deref(),
            category: query.category.as_deref(),
            flow: query.flow.as_deref(),
            scope: query.scope.as_deref(),
            decision: query.decision.as_deref(),
            exclude_vp_audit: false,
        },
    )
    .await;

    let log_page = match result {
        Ok(p) => p,
        Err(e) => {
            // Fail loudly on a read/init failure rather than masking it as an
            // empty (but 200 OK) result — otherwise a storage outage is
            // indistinguishable from "no events occurred", which would let an
            // evidence gap pass unnoticed and undermine the audit trail. Mirrors
            // the credential-delegation endpoint, which also errors on failure.
            tracing::error!(target: "policy_audit", error = %e, "Failed to read audit log");
            return Err((StatusCode::SERVICE_UNAVAILABLE, format!("audit log temporarily unavailable: {e}")));
        }
    };

    Ok(Json(AuditLogResponse {
        events: log_page.events,
        total: log_page.total,
        page: log_page.page,
        page_size: log_page.page_size,
        total_pages: log_page.total_pages,
        category_counts: log_page.category_counts,
    }))
}
