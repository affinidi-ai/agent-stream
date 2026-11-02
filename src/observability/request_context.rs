//! Per-request context shared by every record a request produces: the trace id
//! (continuing Agent Gateway's `X-Gateway-Trace-Id`), the caller, the member and
//! teams the team gate resolved, and the tenant that owns the surface.
//!
//! The pipe handler runs each request inside [`scope`] and fills the context in
//! as the request resolves. Governance capture, policy-decision audit and pipe
//! events read it with [`current`]. Work that outlives the handler's task, such
//! as a streamed response's completion, takes a [`current`] snapshot and
//! re-enters it with [`sync_scope`].

use std::cell::RefCell;
use std::future::Future;

use crate::governance::{CallerKey, UsageAttribution};
use crate::source_auth::AuthenticatedIdentity;

tokio::task_local! {
    static REQUEST_CONTEXT: RefCell<RequestContext>;
}

/// Header carrying the trace id of the request that Agent Gateway forwarded.
pub const TRACE_ID_HEADER: &str = "x-gateway-trace-id";

#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub trace_id: String,
    /// The authenticated caller's principal.
    pub identity: Option<CallerKey>,
    /// Keyed hash of the authenticated caller under the secret shared with
    /// Agent Gateway; absent when no secret is configured.
    pub principal_key: Option<String>,
    /// The identifier the surface's team attribution matches members by, so a
    /// record written before the team gate runs still names the member.
    pub member_identifier: Option<String>,
    pub usage: UsageAttribution,
}

/// Continue the trace Agent Gateway started, or mint a new one. The incoming
/// value is reused only when it parses as a UUID, so a caller cannot inject
/// arbitrary text into every record.
pub fn continue_or_mint_trace_id(incoming: Option<&str>) -> String {
    incoming
        .filter(|value| uuid::Uuid::parse_str(value).is_ok())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

impl RequestContext {
    /// A context for an inbound request, continuing its `X-Gateway-Trace-Id`.
    pub fn for_request(headers: &axum::http::HeaderMap) -> Self {
        let incoming = headers
            .get(TRACE_ID_HEADER)
            .and_then(|v| v.to_str().ok());
        Self {
            trace_id: continue_or_mint_trace_id(incoming),
            ..Default::default()
        }
    }

    pub fn set_identity(
        &mut self,
        identity: Option<&AuthenticatedIdentity>,
    ) {
        self.identity = identity.map(CallerKey::from_identity);
        self.principal_key = identity.and_then(crate::identity::identity_hash::compute_principal_key);
    }

    /// The canonical caller. Before the team gate has run, the member is looked
    /// up by the caller's identifier, as the gate would.
    pub async fn caller(&self) -> Option<CallerKey> {
        let member_id = match &self.usage.member_id {
            Some(id) => Some(id.clone()),
            None => self.lookup_member().await,
        };
        CallerKey::resolve(member_id.as_deref(), self.identity.as_ref())
    }

    async fn lookup_member(&self) -> Option<String> {
        let identifier = self
            .member_identifier
            .as_deref()?;
        crate::members::store::global_member_store()?
            .find_for_gate(identifier)
            .await
            .map(|member| member.id)
    }
}

/// Run `fut` with `ctx` as its request context. Policy decisions made inside
/// it carry the context's trace id.
pub async fn scope<F: Future>(
    ctx: RequestContext,
    fut: F,
) -> F::Output {
    let trace_id = ctx.trace_id.clone();
    crate::observability::policy_audit::REQUEST_TRACE_ID
        .scope(trace_id, REQUEST_CONTEXT.scope(RefCell::new(ctx), fut))
        .await
}

/// Run `f` with `ctx` as its request context.
pub fn sync_scope<R>(
    ctx: RequestContext,
    f: impl FnOnce() -> R,
) -> R {
    let trace_id = ctx.trace_id.clone();
    crate::observability::policy_audit::REQUEST_TRACE_ID
        .sync_scope(trace_id, || REQUEST_CONTEXT.sync_scope(RefCell::new(ctx), f))
}

/// Run `f` attributing the policy decisions and audit records it writes to
/// `tenant_id`, for a path that has no request context of its own. A tenant the
/// current request context already carries wins, and an absent `tenant_id`
/// leaves the context untouched.
pub fn with_tenant<R>(
    tenant_id: Option<&str>,
    f: impl FnOnce() -> R,
) -> R {
    let Some(tenant_id) = tenant_id else {
        return f();
    };
    let mut ctx = current().unwrap_or_default();
    if ctx.usage.tenant_id.is_none() {
        ctx.usage.tenant_id = Some(tenant_id.to_string());
    }
    sync_scope(ctx, f)
}

/// A snapshot of the current request context, outside a request `None`.
pub fn current() -> Option<RequestContext> {
    REQUEST_CONTEXT
        .try_with(|ctx| ctx.borrow().clone())
        .ok()
}

/// The current request's trace id.
pub fn trace_id() -> Option<String> {
    REQUEST_CONTEXT
        .try_with(|ctx| ctx.borrow().trace_id.clone())
        .ok()
        .filter(|id| !id.is_empty())
}

/// The member, teams and tenant the current request is attributed to; empty
/// outside a request.
pub fn usage_attribution() -> UsageAttribution {
    REQUEST_CONTEXT
        .try_with(|ctx| ctx.borrow().usage.clone())
        .unwrap_or_default()
}

/// Update the current request context; a no-op outside a request.
pub fn update(f: impl FnOnce(&mut RequestContext)) {
    let _ = REQUEST_CONTEXT.try_with(|ctx| f(&mut ctx.borrow_mut()));
}

#[cfg(test)]
mod tests {
    #[test]
    fn with_tenant_attributes_work_without_a_request_context() {
        assert_eq!(with_tenant(Some("acme"), || usage_attribution().tenant_id), Some("acme".to_string()));
        assert_eq!(with_tenant(None, || usage_attribution().tenant_id), None);
        assert!(current().is_none());
    }

    #[test]
    fn with_tenant_keeps_the_tenant_a_request_already_carries() {
        let mut ctx = RequestContext::default();
        ctx.usage.tenant_id = Some("owner".to_string());
        let seen = sync_scope(ctx, || with_tenant(Some("other"), || usage_attribution().tenant_id));
        assert_eq!(seen, Some("owner".to_string()));
    }

    use super::*;

    #[test]
    fn a_gateway_trace_id_is_continued_only_when_it_is_a_uuid() {
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(continue_or_mint_trace_id(Some(&id)), id);

        let minted = continue_or_mint_trace_id(Some("not-a-uuid\nforged"));
        assert_ne!(minted, "not-a-uuid\nforged");
        assert!(uuid::Uuid::parse_str(&minted).is_ok());

        let a = continue_or_mint_trace_id(None);
        let b = continue_or_mint_trace_id(Some(""));
        assert!(uuid::Uuid::parse_str(&a).is_ok());
        assert_ne!(a, b);
    }

    #[test]
    fn for_request_reads_the_gateway_trace_header() {
        let id = uuid::Uuid::new_v4().to_string();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Gateway-Trace-Id", id.parse().unwrap());
        assert_eq!(RequestContext::for_request(&headers).trace_id, id);
        assert_ne!(RequestContext::for_request(&axum::http::HeaderMap::new()).trace_id, id);
    }

    #[tokio::test]
    async fn the_context_is_visible_and_updatable_inside_its_scope_only() {
        assert!(current().is_none());
        update(|ctx| ctx.trace_id = "ignored".to_string());

        let ctx = RequestContext {
            trace_id: "trace-1".to_string(),
            ..Default::default()
        };
        let seen = scope(ctx, async {
            update(|ctx| ctx.usage.tenant_id = Some("acme".to_string()));
            let policy_trace = crate::observability::policy_audit::current_span_trace_id();
            (current().unwrap(), trace_id(), policy_trace)
        })
        .await;
        assert_eq!(
            seen.0
                .usage
                .tenant_id
                .as_deref(),
            Some("acme")
        );
        assert_eq!(seen.1.as_deref(), Some("trace-1"));
        assert_eq!(seen.2.as_deref(), Some("trace-1"), "policy decisions share the request trace id");
        assert!(current().is_none());
    }

    #[test]
    fn sync_scope_re_enters_a_snapshot() {
        let ctx = RequestContext {
            trace_id: "trace-2".to_string(),
            ..Default::default()
        };
        assert_eq!(sync_scope(ctx, trace_id).as_deref(), Some("trace-2"));
        assert!(trace_id().is_none());
    }

    #[tokio::test]
    async fn the_caller_is_the_member_once_the_gate_resolved_one() {
        let mut ctx = RequestContext::default();
        ctx.set_identity(Some(&AuthenticatedIdentity::ApiKey { key_name: "bot".to_string() }));
        assert_eq!(
            ctx.caller().await,
            Some(CallerKey::from_identity(&AuthenticatedIdentity::ApiKey { key_name: "bot".to_string() }))
        );

        ctx.usage.member_id = Some("m-1".to_string());
        assert_eq!(ctx.caller().await, Some(CallerKey::member("m-1")));
    }
}
