//! Access declarations for routes that carry no role-based permission guard.
//!
//! Every `.route(...)` registration either names the permission it needs
//! (`RbacGuard::gate`, `maybe_gate`, `require_feature`, [`scope_gate`]), is
//! public under the session guard, or declares here why it needs none. The
//! route-coverage test below fails the test suite for a registration that does
//! neither. It checks that a rule is named, not that a marker's claim is true:
//! [`self_service`], [`handler_checked`], [`public`] and [`source_authenticated`]
//! enforce nothing themselves, so the routes carrying them are pinned in a
//! table that changes only with review. `route_service`, `nest_service`,
//! `fallback`, `fallback_service` and macro-registered routes are not scanned.

use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatContext, PatDelegationContext};
use crate::rbac::Feature;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::MethodRouter,
};
use tracing::warn;

/// Require `feature` in the scopes of an access token with explicit scopes.
/// Sessions and tokens without explicit scopes pass unchanged; their role is
/// not checked here. A request that `require_session_auth` did not
/// authenticate is refused with `401`.
pub fn scope_gate<S>(
    mr: MethodRouter<S>,
    feature: Feature,
) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    mr.layer(axum::middleware::from_fn_with_state(feature, scope_guard))
}

/// Refuse every access token with explicit scopes. Used on writes to the
/// caller's own account, which no scope covers. A request that
/// `require_session_auth` did not authenticate is refused with `401`.
pub fn refuse_scoped_tokens<S>(mr: MethodRouter<S>) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    mr.layer(axum::middleware::from_fn(scoped_token_refusal))
}

/// The route reads only the caller's own data, or data the appliance also
/// publishes without authentication, so it is open to any authenticated
/// caller, including an access token with explicit scopes.
pub fn self_service<S>(mr: MethodRouter<S>) -> MethodRouter<S> {
    mr
}

/// The handler checks the caller's role and access-token scopes itself before
/// doing any work.
pub fn handler_checked<S>(mr: MethodRouter<S>) -> MethodRouter<S> {
    mr
}

/// The route needs no authentication: a public document such as a DID
/// document or revocation list, a redirect, or the OAuth provider's callback.
pub fn public<S>(mr: MethodRouter<S>) -> MethodRouter<S> {
    mr
}

/// The route serves Surface or model traffic on a listener and is
/// authenticated by the Surface's source authentication, not by a management
/// session or token.
pub fn source_authenticated<S>(mr: MethodRouter<S>) -> MethodRouter<S> {
    mr
}

async fn scope_guard(
    State(feature): State<Feature>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(refusal) = unauthenticated(&request, "scope_gate") {
        return refusal;
    }
    if !crate::auth_manager::middleware::pat_scope_allows(
        request
            .extensions()
            .get::<PatContext>(),
        &feature,
    ) {
        warn!(
            token_id = token_id(&request),
            path = %request.uri().path(),
            feature = feature.as_str(),
            "scope_gate: access-token scopes exclude this permission"
        );
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

async fn scoped_token_refusal(
    request: Request,
    next: Next,
) -> Response {
    if let Some(refusal) = unauthenticated(&request, "refuse_scoped_tokens") {
        return refusal;
    }
    if matches!(
        request
            .extensions()
            .get::<PatContext>(),
        Some(PatContext(Some(_)))
    ) {
        warn!(
            token_id = token_id(&request),
            path = %request.uri().path(),
            "refuse_scoped_tokens: route is not available to an access token with explicit scopes"
        );
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

/// `401` for a request `require_session_auth` did not authenticate, so a guard
/// mounted outside the session guard refuses rather than passing everything.
fn unauthenticated(
    request: &Request,
    guard: &str,
) -> Option<Response> {
    if request
        .extensions()
        .get::<AuthGuardOk>()
        .is_some()
    {
        return None;
    }
    warn!(guard, path = %request.uri().path(), "no authenticated caller on the request; session guard not applied");
    Some(StatusCode::UNAUTHORIZED.into_response())
}

/// The id of the access token the request authenticated with, or an empty
/// string for a session.
pub(crate) fn token_id(request: &Request) -> &str {
    request
        .extensions()
        .get::<PatDelegationContext>()
        .map_or("", |context| context.token_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    /// The status for a request that `require_session_auth` authenticated, as a
    /// session (`pat` is `None`) or as an access token.
    async fn status(
        router: Router,
        pat: Option<PatContext>,
    ) -> StatusCode {
        let mut request = axum::http::Request::builder()
            .uri("/v1/example")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(AuthGuardOk("user-1".to_string()));
        if let Some(pat) = pat {
            request
                .extensions_mut()
                .insert(pat);
        }
        router
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    fn scoped(scopes: &[&str]) -> Option<PatContext> {
        Some(PatContext(Some(
            scopes
                .iter()
                .map(|scope| scope.to_string())
                .collect(),
        )))
    }

    fn scope_gated() -> Router {
        Router::new().route("/v1/example", scope_gate(get(ok), Feature::GatewaysView))
    }

    fn refusing() -> Router {
        Router::new().route("/v1/example", refuse_scoped_tokens(get(ok)))
    }

    #[tokio::test]
    async fn scope_gate_admits_a_token_holding_the_scope() {
        assert_eq!(status(scope_gated(), scoped(&["gateways.view"])).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn scope_gate_refuses_a_token_without_the_scope() {
        assert_eq!(status(scope_gated(), scoped(&["metrics.view"])).await, StatusCode::FORBIDDEN);
        assert_eq!(status(scope_gated(), scoped(&[])).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn scope_gate_leaves_sessions_and_unscoped_tokens_unchanged() {
        assert_eq!(status(scope_gated(), None).await, StatusCode::OK);
        assert_eq!(status(scope_gated(), Some(PatContext(None))).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn both_guards_refuse_a_request_the_session_guard_did_not_authenticate() {
        for router in [scope_gated(), refusing()] {
            let mut request = axum::http::Request::builder()
                .uri("/v1/example")
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(PatContext(None));
            let unauthenticated = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/v1/example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status();
            assert_eq!(unauthenticated, StatusCode::UNAUTHORIZED, "a request with neither extension");
            let token_without_guard = router
                .oneshot(request)
                .await
                .unwrap()
                .status();
            assert_eq!(token_without_guard, StatusCode::UNAUTHORIZED, "a token context without the guard marker");
        }
    }

    #[tokio::test]
    async fn refuse_scoped_tokens_refuses_any_token_with_explicit_scopes() {
        assert_eq!(status(refusing(), scoped(&["pipes.edit"])).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn refuse_scoped_tokens_leaves_sessions_and_unscoped_tokens_unchanged() {
        assert_eq!(status(refusing(), None).await, StatusCode::OK);
        assert_eq!(status(refusing(), Some(PatContext(None))).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn markers_do_not_change_the_route() {
        for router in [
            Router::new().route("/v1/example", self_service(get(ok))),
            Router::new().route("/v1/example", handler_checked(get(ok))),
            Router::new().route("/v1/example", public(get(ok))),
            Router::new().route("/v1/example", source_authenticated(get(ok))),
        ] {
            assert_eq!(status(router, scoped(&[])).await, StatusCode::OK);
        }
    }
}

/// Scans every module compiled into the binary, starting at `main.rs` and
/// skipping `#[cfg(test)]` items, for `.route(path, method_router)` calls. A
/// route is declared when its method router is wrapped, outermost, in a guard
/// or declaration, when a router-wide `.layer` or `.route_layer` applies a
/// guard to it, or when its literal path is public under the session guard.
#[cfg(test)]
mod route_coverage {
    use axum::http::Method;
    use std::path::{Path, PathBuf};
    use syn::spanned::Spanned;
    use syn::visit::{self, Visit};

    const DECLARATIONS: &[&str] = &[
        "gate",
        "maybe_gate",
        "require_feature",
        "scope_gate",
        "refuse_scoped_tokens",
        "self_service",
        "handler_checked",
        "public",
        "source_authenticated",
    ];

    /// Method-router constructors whose methods the scan cannot list, so a route
    /// using one is never treated as public.
    const UNKNOWN_METHODS: &[&str] = &["any", "on", "on_service", "any_service"];

    fn method_for(name: &str) -> Option<Method> {
        Some(match name {
            "get" => Method::GET,
            "head" => Method::HEAD,
            "post" => Method::POST,
            "put" => Method::PUT,
            "patch" => Method::PATCH,
            "delete" => Method::DELETE,
            "options" => Method::OPTIONS,
            _ => return None,
        })
    }

    fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| {
            attr.path().is_ident("test")
                || (attr.path().is_ident("cfg")
                    && attr
                        .parse_args::<syn::Ident>()
                        .is_ok_and(|ident| ident == "test"))
        })
    }

    fn is_declaration(name: &str) -> bool {
        DECLARATIONS.contains(&name)
    }

    /// A call such as `scope_gate(...)` or `crate::...::require_feature(...)`.
    fn is_declaration_call(expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Call(call) => matches!(
                call.func.as_ref(),
                syn::Expr::Path(path) if path.path.segments.last().is_some_and(|segment| is_declaration(&segment.ident.to_string()))
            ),
            syn::Expr::Paren(inner) => is_declaration_call(&inner.expr),
            _ => false,
        }
    }

    /// Whether the outermost call around a method router is a guard or a
    /// declaration, so every method it holds is covered.
    fn is_wrapped(expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Call(_) => is_declaration_call(expr),
            syn::Expr::MethodCall(call) => {
                let method = call.method.to_string();
                is_declaration(&method)
                    || ((method == "layer" || method == "route_layer")
                        && call
                            .args
                            .iter()
                            .any(is_declaration_call))
            }
            syn::Expr::Paren(inner) => is_wrapped(&inner.expr),
            _ => false,
        }
    }

    /// The HTTP methods a method router expression registers, sorted, or
    /// `None` when they cannot be listed: it uses a constructor such as `any`,
    /// or is built elsewhere and passed in as a variable.
    fn methods_of(expr: &syn::Expr) -> Option<Vec<Method>> {
        #[derive(Default)]
        struct Methods {
            found: Vec<Method>,
            unknown: bool,
        }

        impl Methods {
            fn record(
                &mut self,
                name: &str,
            ) {
                self.unknown |= UNKNOWN_METHODS.contains(&name);
                self.found
                    .extend(method_for(name));
            }
        }

        impl<'ast> Visit<'ast> for Methods {
            fn visit_expr_method_call(
                &mut self,
                call: &'ast syn::ExprMethodCall,
            ) {
                self.record(&call.method.to_string());
                visit::visit_expr_method_call(self, call);
            }

            fn visit_expr_call(
                &mut self,
                call: &'ast syn::ExprCall,
            ) {
                if let syn::Expr::Path(path) = call.func.as_ref()
                    && let Some(segment) = path.path.segments.last()
                {
                    self.record(&segment.ident.to_string());
                }
                visit::visit_expr_call(self, call);
            }
        }

        let mut methods = Methods::default();
        methods.visit_expr(expr);
        if methods.unknown || methods.found.is_empty() {
            return None;
        }
        methods
            .found
            .sort_by(|a, b| a.as_str().cmp(b.as_str()));
        methods.found.dedup();
        Some(methods.found)
    }

    /// Whether `path` is public under the session guard at a `/` boundary of
    /// the matched entry, so `/v1/resolve-keys` does not count as `/v1/resolve`.
    fn is_public_at_boundary(
        method: &Method,
        path: &str,
    ) -> bool {
        crate::auth_manager::middleware::public_path_entry(method, path)
            .is_some_and(|entry| path == entry || entry.ends_with('/') || path[entry.len()..].starts_with('/'))
    }

    /// A readable name for a route's path: the literal, or the expression that
    /// computes it, such as `callback_route` or `route_config.prefix`.
    fn path_label(expr: &syn::Expr) -> String {
        match expr {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(path), .. }) => path.value(),
            syn::Expr::Reference(reference) => path_label(&reference.expr),
            syn::Expr::Paren(inner) => path_label(&inner.expr),
            syn::Expr::Path(path) => path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::"),
            syn::Expr::Field(field) => {
                let member = match &field.member {
                    syn::Member::Named(name) => name.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };
                format!("{}.{member}", path_label(&field.base))
            }
            _ => "<computed path>".to_string(),
        }
    }

    /// The declaration function called outermost around a method router, and
    /// the `Feature` variant it names, such as `("scope_gate", Some("PipesView"))`.
    fn wrapper_of(expr: &syn::Expr) -> Option<(String, Option<String>)> {
        let syn::Expr::Call(call) = expr else {
            return None;
        };
        let syn::Expr::Path(callee) = call.func.as_ref() else {
            return None;
        };
        let name = callee
            .path
            .segments
            .last()?
            .ident
            .to_string();
        let feature = call
            .args
            .iter()
            .find_map(|arg| match arg {
                syn::Expr::Path(path) => {
                    let segments: Vec<String> = path
                        .path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect();
                    (segments.len() >= 2 && segments[segments.len() - 2] == "Feature")
                        .then(|| segments[segments.len() - 1].clone())
                }
                _ => None,
            });
        Some((name, feature))
    }

    struct Route {
        /// The literal path, or `None` when the path is computed.
        path: Option<String>,
        /// The literal path, or the expression that computes it.
        label: String,
        line: usize,
        wrapped: bool,
        layered: bool,
        /// Sorted methods, or `None` when they cannot be listed.
        methods: Option<Vec<Method>>,
        wrapper: Option<(String, Option<String>)>,
    }

    impl Route {
        fn declares_access(&self) -> bool {
            if self.wrapped || self.layered {
                return true;
            }
            let (Some(path), Some(methods)) = (&self.path, &self.methods) else {
                return false;
            };
            !methods.is_empty()
                && methods
                    .iter()
                    .all(|method| is_public_at_boundary(method, path))
        }

        fn describe(&self) -> String {
            format!(
                "{} {}",
                self.line,
                self.path
                    .as_deref()
                    .unwrap_or("<computed path>")
            )
        }

        fn methods_text(&self) -> String {
            self.methods
                .as_ref()
                .map_or("<any>".to_string(), |methods| {
                    methods
                        .iter()
                        .map(Method::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                })
        }
    }

    struct FileScan {
        module_dir: PathBuf,
        routes: Vec<Route>,
        child_modules: Vec<PathBuf>,
        layer_depth: usize,
    }

    impl FileScan {
        fn new(module_dir: PathBuf) -> Self {
            Self {
                module_dir,
                routes: Vec::new(),
                child_modules: Vec::new(),
                layer_depth: 0,
            }
        }
    }

    impl<'ast> Visit<'ast> for FileScan {
        fn visit_item_mod(
            &mut self,
            item: &'ast syn::ItemMod,
        ) {
            if is_cfg_test(&item.attrs) {
                return;
            }
            let dir = self
                .module_dir
                .join(item.ident.to_string());
            if item.content.is_none() {
                self.child_modules.push(dir);
                return;
            }
            let parent = std::mem::replace(&mut self.module_dir, dir);
            visit::visit_item_mod(self, item);
            self.module_dir = parent;
        }

        fn visit_item_fn(
            &mut self,
            item: &'ast syn::ItemFn,
        ) {
            if !is_cfg_test(&item.attrs) {
                visit::visit_item_fn(self, item);
            }
        }

        fn visit_impl_item_fn(
            &mut self,
            item: &'ast syn::ImplItemFn,
        ) {
            if !is_cfg_test(&item.attrs) {
                visit::visit_impl_item_fn(self, item);
            }
        }

        fn visit_expr_method_call(
            &mut self,
            call: &'ast syn::ExprMethodCall,
        ) {
            if (call.method == "layer" || call.method == "route_layer")
                && call
                    .args
                    .iter()
                    .any(is_declaration_call)
            {
                self.layer_depth += 1;
                self.visit_expr(&call.receiver);
                self.layer_depth -= 1;
                for arg in &call.args {
                    self.visit_expr(arg);
                }
                return;
            }
            if call.method == "route" && call.args.len() == 2 {
                let path = match &call.args[0] {
                    syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(path), .. }) => Some(path.value()),
                    _ => None,
                };
                self.routes.push(Route {
                    path,
                    label: path_label(&call.args[0]),
                    line: call.args[0]
                        .span()
                        .start()
                        .line,
                    wrapped: is_wrapped(&call.args[1]),
                    layered: self.layer_depth > 0,
                    methods: methods_of(&call.args[1]),
                    wrapper: wrapper_of(&call.args[1]),
                });
            }
            visit::visit_expr_method_call(self, call);
        }
    }

    /// The directory a file's `mod name;` declarations resolve against.
    fn module_dir(file: &Path) -> PathBuf {
        let parent = file
            .parent()
            .expect("source file has a parent");
        match file
            .file_name()
            .and_then(|name| name.to_str())
        {
            Some("mod.rs" | "main.rs" | "lib.rs") => parent.to_path_buf(),
            _ => parent.join(
                file.file_stem()
                    .expect("source file has a stem"),
            ),
        }
    }

    fn module_file(module: &Path) -> PathBuf {
        let flat = module.with_extension("rs");
        if flat.is_file() {
            return flat;
        }
        let nested = module.join("mod.rs");
        assert!(nested.is_file(), "no source file for module {}", module.display());
        nested
    }

    fn scan(source: &str) -> FileScan {
        let mut scan = FileScan::new(PathBuf::new());
        scan.visit_file(&syn::parse_file(source).expect("parse source"));
        scan
    }

    fn undeclared(source: &str) -> Vec<String> {
        let mut routes: Vec<Route> = scan(source)
            .routes
            .into_iter()
            .filter(|route| !route.declares_access())
            .collect();
        routes.sort_by_key(|route| route.line);
        routes
            .iter()
            .map(Route::describe)
            .collect()
    }

    /// Every route registered by the modules compiled into the binary, with the
    /// file that registers it, relative to `src/`.
    fn crate_routes() -> Vec<(PathBuf, Route)> {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut pending = vec![src.join("main.rs")];
        let mut routes = Vec::new();
        while let Some(file) = pending.pop() {
            let source = std::fs::read_to_string(&file).expect("read source file");
            let syntax = syn::parse_file(&source).unwrap_or_else(|error| panic!("parse {}: {error}", file.display()));
            let mut scan = FileScan::new(module_dir(&file));
            scan.visit_file(&syntax);
            pending.extend(
                scan.child_modules
                    .iter()
                    .map(|module| module_file(module)),
            );
            let relative = file
                .strip_prefix(&src)
                .unwrap_or(&file)
                .to_path_buf();
            routes.extend(
                scan.routes
                    .into_iter()
                    .map(|route| (relative.clone(), route)),
            );
        }
        routes
    }

    #[test]
    fn every_route_declares_its_access() {
        let routes = crate_routes();
        let findings: Vec<String> = routes
            .iter()
            .filter(|(_, route)| !route.declares_access())
            .map(|(file, route)| format!("{}:{}", file.display(), route.describe()))
            .collect();

        assert!(routes.len() > 100, "the scan found only {} routes; it is missing route registrations", routes.len());
        assert!(
            findings.is_empty(),
            "routes declare no access rule; wrap each in a permission guard (gate, maybe_gate, require_feature, scope_gate) or a declaration (refuse_scoped_tokens, self_service, handler_checked, public, source_authenticated):\n{}",
            findings.join("\n")
        );
    }

    /// Every route that carries a declaration from this module, as
    /// `(methods, path, declaration, permission)`. A computed path is named by
    /// the expression that computes it, and `<any>` stands for methods the scan
    /// cannot list. The declarations that enforce nothing themselves sit here
    /// with the others, so a route added under one, moved onto one, or rewired
    /// to another permission fails until this table changes with it.
    const DECLARED_ROUTES: &[(&str, &str, &str, Option<&str>)] = &[
        ("<any>", "route_path", "source_authenticated", None),
        ("<any>", "variant_route_path", "source_authenticated", None),
        ("DELETE", "/v1/members/{member_id}", "handler_checked", None),
        ("DELETE", "/v1/prompts/{id}", "handler_checked", None),
        ("DELETE", "/v1/teams/{team_id}", "handler_checked", None),
        ("DELETE", "/v1/teams/{team_id}/members/{member_id}", "handler_checked", None),
        ("DELETE", "/v1/users/{user_id}", "handler_checked", None),
        ("GET", "/v1/cache/stats", "handler_checked", None),
        ("GET", "/v1/dashboard/ops-series", "handler_checked", None),
        ("GET", "/v1/drift/dimensions", "handler_checked", None),
        ("GET", "/v1/drift/runs", "handler_checked", None),
        ("GET", "/v1/drift/runs/{id}", "handler_checked", None),
        ("GET", "/v1/drift/series", "handler_checked", None),
        ("GET", "/v1/drift/sessions", "handler_checked", None),
        ("GET", "/v1/drift/verdict", "handler_checked", None),
        ("GET", "/v1/governance/coverage", "handler_checked", None),
        ("GET", "/v1/governance/records", "handler_checked", None),
        ("GET", "/v1/governance/records/{id}", "handler_checked", None),
        ("GET", "/v1/governance/surfaces", "handler_checked", None),
        ("GET", "/v1/governance/verify", "handler_checked", None),
        ("GET", "/v1/member-provisioning", "handler_checked", None),
        ("GET", "/v1/members", "handler_checked", None),
        ("GET", "/v1/members/{member_id}", "handler_checked", None),
        ("GET", "/v1/members/{member_id}/usage", "handler_checked", None),
        ("GET", "/v1/prompt-guard/detector-stats", "handler_checked", None),
        ("GET", "/v1/prompts", "handler_checked", None),
        ("GET", "/v1/prompts/{id}", "handler_checked", None),
        ("GET", "/v1/spend-report", "handler_checked", None),
        ("GET", "/v1/teams", "handler_checked", None),
        ("GET", "/v1/teams/{team_id}", "handler_checked", None),
        ("GET", "/v1/teams/{team_id}/usage", "handler_checked", None),
        ("GET", "/v1/telemetry/rejections", "handler_checked", None),
        ("GET", "/v1/telemetry/series", "handler_checked", None),
        ("GET", "/v1/users", "handler_checked", None),
        ("GET", "/v1/users/{user_id}", "handler_checked", None),
        ("GET", "/{cp_id}/did.json", "public", None),
        ("GET", "/{cp_id}/did.jsonl", "public", None),
        ("GET", "callback_route", "public", None),
        ("GET", "crate::identity::status_list::STATUS_LIST_PATH", "public", None),
        ("GET", "route_config.prefix", "public", None),
        ("GET,POST", "/v1/drift/baseline", "handler_checked", None),
        ("POST", "/v1/drift/eval/cancel", "handler_checked", None),
        ("POST", "/v1/drift/eval/run", "handler_checked", None),
        ("POST", "/v1/member-provisioning/preview", "handler_checked", None),
        ("POST", "/v1/members", "handler_checked", None),
        ("POST", "/v1/prompts", "handler_checked", None),
        ("POST", "/v1/prompts/{id}/render", "handler_checked", None),
        ("POST", "/v1/teams", "handler_checked", None),
        ("POST", "/v1/teams/{team_id}/members", "handler_checked", None),
        ("PUT", "/v1/member-provisioning", "handler_checked", None),
        ("PUT", "/v1/members/{member_id}", "handler_checked", None),
        ("PUT", "/v1/prompts/{id}", "handler_checked", None),
        ("PUT", "/v1/teams/{team_id}", "handler_checked", None),
        ("PUT", "/v1/users/{user_id}", "handler_checked", None),
        ("DELETE", "/v1/user-settings", "refuse_scoped_tokens", None),
        ("GET", "/v1/config/networking", "scope_gate", Some("SettingsView")),
        ("GET", "/v1/config/surface-routing", "scope_gate", Some("PipesView")),
        ("GET", "/v1/gateways", "scope_gate", Some("GatewaysView")),
        ("GET", "/v1/gateways/{id}", "scope_gate", Some("GatewaysView")),
        ("GET", "/v1/gateways/{id}/integrations", "scope_gate", Some("GatewaysView")),
        ("GET", "/v1/gateways/{id}/marketplace", "scope_gate", Some("GatewaysView")),
        ("GET", "/v1/gateways/{id}/policy", "scope_gate", Some("GatewaysView")),
        ("GET", "/v1/gateways/{id}/surfaces", "scope_gate", Some("GatewaysView")),
        ("GET", "/v1/identity/did-document", "self_service", None),
        ("GET", "/v1/identity/resolve-did", "scope_gate", Some("GatewaysView")),
        ("GET", "/v1/identity/resolve-did-document", "scope_gate", Some("GatewaysView")),
        ("GET", "/v1/integrations/config", "scope_gate", Some("IntegrationsView")),
        ("GET", "/v1/integrations/runtime-variables", "scope_gate", Some("IntegrationsView")),
        ("GET", "/v1/limits", "scope_gate", Some("MetricsView")),
        ("GET", "/v1/marketplace/models", "scope_gate", Some("GatewaysView")),
        ("GET", "/v1/marketplace/purchased", "scope_gate", Some("PaymentsView")),
        ("GET", "/v1/mediators", "scope_gate", Some("MediatorsView")),
        ("GET", "/v1/mediators/compatible", "scope_gate", Some("MediatorsView")),
        ("GET", "/v1/mediators/{id}", "scope_gate", Some("MediatorsView")),
        ("GET", "/v1/notifications", "self_service", None),
        ("GET", "/v1/notifications/unread/count", "self_service", None),
        ("GET", "/v1/notifications/user-welcome-template", "scope_gate", Some("NotificationsView")),
        ("GET", "/v1/notifications/{id}", "self_service", None),
        ("GET", "/v1/permissions", "self_service", None),
        ("GET", "/v1/pipes/config", "scope_gate", Some("PipesView")),
        ("GET", "/v1/profile", "self_service", None),
        ("GET", "/v1/prompt-guard/config", "scope_gate", Some("PipesView")),
        ("GET", "/v1/terms/status", "self_service", None),
        ("GET", "/v1/user-settings", "self_service", None),
        ("GET", "/v1/user-settings/overrides", "self_service", None),
        ("GET", "/v1/users/integrations", "scope_gate", Some("IntegrationsView")),
        ("POST", "/v1/gateways/{id}/ping", "scope_gate", Some("GatewaysView")),
        ("POST", "/v1/profile/avatar", "refuse_scoped_tokens", None),
        ("POST", "/v1/terms/acceptances", "refuse_scoped_tokens", None),
        ("POST", "/v1/uploads/image", "scope_gate", Some("PipesEdit")),
        ("POST", "/v1/user-settings", "refuse_scoped_tokens", None),
        ("POST", "/v1/verify/{did}", "scope_gate", Some("GatewaysView")),
        ("PUT", "/v1/profile", "refuse_scoped_tokens", None),
    ];

    /// The declarations defined in this module, which the pinned table covers.
    const PINNED_DECLARATIONS: &[&str] =
        &["scope_gate", "refuse_scoped_tokens", "self_service", "handler_checked", "public", "source_authenticated"];

    type DeclaredRoute = (String, String, String, Option<String>);

    fn describe_declared(route: &DeclaredRoute) -> String {
        let (methods, path, declaration, feature) = route;
        match feature {
            Some(feature) => format!("{methods} {path} {declaration}(Feature::{feature})"),
            None => format!("{methods} {path} {declaration}"),
        }
    }

    #[test]
    fn every_declared_route_is_pinned_with_its_permission() {
        let found: std::collections::BTreeSet<DeclaredRoute> = crate_routes()
            .into_iter()
            .filter_map(|(_, route)| {
                let methods = route.methods_text();
                let (declaration, feature) = route.wrapper?;
                PINNED_DECLARATIONS
                    .contains(&declaration.as_str())
                    .then_some((methods, route.label, declaration, feature))
            })
            .collect();
        let expected: std::collections::BTreeSet<DeclaredRoute> = DECLARED_ROUTES
            .iter()
            .map(|(methods, path, declaration, feature)| {
                (methods.to_string(), path.to_string(), declaration.to_string(), feature.map(str::to_string))
            })
            .collect();
        let unexpected: Vec<String> = found
            .difference(&expected)
            .map(describe_declared)
            .collect();
        let missing: Vec<String> = expected
            .difference(&found)
            .map(describe_declared)
            .collect();
        assert!(
            unexpected.is_empty() && missing.is_empty(),
            "the declared routes differ from DECLARED_ROUTES in src/auth_manager/route_declarations.rs; \
             update that table, and for a scope_gate route the scope table in docs/RBAC.md\n\
             registered but not in the table:\n  {}\nin the table but not registered:\n  {}",
            unexpected.join("\n  "),
            missing.join("\n  ")
        );
    }

    /// The walk starts at `main.rs`, so a module declared in `lib.rs` would be
    /// compiled but never scanned.
    #[test]
    fn the_library_root_declares_no_modules() {
        let lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
        let Ok(source) = std::fs::read_to_string(&lib) else {
            return;
        };
        let syntax = syn::parse_file(&source).expect("parse src/lib.rs");
        assert!(
            !syntax
                .items
                .iter()
                .any(|item| matches!(item, syn::Item::Mod(_))),
            "src/lib.rs declares modules the route-coverage scan does not visit; start crate_routes() from lib.rs too"
        );
    }

    #[test]
    fn a_public_prefix_counts_only_at_a_path_boundary() {
        let source = r#"
            fn routes() -> Router {
                Router::new()
                    .route("/v1/resolve", get(handler))
                    .route("/v1/resolve/{did}", get(handler))
                    .route("/v1/resolve-keys", get(handler))
                    .route("/v1/healthz-admin", get(handler))
                    .route("/ws/dashboard", get(handler))
                    .route("/wsx", get(handler))
            }
        "#;
        let undeclared: Vec<String> = undeclared(source)
            .into_iter()
            .map(|line| {
                line.split_once(' ')
                    .map_or(line.clone(), |(_, path)| path.to_string())
            })
            .collect();
        assert_eq!(undeclared, ["/v1/resolve-keys", "/v1/healthz-admin", "/wsx"]);
    }

    #[test]
    fn a_route_whose_methods_cannot_be_listed_is_never_public() {
        let source = r#"
            fn routes() -> Router {
                Router::new()
                    .route("/v1/health", any(handler))
                    .route("/v1/version", on(MethodFilter::GET, handler))
            }
        "#;
        assert_eq!(undeclared(source).len(), 2);
    }

    #[test]
    fn a_fully_qualified_feature_is_recognised() {
        let source = r#"
            fn routes() -> Router {
                Router::new().route("/v1/x", scope_gate(get(handler), crate::rbac::Feature::PipesView))
            }
        "#;
        let routes = scan(source).routes;
        assert_eq!(routes[0].wrapper, Some(("scope_gate".to_string(), Some("PipesView".to_string()))));
    }

    #[test]
    fn a_route_without_a_declaration_is_reported_with_its_line() {
        let source = "fn routes() -> Router {\n    Router::new()\n        .route(\"/v1/bare\", get(handler))\n        .route(\"/v1/health\", post(handler))\n        .route(&computed, get(handler))\n}\n";
        assert_eq!(undeclared(source), ["3 /v1/bare", "4 /v1/health", "5 <computed path>"]);
    }

    #[test]
    fn a_declaration_must_wrap_the_whole_method_router() {
        let source = r#"
            fn routes() -> Router {
                Router::new()
                    .route("/v1/chained", guard.gate(get(read), Feature::PipesView).post(write))
                    .route("/v1/inner", get(|| async { scope_gate(x, y) }))
                    .route("/v1/layered", get(handler).layer(Extension(public(state))))
            }
        "#;
        assert_eq!(undeclared(source).len(), 3);
    }

    #[test]
    fn guarded_declared_layered_and_public_routes_are_accepted() {
        let source = r#"
            fn routes() -> Router {
                let group = Router::new()
                    .route("/v1/group", get(handler))
                    .layer(require_feature(storage, rbac, Feature::PipesView));
                group
                    .route("/v1/gated", guard.gate(get(handler), Feature::PipesView))
                    .route("/v1/maybe", maybe_gate(guard, post(handler), Feature::PipesEdit))
                    .route("/v1/scoped", scope_gate(get(handler), Feature::PipesView))
                    .route("/v1/per-route", get(handler).layer(require_feature(s, r, Feature::PipesView)))
                    .route("/v1/own", self_service(get(handler)))
                    .route(&listener_path, source_authenticated(get(handler)))
                    .route("/v1/health", get(handler))
                    .layer(Extension(state))
            }
        "#;
        assert!(undeclared(source).is_empty());
    }

    #[test]
    fn test_only_code_is_not_scanned() {
        let source = r#"
            #[cfg(test)]
            mod tests {
                fn app() -> Router { Router::new().route("/v1/test-only", get(handler)) }
            }
            #[cfg(test)]
            fn helper() -> Router { Router::new().route("/v1/helper", get(handler)) }
        "#;
        assert!(undeclared(source).is_empty());
    }
}
