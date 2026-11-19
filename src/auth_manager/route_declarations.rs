//! Access declarations for routes that carry no role-based permission guard.
//!
//! Every route either names the permission it needs (`RbacGuard::gate`,
//! `maybe_gate`, `require_feature`, [`scope_gate`]), is public under the session
//! guard, or declares here why it needs none. The route-coverage test below
//! fails the build for a route that does neither, so a management access token
//! with explicit scopes never reaches a route none of its scopes covers.

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
/// not checked here. It authenticates nobody, so it belongs only on routes
/// behind `require_session_auth`.
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
/// caller's own account, which no scope covers.
pub fn refuse_scoped_tokens<S>(mr: MethodRouter<S>) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    mr.layer(axum::middleware::from_fn(scoped_token_refusal))
}

/// The route reads only the caller's own data, so it is open to any
/// authenticated caller, including an access token with explicit scopes.
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

    async fn status(
        router: Router,
        pat: Option<PatContext>,
    ) -> StatusCode {
        let mut request = axum::http::Request::builder()
            .uri("/v1/example")
            .body(Body::empty())
            .unwrap();
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

    fn method_for(name: &str) -> Option<Method> {
        Some(match name {
            "get" => Method::GET,
            "head" => Method::HEAD,
            "post" | "any" => Method::POST,
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

    /// The HTTP methods a method router expression registers.
    fn methods_of(expr: &syn::Expr) -> Vec<Method> {
        #[derive(Default)]
        struct Methods(Vec<Method>);

        impl<'ast> Visit<'ast> for Methods {
            fn visit_expr_method_call(
                &mut self,
                call: &'ast syn::ExprMethodCall,
            ) {
                self.0
                    .extend(method_for(&call.method.to_string()));
                visit::visit_expr_method_call(self, call);
            }

            fn visit_expr_call(
                &mut self,
                call: &'ast syn::ExprCall,
            ) {
                if let syn::Expr::Path(path) = call.func.as_ref()
                    && let Some(segment) = path.path.segments.last()
                {
                    self.0
                        .extend(method_for(&segment.ident.to_string()));
                }
                visit::visit_expr_call(self, call);
            }
        }

        let mut methods = Methods::default();
        methods.visit_expr(expr);
        methods.0
    }

    struct Route {
        /// The literal path, or `None` when the path is computed.
        path: Option<String>,
        line: usize,
        wrapped: bool,
        layered: bool,
        methods: Vec<Method>,
    }

    impl Route {
        fn declares_access(&self) -> bool {
            if self.wrapped || self.layered {
                return true;
            }
            let Some(path) = &self.path else {
                return false;
            };
            !self.methods.is_empty()
                && self
                    .methods
                    .iter()
                    .all(|method| crate::auth_manager::middleware::is_public_path(method, path))
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
                    line: call.args[0]
                        .span()
                        .start()
                        .line,
                    wrapped: is_wrapped(&call.args[1]),
                    layered: self.layer_depth > 0,
                    methods: methods_of(&call.args[1]),
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

    #[test]
    fn every_route_declares_its_access() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut pending = vec![src.join("main.rs")];
        let mut findings = Vec::new();
        let mut checked = 0;
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
            for route in &scan.routes {
                checked += 1;
                if !route.declares_access() {
                    findings.push(format!(
                        "{}:{}",
                        file.strip_prefix(&src)
                            .unwrap_or(&file)
                            .display(),
                        route.describe()
                    ));
                }
            }
        }

        assert!(checked > 100, "the scan found only {checked} routes; it is missing route registrations");
        assert!(
            findings.is_empty(),
            "routes declare no access rule; wrap each in a permission guard (gate, maybe_gate, require_feature, scope_gate) or a declaration (refuse_scoped_tokens, self_service, handler_checked, public, source_authenticated):\n{}",
            findings.join("\n")
        );
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
