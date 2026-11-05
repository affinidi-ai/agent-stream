//! Per-client throttling and lockout for the public sign-in endpoints.
//!
//! A client is its connecting address, with an IPv6 address grouped by its
//! /64 prefix. `X-Forwarded-For` is read only when the connecting peer is a
//! trusted proxy (`tls.client_auth.trusted_proxies`); from any other peer it
//! is ignored, because any caller can set it.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::RETRY_AFTER},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use moka::future::Cache;
use moka::policy::EvictionPolicy;
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::auth::session::SessionManager;

/// Sign-in requests (registration, passkey login, SAML login and ACS, OIDC
/// login and callback) one client may send per window.
pub(crate) const SIGN_IN_REQUESTS_PER_WINDOW: u32 = 10;
/// `/auth/check` requests one client may send per window. Past it, a request
/// with a valid dashboard session is still answered: the dashboard checks on
/// every load and WebSocket reconnect, and a refusal would sign the user out.
pub(crate) const AUTH_CHECK_REQUESTS_PER_WINDOW: u32 = 120;
/// How long one request budget lasts.
const WINDOW: Duration = Duration::from_secs(60);
/// Failed sign-ins after which a client is locked out of the sign-in endpoints.
const MAX_FAILED_SIGN_INS: u32 = 10;
/// How long a lockout lasts, counted from the client's last failed sign-in.
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Most clients tracked at once per budget; the least used are dropped first.
const MAX_TRACKED_CLIENTS: u64 = 100_000;

const THROTTLED_MESSAGE: &str = "Too many sign-in requests. Try again later.";

/// Proxies whose `X-Forwarded-For` names the client, set once at startup.
static TRUSTED_PROXIES: OnceLock<Vec<IpNet>> = OnceLock::new();

/// Read the client address from `X-Forwarded-For` on requests whose
/// connecting peer is one of `proxies` (`tls.client_auth.trusted_proxies`).
pub fn set_trusted_proxies(proxies: Vec<IpNet>) {
    let _ = TRUSTED_PROXIES.set(proxies);
}

fn trusted_proxies() -> &'static [IpNet] {
    TRUSTED_PROXIES
        .get()
        .map_or(&[], Vec::as_slice)
}

/// Which part of a sign-in a route is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignInStep {
    /// Starts a sign-in or registration; any caller can.
    Start,
    /// Completes one; a `401` (the passkey or SAML response did not verify,
    /// or the provider refused the OIDC code) counts as a failed sign-in.
    Finish,
}

/// Throttle a route that starts a sign-in or registration.
pub async fn sign_in_start(
    request: Request,
    next: Next,
) -> Response {
    throttle_sign_in(AuthThrottle::global(), SignInStep::Start, request, next).await
}

/// Throttle a route that completes a sign-in or registration, counting its
/// failures toward a lockout.
pub async fn sign_in_finish(
    request: Request,
    next: Next,
) -> Response {
    throttle_sign_in(AuthThrottle::global(), SignInStep::Finish, request, next).await
}

/// Throttle `/auth/check`, still answering a request with a valid dashboard
/// session once the client's budget is spent.
pub async fn auth_check(
    State(sessions): State<Arc<SessionManager>>,
    request: Request,
    next: Next,
) -> Response {
    throttle_auth_check(AuthThrottle::global(), &sessions, request, next).await
}

async fn throttle_auth_check(
    throttle: &AuthThrottle,
    sessions: &SessionManager,
    request: Request,
    next: Next,
) -> Response {
    let client = client_key(&request, trusted_proxies());
    if let Err(refusal) = throttle
        .auth_check
        .take(client, Instant::now())
        .await
        && !has_valid_session(sessions, request.headers()).await
    {
        if refusal.first_in_window {
            warn!(client = %client, "Refusing auth checks without a session: rate limit reached");
        }
        return too_many_requests(refusal.retry_after);
    }
    next.run(request).await
}

/// Whether `headers` carry the token of a live dashboard session.
async fn has_valid_session(
    sessions: &SessionManager,
    headers: &HeaderMap,
) -> bool {
    match crate::auth_manager::middleware::extract_session_token_from_headers(headers) {
        Some(token) => sessions
            .validate_session_record(&token)
            .await
            .is_some(),
        None => false,
    }
}

async fn throttle_sign_in(
    throttle: &AuthThrottle,
    step: SignInStep,
    request: Request,
    next: Next,
) -> Response {
    let client = client_key(&request, trusted_proxies());
    if throttle
        .is_locked_out(client)
        .await
    {
        debug!(client = %client, "Refused sign-in request: client locked out");
        return too_many_requests(LOCKOUT);
    }
    if let Err(refusal) = throttle
        .sign_in
        .take(client, Instant::now())
        .await
    {
        if refusal.first_in_window {
            warn!(client = %client, "Refusing sign-in requests: rate limit reached");
        }
        return too_many_requests(refusal.retry_after);
    }
    let response = next.run(request).await;
    if step == SignInStep::Finish {
        // Only a credential that did not verify counts: a malformed request,
        // an unknown or expired challenge, or a policy refusal cannot guess
        // anything, and counting them would let anyone sharing the client's
        // address lock its users out.
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            throttle
                .record_failure(client)
                .await;
        } else if status.is_success() {
            throttle
                .clear_failures(client)
                .await;
        }
    }
    response
}

struct AuthThrottle {
    sign_in: RequestBudget,
    auth_check: RequestBudget,
    /// Failed sign-ins per client, forgotten `LOCKOUT` after the last one.
    failures: Cache<IpAddr, u32>,
}

impl AuthThrottle {
    fn new(
        sign_in_limit: u32,
        auth_check_limit: u32,
    ) -> Self {
        Self::with_capacity(sign_in_limit, auth_check_limit, MAX_TRACKED_CLIENTS)
    }

    /// Track at most `capacity` clients per counter. Each counter evicts its
    /// least recently used client, so a new client is always tracked: with
    /// moka's default admission policy a full cache can refuse a new key,
    /// leaving that client unthrottled.
    fn with_capacity(
        sign_in_limit: u32,
        auth_check_limit: u32,
        capacity: u64,
    ) -> Self {
        Self {
            sign_in: RequestBudget::new(sign_in_limit, capacity),
            auth_check: RequestBudget::new(auth_check_limit, capacity),
            failures: Cache::builder()
                .max_capacity(capacity)
                .eviction_policy(EvictionPolicy::lru())
                .time_to_live(LOCKOUT)
                .build(),
        }
    }

    fn global() -> &'static Self {
        static THROTTLE: OnceLock<AuthThrottle> = OnceLock::new();
        THROTTLE.get_or_init(|| Self::new(SIGN_IN_REQUESTS_PER_WINDOW, AUTH_CHECK_REQUESTS_PER_WINDOW))
    }

    async fn is_locked_out(
        &self,
        client: IpAddr,
    ) -> bool {
        self.failures
            .get(&client)
            .await
            .is_some_and(|failures| failures >= MAX_FAILED_SIGN_INS)
    }

    /// Count a failed sign-in, logging the one that locks the client out.
    async fn record_failure(
        &self,
        client: IpAddr,
    ) {
        let failures = self
            .failures
            .entry(client)
            .and_upsert_with(|existing| async move {
                existing.map_or(1, |entry| {
                    entry
                        .into_value()
                        .saturating_add(1)
                })
            })
            .await
            .into_value();
        if failures == MAX_FAILED_SIGN_INS {
            warn!(client = %client, "Locked a client out of signing in after repeated failed sign-ins");
        }
    }

    async fn clear_failures(
        &self,
        client: IpAddr,
    ) {
        self.failures
            .invalidate(&client)
            .await;
    }
}

/// A fixed-window request budget per client.
struct RequestBudget {
    limit: u32,
    windows: Cache<IpAddr, Arc<Mutex<Window>>>,
}

struct Window {
    started: Instant,
    /// Requests seen in this window, refused ones included.
    requests: u32,
}

/// A request over its client's budget.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    /// How long until the client's next window opens.
    retry_after: Duration,
    /// The first refusal of the window, the one worth logging.
    first_in_window: bool,
}

impl RequestBudget {
    fn new(
        limit: u32,
        capacity: u64,
    ) -> Self {
        Self {
            limit,
            windows: Cache::builder()
                .max_capacity(capacity)
                .eviction_policy(EvictionPolicy::lru())
                .time_to_idle(WINDOW)
                .build(),
        }
    }

    /// Spend one request of `client`'s budget, or refuse it until the next
    /// window opens.
    async fn take(
        &self,
        client: IpAddr,
        now: Instant,
    ) -> Result<(), Refusal> {
        let window = self
            .windows
            .get_with(client, async move { Arc::new(Mutex::new(Window { started: now, requests: 0 })) })
            .await;
        let mut window = window.lock();
        if now.saturating_duration_since(window.started) >= WINDOW {
            window.started = now;
            window.requests = 0;
        }
        window.requests = window
            .requests
            .saturating_add(1);
        if window.requests <= self.limit {
            return Ok(());
        }
        Err(Refusal {
            retry_after: WINDOW.saturating_sub(now.saturating_duration_since(window.started)),
            first_in_window: window.requests == self.limit.saturating_add(1),
        })
    }
}

/// The client a request counts against: its connecting address, or, when that
/// is one of the `trusted` proxies, the address `X-Forwarded-For` names (see
/// [`forwarded_client`]). An IPv6 address is reduced to its /64 prefix (one
/// subscriber's allocation). A request without a connecting address counts
/// against one shared client.
fn client_key(
    request: &Request,
    trusted: &[IpNet],
) -> IpAddr {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| *peer);
    client_of(peer, request.headers(), trusted)
}

/// [`client_key`] for any other route: `X-Forwarded-For` counts only from a
/// trusted proxy.
pub(crate) fn client_address(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
) -> IpAddr {
    client_of(peer, headers, trusted_proxies())
}

fn client_of(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted: &[IpNet],
) -> IpAddr {
    let peer = peer.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |peer| peer.ip());
    let address = forwarded_client(peer, headers, trusted);
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(v6.to_bits() & (u128::MAX << 64))),
        },
        v4 => v4,
    }
}

/// The client behind a trusted proxy: the rightmost `X-Forwarded-For` hop that
/// is not itself a trusted proxy. Hops are read right to left because each
/// proxy appends the address it received from, so only the right end was
/// written by a proxy the appliance trusts. `peer` itself when it is not a
/// trusted proxy or the header names no other client; the last trusted hop
/// when a hop does not parse.
fn forwarded_client(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpNet],
) -> IpAddr {
    use crate::source_auth::peer_cert::forwarded::ip_in_any;
    if !ip_in_any(&peer, trusted) {
        return peer;
    }
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|hop| !hop.is_empty())
        .collect();
    let mut client = peer;
    for hop in hops.iter().rev() {
        let Ok(address) = hop.parse::<IpAddr>() else {
            return client;
        };
        client = address;
        if !ip_in_any(&address, trusted) {
            break;
        }
    }
    client
}

fn too_many_requests(retry_after: Duration) -> Response {
    let mut response = (StatusCode::TOO_MANY_REQUESTS, THROTTLED_MESSAGE).into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(retry_after.as_secs().max(1)));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        routing::{get, post},
    };
    use tower::ServiceExt;

    fn request_from(peer: &str) -> Request {
        let mut request = Request::builder()
            .method("POST")
            .uri("/auth/login/finish")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo::<SocketAddr>(peer.parse().unwrap()));
        request
    }

    /// A sign-in route behind `throttle` that answers with `status`.
    fn route(
        throttle: &'static AuthThrottle,
        step: SignInStep,
        status: StatusCode,
    ) -> Router {
        Router::new()
            .route("/auth/login/finish", post(move || async move { status }))
            .layer(axum::middleware::from_fn(move |request: Request, next: Next| {
                throttle_sign_in(throttle, step, request, next)
            }))
    }

    fn leaked(throttle: AuthThrottle) -> &'static AuthThrottle {
        Box::leak(Box::new(throttle))
    }

    #[tokio::test]
    async fn a_budget_refuses_requests_over_its_limit_until_the_next_window() {
        let budget = RequestBudget::new(3, MAX_TRACKED_CLIENTS);
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let start = Instant::now();
        for _ in 0..3 {
            assert_eq!(
                budget
                    .take(client, start)
                    .await,
                Ok(())
            );
        }
        assert_eq!(
            budget
                .take(client, start + Duration::from_secs(20))
                .await,
            Err(Refusal {
                retry_after: Duration::from_secs(40),
                first_in_window: true,
            }),
            "the fourth request in the window is refused"
        );
        assert_eq!(
            budget
                .take(client, start + Duration::from_secs(30))
                .await,
            Err(Refusal {
                retry_after: Duration::from_secs(30),
                first_in_window: false,
            }),
            "only the first refusal of a window is flagged for logging"
        );

        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        assert_eq!(
            budget
                .take(other, start)
                .await,
            Ok(()),
            "each client has its own budget"
        );

        assert_eq!(
            budget
                .take(client, start + WINDOW)
                .await,
            Ok(()),
            "a new window restores the budget"
        );
        for _ in 0..2 {
            assert_eq!(
                budget
                    .take(client, start + WINDOW)
                    .await,
                Ok(())
            );
        }
        assert!(
            budget
                .take(client, start + WINDOW)
                .await
                .is_err_and(|refusal| refusal.first_in_window),
            "the next window's first refusal is flagged again"
        );
    }

    /// A GET `/auth/check` from `peer`, with `session_token` as its bearer.
    fn auth_check_request(
        peer: &str,
        session_token: Option<&str>,
    ) -> Request {
        let mut request = Request::builder()
            .uri("/auth/check")
            .body(Body::empty())
            .unwrap();
        if let Some(token) = session_token {
            request
                .headers_mut()
                .insert(axum::http::header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
        }
        request
            .extensions_mut()
            .insert(ConnectInfo::<SocketAddr>(peer.parse().unwrap()));
        request
    }

    #[tokio::test]
    async fn auth_checks_over_the_limit_are_answered_only_with_a_valid_session() {
        let throttle = leaked(AuthThrottle::new(1_000, 1));
        let sessions = Arc::new(SessionManager::new());
        let token = sessions
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let app = Router::new()
            .route("/auth/check", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(move |request: Request, next: Next| {
                let sessions = sessions.clone();
                async move { throttle_auth_check(throttle, &sessions, request, next).await }
            }));
        let status = |request: Request| {
            let app = app.clone();
            async move {
                app.oneshot(request)
                    .await
                    .unwrap()
                    .status()
            }
        };

        assert_eq!(status(auth_check_request("198.51.100.20:4000", None)).await, StatusCode::OK);
        assert_eq!(
            status(auth_check_request("198.51.100.20:4000", None)).await,
            StatusCode::TOO_MANY_REQUESTS,
            "a check without a session is refused over the limit"
        );
        assert_eq!(
            status(auth_check_request("198.51.100.20:4000", Some("not-a-session"))).await,
            StatusCode::TOO_MANY_REQUESTS,
            "an unknown session token does not lift the limit"
        );
        assert_eq!(
            status(auth_check_request("198.51.100.20:4000", Some(&token))).await,
            StatusCode::OK,
            "a signed-in dashboard is still answered, so it is not signed out"
        );
        assert_eq!(
            status(auth_check_request("198.51.100.21:4000", None)).await,
            StatusCode::OK,
            "another client has its own budget"
        );
    }

    #[tokio::test]
    async fn sign_in_requests_over_the_limit_get_429_with_retry_after() {
        let throttle = leaked(AuthThrottle::new(2, 100));
        let app = route(throttle, SignInStep::Start, StatusCode::OK);
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(request_from("198.51.100.1:5000"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let refused = app
            .clone()
            .oneshot(request_from("198.51.100.1:5001"))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = refused.headers()[RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&retry_after), "retry after {retry_after}s");

        let other = app
            .oneshot(request_from("198.51.100.2:5000"))
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK, "another client is not throttled");
    }

    #[tokio::test]
    async fn repeated_failed_sign_ins_lock_the_client_out() {
        let throttle = leaked(AuthThrottle::new(1_000, 1_000));
        let failing = route(throttle, SignInStep::Finish, StatusCode::UNAUTHORIZED);
        for _ in 0..MAX_FAILED_SIGN_INS {
            let response = failing
                .clone()
                .oneshot(request_from("198.51.100.3:4000"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let succeeding = route(throttle, SignInStep::Finish, StatusCode::OK);
        let locked = succeeding
            .clone()
            .oneshot(request_from("198.51.100.3:4001"))
            .await
            .unwrap();
        assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS, "even a valid sign-in is refused");
        assert_eq!(
            locked.headers()[RETRY_AFTER],
            LOCKOUT
                .as_secs()
                .to_string()
                .as_str()
        );

        let other = succeeding
            .oneshot(request_from("198.51.100.4:4000"))
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK, "other clients can still sign in");
    }

    #[tokio::test]
    async fn a_successful_sign_in_clears_earlier_failures() {
        let throttle = leaked(AuthThrottle::new(1_000, 1_000));
        let failing = route(throttle, SignInStep::Finish, StatusCode::UNAUTHORIZED);
        let succeeding = route(throttle, SignInStep::Finish, StatusCode::OK);
        for _ in 0..MAX_FAILED_SIGN_INS - 1 {
            failing
                .clone()
                .oneshot(request_from("198.51.100.5:4000"))
                .await
                .unwrap();
        }
        let signed_in = succeeding
            .oneshot(request_from("198.51.100.5:4000"))
            .await
            .unwrap();
        assert_eq!(signed_in.status(), StatusCode::OK);

        let after = failing
            .oneshot(request_from("198.51.100.5:4000"))
            .await
            .unwrap();
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED, "the failure count started again");
        assert!(
            !throttle
                .is_locked_out(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)))
                .await
        );
    }

    #[tokio::test]
    async fn starting_a_sign_in_never_counts_as_a_failure() {
        let throttle = leaked(AuthThrottle::new(1_000, 1_000));
        let app = route(throttle, SignInStep::Start, StatusCode::FORBIDDEN);
        for _ in 0..MAX_FAILED_SIGN_INS + 1 {
            let response = app
                .clone()
                .oneshot(request_from("198.51.100.6:4000"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn clients_are_keyed_by_address_and_ipv6_by_its_64_prefix() {
        let key = |peer: &str| client_key(&request_from(peer), &[]);
        assert_eq!(key("198.51.100.9:1111"), key("198.51.100.9:2222"), "the port does not matter");
        assert_ne!(key("198.51.100.9:1111"), key("198.51.100.10:1111"));
        assert_eq!(key("[2001:db8:1:2:aaaa::1]:443"), key("[2001:db8:1:2:bbbb::2]:443"));
        assert_ne!(key("[2001:db8:1:2::1]:443"), key("[2001:db8:1:3::1]:443"));
        assert_eq!(key("[::ffff:198.51.100.9]:443"), key("198.51.100.9:443"));

        let mut without_peer = Request::builder()
            .body(Body::empty())
            .unwrap();
        without_peer
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.11"));
        assert_eq!(
            client_key(&without_peer, &[]),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "a forwarded-for header is ignored"
        );
    }

    #[tokio::test]
    async fn only_a_credential_that_did_not_verify_counts_toward_a_lockout() {
        let throttle = leaked(AuthThrottle::new(1_000, 1_000));
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::FORBIDDEN,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            let app = route(throttle, SignInStep::Finish, status);
            for _ in 0..MAX_FAILED_SIGN_INS + 1 {
                let response = app
                    .clone()
                    .oneshot(request_from("198.51.100.7:4000"))
                    .await
                    .unwrap();
                assert_eq!(response.status(), status, "a {status} never locks the client out");
            }
        }
        assert!(
            !throttle
                .is_locked_out(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
                .await
        );
    }

    #[test]
    fn behind_a_trusted_proxy_the_client_is_the_rightmost_untrusted_hop() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let key = |peer: &str, forwarded_for: &[&str]| {
            let mut request = request_from(peer);
            for value in forwarded_for {
                request
                    .headers_mut()
                    .append("x-forwarded-for", HeaderValue::from_str(value).unwrap());
            }
            client_key(&request, &trusted)
        };
        let ip = |address: &str| {
            address
                .parse::<IpAddr>()
                .unwrap()
        };

        assert_eq!(key("10.0.0.2:443", &["198.51.100.7"]), ip("198.51.100.7"));
        assert_eq!(
            key("10.0.0.2:443", &["203.0.113.9, 198.51.100.7"]),
            ip("198.51.100.7"),
            "a hop the caller wrote before the proxy's own is not trusted"
        );
        assert_eq!(
            key("10.0.0.2:443", &["198.51.100.7, 10.0.0.5"]),
            ip("198.51.100.7"),
            "trusted proxy hops are skipped"
        );
        assert_eq!(
            key("10.0.0.2:443", &["203.0.113.9", "198.51.100.7"]),
            ip("198.51.100.7"),
            "headers are read in order"
        );
        assert_eq!(key("10.0.0.2:443", &[]), ip("10.0.0.2"), "no header: the proxy itself");
        assert_eq!(key("10.0.0.2:443", &["not-an-address"]), ip("10.0.0.2"), "a garbled hop is not trusted");
        assert_eq!(key("10.0.0.2:443", &["10.0.0.5"]), ip("10.0.0.5"), "only trusted hops: the leftmost of them");
        assert_eq!(
            key("10.0.0.2:443", &["2001:db8:1:2::7"]),
            ip("2001:db8:1:2::"),
            "a forwarded IPv6 client keeps its /64"
        );

        assert_eq!(
            key("203.0.113.50:443", &["198.51.100.7"]),
            ip("203.0.113.50"),
            "from an untrusted peer the header is ignored"
        );
        let mut request = request_from("10.0.0.2:443");
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        assert_eq!(client_key(&request, &[]), ip("10.0.0.2"), "with no trusted proxies the header is ignored");
    }

    /// A full tracker whose clients have each been seen several times must
    /// still keep a newcomer seen once. Moka's default admission policy would
    /// refuse it as less frequent than every tracked client, so its window and
    /// failures would start over on each request.
    #[tokio::test]
    async fn a_full_tracker_still_throttles_and_locks_out_a_new_client() {
        const CAPACITY: u64 = 64;
        let throttle = AuthThrottle::with_capacity(1, 1, CAPACITY);
        let now = Instant::now();
        let regulars: Vec<IpAddr> = (0..CAPACITY)
            .map(|n| IpAddr::V4(Ipv4Addr::new(198, 51, 100, n as u8)))
            .collect();
        for _ in 0..3 {
            for client in &regulars {
                let _ = throttle
                    .sign_in
                    .take(*client, now)
                    .await;
                throttle
                    .record_failure(*client)
                    .await;
            }
            throttle
                .sign_in
                .windows
                .run_pending_tasks()
                .await;
            throttle
                .failures
                .run_pending_tasks()
                .await;
        }

        let newcomer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert!(
            throttle
                .sign_in
                .take(newcomer, now)
                .await
                .is_ok()
        );
        throttle
            .sign_in
            .windows
            .run_pending_tasks()
            .await;
        assert!(
            throttle
                .sign_in
                .take(newcomer, now)
                .await
                .is_err(),
            "the newcomer's window was kept, so its second request is refused"
        );

        for _ in 0..MAX_FAILED_SIGN_INS {
            throttle
                .record_failure(newcomer)
                .await;
            throttle
                .failures
                .run_pending_tasks()
                .await;
        }
        assert!(
            throttle
                .is_locked_out(newcomer)
                .await,
            "the newcomer's failures were kept"
        );
    }
}
