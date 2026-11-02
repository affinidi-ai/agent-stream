use url::{Host, Url};

/// Return a URL-safe-for-logs representation.
///
/// The result removes embedded credentials, query strings, and fragments, which
/// are common places for bearer tokens, invitation material, and API keys. If
/// parsing fails, the original input is not returned.
pub fn redact_url_for_logging(raw: &str) -> String {
    let Ok(mut parsed) = Url::parse(raw.trim()) else {
        return "<invalid-url>".to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

/// The host of a webhook URL, for logs; the rest of it (path, query, userinfo)
/// can carry the webhook's bearer token, as a Slack, Teams or Discord URL does.
pub fn webhook_host(raw: &str) -> String {
    Url::parse(raw.trim())
        .ok()
        .and_then(|parsed| {
            parsed
                .host_str()
                .map(str::to_string)
        })
        .unwrap_or_else(|| "<invalid-url>".to_string())
}

/// Well-known cloud-provider metadata service IPv4 addresses.
/// These must never be reachable through user-supplied URLs.
const CLOUD_METADATA_IPV4: &[std::net::Ipv4Addr] = &[
    // AWS / GCP / Azure / DigitalOcean / OpenStack / HP Helion
    std::net::Ipv4Addr::new(169, 254, 169, 254),
    // AWS ECS task metadata
    std::net::Ipv4Addr::new(169, 254, 170, 2),
    // AWS EKS Pod Identity agent
    std::net::Ipv4Addr::new(169, 254, 170, 23),
    // Oracle Cloud
    std::net::Ipv4Addr::new(192, 0, 0, 192),
    // Alibaba Cloud
    std::net::Ipv4Addr::new(100, 100, 100, 200),
];

/// Well-known cloud-provider metadata service IPv6 addresses.
const CLOUD_METADATA_IPV6: &[std::net::Ipv6Addr] = &[
    // AWS EC2 IPv6 metadata endpoint
    std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254),
    // AWS EKS Pod Identity agent
    std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x23),
];

/// Hostnames used by cloud providers for metadata services.
const CLOUD_METADATA_HOSTNAMES: &[&str] = &["metadata.google.internal", "metadata"];

/// Returns `true` if `ip` is a loopback, unspecified or link-local
/// (169.254/16) address. Link-local hosts instance agents such as the EKS Pod
/// Identity agent and is never a legitimate service endpoint.
fn is_host_local_v4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_link_local()
}

/// Returns `true` if `ip` is a loopback, unspecified or link-local (fe80::/10)
/// IPv6 address.
fn is_host_local_v6(ip: std::net::Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_unicast_link_local()
}

/// Returns `true` if the given IPv4 address is a cloud metadata endpoint.
fn is_cloud_metadata_v4(ip: std::net::Ipv4Addr) -> bool {
    CLOUD_METADATA_IPV4.contains(&ip)
}

/// Returns `true` if the given IPv6 address is a cloud metadata endpoint,
/// including the forms [`embedded_ipv4`] unwraps (e.g. `::ffff:169.254.169.254`,
/// `64:ff9b::a9fe:a9fe`).
fn is_cloud_metadata_v6(ip: std::net::Ipv6Addr) -> bool {
    CLOUD_METADATA_IPV6.contains(&ip) || embedded_ipv4(ip).is_some_and(is_cloud_metadata_v4)
}

/// Returns `true` if the IPv6 address is host-local itself or carries a
/// host-local IPv4 address in a form [`embedded_ipv4`] unwraps.
fn is_host_local_or_embedded_v6(ip: std::net::Ipv6Addr) -> bool {
    is_host_local_v6(ip) || embedded_ipv4(ip).is_some_and(is_host_local_v4)
}

fn is_cloud_metadata_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_cloud_metadata_v4(v4),
        std::net::IpAddr::V6(v6) => is_cloud_metadata_v6(v6),
    }
}

/// Returns `true` if the hostname matches a cloud metadata hostname.
fn is_cloud_metadata_hostname(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h
        .strip_suffix('.')
        .unwrap_or(&h);
    CLOUD_METADATA_HOSTNAMES
        .iter()
        .any(|blocked| *h == **blocked)
}

/// Returns `true` if the parsed URL host is a cloud metadata endpoint.
/// Does NOT block loopback — suitable for the forwarding layer where
/// localhost targets are legitimate in dev/test.
fn is_cloud_metadata_host(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(ip) => is_cloud_metadata_v4(*ip),
        Host::Ipv6(ip) => is_cloud_metadata_v6(*ip),
        Host::Domain(domain) => is_cloud_metadata_hostname(domain),
    }
}

/// Returns `true` if the parsed URL host is a cloud metadata endpoint
/// OR a loopback, unspecified or link-local address. Used at ingestion time
/// (API handlers).
fn is_blocked_host(host: &Host<&str>) -> bool {
    if is_cloud_metadata_host(host) {
        return true;
    }
    match host {
        Host::Ipv4(ip) => is_host_local_v4(*ip),
        Host::Ipv6(ip) => is_host_local_or_embedded_v6(*ip),
        Host::Domain(domain) => {
            let h = domain.to_ascii_lowercase();
            let h = h
                .strip_suffix('.')
                .unwrap_or(&h);
            h == "localhost" || h.ends_with(".localhost")
        }
    }
}

/// Validate that a URL does not point to a cloud-provider metadata service or
/// a loopback or link-local address.
///
/// Accepts `http://` and `https://` URLs to private RFC 1918 ranges (same-VPC
/// agent traffic is legitimate). Only blocks:
///   - Cloud metadata IPs (AWS, GCP, Azure, Oracle, Alibaba, DigitalOcean, …)
///   - Cloud metadata hostnames (`metadata.google.internal`, `metadata`)
///   - Loopback / unspecified addresses (`127.x`, `localhost`, `::1`, `0.0.0.0`)
///   - Link-local addresses (`169.254/16`, `fe80::/10`)
///   - IPv4-mapped, IPv4-compatible and NAT64 forms of the above
///   - Embedded credentials (`user:pass@host`)
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
/// The scheme is not repeated in the error, since `raw` can be a stored
/// secret's value.
pub fn validate_url_not_cloud_metadata(raw: &str) -> Result<Url, String> {
    check_url_not_cloud_metadata(raw).map_err(String::from)
}

/// Why a URL was refused, each with the validator's message: it is not an
/// `http` or `https` URL with a host, or it is one the outbound policy does
/// not allow. A caller answering for a stored secret can tell the two apart
/// without reading the message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UrlRefusal {
    NotHttpUrl(String),
    Refused(String),
}

impl From<UrlRefusal> for String {
    fn from(refusal: UrlRefusal) -> Self {
        match refusal {
            UrlRefusal::NotHttpUrl(message) | UrlRefusal::Refused(message) => message,
        }
    }
}

fn check_url_not_cloud_metadata(raw: &str) -> Result<Url, UrlRefusal> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(UrlRefusal::NotHttpUrl("URL must not be empty".into()));
    }

    let parsed = Url::parse(trimmed).map_err(|e| UrlRefusal::NotHttpUrl(format!("Invalid URL: {e}")))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(UrlRefusal::NotHttpUrl("URL scheme must be http or https".into()));
    }

    if parsed.host().is_none() {
        return Err(UrlRefusal::NotHttpUrl("URL must include a host".into()));
    }

    if parsed
        .host_str()
        .is_some_and(|h| h.is_empty())
    {
        return Err(UrlRefusal::NotHttpUrl("URL must include a host".into()));
    }

    // Reject embedded credentials
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(UrlRefusal::Refused("URL must not contain embedded credentials".into()));
    }

    let host = parsed.host().unwrap(); // safe: checked above

    if is_blocked_host(&host) {
        return Err(UrlRefusal::Refused(format!(
            "URL host '{}' is blocked: cloud-provider metadata services, loopback and link-local addresses \
             are not allowed as target endpoints",
            host
        )));
    }

    Ok(parsed)
}

/// Returns `true` if the resolved `IpAddr` must be blocked.
///
/// Matches the same policy as [`is_blocked_host`] but operates on a concrete
/// `IpAddr` obtained from DNS resolution rather than the raw URL host token.
pub(crate) fn is_blocked_resolved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_cloud_metadata_v4(v4) || is_host_local_v4(v4),
        std::net::IpAddr::V6(v6) => is_cloud_metadata_v6(v6) || is_host_local_or_embedded_v6(v6),
    }
}

fn validate_service_dns_addresses(
    addresses: &[std::net::SocketAddr],
    allow_loopback: bool,
) -> Result<(), String> {
    if addresses.is_empty() {
        return Err("DNS resolution returned no addresses".to_string());
    }
    if let Some(blocked) = addresses
        .iter()
        .find(|address| !(allow_loopback && address.ip().is_loopback()) && is_blocked_resolved_ip(address.ip()))
    {
        return Err(format!(
            "DNS resolution returned blocked loopback, unspecified, link-local, or metadata address {}",
            blocked.ip()
        ));
    }
    Ok(())
}

/// Validate the addresses an operator-configured service endpoint's `host`
/// resolved to: loopback, unspecified, link-local and cloud metadata addresses are refused,
/// except loopback for a host on the test-mode service endpoint allowlist.
/// Private ranges are allowed (same-VPC providers), except for a host whose
/// LLM catalog base URL passed the public-address check at save, which must
/// still resolve only to public addresses. Shared by
/// [`ServiceEndpointDnsResolver`] and the realtime WebSocket dial.
pub(crate) fn validate_service_endpoint_addresses(
    host: &str,
    addresses: &[std::net::SocketAddr],
) -> Result<(), String> {
    validate_service_endpoint_addresses_for(host, addresses, crate::llm_catalog::requires_public_host(host))
}

fn validate_service_endpoint_addresses_for(
    host: &str,
    addresses: &[std::net::SocketAddr],
    public_only: bool,
) -> Result<(), String> {
    if public_only
        && let Some(blocked) = addresses
            .iter()
            .find(|address| is_blocked_resolved_webhook_ip(address.ip()))
    {
        return Err(format!(
            "{host} was saved as a public LLM provider address but now resolves to blocked address {}",
            blocked.ip()
        ));
    }
    let allow_loopback = bdd_service_endpoint_allowlist().is_some_and(|allowlist| {
        allowlist
            .split(',')
            .filter_map(|entry| Url::parse(entry.trim()).ok())
            .any(|url| {
                url.host_str()
                    .is_some_and(|allowed| allowed.eq_ignore_ascii_case(host))
            })
    });
    validate_service_dns_addresses(addresses, allow_loopback)
}

#[derive(Debug, Default)]
pub struct ServiceEndpointDnsResolver;

impl reqwest::dns::Resolve for ServiceEndpointDnsResolver {
    fn resolve(
        &self,
        name: reqwest::dns::Name,
    ) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addresses = lookup_addresses(&host).await?;
            validate_service_endpoint_addresses(&host, &addresses).map_err(resolve_error)?;
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn validate_forwarding_dns_addresses(addresses: &[std::net::SocketAddr]) -> Result<(), String> {
    if addresses.is_empty() {
        return Err("DNS resolution returned no addresses".to_string());
    }
    if let Some(blocked) = addresses
        .iter()
        .find(|address| is_cloud_metadata_ip(address.ip()))
    {
        return Err(format!("DNS resolution returned blocked metadata address {}", blocked.ip()));
    }
    Ok(())
}

/// Reqwest DNS resolver for the A2A/fabric forwarding layer.
///
/// Applies the same policy as [`reject_cloud_metadata_url`] to what a hostname
/// resolves to: only cloud metadata addresses are refused, loopback and private
/// ranges are allowed because forwarding targets are operator-configured and
/// may run on the same host, so `localhost` behaves like `127.0.0.1`. reqwest
/// does not call a resolver for an IP-literal URL, so this does not block
/// `http://169.254.169.254/`; that needs a check on the target URL itself.
#[derive(Debug, Default)]
pub struct ForwardingDnsResolver;

impl reqwest::dns::Resolve for ForwardingDnsResolver {
    fn resolve(
        &self,
        name: reqwest::dns::Name,
    ) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addresses = lookup_addresses(&host).await?;
            validate_forwarding_dns_addresses(&addresses).map_err(resolve_error)?;
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn resolve_error(message: String) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::other(message))
}

async fn lookup_addresses(host: &str) -> Result<Vec<std::net::SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    lookup_host(host, 0)
        .await
        .map_err(|error| resolve_error(format!("DNS resolution failed for {host}: {error}")))
}

async fn lookup_host(
    host: &str,
    port: u16,
) -> std::io::Result<Vec<std::net::SocketAddr>> {
    #[cfg(test)]
    if let Some(addresses) = test_dns::lookup(host, port) {
        return Ok(addresses);
    }
    Ok(tokio::net::lookup_host((host, port))
        .await?
        .collect())
}

/// Reqwest DNS resolver enforcing the strict webhook/payment SSRF policy.
///
/// Mirrors [`ServiceEndpointDnsResolver`] but rejects the full private range set
/// of [`is_blocked_resolved_webhook_ip`] (RFC 1918, full 169.254/16 link-local,
/// shared address space, IPv6 ULA/link-local, multicast, and IPv4-mapped,
/// IPv4-compatible and NAT64 forms) in addition to cloud metadata,
/// loopback, and unspecified. Wired onto clients that dial user-supplied
/// endpoints which must never reach internal networks (e.g. the pipe LLM
/// connection-test path), so an address that passed the pre-request URL check
/// cannot rebind to an internal IP before the connection is made.
#[derive(Debug, Default)]
pub struct WebhookDnsResolver;

impl reqwest::dns::Resolve for WebhookDnsResolver {
    fn resolve(
        &self,
        name: reqwest::dns::Name,
    ) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addresses = lookup_addresses(&host).await?;
            if addresses.is_empty() {
                return Err(resolve_error(format!("DNS resolution returned no addresses for {host}")));
            }
            if let Some(blocked) = addresses
                .iter()
                .find(|address| is_blocked_resolved_webhook_ip(address.ip()))
            {
                return Err(resolve_error(format!(
                    "DNS resolution for {host} returned blocked private, link-local, loopback, unspecified, or metadata address {}",
                    blocked.ip()
                )));
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn resolve_host_blocking(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, String> {
    let host = host.to_string();
    std::thread::spawn(move || {
        use std::net::ToSocketAddrs;
        (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed for '{}': {}", host, e))
            .map(|addrs| addrs.collect())
    })
    .join()
    .map_err(|_| "DNS resolution worker thread panicked".to_string())?
}

/// Shared implementation for DNS-aware URL validation.
///
/// When `block_loopback` is `true` the behaviour matches [`validate_resolved_url`]:
/// the addresses [`is_blocked_resolved_ip`] lists are rejected both statically and
/// after DNS resolution.  When `false` only cloud-provider metadata endpoints are
/// blocked, and loopback / RFC 1918 are allowed — see [`validate_resolved_cloud_metadata_url`].
fn validate_resolved_url_inner_blocking(
    raw: &str,
    block_loopback: bool,
) -> Result<Url, String> {
    let parsed = if block_loopback {
        validate_url_not_cloud_metadata(raw)?
    } else {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("URL must not be empty".into());
        }
        let p = Url::parse(trimmed).map_err(|e| format!("Invalid URL: {e}"))?;
        let scheme = p.scheme();
        if scheme != "http" && scheme != "https" {
            return Err("URL scheme must be http or https".into());
        }
        if p.host().is_none()
            || p.host_str()
                .is_some_and(|h| h.is_empty())
        {
            return Err("URL must include a host".into());
        }
        if !p.username().is_empty() || p.password().is_some() {
            return Err("URL must not contain embedded credentials".into());
        }
        let host = p.host().unwrap();
        if is_cloud_metadata_host(&host) {
            return Err(format!(
                "URL host '{}' is blocked: cloud-provider metadata services are not allowed \
                 as target endpoints",
                host
            ));
        }
        p
    };

    // IP literals were already validated statically — no DNS to do.
    if matches!(parsed.host(), Some(Host::Ipv4(_) | Host::Ipv6(_))) {
        return Ok(parsed);
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must include a host".to_string())?;
    let port = parsed
        .port_or_known_default()
        .unwrap_or(80);

    let addrs = resolve_host_blocking(host, port)?;

    if addrs.is_empty() {
        return Err(format!("DNS resolution for '{}' returned no addresses", host));
    }

    for socket_addr in addrs {
        let ip = socket_addr.ip();
        let blocked = if block_loopback {
            is_blocked_resolved_ip(ip)
        } else {
            is_cloud_metadata_ip(ip)
        };
        if blocked {
            let reason = if block_loopback {
                "cloud-provider metadata services, loopback and link-local addresses are not allowed as target endpoints"
            } else {
                "cloud-provider metadata services are not allowed as target endpoints"
            };
            return Err(format!("URL host '{}' resolves to blocked address '{}': {}", host, ip, reason));
        }
    }

    Ok(parsed)
}

async fn validate_resolved_url_inner(
    raw: &str,
    block_loopback: bool,
) -> Result<Url, String> {
    let parsed = if block_loopback {
        validate_url_not_cloud_metadata(raw)?
    } else {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("URL must not be empty".into());
        }
        let p = Url::parse(trimmed).map_err(|e| format!("Invalid URL: {e}"))?;
        let scheme = p.scheme();
        if scheme != "http" && scheme != "https" {
            return Err("URL scheme must be http or https".into());
        }
        if p.host().is_none()
            || p.host_str()
                .is_some_and(|h| h.is_empty())
        {
            return Err("URL must include a host".into());
        }
        if !p.username().is_empty() || p.password().is_some() {
            return Err("URL must not contain embedded credentials".into());
        }
        let host = p.host().unwrap();
        if is_cloud_metadata_host(&host) {
            return Err(format!(
                "URL host '{}' is blocked: cloud-provider metadata services are not allowed \
                 as target endpoints",
                host
            ));
        }
        p
    };

    if matches!(parsed.host(), Some(Host::Ipv4(_) | Host::Ipv6(_))) {
        return Ok(parsed);
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must include a host".to_string())?;
    let port = parsed
        .port_or_known_default()
        .unwrap_or(80);

    let addrs = lookup_host(host, port)
        .await
        .map_err(|e| format!("DNS resolution failed for '{}': {}", host, e))?;

    if addrs.is_empty() {
        return Err(format!("DNS resolution for '{}' returned no addresses", host));
    }

    for socket_addr in addrs {
        let ip = socket_addr.ip();
        let blocked = if block_loopback {
            is_blocked_resolved_ip(ip)
        } else {
            is_cloud_metadata_ip(ip)
        };
        if blocked {
            let reason = if block_loopback {
                "cloud-provider metadata services, loopback and link-local addresses are not allowed as target endpoints"
            } else {
                "cloud-provider metadata services are not allowed as target endpoints"
            };
            return Err(format!("URL host '{}' resolves to blocked address '{}': {}", host, ip, reason));
        }
    }

    Ok(parsed)
}

/// Validate a URL and then verify that every address it resolves to is safe.
///
/// Defense-in-depth layer on top of [`validate_url_not_cloud_metadata`] that
/// guards against DNS rebinding attacks: a hostname that passes the static check
/// could still resolve to a blocked address.
///
/// - Runs [`validate_url_not_cloud_metadata`] first; propagates its error unchanged.
/// - Skips DNS resolution for IP literals (already validated statically).
/// - Resolves the hostname via [`std::net::ToSocketAddrs`] (blocking OS call).
/// - Rejects if **any** resolved address is one [`is_blocked_resolved_ip`] lists:
///   cloud metadata, loopback, unspecified or link-local.
/// - DNS failures (NXDOMAIN, timeout, …) are returned as errors.
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
pub fn validate_resolved_url_blocking(raw: &str) -> Result<Url, String> {
    validate_resolved_url_inner_blocking(raw, true)
}

/// Validate a URL and then verify asynchronously that every address it resolves to is safe.
pub async fn validate_resolved_url(raw: &str) -> Result<Url, String> {
    validate_resolved_url_inner(raw, true).await
}

/// Validate a URL and verify that every address it resolves to is not a
/// cloud-provider metadata endpoint.
///
/// Like [`validate_resolved_url`] but intentionally allows loopback and
/// RFC 1918 private ranges. Use this for admin-configured JWKS URIs and other
/// endpoints where same-machine or same-VPC access is legitimate, but DNS
/// rebinding to a cloud metadata endpoint must still be prevented.
///
/// Blocks: cloud metadata IPs/hostnames (static + DNS), embedded credentials,
/// non-http(s) schemes.
/// Allows: loopback, RFC 1918 private ranges.
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
pub fn validate_resolved_cloud_metadata_url_blocking(raw: &str) -> Result<Url, String> {
    validate_resolved_url_inner_blocking(raw, false)
}

/// Validate a URL asynchronously and verify that every address it resolves to is not a cloud-provider metadata endpoint.
pub async fn validate_resolved_cloud_metadata_url(raw: &str) -> Result<Url, String> {
    validate_resolved_url_inner(raw, false).await
}

fn bdd_service_endpoint_allowlist() -> Option<String> {
    #[cfg(test)]
    if let Some(allowlist) = test_service_endpoints::current() {
        return Some(allowlist);
    }
    allowlist_from_env(|name| std::env::var(name).ok())
}

/// The BDD harness's exact loopback allowlist, read from `AS_TEST_MODE=true` and
/// `AS_TEST_SERVICE_ENDPOINT_ALLOWLIST`. Compiled into debug builds only, like
/// the test-auth login, so a release binary cannot have its SSRF protection
/// relaxed by environment variables.
#[cfg(debug_assertions)]
fn allowlist_from_env(var: impl Fn(&str) -> Option<String>) -> Option<String> {
    if var("AS_TEST_MODE").as_deref() != Some("true") {
        return None;
    }
    var("AS_TEST_SERVICE_ENDPOINT_ALLOWLIST").filter(|value| !value.trim().is_empty())
}

#[cfg(not(debug_assertions))]
fn allowlist_from_env(_var: impl Fn(&str) -> Option<String>) -> Option<String> {
    None
}

fn parse_service_endpoint_allowlist_blocking(raw: &str) -> Result<Vec<Url>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(validate_resolved_cloud_metadata_url_blocking)
        .collect()
}

async fn parse_service_endpoint_allowlist(raw: &str) -> Result<Vec<Url>, String> {
    let mut allowed = Vec::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        allowed.push(validate_resolved_cloud_metadata_url(entry).await?);
    }
    Ok(allowed)
}

fn validate_service_endpoint_url_inner_blocking(
    raw: &str,
    exact_allowlist: Option<&str>,
) -> Result<Url, String> {
    match validate_resolved_url_blocking(raw) {
        Ok(url) => Ok(url),
        Err(production_error) => {
            let Some(allowlist_raw) = exact_allowlist else {
                return Err(production_error);
            };
            let candidate = validate_resolved_cloud_metadata_url_blocking(raw)?;
            let allowed = parse_service_endpoint_allowlist_blocking(allowlist_raw)?;
            if allowed
                .iter()
                .any(|entry| entry == &candidate)
            {
                Ok(candidate)
            } else {
                Err(format!(
                    "{}; service endpoint '{}' is not in the BDD exact endpoint allowlist",
                    production_error, candidate
                ))
            }
        }
    }
}

/// Validate an operator-configured service endpoint URL.
///
/// Production behavior matches [`validate_resolved_url`]: cloud metadata,
/// loopback, unspecified and link-local hosts, bad schemes, embedded credentials, and DNS
/// rebinding to blocked addresses are rejected. In debug builds only, BDD
/// real-process tests may set `AS_TEST_MODE=true` with
/// `AS_TEST_SERVICE_ENDPOINT_ALLOWLIST` containing exact loopback endpoint URLs
/// generated by the harness. The allowlist remains exact and still blocks cloud
/// metadata endpoints. Release builds ignore both variables.
pub fn validate_service_endpoint_url_blocking(raw: &str) -> Result<Url, String> {
    validate_service_endpoint_url_inner_blocking(raw, bdd_service_endpoint_allowlist().as_deref())
}

/// Validate an operator-configured service endpoint URL asynchronously.
pub async fn validate_service_endpoint_url(raw: &str) -> Result<Url, String> {
    allow_bdd_service_endpoint(raw, validate_resolved_url(raw).await).await
}

/// Validate a service endpoint whose response is shown to the caller, such as
/// a connection test: the strict webhook rules, so private and link-local
/// ranges are refused as well as loopback and cloud metadata.
pub async fn validate_strict_service_endpoint_url(raw: &str) -> Result<Url, String> {
    allow_bdd_service_endpoint(raw, validate_resolved_webhook_url(raw).await).await
}

/// Keep a production validator's verdict, except that a refused URL passes
/// when BDD test mode lists it exactly (cloud metadata stays blocked).
async fn allow_bdd_service_endpoint(
    raw: &str,
    production: Result<Url, String>,
) -> Result<Url, String> {
    match production {
        Ok(url) => Ok(url),
        Err(production_error) => {
            let Some(allowlist_raw) = bdd_service_endpoint_allowlist() else {
                return Err(production_error);
            };
            let candidate = validate_resolved_cloud_metadata_url(raw).await?;
            let allowed = parse_service_endpoint_allowlist(&allowlist_raw).await?;
            if allowed
                .iter()
                .any(|entry| entry == &candidate)
            {
                Ok(candidate)
            } else {
                Err(format!(
                    "{}; service endpoint '{}' is not in the BDD exact endpoint allowlist",
                    production_error, candidate
                ))
            }
        }
    }
}

/// Defense-in-depth check for the forwarding layer. Only blocks cloud metadata
/// endpoints — does NOT block loopback (channels may legitimately target
/// localhost in dev/test environments).
#[allow(dead_code)]
pub fn reject_cloud_metadata_url(raw: &str) -> Result<(), String> {
    let parsed = match Url::parse(raw) {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };

    if let Some(host) = parsed.host()
        && is_cloud_metadata_host(&host)
    {
        return Err(format!(
            "URL host '{}' is blocked: cloud-provider metadata services \
                 are not allowed as target endpoints",
            host
        ));
    }

    Ok(())
}

/// Returns `true` if the IPv4 address is not a public unicast destination:
/// RFC 1918 private, the full 169.254/16 link-local range, shared address
/// space (100.64/10, used for EKS pod networking and some metadata
/// services), the benchmarking range (198.18/15), and multicast, reserved
/// and broadcast (224/3).
fn is_private_or_link_local_v4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    matches!((a, b), (10, _) | (172, 16..=31) | (192, 168) | (169, 254) | (100, 64..=127) | (198, 18..=19) | (224.., _))
}

/// The IPv4 address an IPv6 address carries and is delivered to: the
/// IPv4-mapped (`::ffff:a.b.c.d`), deprecated IPv4-compatible (`::a.b.c.d`)
/// and NAT64 well-known prefix (`64:ff9b::a.b.c.d`) forms.
fn embedded_ipv4(ip: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return Some(mapped);
    }
    let segments = ip.segments();
    let [high, low] = [segments[6], segments[7]];
    let embedded = std::net::Ipv4Addr::from((u32::from(high) << 16) | u32::from(low));
    match segments[..6] {
        [0x64, 0xff9b, 0, 0, 0, 0] => Some(embedded),
        [0, 0, 0, 0, 0, 0] if !ip.is_loopback() && !ip.is_unspecified() => Some(embedded),
        _ => None,
    }
}

/// Returns `true` if the IPv6 address is in a range that must not be
/// reachable from a webhook-style outbound call:
/// - Unique-local (fc00::/7)
/// - Link-local (fe80::/10)
/// - Multicast (ff00::/8)
/// - Local-use NAT64 (64:ff9b:1::/48)
/// - An IPv4-mapped, IPv4-compatible or NAT64 form of a blocked IPv4 address
fn is_private_or_link_local_v6(ip: std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    if ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_multicast() {
        return true;
    }
    if segments[..3] == [0x64, 0xff9b, 0x1] {
        return true;
    }
    embedded_ipv4(ip).is_some_and(|v4| is_private_or_link_local_v4(v4) || is_blocked_resolved_ip(v4.into()))
}

/// Strict SSRF validator for webhook-style outbound endpoints
/// (marketplace purchase proxy, Slack webhooks, …).
///
/// Rejects everything `validate_url_not_cloud_metadata` rejects, and also
/// blocks all private network ranges that have no legitimate use in an
/// externally-reachable payment / webhook target:
///
/// - RFC 1918 private ranges (10/8, 172.16/12, 192.168/16)
/// - Full IPv4 link-local (169.254/16, including metadata IPs)
/// - Shared address space (100.64/10) and benchmarking (198.18/15)
/// - IPv4 multicast, reserved and broadcast (224/3)
/// - IPv6 unique-local (fc00::/7), link-local (fe80::/10) and multicast (ff00::/8)
/// - IPv4-mapped, IPv4-compatible and NAT64 (64:ff9b::/96) forms of any
///   blocked IPv4 address, and local-use NAT64 (64:ff9b:1::/48)
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
pub fn validate_webhook_url(raw: &str) -> Result<Url, String> {
    check_webhook_url(raw).map_err(String::from)
}

/// [`validate_webhook_url`], telling a value that is not an http or https URL
/// from one the policy refuses.
pub(crate) fn check_webhook_url(raw: &str) -> Result<Url, UrlRefusal> {
    // Run the base check first (cloud metadata + loopback + scheme + credentials)
    let parsed = check_url_not_cloud_metadata(raw)?;

    let host = parsed.host().unwrap(); // safe: check_url_not_cloud_metadata verified host exists

    let blocked = match &host {
        Host::Ipv4(ip) => is_private_or_link_local_v4(*ip),
        Host::Ipv6(ip) => is_private_or_link_local_v6(*ip),
        Host::Domain(_) => false,
    };

    if blocked {
        return Err(UrlRefusal::Refused(format!(
            "URL host '{}' is blocked: private and link-local addresses \
             are not allowed as webhook or payment proxy endpoints",
            host
        )));
    }

    Ok(parsed)
}

/// Returns `true` if the resolved `IpAddr` must be blocked for a webhook target.
///
/// Combines the base block-list of [`is_blocked_resolved_ip`] (cloud metadata,
/// loopback, unspecified, link-local) with the ranges [`validate_webhook_url`]
/// lists, which have no legitimate use for externally-reachable webhook endpoints.
pub(crate) fn is_blocked_resolved_webhook_ip(ip: std::net::IpAddr) -> bool {
    if is_blocked_resolved_ip(ip) {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => is_private_or_link_local_v4(v4),
        std::net::IpAddr::V6(v6) => is_private_or_link_local_v6(v6),
    }
}

/// DNS-aware strict SSRF validator for webhook-style outbound endpoints.
///
/// Combines [`validate_webhook_url`] (static checks) with DNS resolution,
/// closing the gap where a domain passes static checks but resolves to a
/// private or cloud-metadata address (DNS rebinding / split-horizon attack).
///
/// Blocks everything [`validate_webhook_url`] blocks, plus any domain that
/// resolves to:
/// - Cloud metadata IPs / hostnames
/// - Loopback / unspecified addresses
/// - Any range [`validate_webhook_url`] blocks
///
/// DNS failures (NXDOMAIN, timeout, empty response) are returned as errors.
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
pub fn validate_resolved_webhook_url_blocking(raw: &str) -> Result<Url, String> {
    // Static checks first (IP literals, scheme, credentials, private ranges).
    let parsed = validate_webhook_url(raw)?;

    // IP literals were fully validated statically — no DNS needed.
    if matches!(parsed.host(), Some(Host::Ipv4(_) | Host::Ipv6(_))) {
        return Ok(parsed);
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must include a host".to_string())?;
    let port = parsed
        .port_or_known_default()
        .unwrap_or(80);

    let addrs = resolve_host_blocking(host, port)?;

    if addrs.is_empty() {
        return Err(format!("DNS resolution for '{}' returned no addresses", host));
    }

    for socket_addr in addrs {
        let ip = socket_addr.ip();
        if is_blocked_resolved_webhook_ip(ip) {
            return Err(format!(
                "URL host '{}' resolves to blocked address '{}': private, link-local, and \
                 cloud-provider metadata addresses are not allowed as webhook endpoints",
                host, ip
            ));
        }
    }

    Ok(parsed)
}

/// DNS-aware strict SSRF validator for webhook-style outbound endpoints.
pub async fn validate_resolved_webhook_url(raw: &str) -> Result<Url, String> {
    check_resolved_webhook_url(raw)
        .await
        .map_err(String::from)
}

/// [`validate_resolved_webhook_url`], telling a value that is not an http or
/// https URL from one the policy refuses.
pub(crate) async fn check_resolved_webhook_url(raw: &str) -> Result<Url, UrlRefusal> {
    let parsed = check_webhook_url(raw)?;

    if matches!(parsed.host(), Some(Host::Ipv4(_) | Host::Ipv6(_))) {
        return Ok(parsed);
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| UrlRefusal::NotHttpUrl("URL must include a host".to_string()))?;
    let port = parsed
        .port_or_known_default()
        .unwrap_or(80);

    let addrs = lookup_host(host, port)
        .await
        .map_err(|e| UrlRefusal::Refused(format!("DNS resolution failed for '{}': {}", host, e)))?;

    if addrs.is_empty() {
        return Err(UrlRefusal::Refused(format!("DNS resolution for '{}' returned no addresses", host)));
    }

    for socket_addr in addrs {
        let ip = socket_addr.ip();
        if is_blocked_resolved_webhook_ip(ip) {
            return Err(UrlRefusal::Refused(format!(
                "URL host '{}' resolves to blocked address '{}': private, link-local, and \
                 cloud-provider metadata addresses are not allowed as webhook endpoints",
                host, ip
            )));
        }
    }

    Ok(parsed)
}

/// Parse the bare host of a destination dialled without a URL (an SMTP
/// server, a Kafka broker): an IP address, a bracketed IPv6 address or a domain
/// name, with no port, userinfo, path or surrounding whitespace. A domain name
/// must already be in its ASCII form (no percent-encoding or Unicode), so the
/// name checked is the name the client later resolves.
pub(crate) fn parse_host(raw: &str) -> Result<Host<String>, String> {
    if raw.is_empty() || raw.trim() != raw {
        return Err("host must be a name or address without surrounding whitespace".to_string());
    }
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        return Ok(match ip {
            std::net::IpAddr::V4(v4) => Host::Ipv4(v4),
            std::net::IpAddr::V6(v6) => Host::Ipv6(v6),
        });
    }
    match Host::parse(raw).map_err(|e| format!("invalid host '{raw}': {e}"))? {
        Host::Domain(domain) if !domain.eq_ignore_ascii_case(raw) => {
            Err(format!("host '{raw}' must be written in its ASCII form, '{domain}'"))
        }
        parsed => Ok(parsed),
    }
}

/// Resolve `host` under the strict webhook policy and return every address it
/// resolved to, all of them checked: loopback, unspecified, private, link-local
/// and cloud metadata addresses are refused, as is a host that does not resolve.
/// Callers dial the returned addresses where their client allows it, so a later
/// DNS answer cannot move the connection. A host and port on the test-mode
/// service endpoint allowlist may be loopback or private; cloud metadata stays
/// blocked for it.
pub async fn resolve_public_host(
    host: &Host<String>,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, String> {
    let addresses: Vec<std::net::SocketAddr> = match host {
        Host::Ipv4(ip) => vec![std::net::SocketAddr::new((*ip).into(), port)],
        Host::Ipv6(ip) => vec![std::net::SocketAddr::new((*ip).into(), port)],
        Host::Domain(domain) => {
            if is_cloud_metadata_hostname(domain) {
                return Err(format!("host '{domain}' is a cloud-provider metadata service"));
            }
            tokio::net::lookup_host((domain.as_str(), port))
                .await
                .map_err(|e| format!("DNS resolution failed for '{domain}': {e}"))?
                .collect()
        }
    };
    if addresses.is_empty() {
        return Err(format!("DNS resolution for '{host}' returned no addresses"));
    }
    let allowlisted = is_allowlisted_service_endpoint(host, port);
    if let Some(blocked) = addresses
        .iter()
        .find(|address| {
            if allowlisted {
                is_cloud_metadata_ip(address.ip())
            } else {
                is_blocked_resolved_webhook_ip(address.ip())
            }
        })
    {
        return Err(format!("host '{host}' resolves to blocked address '{}'", blocked.ip()));
    }
    Ok(addresses)
}

/// Whether `host` and `port` match an entry of the test-mode service endpoint
/// allowlist; the entry's scheme and path are ignored.
fn is_allowlisted_service_endpoint(
    host: &Host<String>,
    port: u16,
) -> bool {
    bdd_service_endpoint_allowlist().is_some_and(|allowlist| {
        allowlist
            .split(',')
            .filter_map(|entry| Url::parse(entry.trim()).ok())
            .any(|url| {
                url.host()
                    .is_some_and(|allowed| &allowed.to_owned() == host)
                    && url.port_or_known_default() == Some(port)
            })
    })
}

/// Unit-test counterpart of the BDD `AS_TEST_SERVICE_ENDPOINT_ALLOWLIST`:
/// lets a test on the current thread reach its own loopback capture servers
/// through the real send paths. The same exact-URL allowlist applies (cloud
/// metadata stays blocked), it is per thread so parallel tests and
/// environment-reading tests are unaffected, and it is compiled into test
/// builds only.
#[cfg(test)]
pub(crate) mod test_service_endpoints {
    use std::cell::RefCell;

    thread_local! {
        static ALLOWLIST: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    pub(super) fn current() -> Option<String> {
        ALLOWLIST.with(|allowlist| allowlist.borrow().clone())
    }

    /// Restores the previous allowlist when dropped.
    pub(crate) struct Allowed(Option<String>);

    impl Drop for Allowed {
        fn drop(&mut self) {
            let previous = self.0.take();
            ALLOWLIST.with(|allowlist| *allowlist.borrow_mut() = previous);
        }
    }

    /// Allow exactly these service endpoint URLs on this thread until the
    /// returned guard drops. Async tests using it must run on a
    /// current-thread runtime (the `#[tokio::test]` default).
    pub(crate) fn allow(urls: &[String]) -> Allowed {
        let previous = ALLOWLIST.with(|allowlist| allowlist.replace(Some(urls.join(","))));
        Allowed(previous)
    }
}

/// Test-only DNS answers for the pre-request URL check and the connect-time
/// resolvers, so a test can rebind a host between the two: the first lookup
/// gets the first answer, each later one the next, and the last repeats. Per
/// thread, like [`test_service_endpoints`], and compiled into test builds only.
#[cfg(test)]
pub(crate) mod test_dns {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};

    thread_local! {
        static HOSTS: RefCell<HashMap<String, Answers>> = RefCell::new(HashMap::new());
    }

    struct Answers {
        addresses: Vec<IpAddr>,
        lookups: usize,
    }

    pub(super) fn lookup(
        host: &str,
        port: u16,
    ) -> Option<Vec<SocketAddr>> {
        HOSTS.with(|hosts| {
            let mut hosts = hosts.borrow_mut();
            let answers = hosts.get_mut(host)?;
            let address = answers.addresses[answers
                .lookups
                .min(answers.addresses.len() - 1)];
            answers.lookups += 1;
            Some(vec![SocketAddr::new(address, port)])
        })
    }

    /// Removes the host's answers when dropped.
    pub(crate) struct Answered(String);

    impl Answered {
        /// How many lookups of the host were answered so far.
        pub(crate) fn lookups(&self) -> usize {
            HOSTS.with(|hosts| {
                hosts
                    .borrow()
                    .get(&self.0)
                    .map_or(0, |answers| answers.lookups)
            })
        }
    }

    impl Drop for Answered {
        fn drop(&mut self) {
            HOSTS.with(|hosts| {
                hosts
                    .borrow_mut()
                    .remove(&self.0)
            });
        }
    }

    /// Answer lookups of `host` on this thread with `addresses` in order.
    /// Async tests using it must run on a current-thread runtime.
    pub(crate) fn answer(
        host: &str,
        addresses: &[IpAddr],
    ) -> Answered {
        assert!(!addresses.is_empty(), "a test DNS host needs at least one answer");
        HOSTS.with(|hosts| {
            hosts.borrow_mut().insert(
                host.to_string(),
                Answers {
                    addresses: addresses.to_vec(),
                    lookups: 0,
                },
            )
        });
        Answered(host.to_string())
    }

    /// A public address answered at the URL check, then loopback for every
    /// later lookup: a DNS-rebinding host.
    pub(crate) fn rebind_to_loopback(host: &str) -> Answered {
        answer(host, &[IpAddr::from([93, 184, 215, 14]), IpAddr::from([127, 0, 0, 1])])
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_scheme_is_left_out_of_the_error() {
        let refused = validate_webhook_url("admin:hunter2").unwrap_err();

        assert_eq!(refused, "URL scheme must be http or https");
    }

    #[test]
    fn a_webhook_check_tells_a_value_that_is_not_an_http_url_from_a_refused_one() {
        for accepted in ["https://hooks.example.com/in", "http://198.51.100.1:8080/in?token=t", " https://h.example "] {
            assert!(check_webhook_url(accepted).is_ok(), "{accepted}");
        }
        for not_a_url in
            ["admin:hunter2", "global-token", "", "ftp://files.example.com/in", "redis://cache:6379", "https://"]
        {
            assert!(matches!(check_webhook_url(not_a_url), Err(UrlRefusal::NotHttpUrl(_))), "{not_a_url}");
        }
        for refused in ["http://10.0.0.5/in", "http://user:pw@hooks.example.com/in", "http://169.254.169.254/"] {
            assert!(matches!(check_webhook_url(refused), Err(UrlRefusal::Refused(_))), "{refused}");
        }
    }

    #[tokio::test]
    async fn a_url_that_does_not_parse_is_left_out_of_the_error() {
        let token_url = "hooks.slack.com/services/T000/B000/secret-token";

        let errors = [
            validate_url_not_cloud_metadata(token_url).unwrap_err(),
            validate_resolved_url_inner_blocking(token_url, false).unwrap_err(),
            validate_resolved_url_inner(token_url, false)
                .await
                .unwrap_err(),
        ];

        for error in errors {
            assert!(error.starts_with("Invalid URL"), "{error}");
            assert!(!error.contains("secret-token"), "{error}");
        }
    }

    #[test]
    fn webhook_host_names_only_the_host() {
        assert_eq!(webhook_host("https://user:pw@hooks.slack.com/services/T/B/X?token=1"), "hooks.slack.com");
        assert_eq!(webhook_host("not a url"), "<invalid-url>");
    }

    // ── helpers ──────────────────────────────────────────────────────────

    fn must_block(url: &str) {
        let result = validate_url_not_cloud_metadata(url);
        assert!(result.is_err(), "Expected '{}' to be blocked, but it was allowed", url);
    }

    fn must_allow(url: &str) {
        let result = validate_url_not_cloud_metadata(url);
        assert!(result.is_ok(), "Expected '{}' to be allowed, but got error: {}", url, result.unwrap_err());
    }

    fn test_env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    const ALLOWLIST: &str = "http://127.0.0.1:9000/v1/chat/completions";

    #[cfg(debug_assertions)]
    #[test]
    fn a_debug_build_reads_the_allowlist_only_in_test_mode() {
        assert_eq!(
            allowlist_from_env(test_env(&[
                ("AS_TEST_MODE", "true"),
                ("AS_TEST_SERVICE_ENDPOINT_ALLOWLIST", ALLOWLIST)
            ])),
            Some(ALLOWLIST.to_string())
        );
        assert_eq!(allowlist_from_env(test_env(&[("AS_TEST_SERVICE_ENDPOINT_ALLOWLIST", ALLOWLIST)])), None);
        assert_eq!(
            allowlist_from_env(test_env(&[("AS_TEST_MODE", "1"), ("AS_TEST_SERVICE_ENDPOINT_ALLOWLIST", ALLOWLIST)])),
            None
        );
        assert_eq!(
            allowlist_from_env(test_env(&[("AS_TEST_MODE", "true"), ("AS_TEST_SERVICE_ENDPOINT_ALLOWLIST", "  ")])),
            None
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn a_release_build_ignores_the_test_mode_allowlist() {
        assert_eq!(
            allowlist_from_env(test_env(&[
                ("AS_TEST_MODE", "true"),
                ("AS_TEST_SERVICE_ENDPOINT_ALLOWLIST", ALLOWLIST)
            ])),
            None
        );
    }

    #[test]
    fn a_host_saved_as_a_public_provider_address_must_stay_public_at_dial_time() {
        let public = "93.184.216.34:443"
            .parse()
            .unwrap();
        let private = "10.0.0.5:443"
            .parse()
            .unwrap();
        let link_local = "169.254.10.1:443"
            .parse()
            .unwrap();

        assert!(validate_service_endpoint_addresses_for("llm.example.com", &[public], true).is_ok());
        for rebound in [private, link_local] {
            let refused = validate_service_endpoint_addresses_for("llm.example.com", &[public, rebound], true);
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|reason| reason.contains("llm.example.com")),
                "{rebound}: {refused:?}"
            );
        }
        // A host no checked catalog URL names keeps the same-VPC allowance.
        assert!(validate_service_endpoint_addresses_for("vllm.internal", &[private], false).is_ok());
    }

    #[test]
    fn service_dns_policy_fails_closed_on_any_blocked_address() {
        let public = "93.184.216.34:0"
            .parse()
            .unwrap();
        let private = "10.0.0.1:0".parse().unwrap();
        let loopback = "127.0.0.1:0".parse().unwrap();
        let metadata = "169.254.169.254:0"
            .parse()
            .unwrap();
        let eks_pod_identity = "169.254.170.23:0"
            .parse()
            .unwrap();
        let link_local = "169.254.10.1:0"
            .parse()
            .unwrap();
        let link_local_v6 = "[fe80::1]:0".parse().unwrap();
        let mapped_link_local = "[::ffff:169.254.10.1]:0"
            .parse()
            .unwrap();

        assert!(validate_service_dns_addresses(&[public, private], false).is_ok());
        assert!(validate_service_dns_addresses(&[public, loopback], false).is_err());
        assert!(validate_service_dns_addresses(&[loopback], true).is_ok());
        assert!(validate_service_dns_addresses(&[metadata], true).is_err());
        for blocked in [eks_pod_identity, link_local, link_local_v6, mapped_link_local] {
            assert!(validate_service_dns_addresses(&[public, blocked], true).is_err(), "{blocked}");
        }
        assert!(validate_service_dns_addresses(&[], false).is_err());
    }

    #[test]
    fn forwarding_dns_policy_blocks_only_metadata_addresses() {
        let public = "93.184.216.34:0"
            .parse()
            .unwrap();
        let private = "10.0.0.1:0".parse().unwrap();
        let loopback = "127.0.0.1:0".parse().unwrap();
        let loopback_v6 = "[::1]:0".parse().unwrap();
        let metadata = "169.254.169.254:0"
            .parse()
            .unwrap();
        let mapped_metadata = "[::ffff:169.254.169.254]:0"
            .parse()
            .unwrap();

        assert!(validate_forwarding_dns_addresses(&[public, private, loopback, loopback_v6]).is_ok());
        assert!(validate_forwarding_dns_addresses(&[loopback, metadata]).is_err());
        assert!(validate_forwarding_dns_addresses(&[mapped_metadata]).is_err());
        assert!(
            validate_forwarding_dns_addresses(&["169.254.170.23:0"
                .parse()
                .unwrap()])
            .is_err()
        );
        assert!(validate_forwarding_dns_addresses(&[]).is_err());
    }

    #[tokio::test]
    async fn forwarding_resolver_resolves_localhost() {
        use reqwest::dns::Resolve;
        use std::str::FromStr;

        let addresses: Vec<_> = ForwardingDnsResolver
            .resolve(reqwest::dns::Name::from_str("localhost").unwrap())
            .await
            .expect("localhost must resolve for forwarding targets")
            .collect();
        assert!(
            addresses
                .iter()
                .all(|address| address.ip().is_loopback())
        );
    }

    #[test]
    fn redacts_url_credentials_query_and_fragment_for_logs() {
        assert_eq!(
            redact_url_for_logging("https://user:pass@example.com/path?token=secret#frag"),
            "https://example.com/path"
        );
        assert_eq!(redact_url_for_logging("not a url?token=secret"), "<invalid-url>");
    }

    // ── Cloud metadata IPs ──────────────────────────────────────────────

    #[test]
    fn blocks_aws_metadata_ip() {
        must_block("http://169.254.169.254/latest/meta-data/");
        must_block("https://169.254.169.254/");
        must_block("http://169.254.169.254:80/");
    }

    #[test]
    fn blocks_aws_ecs_metadata_ip() {
        must_block("http://169.254.170.2/v2/credentials/uid");
    }

    #[test]
    fn blocks_oracle_cloud_metadata_ip() {
        must_block("http://192.0.0.192/latest/");
        must_block("http://192.0.0.192/latest/meta-data/");
    }

    #[test]
    fn blocks_alibaba_cloud_metadata_ip() {
        must_block("http://100.100.100.200/latest/meta-data/");
        must_block("http://100.100.100.200/latest/meta-data/instance-id");
    }

    #[test]
    fn blocks_aws_ipv6_metadata() {
        must_block("http://[fd00:ec2::254]/latest/meta-data/");
    }

    // ── Cloud metadata hostnames ────────────────────────────────────────

    #[test]
    fn blocks_gcp_metadata_hostname() {
        must_block("http://metadata.google.internal/computeMetadata/v1/");
        must_block("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token");
    }

    #[test]
    fn blocks_gcp_metadata_short_hostname() {
        must_block("http://metadata/computeMetadata/v1/");
    }

    #[test]
    fn blocks_gcp_metadata_case_insensitive() {
        must_block("http://Metadata.Google.Internal/computeMetadata/v1/");
        must_block("http://METADATA/computeMetadata/v1/");
    }

    // ── Loopback / unspecified ──────────────────────────────────────────

    #[test]
    fn blocks_localhost() {
        must_block("http://localhost/");
        must_block("http://localhost:8080/api");
        must_block("http://sub.localhost/");
    }

    #[test]
    fn blocks_ipv4_loopback() {
        must_block("http://127.0.0.1/");
        must_block("http://127.0.0.1:3000/");
        must_block("http://127.255.255.255/");
    }

    #[test]
    fn blocks_ipv6_loopback() {
        must_block("http://[::1]/");
        must_block("http://[::1]:8080/");
    }

    #[test]
    fn blocks_unspecified() {
        must_block("http://0.0.0.0/");
        must_block("http://[::]/");
    }

    // ── IPv4-mapped IPv6 ────────────────────────────────────────────────

    #[test]
    fn blocks_ipv4_mapped_metadata() {
        must_block("http://[::ffff:169.254.169.254]/");
        must_block("http://[::ffff:127.0.0.1]/");
        must_block("http://[::ffff:192.0.0.192]/");
        must_block("http://[::ffff:100.100.100.200]/");
    }

    // ── Numeric obfuscation (url crate normalizes to dotted-decimal) ───

    #[test]
    fn blocks_decimal_integer_metadata_ip() {
        // 169.254.169.254 == 2852039166 in decimal
        // The `url` crate parses http://2852039166/ as http://169.254.169.254/
        must_block("http://2852039166/latest/meta-data/");
    }

    #[test]
    fn blocks_hex_metadata_ip() {
        // 169.254.169.254 == 0xa9fea9fe
        must_block("http://0xa9fea9fe/latest/meta-data/");
    }

    #[test]
    fn blocks_octal_metadata_ip() {
        // 169.254.169.254 in octal = 0251.0376.0251.0376
        must_block("http://0251.0376.0251.0376/");
    }

    #[test]
    fn blocks_decimal_loopback() {
        // 127.0.0.1 == 2130706433
        must_block("http://2130706433/");
    }

    // ── Private RFC 1918 IPs MUST pass ──────────────────────────────────

    #[test]
    fn allows_rfc1918_class_a() {
        must_allow("http://10.0.1.5/api/v1/agent");
        must_allow("http://10.255.255.255:8080/");
    }

    #[test]
    fn allows_rfc1918_class_b() {
        must_allow("http://172.16.0.1/");
        must_allow("http://172.20.0.1:3000/");
        must_allow("http://172.31.255.255/");
    }

    #[test]
    fn allows_rfc1918_class_c() {
        must_allow("http://192.168.1.1/");
        must_allow("http://192.168.0.100:443/");
    }

    // ── Public URLs MUST pass ───────────────────────────────────────────

    #[test]
    fn allows_public_urls() {
        must_allow("https://api.example.com/v1/agent");
        must_allow("http://my-agent.internal.company.io:8080/");
        must_allow("https://1.2.3.4/api");
    }

    #[test]
    fn allows_http_scheme() {
        must_allow("http://agent.vpc.local:8000/");
    }

    // ── Embedded credentials blocked ────────────────────────────────────

    #[test]
    fn blocks_embedded_credentials() {
        must_block("http://user:pass@example.com/");
        must_block("https://admin:secret@10.0.0.1/");
    }

    // ── Misc edge cases ─────────────────────────────────────────────────

    #[test]
    fn rejects_empty_url() {
        must_block("");
        must_block("   ");
    }

    #[test]
    fn rejects_non_http_schemes() {
        must_block("ftp://example.com/");
        must_block("file:///etc/passwd");
        must_block("gopher://evil.com/");
    }

    #[test]
    fn blocks_link_local_and_eks_pod_identity() {
        must_block("http://169.254.1.1/");
        must_block("http://169.254.170.23/v1/credentials");
        must_block("http://[fd00:ec2::23]/v1/credentials");
        must_block("http://[fe80::1]/");
        must_block("http://[::ffff:169.254.1.1]/");
    }

    #[test]
    fn service_endpoint_allows_private_and_refuses_link_local() {
        assert!(validate_service_endpoint_url_inner_blocking("http://10.0.0.5/v1/chat/completions", None).is_ok());
        assert!(
            validate_service_endpoint_url_inner_blocking("http://192.168.1.10:11434/v1/chat/completions", None).is_ok()
        );
        for raw in [
            "http://169.254.10.1/v1/chat/completions",
            "http://169.254.170.23/v1/credentials",
            "http://[fe80::1]/v1/chat/completions",
        ] {
            assert!(validate_service_endpoint_url_inner_blocking(raw, None).is_err(), "{raw} should be refused");
        }
    }

    #[test]
    fn service_endpoint_refuses_nat64_and_ipv4_compatible_forms_of_host_local_addresses() {
        for raw in [
            "http://[64:ff9b::a9fe:aa17]/v1/credentials",
            "http://[64:ff9b::169.254.10.1]/v1/chat/completions",
            "http://[64:ff9b::a9fe:a9fe]/latest/meta-data/",
            "http://[64:ff9b::127.0.0.1]/v1/chat/completions",
            "http://[::169.254.10.1]/v1/chat/completions",
        ] {
            assert!(validate_service_endpoint_url_inner_blocking(raw, None).is_err(), "{raw} should be refused");
        }
        for blocked in ["64:ff9b::a9fe:aa17", "64:ff9b::7f00:1", "::a9fe:a01"] {
            assert!(is_blocked_resolved_ip(blocked.parse().unwrap()), "{blocked} should be refused");
        }
        assert!(
            validate_service_endpoint_url_inner_blocking("http://[64:ff9b::10.0.0.5]/v1/chat/completions", None)
                .is_ok()
        );
        assert!(!is_blocked_resolved_ip(
            "64:ff9b::102:304"
                .parse()
                .unwrap()
        ));
    }

    #[test]
    fn forwarding_dns_policy_blocks_nat64_form_of_metadata() {
        let nat64_metadata = "[64:ff9b::a9fe:a9fe]:0"
            .parse()
            .unwrap();
        let nat64_loopback = "[64:ff9b::7f00:1]:0"
            .parse()
            .unwrap();
        assert!(validate_forwarding_dns_addresses(&[nat64_metadata]).is_err());
        assert!(validate_forwarding_dns_addresses(&[nat64_loopback]).is_ok());
    }

    #[test]
    fn service_endpoint_blocks_loopback_by_default() {
        let result = validate_service_endpoint_url_inner_blocking("http://127.0.0.1:8080/token", None);
        assert!(result.is_err(), "expected service endpoint loopback URL to be blocked by default");
    }

    #[test]
    fn service_endpoint_allows_exact_bdd_allowlist_match() {
        let result = validate_service_endpoint_url_inner_blocking(
            "http://127.0.0.1:8080/token",
            Some("http://127.0.0.1:8080/authorize,http://127.0.0.1:8080/token"),
        );
        assert!(result.is_ok(), "expected exact BDD service endpoint URL to be allowed: {result:?}");
    }

    #[test]
    fn service_endpoint_rejects_loopback_not_in_exact_bdd_allowlist() {
        let result = validate_service_endpoint_url_inner_blocking(
            "http://127.0.0.1:8081/token",
            Some("http://127.0.0.1:8080/authorize,http://127.0.0.1:8080/token"),
        );
        assert!(result.is_err(), "expected non-allowlisted service endpoint URL to be blocked");
    }

    #[test]
    fn service_endpoint_still_blocks_cloud_metadata_for_bdd_allowlist() {
        let result = validate_service_endpoint_url_inner_blocking(
            "http://169.254.169.254/latest/meta-data/",
            Some("http://169.254.169.254/latest/meta-data/"),
        );
        assert!(result.is_err(), "expected BDD service endpoint cloud metadata URL to stay blocked");
    }

    // ── Forwarding layer (reject_cloud_metadata_url) ────────────────────

    fn forwarding_must_block(url: &str) {
        let result = reject_cloud_metadata_url(url);
        assert!(result.is_err(), "Expected '{}' to be blocked at forwarding, but it was allowed", url);
    }

    fn forwarding_must_allow(url: &str) {
        let result = reject_cloud_metadata_url(url);
        assert!(
            result.is_ok(),
            "Expected '{}' to be allowed at forwarding, but got error: {}",
            url,
            result.unwrap_err()
        );
    }

    #[test]
    fn forwarding_blocks_metadata_ips() {
        forwarding_must_block("http://169.254.169.254/latest/meta-data/");
        forwarding_must_block("http://192.0.0.192/latest/");
        forwarding_must_block("http://100.100.100.200/latest/meta-data/");
        forwarding_must_block("http://metadata.google.internal/computeMetadata/v1/");
        forwarding_must_block("http://[fd00:ec2::254]/latest/meta-data/");
    }

    #[test]
    fn forwarding_allows_localhost() {
        forwarding_must_allow("http://127.0.0.1:8080/sse");
        forwarding_must_allow("http://localhost:3000/api");
        forwarding_must_allow("http://[::1]:8080/");
    }

    #[test]
    fn forwarding_allows_private_ips() {
        forwarding_must_allow("http://10.0.1.5/api");
        forwarding_must_allow("http://192.168.1.1:8080/");
    }

    // ── Trailing-dot FQDN bypass ────────────────────────────────────────

    #[test]
    fn blocks_trailing_dot_metadata_hostname() {
        must_block("http://metadata.google.internal./computeMetadata/v1/");
        must_block("http://metadata./computeMetadata/v1/");
        must_block("http://Metadata.Google.Internal./computeMetadata/v1/");
    }

    #[test]
    fn blocks_trailing_dot_localhost() {
        must_block("http://localhost./");
        must_block("http://LOCALHOST./");
        must_block("http://sub.localhost./");
    }

    #[test]
    fn forwarding_blocks_trailing_dot_metadata() {
        forwarding_must_block("http://metadata.google.internal./computeMetadata/v1/");
        forwarding_must_block("http://metadata./computeMetadata/v1/");
        forwarding_must_block("http://Metadata.Google.Internal./");
    }

    // ── validate_webhook_url ─────────────────────────────────────────────────

    fn webhook_must_block(url: &str) {
        let result = validate_webhook_url(url);
        assert!(result.is_err(), "Expected webhook '{}' to be blocked, but it was allowed", url);
    }

    fn webhook_must_allow(url: &str) {
        let result = validate_webhook_url(url);
        assert!(result.is_ok(), "Expected webhook '{}' to be allowed, but got error: {}", url, result.unwrap_err());
    }

    #[test]
    fn webhook_blocks_rfc1918_class_a() {
        webhook_must_block("http://10.0.0.1/pay");
        webhook_must_block("http://10.255.255.255:8080/api");
    }

    #[test]
    fn webhook_blocks_rfc1918_class_b() {
        webhook_must_block("http://172.16.0.1/pay");
        webhook_must_block("http://172.31.255.255/api");
    }

    #[test]
    fn webhook_blocks_rfc1918_class_c() {
        webhook_must_block("http://192.168.1.100/pay");
        webhook_must_block("http://192.168.0.1:443/");
    }

    #[test]
    fn webhook_blocks_full_link_local_range() {
        webhook_must_block("http://169.254.1.1/");
        webhook_must_block("http://169.254.169.254/latest/meta-data/");
        webhook_must_block("http://169.254.170.2/v2/credentials/");
    }

    #[test]
    fn webhook_blocks_ipv6_unique_local() {
        webhook_must_block("http://[fc00::1]/pay");
        webhook_must_block("http://[fd12:3456:789a::1]/pay");
    }

    #[test]
    fn webhook_blocks_ipv6_link_local() {
        webhook_must_block("http://[fe80::1]/pay");
        webhook_must_block("http://[fe80::1%2512]/pay");
    }

    #[test]
    fn webhook_blocks_loopback_and_metadata() {
        webhook_must_block("http://127.0.0.1/pay");
        webhook_must_block("http://localhost/pay");
        webhook_must_block("http://169.254.169.254/latest/meta-data/");
    }

    #[test]
    fn webhook_blocks_embedded_credentials() {
        webhook_must_block("http://user:pass@payments.example.com/");
    }

    #[test]
    fn webhook_blocks_non_http_schemes() {
        webhook_must_block("file:///etc/passwd");
        webhook_must_block("ftp://example.com/");
    }

    #[test]
    fn webhook_inherits_base_blocks() {
        webhook_must_block("http://169.254.169.254/latest/meta-data/");
        webhook_must_block("http://127.0.0.1/");
        webhook_must_block("http://localhost/");
        webhook_must_block("http://0.0.0.0/");
        webhook_must_block("file:///etc/passwd");
        webhook_must_block("http://user:pass@example.com/");
    }

    #[test]
    fn webhook_allows_public_urls() {
        webhook_must_allow("https://api.payments.example.com/v1/pay");
        webhook_must_allow("http://1.2.3.4/api");
        webhook_must_allow("https://payments.example.com/webhook");
        webhook_must_allow("https://hooks.slack.com/services/T00/B00/xxx");
        webhook_must_allow("http://my-webhook.example.com/hook");
    }

    #[test]
    fn webhook_blocks_shared_benchmark_multicast_and_broadcast_ranges() {
        webhook_must_block("http://100.64.0.1/hook");
        webhook_must_block("http://100.127.255.254/hook");
        webhook_must_block("http://100.100.100.200/latest/meta-data/");
        webhook_must_block("http://198.18.0.1/hook");
        webhook_must_block("http://198.19.255.255/hook");
        webhook_must_block("http://224.0.0.1/hook");
        webhook_must_block("http://240.0.0.1/hook");
        webhook_must_block("http://255.255.255.255/hook");
        webhook_must_block("http://[ff02::1]/hook");
    }

    #[test]
    fn webhook_allows_public_neighbours_of_blocked_ranges() {
        webhook_must_allow("http://100.63.255.255/hook");
        webhook_must_allow("http://100.128.0.1/hook");
        webhook_must_allow("http://198.17.255.255/hook");
        webhook_must_allow("http://198.20.0.1/hook");
        webhook_must_allow("http://223.255.255.254/hook");
    }

    #[test]
    fn webhook_blocks_nat64_and_ipv4_compatible_forms_of_internal_addresses() {
        webhook_must_block("http://[64:ff9b::a00:5]/hook");
        webhook_must_block("http://[64:ff9b::10.0.0.5]/hook");
        webhook_must_block("http://[64:ff9b::169.254.169.254]/latest/meta-data/");
        webhook_must_block("http://[64:ff9b::127.0.0.1]/hook");
        webhook_must_block("http://[64:ff9b::100.64.0.1]/hook");
        webhook_must_block("http://[64:ff9b:1::1.2.3.4]/hook");
        webhook_must_block("http://[::10.0.0.5]/hook");
        webhook_must_block("http://[::169.254.169.254]/hook");
    }

    #[test]
    fn webhook_allows_nat64_form_of_a_public_address() {
        webhook_must_allow("http://[64:ff9b::1.2.3.4]/hook");
    }

    #[test]
    fn resolved_webhook_ip_check_covers_new_ranges() {
        for blocked in ["100.64.0.1", "198.18.0.1", "255.255.255.255", "64:ff9b::a00:5", "::a00:5", "ff02::1"] {
            let ip: std::net::IpAddr = blocked.parse().unwrap();
            assert!(is_blocked_resolved_webhook_ip(ip), "{blocked} should be blocked");
        }
        for allowed in ["1.2.3.4", "64:ff9b::102:304", "2606:4700::1111"] {
            let ip: std::net::IpAddr = allowed.parse().unwrap();
            assert!(!is_blocked_resolved_webhook_ip(ip), "{allowed} should be allowed");
        }
    }

    #[test]
    fn webhook_blocks_ipv4_mapped_private() {
        webhook_must_block("http://[::ffff:10.0.0.1]/hook");
        webhook_must_block("http://[::ffff:192.168.1.1]/hook");
        webhook_must_block("http://[::ffff:172.16.0.1]/hook");
    }

    // ── validate_resolved_webhook_url ────────────────────────────────────────

    fn resolved_webhook_must_block(url: &str) {
        let result = validate_resolved_webhook_url_blocking(url);
        assert!(result.is_err(), "Expected resolved-webhook '{}' to be blocked, but it was allowed", url);
    }

    fn resolved_webhook_must_allow(url: &str) {
        let result = validate_resolved_webhook_url_blocking(url);
        assert!(
            result.is_ok(),
            "Expected resolved-webhook '{}' to be allowed, but got error: {}",
            url,
            result.unwrap_err()
        );
    }

    #[test]
    fn resolved_webhook_blocks_ip_literal_metadata() {
        resolved_webhook_must_block("http://169.254.169.254/latest/meta-data/");
        resolved_webhook_must_block("http://[fd00:ec2::254]/latest/meta-data/");
    }

    #[test]
    fn resolved_webhook_blocks_ip_literal_loopback() {
        resolved_webhook_must_block("http://127.0.0.1/hook");
        resolved_webhook_must_block("http://[::1]/hook");
    }

    #[test]
    fn strict_service_endpoint_blocks_internal_ranges() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for raw in [
            "http://10.0.0.5/v1/chat/completions",
            "http://192.168.1.10/v1/chat/completions",
            "http://169.254.10.1/v1/chat/completions",
            "http://127.0.0.1:8080/v1/chat/completions",
            "http://169.254.169.254/latest/meta-data",
        ] {
            assert!(
                runtime
                    .block_on(validate_strict_service_endpoint_url(raw))
                    .is_err(),
                "{raw} should be refused"
            );
        }
    }

    #[test]
    fn strict_service_endpoint_allows_a_public_address() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(
            runtime
                .block_on(validate_strict_service_endpoint_url("https://93.184.216.34/v1/chat/completions"))
                .is_ok()
        );
    }

    #[test]
    fn resolved_webhook_blocks_ip_literal_private() {
        resolved_webhook_must_block("http://10.0.0.1/hook");
        resolved_webhook_must_block("http://192.168.1.1/hook");
        resolved_webhook_must_block("http://172.16.0.1/hook");
        resolved_webhook_must_block("http://[fc00::1]/hook");
        resolved_webhook_must_block("http://[fe80::1]/hook");
    }

    #[test]
    fn resolved_webhook_blocks_ip_literal_link_local() {
        resolved_webhook_must_block("http://169.254.1.1/hook");
    }

    #[test]
    fn resolved_webhook_blocks_embedded_credentials() {
        resolved_webhook_must_block("http://user:pass@payments.example.com/");
    }

    #[test]
    fn resolved_webhook_blocks_non_http_schemes() {
        resolved_webhook_must_block("file:///etc/passwd");
        resolved_webhook_must_block("ftp://example.com/");
    }

    #[test]
    fn resolved_webhook_allows_public_ip_literal() {
        resolved_webhook_must_allow("https://1.2.3.4/hook");
        resolved_webhook_must_allow("http://8.8.8.8/hook");
    }

    #[test]
    fn resolved_webhook_resolves_and_allows_public_domain() {
        // Resolves to public IPs — must pass.
        resolved_webhook_must_allow("https://example.com/hook");
    }

    #[test]
    fn resolved_webhook_rejects_localhost_domain() {
        // localhost resolves to 127.0.0.1 — blocked by base check before DNS.
        resolved_webhook_must_block("http://localhost/hook");
    }

    #[test]
    fn test_parse_host_refuses_anything_but_a_bare_host() {
        for raw in [
            "",
            " smtp.example.com",
            "smtp.example.com ",
            "smtp.example.com:25",
            "user@smtp.example.com",
            "smtp.example.com/relay",
            "smtp example.com",
            "[::1",
            "sm%74p.example.com",
            "bücher.example",
        ] {
            assert!(parse_host(raw).is_err(), "{raw:?} should be refused");
        }
    }

    #[test]
    fn test_parse_host_reads_addresses_in_every_spelling() {
        assert_eq!(parse_host("::1"), Ok(Host::Ipv6(std::net::Ipv6Addr::LOCALHOST)));
        assert_eq!(parse_host("[::1]"), Ok(Host::Ipv6(std::net::Ipv6Addr::LOCALHOST)));
        assert_eq!(parse_host("0x7f.1"), Ok(Host::Ipv4(std::net::Ipv4Addr::LOCALHOST)));
        assert_eq!(parse_host("SMTP.Example.com"), Ok(Host::Domain("smtp.example.com".to_string())));
    }

    #[tokio::test]
    async fn test_resolve_public_host_refuses_internal_hosts() {
        for raw in [
            "127.0.0.1",
            "0x7f.1",
            "::1",
            "0.0.0.0",
            "10.0.0.5",
            "172.16.3.4",
            "192.168.1.10",
            "169.254.169.254",
            "169.254.10.1",
            "fd00:ec2::254",
            "fe80::1",
            "::ffff:10.0.0.1",
            "100.64.0.1",
            "64:ff9b::a00:5",
            "localhost",
            "metadata.google.internal",
        ] {
            let host = parse_host(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert!(
                resolve_public_host(&host, 25)
                    .await
                    .is_err(),
                "{raw} should be refused"
            );
        }
    }

    #[tokio::test]
    async fn test_resolve_public_host_returns_the_checked_address() {
        for raw in ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"] {
            let host = parse_host(raw).unwrap();
            let expected = std::net::SocketAddr::new(raw.parse().unwrap(), 587);
            assert_eq!(resolve_public_host(&host, 587).await, Ok(vec![expected]));
        }
    }

    #[tokio::test]
    async fn test_an_allowlisted_test_endpoint_may_be_loopback_but_never_metadata() {
        let _allowed = test_service_endpoints::allow(&[
            "http://127.0.0.1:2525".to_string(),
            "http://169.254.169.254:80".to_string(),
        ]);
        let loopback = parse_host("127.0.0.1").unwrap();
        let metadata = parse_host("169.254.169.254").unwrap();

        assert!(
            resolve_public_host(&loopback, 2525)
                .await
                .is_ok()
        );
        assert!(
            resolve_public_host(&loopback, 2526)
                .await
                .is_err()
        );
        assert!(
            resolve_public_host(&metadata, 80)
                .await
                .is_err()
        );
    }
}
