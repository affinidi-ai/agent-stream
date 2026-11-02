use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::StreamExt;
use reqwest::header::LOCATION;
use url::Url;

const MAX_REDIRECTS: usize = 3;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PRIVATE_HOST_ALLOWLIST: &str = "AS_MEDIATOR_DISCOVERY_PRIVATE_HOST_ALLOWLIST";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressPolicy {
    Public,
    ApprovedPrivate,
    Loopback,
}

fn insecure_local_enabled() -> bool {
    crate::env_compat::var("AS_ALLOW_INSECURE_LOCAL_MEDIATOR_TRANSPORT").as_deref() == Ok("true")
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn private_host_allowed(host: &str) -> bool {
    crate::env_compat::var(PRIVATE_HOST_ALLOWLIST)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .any(|allowed| !allowed.is_empty() && allowed.eq_ignore_ascii_case(host))
}

fn validate_discovery_url(raw: &str) -> Result<(Url, AddressPolicy), String> {
    let url = Url::parse(raw).map_err(|error| format!("invalid discovery URL: {error}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("discovery URL must not contain user information".to_string());
    }
    if url.fragment().is_some() {
        return Err("discovery URL must not contain a fragment".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "discovery URL must contain a host".to_string())?;
    if url.scheme() == "https" {
        if private_host_allowed(host) {
            crate::url_validation::validate_url_not_cloud_metadata(raw)?;
            return Ok((url, AddressPolicy::ApprovedPrivate));
        }
        crate::url_validation::validate_webhook_url(raw).map_err(|_| {
            format!("private mediator discovery host requires exact listing in {PRIVATE_HOST_ALLOWLIST}")
        })?;
        return Ok((url, AddressPolicy::Public));
    }
    if url.scheme() == "http" && insecure_local_enabled() && is_loopback_host(host) {
        return Ok((url, AddressPolicy::Loopback));
    }
    Err("discovery URL must use HTTPS; plaintext is restricted to explicitly enabled loopback development".to_string())
}

fn validate_addresses(
    addresses: &[SocketAddr],
    policy: AddressPolicy,
) -> Result<(), String> {
    let blocked = addresses
        .iter()
        .any(|address| match policy {
            AddressPolicy::Public => crate::url_validation::is_blocked_resolved_webhook_ip(address.ip()),
            AddressPolicy::ApprovedPrivate => crate::url_validation::is_blocked_resolved_ip(address.ip()),
            AddressPolicy::Loopback => !address.ip().is_loopback(),
        });
    if blocked {
        return Err("discovery host resolved outside its approved network policy".to_string());
    }
    Ok(())
}

async fn resolve_once(
    host: &str,
    port: u16,
    policy: AddressPolicy,
) -> Result<Vec<SocketAddr>, String> {
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| format!("discovery DNS resolution failed: {error}"))?
        .collect();
    if addresses.is_empty() {
        return Err("discovery DNS resolution returned no addresses".to_string());
    }
    validate_addresses(&addresses, policy)?;
    Ok(addresses)
}

async fn pinned_client(
    url: &Url,
    policy: AddressPolicy,
) -> Result<reqwest::Client, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "discovery URL must contain a host".to_string())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "discovery URL has no usable port".to_string())?;
    let addresses = resolve_once(host, port, policy).await?;
    reqwest::Client::builder()
        .timeout(TOTAL_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(|error| format!("failed to build pinned discovery client: {error}"))
}

async fn read_bounded(response: reqwest::Response) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err("discovery response exceeds 256 KiB".to_string());
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("failed to read discovery response: {error}"))?;
        if bytes
            .len()
            .saturating_add(chunk.len())
            > MAX_RESPONSE_BYTES
        {
            return Err("discovery response exceeds 256 KiB".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub async fn fetch_public_bounded(raw: &str) -> Result<Vec<u8>, String> {
    tokio::time::timeout(TOTAL_TIMEOUT, fetch_public_bounded_inner(raw))
        .await
        .map_err(|_| "discovery request timed out".to_string())?
}

async fn fetch_public_bounded_inner(raw: &str) -> Result<Vec<u8>, String> {
    let mut current = Url::parse(raw).map_err(|error| format!("invalid discovery URL: {error}"))?;
    for redirect_count in 0..=MAX_REDIRECTS {
        let (validated, address_policy) = validate_discovery_url(current.as_str())?;
        let client = pinned_client(&validated, address_policy).await?;
        let response = client
            .get(validated.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| format!("discovery request failed: {error}"))?;

        if response
            .status()
            .is_redirection()
        {
            if redirect_count == MAX_REDIRECTS {
                return Err("discovery redirect limit exceeded".to_string());
            }
            let location = response
                .headers()
                .get(LOCATION)
                .ok_or_else(|| "discovery redirect is missing Location".to_string())?
                .to_str()
                .map_err(|_| "discovery redirect Location is invalid".to_string())?;
            let next = validated
                .join(location)
                .map_err(|error| format!("invalid discovery redirect: {error}"))?;
            if validated.scheme() == "https" && next.scheme() != "https" {
                return Err("discovery redirect must not downgrade HTTPS".to_string());
            }
            current = next;
            continue;
        }

        if !response.status().is_success() {
            return Err(format!("discovery endpoint returned HTTP {}", response.status()));
        }
        return read_bounded(response).await;
    }
    Err("discovery redirect limit exceeded".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_url_policy_rejects_plaintext_and_private_targets() {
        assert!(validate_discovery_url("https://example.com/oob").is_ok());
        assert!(validate_discovery_url("http://example.com/oob").is_err());
        assert!(validate_discovery_url("https://127.0.0.1/oob").is_err());
        assert!(validate_discovery_url("https://169.254.169.254/latest").is_err());
        assert!(validate_discovery_url("https://10.0.0.1/oob").is_err());
        assert!(validate_discovery_url("https://user@example.com/oob").is_err());
        assert!(validate_discovery_url("https://example.com/oob#fragment").is_err());
    }

    #[test]
    fn resolved_addresses_are_bound_to_the_selected_policy() {
        let public = "93.184.216.34:443"
            .parse::<SocketAddr>()
            .unwrap();
        let private = "10.0.0.1:443"
            .parse::<SocketAddr>()
            .unwrap();
        let loopback = "127.0.0.1:443"
            .parse::<SocketAddr>()
            .unwrap();
        let metadata = "169.254.169.254:443"
            .parse::<SocketAddr>()
            .unwrap();

        assert!(validate_addresses(&[public, loopback], AddressPolicy::Public).is_err());
        assert!(validate_addresses(&[private], AddressPolicy::ApprovedPrivate).is_ok());
        assert!(validate_addresses(&[metadata], AddressPolicy::ApprovedPrivate).is_err());
        assert!(validate_addresses(&[loopback], AddressPolicy::Loopback).is_ok());
        assert!(validate_addresses(&[loopback, public], AddressPolicy::Loopback).is_err());
    }
}
