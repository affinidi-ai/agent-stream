//! Destinations that integrations dial directly: the SMTP server of an email
//! integration and the Redis, Kafka or Pulsar host of a stream. A destination
//! is checked against the strict outbound policy ([`resolve_public_host`])
//! when an integration is saved with a new or changed destination ([`check`]),
//! and again by the sender on every test and delivery, which dials only what
//! was checked. Loopback, private, link-local and cloud metadata addresses are
//! refused, and so is anything that is not a TCP host and port. A saved
//! destination that no longer passes, because its name now resolves elsewhere,
//! its secret changed or it was saved before these checks, is refused when it
//! delivers.

use std::net::SocketAddr;

use serde_json::Value;

use redis::{ConnectionAddr, ConnectionInfo, IntoConnectionInfo};
use tracing::warn;
use url::{Host, Url};

use crate::url_validation::{parse_host, resolve_public_host};

const KAFKA_DEFAULT_PORT: u16 = 9092;
/// The most brokers a `brokers` list may name; each one is resolved in turn.
const KAFKA_MAX_BROKERS: usize = 32;
const PULSAR_DEFAULT_PORT: u16 = 6650;
const PULSAR_TLS_DEFAULT_PORT: u16 = 6651;
const SECRET_REFERENCE_SUFFIX: &str = "_secret_id";

/// Why a destination was refused before connecting.
#[derive(Debug, thiserror::Error)]
pub enum DestinationError {
    /// The setting is missing or is not a supported host or URL.
    #[error("{0}")]
    Invalid(String),
    /// The host did not resolve, or resolved to an address the strict outbound
    /// policy refuses. The reason is logged and never returned, so the answer
    /// does not reveal internal addresses or which internal names exist.
    #[error(
        "The destination must resolve to a public address: private, loopback, link-local and cloud metadata addresses are not allowed"
    )]
    NotPublic,
}

/// Check the SMTP server `host` and return the address to dial.
pub async fn smtp(
    host: &str,
    port: u16,
) -> Result<SocketAddr, DestinationError> {
    let parsed = host_of("smtp_host", host)?;
    first_public_address("smtp_host", &parsed, port).await
}

/// Parse `redis_url` with the Redis client's own parser and return its
/// connection settings with the host replaced by the checked address. Only a
/// TCP URL (`redis://`) is accepted, so Unix socket URLs are refused.
pub async fn redis(redis_url: &str) -> Result<ConnectionInfo, DestinationError> {
    let invalid = || DestinationError::Invalid("redis_url must be a redis://host:port URL".to_string());
    let info = redis_url
        .into_connection_info()
        .map_err(|_| invalid())?;
    let ConnectionAddr::Tcp(host, port) = info.addr() else {
        return Err(invalid());
    };
    let port = *port;
    let parsed = host_of("redis_url", host)?;
    let address = first_public_address("redis_url", &parsed, port).await?;
    Ok(info.set_addr(ConnectionAddr::Tcp(address.ip().to_string(), port)))
}

/// Check every broker of a Kafka `bootstrap.servers` list
/// (`[PROTOCOL://]host[:port]`, comma separated, IPv6 in brackets, port 9092 by
/// default) and return the list rebuilt from the checked hosts, so the client
/// resolves exactly the names that were checked.
pub async fn kafka_brokers(brokers: &str) -> Result<String, DestinationError> {
    let invalid = || {
        DestinationError::Invalid(format!(
            "brokers must be a comma-separated list of at most {KAFKA_MAX_BROKERS} host:port entries"
        ))
    };
    let entries: Vec<&str> = brokers
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.is_empty() || entries.len() > KAFKA_MAX_BROKERS {
        return Err(invalid());
    }
    let mut checked = Vec::with_capacity(entries.len());
    for entry in entries {
        let (protocol, address) = match entry.split_once("://") {
            Some((protocol, address))
                if !protocol.is_empty()
                    && protocol
                        .bytes()
                        .all(|b| b.is_ascii_alphabetic() || b == b'_') =>
            {
                (Some(protocol), address)
            }
            Some(_) => return Err(invalid()),
            None => (None, entry),
        };
        let (host, port) = split_host_port(address, KAFKA_DEFAULT_PORT).ok_or_else(invalid)?;
        let parsed = host_of("brokers", host)?;
        first_public_address("brokers", &parsed, port).await?;
        checked.push(match protocol {
            Some(protocol) => format!("{protocol}://{parsed}:{port}"),
            None => format!("{parsed}:{port}"),
        });
    }
    Ok(checked.join(","))
}

/// Check a Pulsar service URL (`pulsar://` or `pulsar+ssl://` with a host and an
/// optional port, nothing else) and return it rebuilt from the checked host.
pub async fn pulsar_url(brokers: &str) -> Result<String, DestinationError> {
    let invalid =
        || DestinationError::Invalid("brokers must be a pulsar://host:port or pulsar+ssl://host:port URL".to_string());
    let url = Url::parse(brokers).map_err(|_| invalid())?;
    let default_port = match url.scheme() {
        "pulsar" => PULSAR_DEFAULT_PORT,
        "pulsar+ssl" => PULSAR_TLS_DEFAULT_PORT,
        _ => return Err(invalid()),
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(invalid)?;
    let port = url
        .port()
        .unwrap_or(default_port);
    let parsed = host_of("brokers", host)?;
    first_public_address("brokers", &parsed, port).await?;
    Ok(format!("{}://{parsed}:{port}", url.scheme()))
}

/// Check the destination a new or changed `configuration` names: the SMTP
/// server of an email integration, or the Redis, Kafka or Pulsar host of a
/// stream. A destination setting that is absent is left to the sender, as is
/// an SMTP port it cannot use (whether the host is public does not depend on
/// the port), and other integration types are checked when they send.
pub async fn check(
    integration_type: &str,
    configuration: &Value,
) -> Result<(), DestinationError> {
    let setting = |key: &str| {
        configuration
            .get(key)
            .and_then(Value::as_str)
    };
    match integration_type {
        "email" => {
            let Some(host) = setting("smtp_host") else {
                return Ok(());
            };
            let port = configuration
                .get("smtp_port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .unwrap_or_default();
            smtp(host, port)
                .await
                .map(|_| ())
        }
        "stream" => match (setting("platform").unwrap_or("kafka"), setting("redis_url"), setting("brokers")) {
            ("redis", Some(redis_url), _) => redis(redis_url)
                .await
                .map(|_| ()),
            ("kafka", _, Some(brokers)) => kafka_brokers(brokers)
                .await
                .map(|_| ()),
            ("pulsar", _, Some(brokers)) => pulsar_url(brokers)
                .await
                .map(|_| ()),
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

/// The settings that decide where an integration of `integration_type`
/// delivers, each also as the `<key>_secret_id` reference a delivery resolves
/// into it.
fn destination_keys(integration_type: &str) -> Vec<String> {
    let keys: &[&str] = match integration_type {
        "email" => &["smtp_host", "smtp_port"],
        "stream" => &["platform", "brokers", "redis_url"],
        _ => &[],
    };
    keys.iter()
        .flat_map(|key| [key.to_string(), format!("{key}{SECRET_REFERENCE_SUFFIX}")])
        .collect()
}

/// The destination settings of `configuration`, and nothing else, so a check
/// resolves only the secret references that decide where it delivers.
pub fn destination_settings(
    integration_type: &str,
    configuration: &Value,
) -> Value {
    Value::Object(
        destination_keys(integration_type)
            .into_iter()
            .filter_map(|key| {
                configuration
                    .get(&key)
                    .map(|value| (key, value.clone()))
            })
            .collect(),
    )
}

fn host_of(
    setting: &str,
    raw: &str,
) -> Result<Host<String>, DestinationError> {
    parse_host(raw).map_err(|_| DestinationError::Invalid(format!("{setting} must name a host name or IP address")))
}

async fn first_public_address(
    setting: &str,
    host: &Host<String>,
    port: u16,
) -> Result<SocketAddr, DestinationError> {
    let addresses = resolve_public_host(host, port)
        .await
        .map_err(|reason| {
            warn!(setting, %host, port, %reason, "Refused an integration destination");
            DestinationError::NotPublic
        })?;
    addresses
        .first()
        .copied()
        .ok_or(DestinationError::NotPublic)
}

/// Split `host[:port]` or `[ipv6][:port]`, defaulting the port. A zero or
/// non-numeric port is refused.
fn split_host_port(
    address: &str,
    default_port: u16,
) -> Option<(&str, u16)> {
    let (host, port) = if address.starts_with('[') {
        let end = address.find(']')?;
        let (host, rest) = address.split_at(end + 1);
        if rest.is_empty() {
            (host, None)
        } else {
            (host, Some(rest.strip_prefix(':')?))
        }
    } else {
        match address.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (address, None),
        }
    };
    let port = match port {
        Some(port) => port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)?,
        None => default_port,
    };
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn assert_not_public<T: std::fmt::Debug>(
        result: Result<T, DestinationError>,
        case: &str,
    ) {
        match result {
            Err(DestinationError::NotPublic) => {}
            other => panic!("{case}: expected NotPublic, got {other:?}"),
        }
    }

    fn assert_invalid<T: std::fmt::Debug>(
        result: Result<T, DestinationError>,
        case: &str,
    ) {
        match result {
            Err(DestinationError::Invalid(_)) => {}
            other => panic!("{case}: expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_smtp_internal_hosts_are_refused() {
        for host in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.10",
            "169.254.169.254",
            "::1",
            "fd00:ec2::254",
            "localhost",
            "metadata.google.internal",
        ] {
            assert_not_public(smtp(host, 25).await, host);
        }
    }

    #[tokio::test]
    async fn test_smtp_host_with_a_port_userinfo_or_path_is_invalid() {
        for host in ["", "smtp.example.com:25", "user@smtp.example.com", "smtp.example.com/relay", "sm%74p.example.com"]
        {
            assert_invalid(smtp(host, 25).await, host);
        }
    }

    #[tokio::test]
    async fn test_smtp_public_host_is_returned_for_dialling() {
        let address = smtp("93.184.216.34", 587).await;
        match address {
            Ok(address) => assert_eq!(address, SocketAddr::from(([93, 184, 216, 34], 587))),
            other => panic!("expected the checked address, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_redis_socket_and_foreign_urls_are_invalid() {
        for url in [
            "unix:///var/run/redis.sock",
            "redis+unix:///var/run/redis.sock",
            "valkey+unix:///var/run/redis.sock",
            "http://93.184.216.34:6379",
            "redis://ho%73t.example.com:6379",
            "not a url",
        ] {
            assert_invalid(redis(url).await, url);
        }
    }

    #[tokio::test]
    async fn test_redis_internal_hosts_are_refused() {
        for url in [
            "redis://127.0.0.1:6379",
            "redis://0x7f.1:6379",
            "redis://10.0.0.5",
            "redis://[::1]:6379",
            "redis://169.254.169.254:80",
            "redis://localhost",
        ] {
            assert_not_public(redis(url).await, url);
        }
    }

    #[tokio::test]
    async fn test_redis_connection_is_pinned_to_the_checked_address() {
        let info = match redis("redis://:stream-pass@93.184.216.34:6380/2").await {
            Ok(info) => info,
            other => panic!("expected connection settings, got {other:?}"),
        };

        assert_eq!(info.addr(), &ConnectionAddr::Tcp("93.184.216.34".to_string(), 6380));
        assert_eq!(
            info.redis_settings()
                .password(),
            Some("stream-pass")
        );
        assert_eq!(info.redis_settings().db(), 2);
    }

    #[tokio::test]
    async fn test_kafka_one_internal_broker_refuses_the_list() {
        for brokers in [
            "10.0.0.5:9092",
            "93.184.216.34:9092,127.0.0.1:9092",
            "PLAINTEXT://169.254.169.254:9092",
            "[::1]:9092",
            "localhost",
        ] {
            assert_not_public(kafka_brokers(brokers).await, brokers);
        }
    }

    #[tokio::test]
    async fn test_kafka_malformed_lists_are_invalid() {
        for brokers in [
            "",
            " , ",
            "user@93.184.216.34:9092",
            "93.184.216.34:broker",
            "93.184.216.34:0",
            "93.184.216.34:9092/path",
            "ho%73t.example.com:9092",
            "://93.184.216.34",
            "SASL SSL://93.184.216.34",
        ] {
            assert_invalid(kafka_brokers(brokers).await, brokers);
        }
    }

    #[tokio::test]
    async fn test_kafka_list_longer_than_the_limit_is_invalid() {
        let at_limit = vec!["93.184.216.34:9092"; KAFKA_MAX_BROKERS].join(",");
        let over_limit = vec!["93.184.216.34:9092"; KAFKA_MAX_BROKERS + 1].join(",");

        match kafka_brokers(&at_limit).await {
            Ok(rebuilt) => assert_eq!(rebuilt, at_limit),
            other => panic!("a list at the limit must pass, got {other:?}"),
        }
        assert_invalid(kafka_brokers(&over_limit).await, "over the limit");
    }

    #[tokio::test]
    async fn test_kafka_list_is_rebuilt_from_the_checked_hosts() {
        let rebuilt =
            kafka_brokers(" 93.184.216.34 , SASL_SSL://93.184.216.35:9093,[2606:2800:220:1:248:1893:25c8:1946]:9094")
                .await;

        match rebuilt {
            Ok(rebuilt) => assert_eq!(
                rebuilt,
                "93.184.216.34:9092,SASL_SSL://93.184.216.35:9093,[2606:2800:220:1:248:1893:25c8:1946]:9094"
            ),
            other => panic!("expected the rebuilt list, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_pulsar_internal_hosts_are_refused() {
        for url in
            ["pulsar://127.0.0.1:6650", "pulsar+ssl://10.0.0.5", "pulsar://[fd00:ec2::254]:6650", "pulsar://localhost"]
        {
            assert_not_public(pulsar_url(url).await, url);
        }
    }

    #[tokio::test]
    async fn test_pulsar_urls_other_than_a_service_url_are_invalid() {
        for url in [
            "http://93.184.216.34:8080",
            "93.184.216.34:6650",
            "pulsar://user@93.184.216.34:6650",
            "pulsar://93.184.216.34:6650/admin",
            "pulsar://93.184.216.34:6650?x=1",
            "pulsar://ho%73t.example.com:6650",
            "pulsar://",
        ] {
            assert_invalid(pulsar_url(url).await, url);
        }
    }

    #[tokio::test]
    async fn test_pulsar_url_is_rebuilt_with_its_default_port() {
        for (url, expected) in [
            ("pulsar://93.184.216.34", "pulsar://93.184.216.34:6650"),
            ("pulsar+ssl://93.184.216.34", "pulsar+ssl://93.184.216.34:6651"),
            ("pulsar://93.184.216.34:7000/", "pulsar://93.184.216.34:7000"),
        ] {
            match pulsar_url(url).await {
                Ok(rebuilt) => assert_eq!(rebuilt, expected),
                other => panic!("{url}: expected {expected}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_split_host_port_defaults_and_brackets() {
        assert_eq!(split_host_port("broker", 9092), Some(("broker", 9092)));
        assert_eq!(split_host_port("broker:9093", 9092), Some(("broker", 9093)));
        assert_eq!(split_host_port("[::1]", 9092), Some(("[::1]", 9092)));
        assert_eq!(split_host_port("[::1]:9093", 9092), Some(("[::1]", 9093)));
        assert_eq!(split_host_port("[::1]9093", 9092), None);
        assert_eq!(split_host_port("broker:", 9092), None);
    }

    #[tokio::test]
    async fn test_check_refuses_an_internal_destination_of_each_kind() {
        for (integration_type, configuration) in [
            ("email", json!({ "smtp_host": "10.0.0.5", "smtp_port": 25 })),
            ("stream", json!({ "platform": "redis", "redis_url": "redis://127.0.0.1:6379" })),
            ("stream", json!({ "brokers": "169.254.169.254:9092" })),
            ("stream", json!({ "platform": "pulsar", "brokers": "pulsar://[::1]:6650" })),
        ] {
            assert_not_public(check(integration_type, &configuration).await, &configuration.to_string());
        }
    }

    #[tokio::test]
    async fn test_check_refuses_a_redis_socket() {
        let socket = json!({ "platform": "redis", "redis_url": "unix:///var/run/redis.sock" });
        assert_invalid(check("stream", &socket).await, "redis socket");
    }

    #[tokio::test]
    async fn test_check_checks_an_smtp_host_without_a_usable_port() {
        for port in [json!(null), json!("smtp"), json!(70000)] {
            assert_not_public(
                check("email", &json!({ "smtp_host": "10.0.0.5", "smtp_port": port })).await,
                &port.to_string(),
            );
            match check("email", &json!({ "smtp_host": "93.184.216.34", "smtp_port": port })).await {
                Ok(()) => {}
                other => panic!("{port}: expected Ok, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_check_accepts_a_public_or_absent_destination() {
        for (integration_type, configuration) in [
            ("email", json!({ "smtp_host": "93.184.216.34", "smtp_port": 587 })),
            ("email", json!({})),
            ("stream", json!({ "platform": "kafka", "brokers": "93.184.216.34:9092" })),
            ("stream", json!({ "platform": "kinesis", "region": "us-east-1" })),
        ] {
            match check(integration_type, &configuration).await {
                Ok(()) => {}
                other => panic!("{configuration}: expected Ok, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_destination_settings_keep_only_where_the_integration_delivers() {
        let configuration = json!({
            "platform": "redis",
            "redis_url_secret_id": "cache-url",
            "topic": "events",
            "smtp_password_secret_id": "mail-pass",
        });

        assert_eq!(
            destination_settings("stream", &configuration),
            json!({ "platform": "redis", "redis_url_secret_id": "cache-url" })
        );
        assert_eq!(destination_settings("webhook", &configuration), json!({}));
    }
}
