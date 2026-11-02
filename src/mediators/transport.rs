use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;

use serde_json::Value;
use url::Url;

const INSECURE_LOCAL_OPT_IN: &str = "AS_ALLOW_INSECURE_LOCAL_MEDIATOR_TRANSPORT";
const MAX_REFERENCE_DEPTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentRole {
    Root,
    EndpointReference,
}

#[derive(Debug, Default)]
struct DocumentValidation {
    referenced_dids: Vec<String>,
    has_socket_endpoint: bool,
    has_auth_endpoint: bool,
    has_plaintext_socket: bool,
    has_plaintext_auth: bool,
    plaintext_hosts: HashSet<String>,
}

fn insecure_local_enabled() -> bool {
    crate::env_compat::var(INSECURE_LOCAL_OPT_IN).as_deref() == Ok("true")
}

fn service_has_type(
    service: &Value,
    expected: &str,
) -> bool {
    service
        .get("type")
        .is_some_and(|service_type| {
            service_type.as_str() == Some(expected)
                || service_type
                    .as_array()
                    .is_some_and(|types| {
                        types
                            .iter()
                            .any(|value| value.as_str() == Some(expected))
                    })
        })
}

fn collect_endpoint_values(
    value: &Value,
    endpoints: &mut Vec<String>,
) {
    if let Some(endpoint) = value.as_str() {
        endpoints.push(endpoint.to_string());
        return;
    }
    if let Some(values) = value.as_array() {
        for value in values {
            collect_endpoint_values(value, endpoints);
        }
        return;
    }
    if let Some(value) = value.as_object()
        && let Some(endpoint) = value
            .get("uri")
            .or_else(|| value.get("url"))
            .and_then(Value::as_str)
    {
        endpoints.push(endpoint.to_string());
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn no_proxy_covers(
    host: &str,
    port: Option<u16>,
) -> bool {
    let proxy_configured = ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .any(|name| std::env::var_os(name).is_some());
    if !proxy_configured {
        return true;
    }

    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    no_proxy
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|entry| {
            entry == "*"
                || entry.eq_ignore_ascii_case(host)
                || port.is_some_and(|port| entry.eq_ignore_ascii_case(&format!("{host}:{port}")))
                || (host.eq_ignore_ascii_case("localhost") && entry.eq_ignore_ascii_case(".localhost"))
        })
}

fn validate_url(
    raw: &str,
    allowed_secure_scheme: &str,
    allowed_plaintext_scheme: &str,
    allow_insecure_local: bool,
) -> Result<(Url, bool), String> {
    let url = Url::parse(raw).map_err(|error| format!("invalid mediator endpoint: {error}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("mediator endpoint must not contain user information".to_string());
    }
    if url.fragment().is_some() {
        return Err("mediator endpoint must not contain a fragment".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "mediator endpoint must contain a host".to_string())?;

    if url.scheme() == allowed_secure_scheme {
        return Ok((url, false));
    }
    if url.scheme() != allowed_plaintext_scheme {
        return Err(format!("mediator endpoint must use {allowed_secure_scheme}"));
    }
    if !allow_insecure_local || !is_loopback_host(host) {
        return Err(format!(
            "plaintext mediator endpoint requires {INSECURE_LOCAL_OPT_IN}=true and an exact loopback host"
        ));
    }
    if !no_proxy_covers(host, url.port_or_known_default()) {
        return Err("plaintext loopback mediator endpoint must bypass configured proxies via NO_PROXY".to_string());
    }
    tracing::warn!(
        endpoint = %crate::url_validation::redact_url_for_logging(raw),
        "Using explicitly enabled plaintext loopback mediator transport"
    );
    Ok((url, true))
}

fn validate_document(
    expected_did: &str,
    document: &Value,
    role: DocumentRole,
    allow_insecure_local: bool,
) -> Result<DocumentValidation, String> {
    let document_id = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "mediator DID document is missing its id".to_string())?;
    if document_id != expected_did {
        return Err("mediator DID document id does not match the configured DID".to_string());
    }
    let services = document
        .get("service")
        .and_then(Value::as_array)
        .ok_or_else(|| "mediator DID document has no services".to_string())?;

    let mut validation = DocumentValidation::default();
    for service in services {
        let service_id = service
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let is_didcomm = service_has_type(service, "DIDCommMessaging");
        let is_auth = service_id.ends_with("#auth");
        if !is_didcomm && !is_auth {
            continue;
        }

        let mut endpoints = Vec::new();
        if let Some(service_endpoint) = service.get("serviceEndpoint") {
            collect_endpoint_values(service_endpoint, &mut endpoints);
        }
        if endpoints.is_empty() {
            return Err("mediator service has no usable endpoint".to_string());
        }

        for endpoint in endpoints {
            if endpoint.starts_with("did:") {
                if !is_didcomm {
                    return Err("mediator authentication endpoint must be an HTTPS URL".to_string());
                }
                validation
                    .referenced_dids
                    .push(endpoint);
                continue;
            }

            if is_didcomm {
                let (url, plaintext) = if endpoint
                    .get(
                        ..endpoint
                            .find(':')
                            .unwrap_or(0),
                    )
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
                {
                    validate_url(&endpoint, "https", "http", allow_insecure_local)?
                } else {
                    let result = validate_url(&endpoint, "wss", "ws", allow_insecure_local)?;
                    validation.has_socket_endpoint = true;
                    result
                };
                if plaintext {
                    validation.has_plaintext_socket = true;
                    validation
                        .plaintext_hosts
                        .insert(
                            url.host_str()
                                .unwrap_or_default()
                                .to_ascii_lowercase(),
                        );
                }
            }

            if is_auth {
                let (url, plaintext) = validate_url(&endpoint, "https", "http", allow_insecure_local)?;
                validation.has_auth_endpoint = true;
                if plaintext {
                    validation.has_plaintext_auth = true;
                    validation
                        .plaintext_hosts
                        .insert(
                            url.host_str()
                                .unwrap_or_default()
                                .to_ascii_lowercase(),
                        );
                }
            }
        }
    }

    if !validation.has_socket_endpoint
        && validation
            .referenced_dids
            .is_empty()
    {
        return Err("mediator DID document has no WSS endpoint".to_string());
    }
    if role == DocumentRole::Root && !validation.has_auth_endpoint {
        return Err("mediator DID document has no HTTPS authentication endpoint".to_string());
    }
    if validation.has_plaintext_socket != validation.has_plaintext_auth {
        return Err("plaintext local mediator transport requires matching WS and HTTP endpoints".to_string());
    }
    if validation
        .plaintext_hosts
        .len()
        > 1
    {
        return Err(
            "plaintext mediator socket and authentication endpoints must use the same loopback host".to_string()
        );
    }
    Ok(validation)
}

fn did_web_document_url(did: &str) -> Result<String, String> {
    use affinidi_did_common::{DID, DIDMethod};

    let parsed: DID = did
        .parse()
        .map_err(|error| format!("Invalid did:web mediator DID: {error}"))?;
    let DIDMethod::Web { domain, path_segments, .. } = parsed.method() else {
        return Err("Expected a did:web mediator DID".to_string());
    };
    let domain = urlencoding::decode(&domain).map_err(|error| format!("Invalid did:web domain: {error}"))?;
    let mut url = format!("https://{domain}");
    if path_segments.is_empty() {
        url.push_str("/.well-known/did.json");
    } else {
        for segment in path_segments {
            let segment = urlencoding::decode(&segment).map_err(|error| format!("Invalid did:web path: {error}"))?;
            url.push('/');
            url.push_str(&segment);
        }
        url.push_str("/did.json");
    }
    Ok(url)
}

async fn resolve_mediator_document(did: &str) -> Result<Value, String> {
    if did.starts_with("did:web:") {
        let url = did_web_document_url(did)?;
        let bytes = crate::outbound_fetch::fetch_public_bounded(&url).await?;
        return serde_json::from_slice(&bytes).map_err(|error| format!("Invalid did:web document: {error}"));
    }

    #[cfg(feature = "didwebvh")]
    if did.starts_with("did:webvh:") {
        use didwebvh_rs::DIDWebVHState;
        use didwebvh_rs::log_entry::LogEntryMethods;
        use didwebvh_rs::url::WebVHURL;

        let parsed =
            WebVHURL::parse_did_url(did).map_err(|error| format!("Invalid did:webvh mediator DID: {error}"))?;
        let log_url = parsed
            .get_http_url(Some("did.jsonl"))
            .map_err(|error| format!("Invalid did:webvh log URL: {error}"))?;
        let log_bytes = crate::outbound_fetch::fetch_public_bounded(log_url.as_str()).await?;
        let log = std::str::from_utf8(&log_bytes).map_err(|_| "did:webvh log is not valid UTF-8".to_string())?;

        let mut state = DIDWebVHState::default();
        if let Ok((entry, _)) = state
            .resolve_log_owned(did, log, None)
            .await
        {
            return entry
                .get_did_document()
                .map_err(|error| format!("Invalid did:webvh document: {error}"));
        }

        let witness_url = parsed
            .get_http_url(Some("did-witness.json"))
            .map_err(|error| format!("Invalid did:webvh witness URL: {error}"))?;
        let witness_bytes = crate::outbound_fetch::fetch_public_bounded(witness_url.as_str()).await?;
        let witness =
            std::str::from_utf8(&witness_bytes).map_err(|_| "did:webvh witness file is not valid UTF-8".to_string())?;
        let mut state = DIDWebVHState::default();
        let (entry, _) = state
            .resolve_log_owned(did, log, Some(witness))
            .await
            .map_err(|error| format!("Invalid did:webvh log or witnesses: {error}"))?;
        return entry
            .get_did_document()
            .map_err(|error| format!("Invalid did:webvh document: {error}"));
    }

    if did.starts_with("did:peer:") || did.starts_with("did:key:") {
        return serde_json::to_value(
            crate::gateways::did_cache::shared_resolver()
                .resolve(did)
                .await
                .map_err(|error| format!("Failed to resolve local mediator DID: {error}"))?
                .doc,
        )
        .map_err(|error| format!("Failed to serialize local mediator DID document: {error}"));
    }

    Err("Mediator resolution supports did:web, did:webvh, did:peer, and did:key only".to_string())
}

pub async fn resolve_and_validate_mediator_documents(
    mediator_did: &str,
    supplied_document: Option<Value>,
) -> Result<Vec<(String, Value)>, String> {
    let root_document = match supplied_document {
        Some(document) => document,
        None => resolve_mediator_document(mediator_did).await?,
    };

    let allow_insecure_local = insecure_local_enabled();
    let mut pending = VecDeque::from([(mediator_did.to_string(), root_document, DocumentRole::Root, 0usize)]);
    let mut visited = HashSet::new();
    let mut documents = Vec::new();

    while let Some((did, document, role, depth)) = pending.pop_front() {
        if depth > MAX_REFERENCE_DEPTH {
            return Err("mediator endpoint DID reference depth exceeded".to_string());
        }
        if !visited.insert(did.clone()) {
            return Err("mediator endpoint DID reference cycle detected".to_string());
        }
        let validation = validate_document(&did, &document, role, allow_insecure_local)?;
        for referenced_did in validation.referenced_dids {
            let referenced_document = resolve_mediator_document(&referenced_did).await?;
            pending.push_back((referenced_did, referenced_document, DocumentRole::EndpointReference, depth + 1));
        }
        documents.push((did, document));
    }

    Ok(documents)
}

fn rest_endpoint(document: &Value) -> Option<String> {
    let mut endpoints = Vec::new();
    for service in document
        .get("service")?
        .as_array()?
        .iter()
        .filter(|service| service_has_type(service, "DIDCommMessaging"))
    {
        if let Some(service_endpoint) = service.get("serviceEndpoint") {
            collect_endpoint_values(service_endpoint, &mut endpoints);
        }
    }
    endpoints
        .into_iter()
        .find(|endpoint| Url::parse(endpoint).is_ok_and(|url| url.scheme() == "https" || url.scheme() == "http"))
        .map(|endpoint| {
            endpoint
                .trim_end_matches('/')
                .to_string()
        })
}

/// The mediator's HTTP(S) DIDComm endpoint, path included, as its validated
/// DID documents publish it. Invitation links and connection point service
/// endpoints are built from it.
pub async fn resolve_mediator_rest_endpoint(
    mediator_did: &str,
    supplied_document: Option<Value>,
) -> Result<String, String> {
    resolve_and_validate_mediator_documents(mediator_did, supplied_document)
        .await?
        .iter()
        .find_map(|(_, document)| rest_endpoint(document))
        .ok_or_else(|| "mediator DID document has no HTTPS DIDComm endpoint".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(
        ws: &str,
        auth: &str,
    ) -> Value {
        serde_json::json!({
            "id": "did:web:mediator.example",
            "service": [
                {
                    "id": "did:web:mediator.example#didcomm",
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [
                        {"uri": "https://mediator.example/didcomm"},
                        {"uri": ws}
                    ]
                },
                {
                    "id": "did:web:mediator.example#auth",
                    "type": "Authentication",
                    "serviceEndpoint": auth
                }
            ]
        })
    }

    #[test]
    fn rest_endpoint_keeps_the_mediator_path() {
        let document = serde_json::json!({
            "id": "did:webvh:scid:mediator.example",
            "service": [{
                "id": "did:webvh:scid:mediator.example#service",
                "type": ["DIDCommMessaging"],
                "serviceEndpoint": [
                    {"uri": "wss://mediator.example/mediator/v1/ws"},
                    {"uri": "https://mediator.example/mediator/v1/"}
                ]
            }]
        });

        assert_eq!(rest_endpoint(&document).as_deref(), Some("https://mediator.example/mediator/v1"));
    }

    #[test]
    fn rest_endpoint_keeps_a_loopback_port() {
        let mut document = document("ws://localhost:7037/ws", "http://localhost:7037/authenticate");
        document["service"][0]["serviceEndpoint"][0]["uri"] = serde_json::json!("http://localhost:7037");

        assert_eq!(rest_endpoint(&document).as_deref(), Some("http://localhost:7037"));
    }

    #[test]
    fn rest_endpoint_ignores_non_didcomm_services_and_socket_only_documents() {
        let document = serde_json::json!({
            "id": "did:web:mediator.example",
            "service": [
                {"id": "#auth", "type": "Authentication", "serviceEndpoint": "https://mediator.example/authenticate"},
                {"id": "#didcomm", "type": "DIDCommMessaging", "serviceEndpoint": [{"uri": "wss://mediator.example/ws"}]}
            ]
        });

        assert_eq!(rest_endpoint(&document), None);
    }

    #[tokio::test]
    async fn resolved_rest_endpoint_comes_from_the_validated_document() {
        let document = document("wss://mediator.example/ws", "https://mediator.example/authenticate");

        let endpoint = resolve_mediator_rest_endpoint("did:web:mediator.example", Some(document))
            .await
            .unwrap();

        assert_eq!(endpoint, "https://mediator.example/didcomm");
    }

    #[tokio::test]
    async fn rest_endpoint_is_refused_when_the_document_fails_validation() {
        let document = document("ws://mediator.example/ws", "https://mediator.example/authenticate");

        let result = resolve_mediator_rest_endpoint("did:web:mediator.example", Some(document)).await;

        assert!(result.is_err());
    }

    #[test]
    fn did_web_urls_are_derived_without_network_resolution() {
        assert_eq!(
            did_web_document_url("did:web:mediator.example").unwrap(),
            "https://mediator.example/.well-known/did.json"
        );
        assert_eq!(
            did_web_document_url("did:web:mediator.example%3A8443:tenant:one").unwrap(),
            "https://mediator.example:8443/tenant/one/did.json"
        );
    }

    #[test]
    fn production_requires_wss_and_https() {
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("wss://mediator.example/ws", "https://mediator.example/auth"),
                DocumentRole::Root,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("ws://mediator.example/ws", "https://mediator.example/auth"),
                DocumentRole::Root,
                false,
            )
            .is_err()
        );
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("wss://mediator.example/ws", "http://mediator.example/auth"),
                DocumentRole::Root,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn local_opt_in_is_restricted_to_loopback() {
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("ws://127.0.0.1:7037/ws", "http://127.0.0.1:7037/auth"),
                DocumentRole::Root,
                true,
            )
            .is_ok()
        );
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("ws://192.168.1.10/ws", "http://192.168.1.10/auth"),
                DocumentRole::Root,
                true,
            )
            .is_err()
        );
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("ws://127.0.0.1:7037/ws", "https://127.0.0.1:7037/auth"),
                DocumentRole::Root,
                true,
            )
            .is_err()
        );
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("wss://127.0.0.1:7037/ws", "http://127.0.0.1:7037/auth"),
                DocumentRole::Root,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_identity_confusion_and_unsafe_url_forms() {
        assert!(
            validate_document(
                "did:web:other.example",
                &document("wss://mediator.example/ws", "https://mediator.example/auth"),
                DocumentRole::Root,
                false,
            )
            .is_err()
        );
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("wss://user@mediator.example/ws", "https://mediator.example/auth"),
                DocumentRole::Root,
                false,
            )
            .is_err()
        );
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("wss://mediator.example/ws#fragment", "https://mediator.example/auth"),
                DocumentRole::Root,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_mixed_downgrade_and_prefix_confusion() {
        let mut mixed = document("wss://mediator.example/ws", "https://mediator.example/auth");
        mixed["service"][0]["serviceEndpoint"] = serde_json::json!([
            {"uri": "wss://mediator.example/ws"},
            {"uri": "ws://mediator.example/ws"}
        ]);
        assert!(validate_document("did:web:mediator.example", &mixed, DocumentRole::Root, false,).is_err());
        assert!(
            validate_document(
                "did:web:mediator.example",
                &document("wssx://mediator.example/ws", "https://mediator.example/auth"),
                DocumentRole::Root,
                false,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn supplied_document_is_rejected_before_resolution_or_transport() {
        let result = resolve_and_validate_mediator_documents(
            "did:web:mediator.example",
            Some(document("ws://mediator.example/ws", "http://mediator.example/auth")),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn supplied_document_must_match_the_independent_mediator_did() {
        let result = resolve_and_validate_mediator_documents(
            "did:web:configured.example",
            Some(document("wss://mediator.example/ws", "https://mediator.example/auth")),
        )
        .await;

        assert_eq!(result.unwrap_err(), "mediator DID document id does not match the configured DID");
    }

    #[test]
    fn endpoint_reference_requires_secure_socket_but_not_duplicate_auth() {
        let root = serde_json::json!({
            "id": "did:web:mediator.example",
            "service": [
                {
                    "id": "did:web:mediator.example#didcomm",
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": "did:web:endpoint.example"
                },
                {
                    "id": "did:web:mediator.example#auth",
                    "type": "Authentication",
                    "serviceEndpoint": "https://mediator.example/auth"
                }
            ]
        });
        let validation = validate_document("did:web:mediator.example", &root, DocumentRole::Root, false).unwrap();
        assert_eq!(validation.referenced_dids, vec!["did:web:endpoint.example"]);

        let endpoint = serde_json::json!({
            "id": "did:web:endpoint.example",
            "service": [{
                "id": "did:web:endpoint.example#didcomm",
                "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": "wss://endpoint.example/ws"}
            }]
        });
        assert!(
            validate_document("did:web:endpoint.example", &endpoint, DocumentRole::EndpointReference, false,).is_ok()
        );
    }
}
