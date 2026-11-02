//! Redaction for storage export
//!
//! Redacts credentials, key material, personal data and user content from
//! JSON records, by key name and by the shape of string values.

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// Directories excluded entirely from export, together with any backup copy
/// named `<dir>.<suffix>`: key material, credentials and their hashes,
/// delegated OAuth tokens, people, received DIDComm messages, cached DID
/// documents named after the DID, and user media.
pub const EXCLUDED_DIRS: &[&str] = &[
    "identities",
    "secrets",
    "vc_keys",
    "passkeys",
    "apikeys",
    "api_keys",
    "access_tokens",
    "certificates",
    "sessions",
    "avatars",
    "delegation_vault",
    "multimedia_store",
    "messages",
    "members",
    "enrolment",
    "did",
    "did_cache",
];

/// JSON keys whose values are DIDs — replaced with `did:redacted:{hash8}`
const DID_KEYS: &[&str] = &[
    "did",
    "our_did",
    "their_did",
    "mediator_did",
    "identity_did",
    "connection_point_did",
    "our_temporary_did",
    "our_secure_did",
    "their_temporary_did",
    "their_secure_did",
];

/// JSON keys whose values are direct PII — replaced with `[REDACTED]`
const PII_KEYS: &[&str] = &[
    "user_id",
    "first_name",
    "last_name",
    "full_name",
    "display_name",
    "saml_id",
    "subject",
    "principal_key",
    "caller_principal",
    "created_by",
];

/// A key containing any of these holds direct PII — replaced with `[REDACTED]`
const PII_KEY_MARKERS: &[&str] = &["username", "phone"];

/// JSON keys whose values are auth/secret material — replaced with `[REDACTED-SECRET]`
const SECRET_KEYS: &[&str] = &["oob_message", "oob_url", "challenge"];

/// A key containing any of these is treated as auth/secret material, so a
/// credential field added later is redacted without being listed here. Keys
/// are compared lowercased with `-` read as `_`, so `X-API-Key` matches.
const SECRET_KEY_MARKERS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "private_key",
    "privatekey",
    "credential",
    "authorization",
    "cookie",
    "verifier",
    "api_key",
    "apikey",
    "session",
    "header",
    "jwt",
];

/// Private members of a JSON Web Key, redacted in any object that has a `kty`.
const JWK_PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "k", "oth"];

/// JSON keys whose values are user content (prompts, completions, captured
/// traffic) — replaced with `[REDACTED-CONTENT]`
const CONTENT_KEYS: &[&str] = &[
    "prompt",
    "prompt_messages",
    "completion",
    "completion_text",
    "messages",
    "input",
    "output",
    "body",
    "request_body",
    "response_body",
    "payload",
    "latest_payload",
    "last_payload",
    "message_body",
    "sample_input",
    "transcript",
];

/// JSON keys whose values are wallet/financial PII — replaced with `[REDACTED-WALLET]`
const WALLET_KEYS: &[&str] = &["pay_to", "from_address", "tx_hash"];

/// JSON keys whose entire subtree values should be deep-redacted
/// (all string values replaced, because content is free-form and may contain credentials)
const DEEP_REDACT_KEYS: &[&str] = &["configuration"];

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap());

static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap());

static DID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"did:[a-z]+:[A-Za-z0-9._:%-]+").unwrap());

/// Returns true if the given directory name, or a backup copy of it named
/// `<dir>.<suffix>`, should be excluded from export.
pub fn is_excluded_dir(dir_name: &str) -> bool {
    EXCLUDED_DIRS
        .iter()
        .any(|excluded| {
            dir_name == *excluded
                || dir_name
                    .strip_prefix(excluded)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
}

/// Produce a short correlation-safe hash of a DID value.
/// Returns first 8 hex chars of SHA-256, allowing cross-reference in the export
/// without revealing the actual DID.
fn did_hash(did: &str) -> String {
    let hash = Sha256::digest(did.as_bytes());
    format!("did:redacted:{}", hex::encode(&hash[..4]))
}

/// How the value under one JSON key is redacted.
enum Rule {
    Config,
    Did,
    Secret,
    Content,
    Pii,
    Email,
    Wallet,
    Walk,
}

fn rule_for(
    key: &str,
    in_jwk: bool,
) -> Rule {
    let key = key
        .to_lowercase()
        .replace('-', "_");
    let key = key.as_str();
    let has_marker = |markers: &[&str]| {
        markers
            .iter()
            .any(|marker| key.contains(marker))
    };
    if DEEP_REDACT_KEYS.contains(&key) {
        Rule::Config
    } else if DID_KEYS.contains(&key) {
        Rule::Did
    } else if SECRET_KEYS.contains(&key)
        || has_marker(SECRET_KEY_MARKERS)
        || (in_jwk && JWK_PRIVATE_MEMBERS.contains(&key))
    {
        Rule::Secret
    } else if CONTENT_KEYS.contains(&key) {
        Rule::Content
    } else if key.contains("email") {
        Rule::Email
    } else if PII_KEYS.contains(&key) || has_marker(PII_KEY_MARKERS) {
        Rule::Pii
    } else if WALLET_KEYS.contains(&key) {
        Rule::Wallet
    } else {
        Rule::Walk
    }
}

/// Recursively redact credentials, key material, PII and user content from a
/// JSON value, by key name and by the shape of every string it holds.
pub fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let in_jwk = map.contains_key("kty");
            for (key, val) in map.iter_mut() {
                match rule_for(key, in_jwk) {
                    Rule::Config => replace_strings(val, &|_| "[REDACTED-CONFIG]".to_string()),
                    Rule::Did => replace_strings(val, &|s| {
                        if s.starts_with("did:") {
                            did_hash(s)
                        } else {
                            redact_text(s)
                        }
                    }),
                    Rule::Secret => replace_strings(val, &|_| "[REDACTED-SECRET]".to_string()),
                    Rule::Content => replace_strings(val, &|_| "[REDACTED-CONTENT]".to_string()),
                    Rule::Pii => replace_strings(val, &|_| "[REDACTED]".to_string()),
                    Rule::Email => replace_strings(val, &|_| "[REDACTED-EMAIL]".to_string()),
                    Rule::Wallet => replace_strings(val, &|_| "[REDACTED-WALLET]".to_string()),
                    Rule::Walk => redact_json(val),
                }
            }
            redact_keys(map);
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json(item);
            }
        }
        Value::String(s) => *s = redact_free_text(s),
        _ => {}
    }
}

/// Replace every non-empty string in a JSON subtree with `replace(string)`;
/// numbers, booleans and nulls are kept.
fn replace_strings(
    value: &mut Value,
    replace: &dyn Fn(&str) -> String,
) {
    match value {
        Value::String(s) if !s.is_empty() => {
            *s = replace(s);
        }
        Value::Object(map) => {
            for val in map.values_mut() {
                replace_strings(val, replace);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                replace_strings(item, replace);
            }
        }
        _ => {}
    }
}

/// A free-text string: a whole DID becomes its correlation hash, and emails,
/// DIDs and IPv4 addresses inside it are redacted.
fn redact_free_text(value: &str) -> String {
    if value.starts_with("did:") && value.len() > 10 && !value.contains(char::is_whitespace) {
        did_hash(value)
    } else {
        redact_text(value)
    }
}

/// Object keys can be data too (a DID, an email or an address used as a map
/// key). Such a key becomes a correlation hash: a DID's own hash, otherwise
/// `redacted:<hash8>`.
fn redact_keys(map: &mut Map<String, Value>) {
    if !map
        .keys()
        .any(|key| redact_text(key) != *key)
    {
        return;
    }
    for (key, val) in std::mem::take(map) {
        let key = if redact_text(&key) == key {
            key
        } else if key.starts_with("did:") {
            did_hash(&key)
        } else {
            format!("redacted:{}", hex::encode(&Sha256::digest(key.as_bytes())[..4]))
        };
        map.insert(key, val);
    }
}

/// Redact emails, DIDs and IPv4 addresses in free text.
pub fn redact_text(content: &str) -> String {
    let result = EMAIL_RE.replace_all(content, "[REDACTED-EMAIL]");
    let result = DID_RE.replace_all(&result, "did:redacted:***");
    let result = IPV4_RE.replace_all(&result, "[REDACTED-IP]");
    result.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_excluded_dirs() {
        assert!(is_excluded_dir("identities"));
        assert!(is_excluded_dir("secrets"));
        assert!(is_excluded_dir("avatars"));
        assert!(!is_excluded_dir("channels"));
        assert!(!is_excluded_dir("metrics"));
    }

    #[test]
    fn test_did_hash_consistency() {
        let hash1 = did_hash("did:peer:abc123");
        let hash2 = did_hash("did:peer:abc123");
        assert_eq!(hash1, hash2, "same DID should produce same hash");
        assert!(hash1.starts_with("did:redacted:"));
        assert_eq!(hash1.len(), "did:redacted:".len() + 8);
    }

    #[test]
    fn test_did_hash_different_dids() {
        let hash1 = did_hash("did:peer:abc123");
        let hash2 = did_hash("did:peer:xyz789");
        assert_ne!(hash1, hash2, "different DIDs should produce different hashes");
    }

    #[test]
    fn test_redact_json_session() {
        let mut val = json!({
            "token": "secret-session-token",
            "username": "alice",
            "user_id": "u-123",
            "created_at": "2025-01-01T00:00:00Z",
            "expires_at": "2025-01-02T00:00:00Z"
        });
        redact_json(&mut val);
        assert_eq!(val["token"], "[REDACTED-SECRET]");
        assert_eq!(val["username"], "[REDACTED]");
        assert_eq!(val["user_id"], "[REDACTED]");
        assert_eq!(val["created_at"], "2025-01-01T00:00:00Z");
    }

    #[test]
    fn test_redact_json_settings_prometheus_password_hash() {
        let mut val = json!({
            "prometheus_auth_enabled": true,
            "prometheus_auth_password_hash": "$2b$12$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012",
            "refresh_interval_seconds": 5
        });
        redact_json(&mut val);
        assert_eq!(val["prometheus_auth_password_hash"], "[REDACTED-SECRET]");
        assert_eq!(val["prometheus_auth_enabled"], true);
        assert_eq!(val["refresh_interval_seconds"], 5);
    }

    #[test]
    fn test_redact_json_gateway() {
        let mut val = json!({
            "name": "my-gateway",
            "description": "Test gateway",
            "did": "did:peer:2.Ez6LSkGy4e7xNAREqtBPSmUu2Ni4GcmPBkJHbaSqcjgCcw.Vz6Mkud87w",
            "exposed_channels": ["ch-1", "ch-2"]
        });
        redact_json(&mut val);
        assert!(
            val["did"]
                .as_str()
                .unwrap()
                .starts_with("did:redacted:")
        );
        assert_eq!(val["name"], "my-gateway"); // config name preserved
    }

    #[test]
    fn test_redact_json_wallet_fields() {
        let mut val = json!({
            "correlation_id": "corr-123",
            "settlement": {
                "tx_hash": "0xabcdef1234567890",
                "pay_to": "0xWalletAddress123",
                "from_address": "0xSenderAddress456",
                "amount": "1.5",
                "network": "base-mainnet"
            }
        });
        redact_json(&mut val);
        assert_eq!(val["settlement"]["tx_hash"], "[REDACTED-WALLET]");
        assert_eq!(val["settlement"]["pay_to"], "[REDACTED-WALLET]");
        assert_eq!(val["settlement"]["from_address"], "[REDACTED-WALLET]");
        assert_eq!(val["settlement"]["amount"], "1.5"); // amount preserved
    }

    #[test]
    fn test_redact_json_integration_configuration() {
        let mut val = json!({
            "name": "email-notifier",
            "configuration": {
                "smtp_host": "smtp.example.com",
                "smtp_user": "admin@example.com",
                "smtp_password": "hunter2",
                "port": 587
            },
            "content": {
                "subject": "Alert",
                "body": "Hello"
            }
        });
        redact_json(&mut val);
        assert_eq!(val["configuration"]["smtp_host"], "[REDACTED-CONFIG]");
        assert_eq!(val["configuration"]["smtp_password"], "[REDACTED-CONFIG]");
        assert_eq!(val["configuration"]["port"], 587); // numbers preserved
        assert_eq!(val["name"], "email-notifier"); // name outside config preserved
    }

    #[test]
    fn test_redact_json_connection_with_dids() {
        let mut val = json!({
            "our_temporary_did": "did:key:z6Mk123",
            "our_secure_did": "did:peer:2.abc",
            "their_temporary_did": "did:key:z6Mk456",
            "their_secure_did": "did:peer:2.xyz",
            "mediator_did": "did:web:mediator.example.com",
            "invitation_id": "inv-001"
        });
        redact_json(&mut val);
        for key in ["our_temporary_did", "our_secure_did", "their_temporary_did", "their_secure_did", "mediator_did"] {
            assert!(
                val[key]
                    .as_str()
                    .unwrap()
                    .starts_with("did:redacted:"),
                "key {key} not redacted"
            );
        }
        assert_eq!(val["invitation_id"], "inv-001");
    }

    #[test]
    fn test_redact_json_email_in_value() {
        let mut val = json!({
            "notification_to": "user@example.com",
            "count": 5
        });
        redact_json(&mut val);
        assert_eq!(val["notification_to"], "[REDACTED-EMAIL]");
        assert_eq!(val["count"], 5);
    }

    #[test]
    fn test_redact_json_empty_values_unchanged() {
        let mut val = json!({
            "token": "",
            "username": "",
            "email": ""
        });
        redact_json(&mut val);
        assert_eq!(val["token"], "");
        assert_eq!(val["username"], "");
        assert_eq!(val["email"], "");
    }

    #[test]
    fn credential_fields_are_redacted_by_name_at_any_depth() {
        let mut val = json!({
            "provider": {
                "refresh_token": "rt",
                "access_token": "at",
                "id_token": "it",
                "code_verifier": "cv",
                "client_secret": "cs",
                "smtp_password": "pw",
                "Authorization": "Bearer x",
                "set_cookie": "c=1",
                "signing_private_key": "pk",
                "token_hash": "th",
                "expires_in": 3600,
                "provider_name": "github"
            }
        });
        redact_json(&mut val);
        for key in [
            "refresh_token",
            "access_token",
            "id_token",
            "code_verifier",
            "client_secret",
            "smtp_password",
            "Authorization",
            "set_cookie",
            "signing_private_key",
            "token_hash",
        ] {
            assert_eq!(val["provider"][key], "[REDACTED-SECRET]", "{key}");
        }
        assert_eq!(val["provider"]["expires_in"], 3600);
        assert_eq!(val["provider"]["provider_name"], "github");
    }

    #[test]
    fn a_secret_valued_object_or_array_is_redacted_whole() {
        let mut val = json!({
            "our_secrets": [{ "id": "did:peer:x#key-1", "type": "JsonWebKey2020", "material": { "d": "dd" } }],
            "secret_material": { "kty": "OKP", "x": "pub", "d": "dd" },
            "name": "mediator"
        });
        redact_json(&mut val);
        let text = val.to_string();
        assert!(!text.contains("dd"), "{text}");
        assert!(!text.contains("JsonWebKey2020"), "{text}");
        assert_eq!(val["our_secrets"][0]["material"]["d"], "[REDACTED-SECRET]");
        assert_eq!(val["name"], "mediator");
    }

    #[test]
    fn jwk_private_members_are_redacted_and_public_members_kept() {
        let mut val = json!({
            "verificationMethod": [{
                "publicKeyJwk": { "kty": "RSA", "n": "modulus", "e": "AQAB", "d": "priv", "p": "p1", "q": "q1",
                                  "dp": "dp1", "dq": "dq1", "qi": "qi1" }
            }],
            "symmetric": { "kty": "oct", "k": "shared" },
            "plain": { "d": "not-a-jwk" }
        });
        redact_json(&mut val);
        let jwk = &val["verificationMethod"][0]["publicKeyJwk"];
        for member in ["d", "p", "q", "dp", "dq", "qi"] {
            assert_eq!(jwk[member], "[REDACTED-SECRET]", "{member}");
        }
        assert_eq!(jwk["n"], "modulus");
        assert_eq!(jwk["e"], "AQAB");
        assert_eq!(val["symmetric"]["k"], "[REDACTED-SECRET]");
        assert_eq!(val["plain"]["d"], "not-a-jwk");
    }

    #[test]
    fn user_content_is_redacted() {
        let mut val = json!({
            "prompt": "my ssn is 123-45-6789",
            "completion": "ok",
            "messages": [{ "role": "user", "content": "hello" }],
            "output": "reply",
            "latency_ms": 12,
            "surface_id": "s1"
        });
        redact_json(&mut val);
        assert_eq!(val["prompt"], "[REDACTED-CONTENT]");
        assert_eq!(val["completion"], "[REDACTED-CONTENT]");
        assert_eq!(val["messages"][0]["content"], "[REDACTED-CONTENT]");
        assert_eq!(val["output"], "[REDACTED-CONTENT]");
        assert_eq!(val["latency_ms"], 12);
        assert_eq!(val["surface_id"], "s1");
    }

    #[test]
    fn test_excluded_credential_and_media_dirs() {
        for dir in [
            "delegation_vault",
            "access_tokens",
            "api_keys",
            "multimedia_store",
            "messages",
            "members",
            "enrolment",
            "did",
            "did_cache",
            "passkeys.backup-2026-10-01",
            "sessions.bak",
        ] {
            assert!(is_excluded_dir(dir), "{dir}");
        }
        for dir in ["surfaces", "passkeysx", "did_logs", "membership"] {
            assert!(!is_excluded_dir(dir), "{dir}");
        }
    }

    #[test]
    fn hyphenated_header_names_and_header_maps_are_redacted() {
        let mut val = json!({
            "headers": { "X-API-Key": "k1", "Content-Type": "application/json" },
            "upstream": { "x-goog-api-key": "k2", "Ocp-Apim-Subscription-Key": "k3" },
            "header_name": "X-Custom-Auth"
        });
        redact_json(&mut val);
        let text = val.to_string();
        for leaked in ["k1", "k2", "application/json", "X-Custom-Auth"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert!(
            val["headers"]
                .get("X-API-Key")
                .is_some(),
            "header names are kept"
        );
    }

    #[test]
    fn strings_in_arrays_and_mid_sentence_are_scrubbed() {
        let mut val = json!({
            "to_dids": ["did:peer:2.Ezabcdef"],
            "notify": ["alice@corp.com", "plain"],
            "note": "sent to bob@corp.com from 10.1.2.3 via did:web:example.com",
            "count": 2
        });
        redact_json(&mut val);
        assert!(
            val["to_dids"][0]
                .as_str()
                .unwrap()
                .starts_with("did:redacted:")
        );
        assert_eq!(val["notify"][0], "[REDACTED-EMAIL]");
        assert_eq!(val["notify"][1], "plain");
        let note = val["note"].as_str().unwrap();
        for leaked in ["bob@corp.com", "10.1.2.3", "did:web:example.com"] {
            assert!(!note.contains(leaked), "{leaked} in {note}");
        }
        assert_eq!(val["count"], 2);
    }

    #[test]
    fn keys_that_are_data_become_correlation_hashes() {
        let mut val = json!({
            "connections": {
                "did:peer:2.Ezabcdef": { "count": 1 },
                "alice@corp.com": { "count": 2 },
                "203.0.113.9": { "count": 3 },
                "surface-1": { "count": 4 }
            }
        });
        redact_json(&mut val);
        let text = val.to_string();
        for leaked in ["did:peer:2.Ezabcdef", "alice@corp.com", "203.0.113.9"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        let connections = val["connections"]
            .as_object()
            .unwrap();
        assert_eq!(connections.len(), 4, "distinct keys stay distinct");
        assert_eq!(connections["surface-1"]["count"], 4);
        assert!(connections.contains_key(&did_hash("did:peer:2.Ezabcdef")));
    }

    #[test]
    fn every_content_and_person_key_is_redacted() {
        let mut val = json!({
            "transcript": "caller said hello",
            "sample_input": "{\"prompt\":\"hi\"}",
            "message_body": { "text": "passport X1234567" },
            "full_name": "John Smith",
            "display_name": "Johnny",
            "contact_email": "j@corp.com",
            "did": "not-a-did reach me at j@corp.com"
        });
        redact_json(&mut val);
        assert_eq!(val["transcript"], "[REDACTED-CONTENT]");
        assert_eq!(val["sample_input"], "[REDACTED-CONTENT]");
        assert_eq!(val["message_body"]["text"], "[REDACTED-CONTENT]");
        assert_eq!(val["full_name"], "[REDACTED]");
        assert_eq!(val["display_name"], "[REDACTED]");
        assert_eq!(val["contact_email"], "[REDACTED-EMAIL]");
        assert_eq!(val["did"], "not-a-did reach me at [REDACTED-EMAIL]");
    }

    #[test]
    fn person_fields_are_redacted_whatever_their_shape() {
        let mut val = json!({
            "prometheus_auth_username": "metrics-admin",
            "created_by": "alice",
            "phone_number": "+15550100",
            "email": ["a@corp.com", "b@corp.com"],
            "subject": "user-42",
            "principal_key": "member:alice"
        });
        redact_json(&mut val);
        assert_eq!(val["prometheus_auth_username"], "[REDACTED]");
        assert_eq!(val["created_by"], "[REDACTED]");
        assert_eq!(val["phone_number"], "[REDACTED]");
        assert_eq!(val["email"], json!(["[REDACTED-EMAIL]", "[REDACTED-EMAIL]"]));
        assert_eq!(val["subject"], "[REDACTED]");
        assert_eq!(val["principal_key"], "[REDACTED]");
    }

    #[test]
    fn test_redact_text_emails() {
        let input = "Sending to user@example.com and admin@test.org";
        let result = redact_text(input);
        assert!(!result.contains("user@example.com"));
        assert!(!result.contains("admin@test.org"));
        assert!(result.contains("[REDACTED-EMAIL]"));
    }

    #[test]
    fn test_redact_text_ips() {
        let input = "Connection from 192.168.1.100 to 10.0.0.1";
        let result = redact_text(input);
        assert!(!result.contains("192.168.1.100"));
        assert!(!result.contains("10.0.0.1"));
        assert!(result.contains("[REDACTED-IP]"));
    }

    #[test]
    fn test_redact_text_dids() {
        let input = "Resolved did:peer:2.Ez6LSk from did:web:example.com";
        let result = redact_text(input);
        assert!(!result.contains("did:peer:2.Ez6LSk"));
        assert!(!result.contains("did:web:example.com"));
        assert!(result.contains("did:redacted:***"));
    }

    #[test]
    fn test_redact_text_mixed() {
        let input = "2025-03-18 10:00:00 [INFO] User admin@corp.com from 10.1.2.3 resolved did:key:z6Mk12345";
        let result = redact_text(input);
        assert!(result.contains("2025-03-18 10:00:00 [INFO]"));
        assert!(!result.contains("admin@corp.com"));
        assert!(!result.contains("10.1.2.3"));
        assert!(!result.contains("did:key:z6Mk12345"));
    }
}
