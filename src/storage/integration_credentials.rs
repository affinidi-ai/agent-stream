//! How the integration API answers, accepts and delivers credentials.
//!
//! Responses leave stored credentials out. A save that leaves a stored inline
//! credential out keeps it, `null` clears it, and a new credential is a
//! `<key>_secret_id` (or `headers_secret_id`) reference to the secrets store,
//! resolved for the integration's tenant at delivery.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, LazyLock, OnceLock};

use axum::http::StatusCode;
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value as JsonValue};

use crate::auth_manager::pat::PatResourceScope;
use crate::secrets::{SecretsStore, SurfaceSecrets};
use crate::storage::Integration;
use crate::tenancy::PatTenantContext;
use crate::url_validation::UrlRefusal;

/// A placeholder for a stored credential. The API never answers it, so a
/// request carrying it is refused rather than guessed at.
pub(crate) const MASKED_CREDENTIAL: &str = "********";

const REFERENCE_SUFFIX: &str = "_secret_id";
const HEADERS: &str = "headers";
const HEADER_REFERENCES: &str = "headers_secret_id";

/// Configuration keys that embed a credential without naming one: a webhook URL
/// (Slack, Teams, Discord, or a `?token=` query) is a bearer secret, a Redis URL
/// can carry a password and webhook headers carry auth tokens.
const CREDENTIAL_KEYS: &[&str] = &[HEADERS, "redis_url", "url", "webhook_url"];

/// Key endings that name a credential (`smtp_password`, `signing_secret`,
/// Langfuse `secret_key`, `provider_api_key`, Pulsar `auth_token`, ...).
const CREDENTIAL_KEY_SUFFIXES: &[&str] =
    &["password", "secret", "secret_key", "api_key", "apikey", "token", "private_key", "access_key", "credentials"];

/// The one credential a save may carry inline: the webhook signing secret, which
/// the dashboard generates and never leaves the appliance except as a signature.
const SIGNING_SECRET: &str = "signing_secret";
const MIN_SIGNING_SECRET_LEN: usize = 32;

/// URL keys whose host and port a save pins when they are references, so a
/// later edit of the secret's value cannot move the destination.
const URL_KEYS: &[&str] = &["redis_url", "url", "webhook_url"];

const REDIS_URL: &str = "redis_url";

/// Whether `raw` is a `redis://` URL with a host, the only Redis URL a stream
/// delivers to. A referenced value is checked with this before anything that
/// could describe it, so every other value gets the same answer.
fn is_redis_url(raw: &str) -> bool {
    url::Url::parse(raw.trim()).is_ok_and(|url| {
        url.scheme() == "redis"
            && url
                .host_str()
                .is_some_and(|host| !host.is_empty())
    })
}

/// The destination a save recorded for the references it resolved: the host
/// and port of each referenced URL and a digest of each referenced routing
/// header. Set by the server only.
pub(crate) const PINNED_DESTINATION: &str = "pinned_destination";

/// Header-name parts that mark a credential. A header carries a credential
/// under many more names than a configuration key does.
const CREDENTIAL_HEADER_PARTS: &[&str] = &["auth", "cookie", "cred", "key", "pass", "secret", "session", "token"];

/// Settings that decide where an integration delivers, and so where a kept
/// credential would be sent.
const DESTINATION_KEYS: &[&str] =
    &["url", "webhook_url", "redis_url", "smtp_host", "smtp_port", "brokers", "host", "platform", "region"];

/// Headers a shared ingress or virtual-host proxy routes on.
const ROUTING_HEADERS: &[&str] = &["host", "x-forwarded-host", "forwarded"];

/// Matched case-insensitively, since `configuration` is free-form JSON.
fn is_credential_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    CREDENTIAL_KEYS.contains(&key.as_str())
        || CREDENTIAL_KEY_SUFFIXES
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

/// A header name counts when it contains a credential part anywhere, so
/// `X-Authorization`, `Authentication`, `X-Credential` and `X-Passwd` count as
/// well as `apikey`, `token` and `X-Password`. A header counted by mistake is
/// only sent by reference.
fn is_credential_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    CREDENTIAL_HEADER_PARTS
        .iter()
        .any(|part| name.contains(part))
}

/// A `${NAME}` runtime-variable reference. A `${NAME:default}` reference is not
/// matched, since its default is a literal that can hold a secret.
static TEMPLATE_REFERENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{[A-Za-z0-9_]+\}").expect("valid template reference regex"));

/// A value made only of runtime-variable references is a template filled at
/// delivery, not a stored secret.
fn is_template_only(text: &str) -> bool {
    TEMPLATE_REFERENCE.is_match(text)
        && TEMPLATE_REFERENCE
            .replace_all(text, "")
            .trim()
            .is_empty()
}

/// Whether a credential value holds something secret, so a response leaves it out.
fn holds_secret(value: &JsonValue) -> bool {
    match value {
        JsonValue::Null => false,
        JsonValue::String(text) => !text.is_empty() && !is_template_only(text),
        _ => true,
    }
}

fn is_hidden(
    key: &str,
    value: &JsonValue,
) -> bool {
    !key.eq_ignore_ascii_case(HEADERS) && is_credential_key(key) && holds_secret(value)
}

fn is_hidden_header(
    name: &str,
    value: &JsonValue,
) -> bool {
    is_credential_header(name) && holds_secret(value)
}

/// An integration as the API answers it, with every stored credential left
/// out of its configuration. The only way to build one is from an
/// [`Integration`], so no handler can answer a credential by forgetting a step.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub(crate) struct IntegrationView(Integration);

impl From<Integration> for IntegrationView {
    fn from(mut integration: Integration) -> Self {
        if let Some(entries) = integration
            .configuration
            .as_object_mut()
        {
            omit_credentials(entries);
            omit_routing_header_digests(entries);
        }
        Self(integration)
    }
}

/// A routing header's value is usually a guessable host name, so its digest
/// would confirm a guess. Responses keep the pinned URL hosts and leave the
/// digests out.
fn omit_routing_header_digests(entries: &mut Map<String, JsonValue>) {
    if let Some(pin) = entries
        .get_mut(PINNED_DESTINATION)
        .and_then(JsonValue::as_object_mut)
    {
        pin.remove(HEADERS);
    }
}

impl IntegrationView {
    #[cfg(test)]
    pub(crate) fn integration(&self) -> &Integration {
        &self.0
    }
}

fn omit_credentials(entries: &mut Map<String, JsonValue>) {
    entries.retain(|key, value| {
        if key.eq_ignore_ascii_case(HEADERS) {
            return match value.as_object_mut() {
                Some(headers) => {
                    headers.retain(|name, value| !is_hidden_header(name, value));
                    true
                }
                None => !holds_secret(value),
            };
        }
        !is_hidden(key, value)
    });
}

type Refusal = (StatusCode, String);

fn refuse(message: String) -> Refusal {
    (StatusCode::BAD_REQUEST, message)
}

/// Whether a request may carry a new credential inline. A save stores what it
/// is sent, so only a reference is accepted; a test sends it once and stores
/// nothing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewCredentials {
    ReferencesOnly,
    InlineAllowed,
}

/// Applies the credential rules to a create, update or test `configuration`,
/// with `stored` the saved integration it edits (`None` on create or a test
/// without one).
///
/// A stored inline credential the request leaves out (or sends as `""`) is
/// kept, unless a reference replaces it; `null` clears it. A kept secret is
/// refused when the type or any destination differs from `stored`, so it is
/// never sent somewhere new.
pub(crate) fn apply_credential_rules(
    integration_type: &str,
    configuration: &mut JsonValue,
    stored: Option<&Integration>,
    new_credentials: NewCredentials,
) -> Result<(), Refusal> {
    let Some(entries) = configuration.as_object_mut() else {
        return Ok(());
    };
    entries.remove(PINNED_DESTINATION);
    refuse_placeholders(entries, None)?;
    normalise_references(entries)?;
    let cleared = take_cleared(entries);
    if new_credentials == NewCredentials::ReferencesOnly {
        refuse_new_inline_credentials(entries)?;
    }
    let Some(stored) = stored else {
        return Ok(());
    };
    let mut merged = entries.clone();
    if keep_stored_credentials(&mut merged, stored, &cleared) && destination_changed(integration_type, &merged, stored)
    {
        return Err(refuse("Re-enter the credentials when changing where this integration sends".to_string()));
    }
    *entries = merged;
    Ok(())
}

fn refuse_placeholders(
    entries: &Map<String, JsonValue>,
    parent: Option<&str>,
) -> Result<(), Refusal> {
    for (key, value) in entries {
        let path = parent.map_or_else(|| key.clone(), |parent| format!("{parent}.{key}"));
        match value {
            JsonValue::String(text) if text == MASKED_CREDENTIAL => {
                return Err(refuse(format!("Re-enter the value for {path}, or leave it out to keep the saved one")));
            }
            JsonValue::Object(nested) => refuse_placeholders(nested, Some(&path))?,
            _ => {}
        }
    }
    Ok(())
}

fn is_unset(value: Option<&JsonValue>) -> bool {
    match value {
        None | Some(JsonValue::Null) => true,
        Some(JsonValue::String(text)) => text.is_empty(),
        Some(_) => false,
    }
}

/// Looks `name` up case-insensitively, as credential keys are matched.
fn named<'a>(
    entries: &'a Map<String, JsonValue>,
    name: &str,
) -> Option<&'a JsonValue> {
    entries
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn header_named<'a>(
    headers: Option<&'a JsonValue>,
    name: &str,
) -> Option<&'a JsonValue> {
    named(headers.and_then(JsonValue::as_object)?, name)
}

/// Drops empty references, checks each names a credential, and refuses a
/// credential sent both inline and by reference.
fn normalise_references(entries: &mut Map<String, JsonValue>) -> Result<(), Refusal> {
    if let Some(key) = entries.keys().find(|key| {
        !key.ends_with(REFERENCE_SUFFIX)
            && key
                .to_ascii_lowercase()
                .ends_with(REFERENCE_SUFFIX)
    }) {
        return Err(refuse(format!("{key} must end in {REFERENCE_SUFFIX}")));
    }
    entries.retain(|key, value| !(key.ends_with(REFERENCE_SUFFIX) && is_unset(Some(value))));
    if let Some(references) = entries.get_mut(HEADER_REFERENCES) {
        let Some(references) = references.as_object_mut() else {
            return Err(refuse(format!("{HEADER_REFERENCES} must map header names to secret ids")));
        };
        references.retain(|_, reference| !is_unset(Some(reference)));
    }
    for (key, value) in entries.iter() {
        let Some(credential) = key.strip_suffix(REFERENCE_SUFFIX) else {
            continue;
        };
        if key == HEADER_REFERENCES {
            for (name, reference) in value
                .as_object()
                .into_iter()
                .flatten()
            {
                if !reference.is_string() {
                    return Err(refuse(format!("{HEADER_REFERENCES}.{name} must be a secret id")));
                }
                if !is_unset(header_named(entries.get(HEADERS), name)) {
                    return Err(refuse(format!("Send the {name} header inline or by reference, not both")));
                }
            }
            continue;
        }
        if !is_credential_key(credential) || credential.eq_ignore_ascii_case(HEADERS) {
            return Err(refuse(format!("{key} does not name a credential")));
        }
        if !value.is_string() {
            return Err(refuse(format!("{key} must be a secret id")));
        }
        if !is_unset(named(entries, credential)) {
            return Err(refuse(format!("Send {credential} or {key}, not both")));
        }
    }
    Ok(())
}

/// Removes every credential the request sets to `null` and returns their
/// lower-cased names (headers prefixed `headers.`, and `headers` itself when
/// every header is cleared), so they are cleared instead of kept. A credential
/// sent as `""` is removed too, which keeps it.
fn take_cleared(entries: &mut Map<String, JsonValue>) -> HashSet<String> {
    let mut cleared = HashSet::new();
    entries.retain(|key, value| {
        if key.eq_ignore_ascii_case(HEADERS) && value.is_null() {
            cleared.insert(HEADERS.to_string());
            return false;
        }
        if key.eq_ignore_ascii_case(HEADERS) || !is_credential_key(key) || !is_unset(Some(value)) {
            return true;
        }
        if value.is_null() {
            cleared.insert(key.to_ascii_lowercase());
        }
        false
    });
    if let Some(headers) = entries
        .get_mut(HEADERS)
        .and_then(JsonValue::as_object_mut)
    {
        headers.retain(|name, value| {
            if !is_credential_header(name) || !is_unset(Some(value)) {
                return true;
            }
            if value.is_null() {
                cleared.insert(format!("{HEADERS}.{}", name.to_ascii_lowercase()));
            }
            false
        });
    }
    cleared
}

fn refuse_new_inline_credentials(entries: &Map<String, JsonValue>) -> Result<(), Refusal> {
    for (key, value) in entries {
        if key.eq_ignore_ascii_case(HEADERS) {
            for (name, value) in value
                .as_object()
                .into_iter()
                .flatten()
            {
                if is_hidden_header(name, value) {
                    return Err(refuse(format!(
                        "Store the {name} header in Secrets and reference it in {HEADER_REFERENCES}"
                    )));
                }
            }
        } else if is_hidden(key, value) {
            if !key.eq_ignore_ascii_case(SIGNING_SECRET) {
                return Err(refuse(format!("Store {key} in Secrets and send {key}{REFERENCE_SUFFIX}")));
            }
            if value
                .as_str()
                .is_some_and(|secret| secret.chars().count() < MIN_SIGNING_SECRET_LEN)
            {
                return Err(refuse(format!("{key} must be at least {MIN_SIGNING_SECRET_LEN} characters")));
            }
        }
    }
    Ok(())
}

/// Puts back each stored inline credential the request left out, templates
/// included since a form may have no field for one, and returns whether a
/// secret was kept.
fn keep_stored_credentials(
    entries: &mut Map<String, JsonValue>,
    stored: &Integration,
    cleared: &HashSet<String>,
) -> bool {
    let Some(stored_entries) = stored
        .configuration
        .as_object()
    else {
        return false;
    };
    let mut kept = false;
    for (key, value) in stored_entries {
        if key.eq_ignore_ascii_case(HEADERS)
            || !is_credential_key(key)
            || is_unset(Some(value))
            || named(entries, key).is_some()
            || named(entries, &format!("{key}{REFERENCE_SUFFIX}")).is_some()
            || cleared.contains(&key.to_ascii_lowercase())
        {
            continue;
        }
        entries.insert(key.clone(), value.clone());
        kept |= holds_secret(value);
    }
    let stored_headers = stored_entries
        .get(HEADERS)
        .and_then(JsonValue::as_object)
        .filter(|_| !cleared.contains(HEADERS));
    for (name, value) in stored_headers
        .into_iter()
        .flatten()
    {
        if !is_hidden_header(name, value)
            || header_named(entries.get(HEADERS), name).is_some()
            || header_named(entries.get(HEADER_REFERENCES), name).is_some()
            || cleared.contains(&format!("{HEADERS}.{}", name.to_ascii_lowercase()))
        {
            continue;
        }
        let headers = entries
            .entry(HEADERS)
            .or_insert_with(|| JsonValue::Object(Map::new()));
        if !headers.is_object() {
            *headers = JsonValue::Object(Map::new());
        }
        if let Some(headers) = headers.as_object_mut() {
            headers.insert(name.clone(), value.clone());
            kept = true;
        }
    }
    kept
}

/// A missing key, `null` and `""` all mean "not set", so a form that sends
/// empty fields it never stored does not count as a new destination.
fn setting<'a>(
    entries: &'a Map<String, JsonValue>,
    key: &str,
) -> Option<&'a JsonValue> {
    let value = entries.get(key);
    (!is_unset(value))
        .then_some(value)
        .flatten()
}

/// The routing headers `entries` sends, inline or by reference, keyed by
/// lower-cased name and whether the value is a secret reference.
fn routing_headers(entries: &Map<String, JsonValue>) -> BTreeMap<(String, bool), &JsonValue> {
    [(HEADERS, false), (HEADER_REFERENCES, true)]
        .into_iter()
        .flat_map(|(key, by_reference)| {
            entries
                .get(key)
                .and_then(JsonValue::as_object)
                .into_iter()
                .flatten()
                .map(move |(name, value)| ((name.to_ascii_lowercase(), by_reference), value))
        })
        .filter(|((name, _), value)| ROUTING_HEADERS.contains(&name.as_str()) && !is_unset(Some(value)))
        .collect()
}

/// Whether `entries` would deliver somewhere `stored` does not. A destination
/// held in a secret reference counts as well as an inline one, so a kept
/// credential cannot follow a swapped reference.
fn destination_changed(
    integration_type: &str,
    entries: &Map<String, JsonValue>,
    stored: &Integration,
) -> bool {
    let empty = Map::new();
    let stored_entries = stored
        .configuration
        .as_object()
        .unwrap_or(&empty);
    integration_type != stored.integration_type
        || DESTINATION_KEYS
            .iter()
            .flat_map(|key| [key.to_string(), format!("{key}{REFERENCE_SUFFIX}")])
            .any(|key| setting(entries, &key) != setting(stored_entries, &key))
        || routing_headers(entries) != routing_headers(stored_entries)
        || smtp_encryption_dropped(entries, stored)
}

/// True when the stored email integration sends over TLS and `entries` would
/// send in the clear, so a kept SMTP password would cross the network
/// unencrypted.
fn smtp_encryption_dropped(
    entries: &Map<String, JsonValue>,
    stored: &Integration,
) -> bool {
    use crate::integrations::email_service::SmtpSecurity;
    let stored_security = stored
        .configuration
        .as_object()
        .and_then(SmtpSecurity::of_configuration);
    stored.integration_type == "email"
        && stored_security.is_some_and(|security| security != SmtpSecurity::Plaintext)
        && SmtpSecurity::of_configuration(entries) == Some(SmtpSecurity::Plaintext)
}

/// The secrets `configuration` references, by the id each reference names.
pub(crate) fn referenced_secrets(configuration: &JsonValue) -> HashSet<String> {
    secret_references(configuration)
        .into_iter()
        .map(|(_, reference)| reference)
        .collect()
}

/// Every secret reference in `configuration`, as (where it is, secret id).
fn secret_references(configuration: &JsonValue) -> Vec<(String, String)> {
    let mut references = Vec::new();
    for (key, value) in configuration
        .as_object()
        .into_iter()
        .flatten()
    {
        if key == HEADER_REFERENCES {
            for (name, reference) in value
                .as_object()
                .into_iter()
                .flatten()
            {
                if let Some(reference) = reference.as_str() {
                    references.push((format!("{HEADER_REFERENCES}.{name}"), reference.to_string()));
                }
            }
        } else if key.ends_with(REFERENCE_SUFFIX)
            && let Some(reference) = value.as_str()
        {
            references.push((key.clone(), reference.to_string()));
        }
    }
    references
}

/// Whether `configuration` would send a referenced secret somewhere `stored`
/// does not: a reference `stored` does not hold, or any reference once the
/// destination changes.
pub(crate) fn pairs_secret_with_new_destination(
    integration_type: &str,
    configuration: &JsonValue,
    stored: Option<&Integration>,
) -> bool {
    let references = secret_references(configuration);
    if references.is_empty() {
        return false;
    }
    let Some(stored) = stored else {
        return true;
    };
    let empty = Map::new();
    if destination_changed(
        integration_type,
        configuration
            .as_object()
            .unwrap_or(&empty),
        stored,
    ) {
        return true;
    }
    let held: HashSet<_> = secret_references(&stored.configuration)
        .into_iter()
        .collect();
    references
        .into_iter()
        .any(|reference| !held.contains(&reference))
}

/// The setting that is the address an integration of `integration_type`
/// delivers to: a webhook's `url`, a Slack `webhook_url`, and the `redis_url`
/// of a Redis stream. Other types, and other URL keys, deliver to no URL.
fn address_key(
    integration_type: &str,
    configuration: &JsonValue,
) -> Option<&'static str> {
    match integration_type {
        "webhook" => Some("url"),
        "slack" => Some("webhook_url"),
        "stream"
            if configuration
                .get("platform")
                .and_then(JsonValue::as_str)
                == Some("redis") =>
        {
            Some("redis_url")
        }
        _ => None,
    }
}

/// Whether every secret `configuration` references is the URL an integration
/// of `integration_type` delivers to (see [`address_key`]). Such a value only
/// ever becomes the address of the request, so it reaches no one but that
/// address's own host, and the save pins that host. A URL key the type does
/// not deliver to would only be pinned, and the pin answered, so it counts as
/// more than the address. A routing header could hand the request to another
/// virtual host behind the same ingress, and a kept inline credential would
/// follow the address, so either one counts as more than the address too.
pub(crate) fn references_only_addresses(
    integration_type: &str,
    configuration: &JsonValue,
) -> bool {
    let Some(address) = address_key(integration_type, configuration) else {
        return false;
    };
    let empty = Map::new();
    routing_headers(
        configuration
            .as_object()
            .unwrap_or(&empty),
    )
    .is_empty()
        && inline_credentials(configuration).is_empty()
        && secret_references(configuration)
            .iter()
            .all(|(key, _)| key.strip_suffix(REFERENCE_SUFFIX) == Some(address))
}

/// Whether `configuration` sends the signing secret `stored` holds. The secret
/// signs whatever a test sends, so a destination it was not confirmed for would
/// receive signatures its real receiver accepts.
pub(crate) fn keeps_signing_secret(
    configuration: &JsonValue,
    stored: &Integration,
) -> bool {
    let signing_secret = |configuration: &JsonValue| {
        configuration
            .as_object()
            .and_then(|entries| named(entries, SIGNING_SECRET))
            .filter(|value| holds_secret(value))
            .cloned()
    };
    signing_secret(configuration).is_some_and(|value| signing_secret(&stored.configuration) == Some(value))
}

/// The first URL key `configuration` references, which a refusal answered
/// while values are hidden is named after.
pub(crate) fn referenced_url_key(configuration: &JsonValue) -> Option<&'static str> {
    URL_KEYS
        .iter()
        .copied()
        .find(|key| {
            configuration
                .get(format!("{key}{REFERENCE_SUFFIX}"))
                .is_some()
        })
}

/// The one answer, per key, to any refusal of a referenced URL while secret
/// values are hidden. It names no host, reason or shape, so it tells nothing
/// of what the secret holds.
pub(crate) fn hidden_url_refusal(key: &str) -> Refusal {
    refuse(format!("{key}{REFERENCE_SUFFIX} does not name a destination this integration may send to"))
}

/// `refusal`, or while values are hidden and `configuration` references a URL,
/// [`hidden_url_refusal`] for it.
pub(crate) fn hide_url_refusal(
    reveal_values: bool,
    configuration: &JsonValue,
    refusal: Refusal,
) -> Refusal {
    match referenced_url_key(configuration) {
        Some(key) if !reveal_values => hidden_url_refusal(key),
        _ => refusal,
    }
}

/// Whether `configuration`, of `integration_type`, delivers where `stored`
/// does, so saving or testing it chooses nothing new. The same rule as the
/// destination lock: a missing field, `null` and `""` all count as unset.
pub(crate) fn same_destination(
    integration_type: &str,
    configuration: &JsonValue,
    stored: &Integration,
) -> bool {
    let empty = Map::new();
    !destination_changed(
        integration_type,
        configuration
            .as_object()
            .unwrap_or(&empty),
        stored,
    )
}

/// Where a configuration stores a credential inline: a top-level key, or a
/// header in the headers object stored under `headers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InlineCredential {
    Key(String),
    Header { headers: String, name: String },
}

impl InlineCredential {
    /// The credential's name, never its value: the key, or `headers.<name>`.
    pub(crate) fn name(&self) -> String {
        match self {
            Self::Key(key) => key.clone(),
            Self::Header { name, .. } => format!("{HEADERS}.{name}"),
        }
    }

    /// The value stored inline.
    pub(crate) fn value<'a>(
        &self,
        configuration: &'a JsonValue,
    ) -> Option<&'a JsonValue> {
        match self {
            Self::Key(key) => configuration.get(key),
            Self::Header { headers, name } => configuration
                .get(headers)
                .and_then(|headers| headers.get(name)),
        }
    }

    /// The secret `configuration` already references for this credential,
    /// which a delivery sends in place of the inline value. A `null` or empty
    /// reference names no secret, so it does not count.
    pub(crate) fn reference<'a>(
        &self,
        configuration: &'a JsonValue,
    ) -> Option<&'a str> {
        match self {
            Self::Key(key) => configuration
                .as_object()
                .and_then(|entries| named(entries, &format!("{key}{REFERENCE_SUFFIX}"))),
            Self::Header { name, .. } => header_named(configuration.get(HEADER_REFERENCES), name),
        }
        .and_then(JsonValue::as_str)
        .filter(|reference| !reference.is_empty())
    }

    /// Removes the inline value from `configuration`.
    pub(crate) fn remove(
        &self,
        configuration: &mut JsonValue,
    ) {
        match self {
            Self::Key(key) => {
                configuration
                    .as_object_mut()
                    .map(|entries| entries.remove(key));
            }
            Self::Header { headers, name } => {
                configuration
                    .get_mut(headers)
                    .and_then(JsonValue::as_object_mut)
                    .map(|headers| headers.remove(name));
            }
        }
    }

    /// Replaces the inline value with a reference to `secret_id`: a
    /// `<key>_secret_id`, or an entry in `headers_secret_id`.
    pub(crate) fn replace_with_reference(
        &self,
        configuration: &mut JsonValue,
        secret_id: &str,
    ) -> anyhow::Result<()> {
        self.remove(configuration);
        let Some(entries) = configuration.as_object_mut() else {
            anyhow::bail!("the configuration is not an object");
        };
        match self {
            Self::Key(key) => {
                entries.insert(format!("{key}{REFERENCE_SUFFIX}"), JsonValue::String(secret_id.to_string()));
            }
            Self::Header { name, .. } => {
                let Some(references) = entries
                    .entry(HEADER_REFERENCES)
                    .or_insert_with(|| JsonValue::Object(Map::new()))
                    .as_object_mut()
                else {
                    anyhow::bail!("{HEADER_REFERENCES} is not an object");
                };
                references.insert(name.clone(), JsonValue::String(secret_id.to_string()));
            }
        }
        Ok(())
    }
}

/// The inline credentials `configuration` stores that a save would now
/// refuse. The signing secret may stay inline, so it is not included.
pub(crate) fn inline_credentials(configuration: &JsonValue) -> Vec<InlineCredential> {
    let mut credentials = Vec::new();
    for (key, value) in configuration
        .as_object()
        .into_iter()
        .flatten()
    {
        if key.eq_ignore_ascii_case(HEADERS) {
            credentials.extend(
                value
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(name, value)| is_hidden_header(name, value))
                    .map(|(name, _)| InlineCredential::Header {
                        headers: key.clone(),
                        name: name.clone(),
                    }),
            );
        } else if is_hidden(key, value) && !key.eq_ignore_ascii_case(SIGNING_SECRET) {
            credentials.push(InlineCredential::Key(key.clone()));
        }
    }
    credentials
}

/// The secrets a check approved, each with where its value goes in the
/// configuration. Not `Debug`, so the values cannot reach a log by accident.
pub(crate) struct AuthorizedSecrets(Vec<(String, String)>);

impl AuthorizedSecrets {
    /// Puts each approved value where its reference was, and drops the references.
    pub(crate) fn fill(
        self,
        configuration: &mut JsonValue,
    ) -> anyhow::Result<()> {
        fill_references(configuration, self.0)
    }
}

/// Checks each secret reference in `configuration` the way a Surface's are
/// checked on save: the secret must exist, belong to a tenant the integration's
/// owner may reference, and fall inside a scoped token's namespace. Returns the
/// secrets it approved, so a caller that sends them right away sends the value
/// that was checked.
pub(crate) async fn resolve_authorized_references(
    configuration: &JsonValue,
    store: Option<&Arc<dyn SecretsStore>>,
    owner_tenant_id: Option<&str>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<AuthorizedSecrets, Refusal> {
    let references = secret_references(configuration);
    if references.is_empty() {
        return Ok(AuthorizedSecrets(Vec::new()));
    }
    let Some(store) = store else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "The secrets store is not configured".to_string()));
    };
    let mut approved = Vec::with_capacity(references.len());
    for (key, reference) in references {
        let secret = crate::identity::handlers::pipe_tenancy::resolve_authorized_secret(
            store.as_ref(),
            owner_tenant_id,
            context,
            scope,
            &reference,
        )
        .await
        .map_err(|_| refuse(format!("{key} does not name a secret this integration may use")))?;
        approved.push((key, secret.value));
    }
    Ok(AuthorizedSecrets(approved))
}

/// [`resolve_authorized_references`] for a save, which stores the references
/// and not the values.
pub(crate) async fn authorize_secret_references(
    configuration: &JsonValue,
    store: Option<&Arc<dyn SecretsStore>>,
    owner_tenant_id: Option<&str>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), Refusal> {
    resolve_authorized_references(configuration, store, owner_tenant_id, context, scope)
        .await
        .map(|_| ())
}

/// Replaces each secret reference in `configuration` with the secret's value,
/// resolved for `owner_tenant_id`. A reference that does not resolve, or names
/// a secret the owner may not use, fails, so a credential is never sent empty.
pub(crate) async fn resolve_secret_references(
    configuration: &mut JsonValue,
    owner_tenant_id: Option<&str>,
    store: Option<Arc<dyn SecretsStore>>,
) -> anyhow::Result<()> {
    let references = secret_references(configuration);
    if references.is_empty() {
        return Ok(());
    }
    let secrets = SurfaceSecrets::new(store, owner_tenant_id.map(str::to_string));
    let mut resolved = Vec::with_capacity(references.len());
    for (key, reference) in references {
        let secret = match secrets
            .resolve(&reference)
            .await
        {
            Ok(Some(secret)) => secret,
            Ok(None) => anyhow::bail!("the secret referenced by {key} is not available"),
            Err(error) => {
                tracing::warn!(key = %key, error = %error, "integration secret reference could not be resolved");
                return Err(error.context(format!("the secret referenced by {key} could not be used")));
            }
        };
        resolved.push((key, secret.value));
    }
    fill_references(configuration, resolved)
}

fn fill_references(
    configuration: &mut JsonValue,
    resolved: Vec<(String, String)>,
) -> anyhow::Result<()> {
    let Some(entries) = configuration.as_object_mut() else {
        return Ok(());
    };
    for (key, value) in resolved {
        if let Some(name) = key.strip_prefix(&format!("{HEADER_REFERENCES}.")) {
            let Some(headers) = entries
                .entry(HEADERS)
                .or_insert_with(|| JsonValue::Object(Map::new()))
                .as_object_mut()
            else {
                anyhow::bail!("{HEADERS} must be an object to take the header referenced by {key}");
            };
            headers.insert(name.to_string(), JsonValue::String(value));
        } else if let Some(credential) = key.strip_suffix(REFERENCE_SUFFIX) {
            entries.insert(credential.to_string(), JsonValue::String(value));
        }
    }
    entries.retain(|key, _| !key.ends_with(REFERENCE_SUFFIX));
    Ok(())
}

/// Whether a reference in `configuration` decides where it sends: a URL key
/// or a routing header held in `headers_secret_id`.
fn has_destination_references(configuration: &JsonValue) -> bool {
    URL_KEYS.iter().any(|key| {
        configuration
            .get(format!("{key}{REFERENCE_SUFFIX}"))
            .is_some()
    }) || configuration
        .get(HEADER_REFERENCES)
        .and_then(JsonValue::as_object)
        .into_iter()
        .flatten()
        .any(|(name, _)| {
            ROUTING_HEADERS.contains(
                &name
                    .to_ascii_lowercase()
                    .as_str(),
            )
        })
}

/// Where `resolved` sends for each reference in `configuration` that decides
/// the destination: the host and port of each referenced URL, and a SHA-256
/// digest of each referenced routing header so the pin never holds its value.
/// `None` when no reference decides the destination.
fn destination_of(
    configuration: &JsonValue,
    resolved: &JsonValue,
) -> anyhow::Result<Option<JsonValue>> {
    use sha2::{Digest, Sha256};

    let mut pin = Map::new();
    for key in URL_KEYS {
        let reference = format!("{key}{REFERENCE_SUFFIX}");
        if configuration
            .get(&reference)
            .is_none()
        {
            continue;
        }
        let url = resolved
            .get(*key)
            .and_then(JsonValue::as_str)
            .and_then(|text| url::Url::parse(text.trim()).ok())
            .ok_or_else(|| anyhow::anyhow!("the secret referenced by {reference} does not hold a URL"))?;
        let Some(host) = url.host_str() else {
            anyhow::bail!("the URL referenced by {reference} has no host");
        };
        let address = match url.port_or_known_default() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        pin.insert(key.to_string(), JsonValue::String(address));
    }
    let mut headers = Map::new();
    for name in configuration
        .get(HEADER_REFERENCES)
        .and_then(JsonValue::as_object)
        .into_iter()
        .flatten()
        .map(|(name, _)| name)
    {
        let lower = name.to_ascii_lowercase();
        if !ROUTING_HEADERS.contains(&lower.as_str()) {
            continue;
        }
        let value = resolved
            .get(HEADERS)
            .and_then(|headers| headers.get(name))
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        headers.insert(lower, JsonValue::String(hex::encode(Sha256::digest(value.as_bytes()))));
    }
    if !headers.is_empty() {
        pin.insert(HEADERS.to_string(), JsonValue::Object(headers));
    }
    Ok((!pin.is_empty()).then_some(JsonValue::Object(pin)))
}

/// Resolves the references a save keeps for `owner_tenant_id`, refuses a
/// referenced webhook URL the destination rules do not allow, and records in
/// `pinned_destination` where the references send, so a later edit of a
/// secret's value cannot move the integration without a save.
pub(crate) async fn pin_destination(
    configuration: &mut JsonValue,
    owner_tenant_id: Option<&str>,
    store: Option<Arc<dyn SecretsStore>>,
) -> Result<(), Refusal> {
    if !has_destination_references(configuration) {
        return Ok(());
    }
    let mut resolved = configuration.clone();
    resolve_secret_references(&mut resolved, owner_tenant_id, store)
        .await
        .map_err(|e| refuse(e.to_string()))?;
    for key in URL_KEYS {
        if configuration
            .get(format!("{key}{REFERENCE_SUFFIX}"))
            .is_none()
        {
            continue;
        }
        let Some(url) = resolved
            .get(*key)
            .and_then(JsonValue::as_str)
        else {
            continue;
        };
        let not_a_url =
            |kind: &str| refuse(format!("the secret referenced by {key}{REFERENCE_SUFFIX} does not hold {kind} URL"));
        if *key == REDIS_URL {
            if !is_redis_url(url) {
                return Err(not_a_url("a redis://"));
            }
            continue;
        }
        match crate::url_validation::check_webhook_url(url) {
            Ok(_) => {}
            Err(UrlRefusal::NotHttpUrl(_)) => return Err(not_a_url("an http or https")),
            Err(UrlRefusal::Refused(reason)) => {
                return Err(refuse(format!(
                    "{key}{REFERENCE_SUFFIX} names a URL this integration may not send to: {reason}"
                )));
            }
        }
    }
    let pin = destination_of(configuration, &resolved).map_err(|e| refuse(e.to_string()))?;
    if let (Some(entries), Some(pin)) = (configuration.as_object_mut(), pin) {
        entries.insert(PINNED_DESTINATION.to_string(), pin);
    }
    Ok(())
}

/// What [`pin_migrated_destination`] did with the pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigratedPin {
    /// No reference decides where the integration sends.
    Unchanged,
    /// The pin records where the references send now.
    Pinned,
    /// The references the integration already held resolve somewhere other
    /// than its pin, so the old pin was kept and deliveries stay refused until
    /// a save confirms the new destination.
    KeptMoved,
}

/// Records in `migrated`'s `pinned_destination` where it sends, as a save
/// would, for a configuration whose inline credentials became references.
/// `original` still holds the inline values, so the pin is read from it
/// without the new secrets having been written. The destination rules are not
/// checked: delivery already refuses a host they do not allow. A pin the
/// original's own references no longer match is kept, so the migration never
/// confirms a destination change a save has to confirm.
pub(crate) async fn pin_migrated_destination(
    original: &JsonValue,
    migrated: &mut JsonValue,
    owner_tenant_id: Option<&str>,
    store: Option<Arc<dyn SecretsStore>>,
) -> anyhow::Result<MigratedPin> {
    if !has_destination_references(migrated) {
        return Ok(MigratedPin::Unchanged);
    }
    let mut resolved = original.clone();
    drop_unset_references(&mut resolved);
    resolve_secret_references(&mut resolved, owner_tenant_id, store).await?;
    if let Some(pinned) = original.get(PINNED_DESTINATION)
        && destination_moved(original, &resolved, Some(pinned))?
    {
        return Ok(MigratedPin::KeptMoved);
    }
    if let (Some(pin), Some(entries)) = (destination_of(migrated, &resolved)?, migrated.as_object_mut()) {
        entries.insert(PINNED_DESTINATION.to_string(), pin);
    }
    Ok(MigratedPin::Pinned)
}

/// Removes every reference that names no secret (`null` or empty), which the
/// migration replaces rather than resolves.
fn drop_unset_references(configuration: &mut JsonValue) {
    let is_set = |value: &JsonValue| {
        value
            .as_str()
            .is_some_and(|reference| !reference.is_empty())
    };
    let Some(entries) = configuration.as_object_mut() else {
        return;
    };
    entries.retain(|key, value| key == HEADER_REFERENCES || !key.ends_with(REFERENCE_SUFFIX) || is_set(value));
    if let Some(headers) = entries
        .get_mut(HEADER_REFERENCES)
        .and_then(JsonValue::as_object_mut)
    {
        headers.retain(|_, value| is_set(value));
    }
}

/// Whether `configuration`'s references, resolved to `resolved`, send somewhere
/// other than `pinned`, or decide a destination that was never pinned.
pub(crate) fn destination_moved(
    configuration: &JsonValue,
    resolved: &JsonValue,
    pinned: Option<&JsonValue>,
) -> anyhow::Result<bool> {
    Ok(destination_of(configuration, resolved)?.is_some_and(|current| pinned != Some(&current)))
}

/// Refuses a delivery whose references now resolve somewhere other than the
/// destination its last save pinned.
fn verify_pinned_destination(
    configuration: &JsonValue,
    resolved: &JsonValue,
) -> anyhow::Result<()> {
    if destination_moved(configuration, resolved, configuration.get(PINNED_DESTINATION))? {
        anyhow::bail!(
            "a secret this integration references now points somewhere else; save the integration again to confirm the new destination"
        );
    }
    Ok(())
}

/// Pins the destination of each saved integration whose references decide
/// where it sends but that no save has pinned yet, as a save would. Logs
/// names only; an integration that cannot be pinned is left as it is, and its
/// deliveries are refused until it is saved again. Stops before the next
/// integration once `still_current` turns false.
pub(crate) async fn pin_unpinned_destinations(
    storage: &crate::storage::IntegrationStorage,
    store: Option<Arc<dyn SecretsStore>>,
    still_current: &(dyn Fn() -> bool + Sync),
) {
    let integrations = match storage.list().await {
        Ok(integrations) => integrations,
        Err(error) => {
            tracing::warn!(error = %error, "could not list integrations to pin their destinations");
            return;
        }
    };
    for mut integration in integrations {
        if integration
            .configuration
            .get(PINNED_DESTINATION)
            .is_some()
            || !has_destination_references(&integration.configuration)
        {
            continue;
        }
        if !still_current() {
            tracing::info!("Integration destination pinning stopped because the activation was superseded");
            return;
        }
        let pinned = pin_destination(
            &mut integration.configuration,
            integration
                .tenant_id
                .as_deref(),
            store.clone(),
        )
        .await;
        match pinned {
            Ok(()) => match storage
                .update(&integration.id, &integration)
                .await
            {
                Ok(()) => tracing::info!(integration_id = %integration.id, "pinned integration destination"),
                Err(error) => tracing::warn!(
                    integration_id = %integration.id,
                    error = %error,
                    "could not save integration destination pin"
                ),
            },
            Err((_, reason)) => tracing::warn!(
                integration_id = %integration.id,
                reason = %reason,
                "could not pin integration destination; its deliveries are refused until it is saved again"
            ),
        }
    }
}

static SECRETS_STORE: OnceLock<Arc<dyn SecretsStore>> = OnceLock::new();

/// Sets the secrets store integration deliveries resolve references from.
pub fn init_secrets_store(store: Arc<dyn SecretsStore>) {
    let _ = SECRETS_STORE.set(store);
}

pub(crate) fn secrets_store() -> Option<Arc<dyn SecretsStore>> {
    SECRETS_STORE.get().cloned()
}

/// The integration a delivery sends with: its secret references resolved for
/// its own tenant, refused when they no longer resolve to the pinned
/// destination.
#[tracing::instrument(skip_all, fields(integration_id = %integration.id))]
pub(crate) async fn with_resolved_secrets(integration: &Integration) -> anyhow::Result<Integration> {
    let mut resolved = integration.clone();
    resolve_secret_references(
        &mut resolved.configuration,
        integration
            .tenant_id
            .as_deref(),
        secrets_store(),
    )
    .await?;
    verify_pinned_destination(&integration.configuration, &resolved.configuration)?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::store::memory::{MemorySecretsStore, secret};

    const AUTH_HEADER: &str = "Bearer header-token-789";
    const SIGNING_SECRET: &str = "whsec-456";

    fn stored(
        integration_type: &str,
        configuration: JsonValue,
    ) -> Integration {
        Integration::new(
            "stored".into(),
            String::new(),
            integration_type.into(),
            configuration,
            serde_json::json!({}),
            "active".into(),
            None,
        )
    }

    fn stored_webhook() -> Integration {
        stored(
            "webhook",
            serde_json::json!({
                "url": "https://hooks.example.com/in/secret-path",
                "headers": { "Authorization": AUTH_HEADER, "Host": "hooks.example.com" },
                "signing_secret": SIGNING_SECRET,
            }),
        )
    }

    fn view(integration: Integration) -> JsonValue {
        IntegrationView::from(integration)
            .integration()
            .configuration
            .clone()
    }

    fn apply(
        integration_type: &str,
        mut configuration: JsonValue,
        stored: &Integration,
    ) -> Result<JsonValue, Refusal> {
        apply_credential_rules(integration_type, &mut configuration, Some(stored), NewCredentials::InlineAllowed)
            .map(|()| configuration)
    }

    #[test]
    fn credential_keys_match_case_insensitively_and_by_common_suffixes() {
        let configuration = view(stored(
            "webhook",
            serde_json::json!({
                "SMTP_PASSWORD": "upper",
                "apiKey": "camel",
                "private_key": "pem",
                "aws_secret_access_key": "aws",
                "access_key": "id",
                "service_credentials": "creds",
                "region": "eu-west-1",
                "smtp_password_secret_id": "smtp-global",
            }),
        ));

        assert_eq!(
            configuration,
            serde_json::json!({ "region": "eu-west-1", "smtp_password_secret_id": "smtp-global" })
        );
    }

    #[test]
    fn credential_headers_are_left_out_and_others_stay_visible() {
        let headers = view(stored(
            "webhook",
            serde_json::json!({
                "headers": {
                    "Authorization": "Bearer ${TOKEN}",
                    "Proxy-Authorization": "Basic abc",
                    "Cookie": "session=1",
                    "X-Api-Key": "${API_KEY:sk-default}",
                    "X-Auth-Token": "t",
                    "X-Signing-Secret": "s",
                    "X-Tenant-Token": "${TENANT_TOKEN}",
                    "X-Surface": "${SURFACE_ID}",
                    "X-Static": "sk-literal",
                    "Host": "hooks.example.com",
                    "apikey": "sb-key",
                    "token": "t",
                    "X-Password": "p",
                    "X-Client-Credentials": "c",
                    "X-Authorization": "Bearer abc",
                    "Authentication": "Basic abc",
                    "X-Auth": "a",
                    "X-Credential": "c",
                    "X-Passwd": "p",
                    "X-Session-Id": "s",
                },
            }),
        ))["headers"]
            .clone();

        assert_eq!(
            headers,
            serde_json::json!({
                "X-Tenant-Token": "${TENANT_TOKEN}",
                "X-Surface": "${SURFACE_ID}",
                "X-Static": "sk-literal",
                "Host": "hooks.example.com",
            })
        );
    }

    #[test]
    fn empty_and_absent_credentials_are_answered_as_stored() {
        let configuration = serde_json::json!({ "smtp_password": "", "signing_secret": null, "port": 25 });

        assert_eq!(view(stored("email", configuration.clone())), configuration);
    }

    #[test]
    fn left_out_credentials_are_kept_while_the_destination_is_unchanged() {
        let kept = apply("webhook", view(stored_webhook()), &stored_webhook()).unwrap();

        assert_eq!(kept, stored_webhook().configuration);
    }

    #[test]
    fn a_kept_credential_is_refused_when_the_destination_changes() {
        let email = stored("email", serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password": "p" }));
        let kafka = stored("stream", serde_json::json!({ "brokers": "kafka:9092", "sasl_password": "sasl" }));
        let cases = [
            ("webhook url", "webhook", serde_json::json!({ "url": "https://attacker.example/hook" }), stored_webhook()),
            ("smtp host", "email", serde_json::json!({ "smtp_host": "smtp.attacker.example" }), email.clone()),
            ("brokers", "stream", serde_json::json!({ "brokers": "attacker:9092" }), kafka),
            ("type", "slack", serde_json::json!({ "smtp_host": "smtp.example.com" }), email),
        ];

        for (case, integration_type, configuration, stored) in cases {
            let refused = apply(integration_type, configuration, &stored).unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{case}");
        }
    }

    #[test]
    fn the_signing_secret_is_not_kept_for_a_new_destination() {
        let configuration = serde_json::json!({
            "url": "https://new.example.com/hook",
            "headers": { "Authorization": JsonValue::Null, "Host": "hooks.example.com" },
        });

        let refused = apply("webhook", configuration, &stored_webhook()).unwrap_err();

        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_new_destination_with_every_credential_replaced_is_accepted() {
        let configuration = serde_json::json!({
            "url": "https://new.example.com/hook",
            "signing_secret": "whsec-new",
            "headers": { "Authorization": JsonValue::Null },
            "headers_secret_id": { "Authorization": "new-token" },
        });

        let applied = apply("webhook", configuration, &stored_webhook()).unwrap();

        assert_eq!(applied["signing_secret"], "whsec-new");
        assert_eq!(applied["headers_secret_id"]["Authorization"], "new-token");
        assert!(
            !applied
                .to_string()
                .contains(AUTH_HEADER)
        );
    }

    #[test]
    fn routing_headers_count_as_part_of_the_destination() {
        let changed = [
            ("added", serde_json::json!({ "Host": "hooks.example.com", "X-Forwarded-Host": "other-vhost.example" })),
            ("changed", serde_json::json!({ "host": "other-vhost.example" })),
            ("removed", serde_json::json!({})),
            ("forwarded", serde_json::json!({ "Host": "hooks.example.com", "Forwarded": "host=other-vhost.example" })),
        ];
        for (case, headers) in changed {
            let configuration =
                serde_json::json!({ "url": "https://hooks.example.com/in/secret-path", "headers": headers });
            let refused = apply("webhook", configuration, &stored_webhook()).unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{case}");
        }

        let kept = serde_json::json!({ "url": "https://hooks.example.com/in/secret-path", "headers": { "HOST": "hooks.example.com" } });
        let applied = apply("webhook", kept, &stored_webhook()).unwrap();
        assert_eq!(applied["headers"]["Authorization"], AUTH_HEADER);
    }

    fn stored_webhook_by_reference() -> Integration {
        stored(
            "webhook",
            serde_json::json!({
                "url_secret_id": "url-a",
                "signing_secret": SIGNING_SECRET,
                "headers": { "Authorization": AUTH_HEADER },
            }),
        )
    }

    #[test]
    fn a_swapped_destination_reference_cannot_keep_a_stored_credential() {
        let stored = stored_webhook_by_reference();
        for (case, configuration) in [
            ("swapped url reference", serde_json::json!({ "url_secret_id": "url-b" })),
            ("inline url replacing the reference", serde_json::json!({ "url": "https://attacker.example/hook" })),
            ("reference dropped", serde_json::json!({})),
        ] {
            let refused = apply("webhook", configuration, &stored).unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{case}");
        }

        let kept = apply("webhook", serde_json::json!({ "url_secret_id": "url-a" }), &stored).unwrap();
        assert_eq!(kept["signing_secret"], SIGNING_SECRET);
        assert_eq!(kept["headers"]["Authorization"], AUTH_HEADER);

        let replaced = apply(
            "webhook",
            serde_json::json!({
                "url_secret_id": "url-b",
                "signing_secret": "whsec-new",
                "headers": { "Authorization": JsonValue::Null },
            }),
            &stored,
        )
        .unwrap();
        assert_eq!(replaced["signing_secret"], "whsec-new");
        assert!(
            !replaced
                .to_string()
                .contains(AUTH_HEADER)
        );
    }

    #[test]
    fn a_routing_header_by_reference_counts_as_part_of_the_destination() {
        let url = "https://hooks.example.com/in/secret-path";
        for (case, configuration) in [
            (
                "added by reference",
                serde_json::json!({
                    "url": url,
                    "headers": { "Host": "hooks.example.com" },
                    "headers_secret_id": { "X-Forwarded-Host": "vhost-ref" },
                }),
            ),
            (
                "moved to a reference",
                serde_json::json!({ "url": url, "headers": {}, "headers_secret_id": { "host": "vhost-ref" } }),
            ),
        ] {
            let refused = apply("webhook", configuration, &stored_webhook()).unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{case}");
        }

        let mut by_reference = stored_webhook();
        by_reference.configuration["headers_secret_id"] = serde_json::json!({ "Host": "vhost-ref" });
        by_reference.configuration["headers"] = serde_json::json!({ "Authorization": AUTH_HEADER });
        let kept = apply(
            "webhook",
            serde_json::json!({ "url": url, "headers_secret_id": { "host": "vhost-ref" } }),
            &by_reference,
        )
        .unwrap();
        assert_eq!(kept["headers"]["Authorization"], AUTH_HEADER);
    }

    #[test]
    fn a_new_inline_url_must_be_a_reference_on_save() {
        for configuration in [
            serde_json::json!({ "url": "https://hooks.example.com/in" }),
            serde_json::json!({ "redis_url": "redis://cache:6379" }),
            serde_json::json!({ "webhook_url": "https://hooks.slack.com/services/T/B/X" }),
            serde_json::json!({ "url": "https://user:pw@hooks.example.com/in" }),
        ] {
            let mut sent = configuration.clone();
            let refused =
                apply_credential_rules("webhook", &mut sent, None, NewCredentials::ReferencesOnly).unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{configuration}");
            assert!(
                refused
                    .1
                    .contains(REFERENCE_SUFFIX),
                "{}",
                refused.1
            );

            let mut tested = configuration.clone();
            apply_credential_rules("webhook", &mut tested, None, NewCredentials::InlineAllowed).unwrap();
            assert_eq!(tested, configuration);
        }

        let templated = serde_json::json!({ "url": "${HOOK_URL}", "redis_url_secret_id": "redis-url" });
        let mut saved = templated.clone();
        apply_credential_rules("stream", &mut saved, None, NewCredentials::ReferencesOnly).unwrap();
        assert_eq!(saved, templated);
    }

    #[test]
    fn a_new_signing_secret_must_be_at_least_32_characters_on_save() {
        let mut short = serde_json::json!({ "signing_secret": "whsec-too-short" });
        let refused = apply_credential_rules("webhook", &mut short, None, NewCredentials::ReferencesOnly).unwrap_err();
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(refused.1.contains("32"), "{}", refused.1);

        let generated = serde_json::json!({ "signing_secret": "3f2c1a9e-7b4d-4e8a-9c61-0d5f2b7e8a14" });
        let mut saved = generated.clone();
        apply_credential_rules("webhook", &mut saved, None, NewCredentials::ReferencesOnly).unwrap();
        assert_eq!(saved, generated);

        let kept = stored("webhook", serde_json::json!({ "url_secret_id": "url-a", "signing_secret": "short" }));
        let mut renamed = serde_json::json!({ "url_secret_id": "url-a" });
        apply_credential_rules("webhook", &mut renamed, Some(&kept), NewCredentials::ReferencesOnly).unwrap();
        assert_eq!(renamed["signing_secret"], "short");
    }

    #[test]
    fn a_client_cannot_set_the_pinned_destination() {
        let mut sent =
            serde_json::json!({ "url_secret_id": "url-a", PINNED_DESTINATION: { "url": "attacker.example:443" } });

        apply_credential_rules("webhook", &mut sent, None, NewCredentials::ReferencesOnly).unwrap();

        assert_eq!(sent, serde_json::json!({ "url_secret_id": "url-a" }));
    }

    #[test]
    fn same_destination_compares_only_where_the_integration_delivers() {
        let email =
            stored("email", serde_json::json!({ "smtp_host": "10.0.0.5", "smtp_port": 25, "smtp_password": "old" }));
        let stream =
            stored("stream", serde_json::json!({ "platform": "redis", "redis_url": "redis://10.0.0.5", "topic": "a" }));

        assert!(same_destination(
            "email",
            &serde_json::json!({ "smtp_host": "10.0.0.5", "smtp_port": 25, "smtp_password": "new" }),
            &email
        ));
        assert!(!same_destination("email", &serde_json::json!({ "smtp_host": "10.0.0.6", "smtp_port": 25 }), &email));
        assert!(!same_destination("email", &serde_json::json!({ "smtp_host": "10.0.0.5", "smtp_port": 2525 }), &email));
        assert!(!same_destination("stream", &serde_json::json!({ "smtp_host": "10.0.0.5", "smtp_port": 25 }), &email));
        assert!(same_destination(
            "stream",
            &serde_json::json!({ "platform": "redis", "redis_url": "redis://10.0.0.5", "topic": "b" }),
            &stream
        ));
        assert!(!same_destination(
            "stream",
            &serde_json::json!({ "platform": "kafka", "redis_url": "redis://10.0.0.5", "topic": "a" }),
            &stream
        ));
        assert!(!same_destination(
            "stream",
            &serde_json::json!({ "platform": "redis", "redis_url_secret_id": "cache-url", "topic": "a" }),
            &stream
        ));
    }

    #[test]
    fn a_dashboard_rename_with_blank_fields_keeps_the_same_destination() {
        let kafka =
            stored("stream", serde_json::json!({ "platform": "kafka", "brokers": "kafka:9092", "topic": "events" }));

        assert!(same_destination(
            "stream",
            &serde_json::json!({
                "platform": "kafka",
                "brokers": "kafka:9092",
                "topic": "events",
                "region": "",
                "redis_url": "",
                "redis_url_secret_id": "",
            }),
            &kafka
        ));
    }

    #[test]
    fn a_response_shows_the_pinned_host_and_not_the_routing_header_digests() {
        let shown = view(stored(
            "webhook",
            serde_json::json!({
                "url_secret_id": "url-a",
                "headers_secret_id": { "Host": "host-a" },
                PINNED_DESTINATION: {
                    "url": "hooks.example.com:443",
                    "headers": { "host": "0d8f3c3a1d4b6e2f9a7c5b4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0" },
                },
            }),
        ));

        assert_eq!(shown[PINNED_DESTINATION], serde_json::json!({ "url": "hooks.example.com:443" }));
    }

    #[test]
    fn a_missing_null_or_empty_destination_field_counts_as_unset() {
        let kafka = stored(
            "stream",
            serde_json::json!({ "platform": "kafka", "brokers": "kafka:9092", "sasl_password": "sasl" }),
        );
        let configuration = serde_json::json!({ "platform": "kafka", "brokers": "kafka:9092", "region": "", "host": null, "redis_url": "" });

        let applied = apply("stream", configuration, &kafka).unwrap();

        assert_eq!(applied["sasl_password"], "sasl");
    }

    #[test]
    fn the_old_placeholder_is_refused_naming_its_path() {
        for (configuration, path) in [
            (serde_json::json!({ "smtp_password": MASKED_CREDENTIAL }), "smtp_password"),
            (serde_json::json!({ "headers": { "authorization": MASKED_CREDENTIAL } }), "headers.authorization"),
        ] {
            let refused = apply("webhook", configuration, &stored_webhook()).unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST);
            assert!(refused.1.contains(path), "{}", refused.1);
        }
    }

    #[test]
    fn a_left_out_template_credential_is_kept_without_locking_the_destination() {
        let templated = stored(
            "email",
            serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password": "${SMTP_PASSWORD}" }),
        );
        assert_eq!(view(templated.clone())["smtp_password"], "${SMTP_PASSWORD}");

        let applied = apply("email", serde_json::json!({ "smtp_host": "smtp.other.example" }), &templated).unwrap();

        assert_eq!(applied["smtp_password"], "${SMTP_PASSWORD}");
    }

    #[test]
    fn null_clears_a_stored_credential_and_empty_keeps_it() {
        let configuration = serde_json::json!({
            "url": "",
            "signing_secret": null,
            "headers": { "Host": "hooks.example.com", "authorization": null },
        });

        let applied = apply("webhook", configuration, &stored_webhook()).unwrap();

        assert_eq!(
            applied,
            serde_json::json!({ "url": "https://hooks.example.com/in/secret-path", "headers": { "Host": "hooks.example.com" } })
        );
    }

    #[test]
    fn credential_keys_are_kept_cleared_and_replaced_whatever_their_case() {
        let stored = stored("langfuse", serde_json::json!({ "host": "https://cloud.langfuse.com", "API_KEY": "old" }));

        let cleared =
            apply("langfuse", serde_json::json!({ "host": "https://cloud.langfuse.com", "api_key": null }), &stored)
                .unwrap();
        assert_eq!(cleared, serde_json::json!({ "host": "https://cloud.langfuse.com" }));

        let replaced = apply(
            "langfuse",
            serde_json::json!({ "host": "https://cloud.langfuse.com", "api_key_secret_id": "key-ref" }),
            &stored,
        )
        .unwrap();
        assert_eq!(
            replaced,
            serde_json::json!({ "host": "https://cloud.langfuse.com", "api_key_secret_id": "key-ref" })
        );

        let kept = apply("langfuse", serde_json::json!({ "host": "https://cloud.langfuse.com" }), &stored).unwrap();
        assert_eq!(kept["API_KEY"], "old");
    }

    #[test]
    fn a_credential_sent_inline_and_by_reference_is_refused() {
        let cases = [
            serde_json::json!({ "smtp_password": "x", "smtp_password_secret_id": "smtp-global" }),
            serde_json::json!({ "Smtp_Password": "x", "smtp_password_secret_id": "smtp-global" }),
            serde_json::json!({ "headers": { "Authorization": "${TOKEN}" }, "headers_secret_id": { "authorization": "t" } }),
            serde_json::json!({ "topic_secret_id": "smtp-global" }),
            serde_json::json!({ "smtp_password_secret_id": 7 }),
            serde_json::json!({ "headers_secret_id": "t" }),
        ];

        for configuration in cases {
            let mut sent = configuration.clone();
            let refused = apply_credential_rules("email", &mut sent, None, NewCredentials::InlineAllowed).unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{configuration}");
        }
    }

    #[test]
    fn new_inline_credentials_must_be_references_on_save() {
        for configuration in [
            serde_json::json!({ "smtp_password": "p" }),
            serde_json::json!({ "secret_key": "sk" }),
            serde_json::json!({ "headers": { "X-Api-Key": "k" } }),
            serde_json::json!({ "headers": { "X-Authorization": "Bearer abc" } }),
            serde_json::json!({ "headers": { "apikey": "k" } }),
            serde_json::json!({ "headers": { "token": "t" } }),
            serde_json::json!({ "headers": { "X-Password": "p" } }),
        ] {
            let mut sent = configuration.clone();
            let refused =
                apply_credential_rules("webhook", &mut sent, None, NewCredentials::ReferencesOnly).unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{configuration}");

            let mut tested = configuration.clone();
            apply_credential_rules("webhook", &mut tested, None, NewCredentials::InlineAllowed).unwrap();
            assert_eq!(tested, configuration);
        }

        let allowed = serde_json::json!({
            "url_secret_id": "url-a",
            "signing_secret": "3f2c1a9e-7b4d-4e8a-9c61-0d5f2b7e8a14",
            "headers": { "Authorization": "${TOKEN}", "X-Trace": "abc" },
        });
        let mut saved = allowed.clone();
        apply_credential_rules("webhook", &mut saved, None, NewCredentials::ReferencesOnly).unwrap();
        assert_eq!(saved, allowed);
    }

    #[test]
    fn headers_null_clears_every_stored_credential_header() {
        let stored = stored(
            "webhook",
            serde_json::json!({ "url": "https://hooks.example.com/in", "headers": { "Authorization": AUTH_HEADER } }),
        );

        let applied =
            apply("webhook", serde_json::json!({ "url": "https://hooks.example.com/in", "headers": null }), &stored)
                .unwrap();

        assert_eq!(applied, serde_json::json!({ "url": "https://hooks.example.com/in" }));
    }

    #[test]
    fn a_reference_suffix_in_another_case_is_refused() {
        for configuration in [
            serde_json::json!({ "smtp_host": "h", "smtp_password_SECRET_ID": "smtp-global" }),
            serde_json::json!({ "smtp_host": "h", "smtp_password_Secret_Id": "" }),
        ] {
            let mut sent = configuration.clone();
            let refused = apply_credential_rules("email", &mut sent, None, NewCredentials::InlineAllowed).unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{configuration}");
            assert!(
                refused
                    .1
                    .contains(REFERENCE_SUFFIX),
                "{}",
                refused.1
            );
        }
    }

    #[test]
    fn a_secret_is_paired_with_a_destination_when_its_reference_or_the_destination_is_new() {
        let held = stored(
            "email",
            serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password_secret_id": "smtp-global" }),
        );
        let paired = [
            ("a reference on create", serde_json::json!({ "smtp_password_secret_id": "smtp-global" }), None),
            (
                "a different reference",
                serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password_secret_id": "smtp-other" }),
                Some(&held),
            ),
            (
                "a held reference sent to a new host",
                serde_json::json!({ "smtp_host": "smtp.attacker.example", "smtp_password_secret_id": "smtp-global" }),
                Some(&held),
            ),
        ];
        for (case, configuration, stored) in paired {
            assert!(pairs_secret_with_new_destination("email", &configuration, stored), "{case}");
        }

        let unchanged = [
            ("no reference", serde_json::json!({ "smtp_host": "smtp.attacker.example" }), None),
            (
                "the held reference and destination",
                serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password_secret_id": "smtp-global" }),
                Some(&held),
            ),
        ];
        for (case, configuration, stored) in unchanged {
            assert!(!pairs_secret_with_new_destination("email", &configuration, stored), "{case}");
        }
    }

    #[test]
    fn only_a_referenced_url_with_nothing_else_secret_or_routing_counts_as_address_only() {
        let address_only = [
            ("a webhook url", "webhook", serde_json::json!({ "url_secret_id": "hook-url" })),
            ("a slack webhook url", "slack", serde_json::json!({ "webhook_url_secret_id": "hook-url" })),
            (
                "a redis stream url",
                "stream",
                serde_json::json!({ "platform": "redis", "redis_url_secret_id": "redis-url" }),
            ),
            (
                "a url with a signing secret and a plain header",
                "webhook",
                serde_json::json!({
                    "url_secret_id": "hook-url",
                    "signing_secret": SIGNING_SECRET,
                    "headers": { "X-Trace": "abc" },
                }),
            ),
        ];
        for (case, integration_type, configuration) in address_only {
            assert!(references_only_addresses(integration_type, &configuration), "{case}");
        }

        let more_than_the_address = [
            (
                "a referenced header",
                "webhook",
                serde_json::json!({ "url_secret_id": "hook-url", "headers_secret_id": { "Authorization": "t" } }),
            ),
            (
                "a referenced password",
                "webhook",
                serde_json::json!({ "url_secret_id": "hook-url", "smtp_password_secret_id": "p" }),
            ),
            (
                "an inline host header",
                "webhook",
                serde_json::json!({ "url_secret_id": "hook-url", "headers": { "Host": "attacker.example" } }),
            ),
            (
                "an inline forwarded host header",
                "webhook",
                serde_json::json!({ "url_secret_id": "hook-url", "headers": { "X-Forwarded-Host": "attacker.example" } }),
            ),
            (
                "a kept inline credential header",
                "webhook",
                serde_json::json!({ "url_secret_id": "hook-url", "headers": { "Authorization": AUTH_HEADER } }),
            ),
            ("a redis url on a webhook", "webhook", serde_json::json!({ "redis_url_secret_id": "redis-url" })),
            ("a redis url on email", "email", serde_json::json!({ "redis_url_secret_id": "redis-url" })),
            ("a slack url on a webhook", "webhook", serde_json::json!({ "webhook_url_secret_id": "hook-url" })),
            ("a webhook url on slack", "slack", serde_json::json!({ "url_secret_id": "hook-url" })),
            (
                "a redis url on a kafka stream",
                "stream",
                serde_json::json!({ "platform": "kafka", "redis_url_secret_id": "redis-url" }),
            ),
            (
                "a redis url on a stream without a platform",
                "stream",
                serde_json::json!({ "redis_url_secret_id": "redis-url" }),
            ),
            (
                "both the address and another url",
                "webhook",
                serde_json::json!({ "url_secret_id": "hook-url", "redis_url_secret_id": "redis-url" }),
            ),
        ];
        for (case, integration_type, configuration) in more_than_the_address {
            assert!(!references_only_addresses(integration_type, &configuration), "{case}");
        }
    }

    #[test]
    fn inline_credentials_are_named_without_their_values() {
        let mut names: Vec<String> = inline_credentials(&serde_json::json!({
            "webhook_url": "https://hooks.slack.com/services/T/B/X",
            "smtp_password": "${SMTP_PASSWORD}",
            "signing_secret": SIGNING_SECRET,
            "smtp_password_secret_id": "smtp-global",
            "headers": { "Authorization": AUTH_HEADER, "X-Trace": "abc" },
        }))
        .iter()
        .map(InlineCredential::name)
        .collect();
        names.sort();

        assert_eq!(names, vec!["headers.Authorization", "webhook_url"]);
    }

    #[test]
    fn an_inline_credential_is_replaced_by_a_reference_where_it_was() {
        let mut configuration = serde_json::json!({
            "webhook_url": "https://hooks.slack.com/services/T/B/X",
            "headers": { "Authorization": AUTH_HEADER, "X-Trace": "abc" },
        });
        let url = InlineCredential::Key("webhook_url".to_string());
        let header = InlineCredential::Header {
            headers: "headers".to_string(),
            name: "Authorization".to_string(),
        };

        assert_eq!(url.value(&configuration), Some(&serde_json::json!("https://hooks.slack.com/services/T/B/X")));
        assert_eq!(header.value(&configuration), Some(&serde_json::json!(AUTH_HEADER)));
        url.replace_with_reference(&mut configuration, "slack-url")
            .unwrap();
        header
            .replace_with_reference(&mut configuration, "auth-header")
            .unwrap();

        assert_eq!(
            configuration,
            serde_json::json!({
                "webhook_url_secret_id": "slack-url",
                "headers": { "X-Trace": "abc" },
                "headers_secret_id": { "Authorization": "auth-header" },
            })
        );
        assert_eq!(url.reference(&configuration), Some("slack-url"));
        assert_eq!(header.reference(&serde_json::json!({ "headers_secret_id": { "authorization": "x" } })), Some("x"));
        assert_eq!(header.reference(&serde_json::json!({ "headers_secret_id": { "X-Trace": "x" } })), None);
        assert_eq!(url.reference(&serde_json::json!({ "webhook_url_secret_id": "" })), None);
        assert_eq!(header.reference(&serde_json::json!({ "headers_secret_id": { "Authorization": null } })), None);
    }

    fn stored_smtp(configuration: JsonValue) -> Integration {
        let mut configuration = configuration;
        configuration["smtp_host"] = serde_json::json!("smtp.example.com");
        configuration["smtp_password"] = serde_json::json!("p");
        stored("email", configuration)
    }

    #[test]
    fn a_kept_password_is_refused_when_smtp_encryption_is_turned_off() {
        let stored = stored_smtp(serde_json::json!({ "smtp_port": 25, "use_tls": false }));
        let configuration = serde_json::json!({
            "smtp_host": "smtp.example.com",
            "smtp_port": 25,
            "use_tls": false,
            "use_starttls": false,
        });

        let refused = apply("email", configuration, &stored).unwrap_err();

        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_kept_password_is_accepted_when_smtp_encryption_is_unchanged() {
        let cases = [
            (serde_json::json!({ "smtp_port": 587 }), serde_json::json!({ "smtp_port": 587, "use_tls": false })),
            (
                serde_json::json!({ "smtp_port": 25, "use_tls": false, "use_starttls": false }),
                serde_json::json!({ "smtp_port": 25, "use_tls": false, "use_starttls": false }),
            ),
        ];

        for (stored, mut sent) in cases {
            sent["smtp_host"] = serde_json::json!("smtp.example.com");
            let applied = apply("email", sent, &stored_smtp(stored)).unwrap();
            assert_eq!(applied["smtp_password"], "p");
        }
    }

    fn store() -> Option<Arc<dyn SecretsStore>> {
        Some(Arc::new(MemorySecretsStore::with(vec![
            secret("id-global", "token-global", "global-token", None),
            secret("id-tenant-b", "token-b", "tenant-b-token", Some("tenant-b")),
        ])))
    }

    #[tokio::test]
    async fn references_resolve_into_the_credentials_they_name() {
        let mut configuration = serde_json::json!({
            "secret_key_secret_id": "token-b",
            "headers": { "X-Trace": "abc" },
            "headers_secret_id": { "Authorization": "id-global" },
        });

        resolve_secret_references(&mut configuration, Some("tenant-b"), store())
            .await
            .unwrap();

        assert_eq!(
            configuration,
            serde_json::json!({
                "secret_key": "tenant-b-token",
                "headers": { "X-Trace": "abc", "Authorization": "global-token" },
            })
        );
    }

    #[tokio::test]
    async fn a_reference_that_cannot_be_used_fails_the_delivery() {
        for (case, owner, reference, store, reason) in [
            ("another tenant's secret", Some("tenant-a"), "token-b", store(), "could not be used"),
            ("tenant secret for an appliance-wide owner", None, "token-b", store(), "could not be used"),
            ("deleted secret", None, "missing", store(), "is not available"),
            ("no store", None, "token-global", None, "is not available"),
        ] {
            let mut configuration = serde_json::json!({ "secret_key_secret_id": reference });
            let error = resolve_secret_references(&mut configuration, owner, store)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("secret_key_secret_id"), "{case}: {error}");
            assert!(error.contains(reason), "{case}: {error}");
            assert!(
                configuration
                    .get("secret_key")
                    .is_none(),
                "{case}"
            );
        }
    }

    fn url_store() -> Arc<MemorySecretsStore> {
        Arc::new(MemorySecretsStore::with(vec![
            secret("id-hook-a", "hook-a", "https://hooks.example.com/in/a", None),
            secret("id-hook-b", "hook-b", "https://hooks.example.com:8443/in/b", None),
            secret("id-private", "private-hook", "http://10.0.0.5/in", None),
            secret("id-vhost", "vhost", "hooks.example.com", None),
            secret("id-redis", "redis-url", "redis://:redis-pass@cache:6379", None),
            secret("id-word", "not-a-url", "global-token", None),
            secret("id-login", "login", "admin:hunter2", None),
            secret("id-ftp", "ftp-hook", "ftp://files.example.com/in", None),
            secret("id-db", "db-url", "postgres://u:p@db.internal:5432/app", None),
        ]))
    }

    #[tokio::test]
    async fn a_referenced_redis_url_that_is_not_a_redis_url_gets_one_answer_whatever_it_holds() {
        let store = url_store();
        let mut answers = std::collections::BTreeSet::new();
        for reference in ["login", "not-a-url", "ftp-hook", "db-url", "hook-a"] {
            let mut sent = serde_json::json!({ "platform": "redis", "redis_url_secret_id": reference });
            let refused = pin_destination(&mut sent, None, as_store(&store))
                .await
                .unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{reference}: {}", refused.1);
            for secret_text in ["admin", "hunter2", "global-token", "ftp", "db.internal", "5432", "hooks.example.com"] {
                assert!(
                    !refused
                        .1
                        .contains(secret_text),
                    "{reference}: {}",
                    refused.1
                );
            }
            assert!(
                sent.get(PINNED_DESTINATION)
                    .is_none(),
                "{reference}"
            );
            answers.insert(refused.1);
        }
        assert_eq!(
            answers
                .into_iter()
                .collect::<Vec<_>>(),
            ["the secret referenced by redis_url_secret_id does not hold a redis:// URL"]
        );
    }

    #[tokio::test]
    async fn a_referenced_value_that_is_not_an_http_url_is_refused_without_describing_it() {
        let store = url_store();
        for (case, configuration) in [
            ("a login", serde_json::json!({ "url_secret_id": "login" })),
            ("a login as a slack url", serde_json::json!({ "webhook_url_secret_id": "login" })),
            ("a word", serde_json::json!({ "url_secret_id": "not-a-url" })),
            ("another scheme", serde_json::json!({ "url_secret_id": "ftp-hook" })),
        ] {
            let mut sent = configuration.clone();
            let refused = pin_destination(&mut sent, None, as_store(&store))
                .await
                .unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{case}: {}", refused.1);
            assert!(
                refused
                    .1
                    .ends_with("does not hold an http or https URL"),
                "{case}: {}",
                refused.1
            );
            for secret_text in ["admin", "hunter2", "global-token", "ftp", "files.example.com"] {
                assert!(
                    !refused
                        .1
                        .contains(secret_text),
                    "{case}: {}",
                    refused.1
                );
            }
        }
    }

    fn as_store(store: &Arc<MemorySecretsStore>) -> Option<Arc<dyn SecretsStore>> {
        Some(store.clone())
    }

    #[tokio::test]
    async fn a_save_pins_the_host_and_port_of_each_referenced_url_and_routing_header() {
        let store = url_store();
        let mut configuration = serde_json::json!({
            "url_secret_id": "hook-a",
            "redis_url_secret_id": "redis-url",
            "headers_secret_id": { "Host": "vhost", "Authorization": "hook-b" },
        });

        pin_destination(&mut configuration, None, as_store(&store))
            .await
            .unwrap();

        let pin = &configuration[PINNED_DESTINATION];
        assert_eq!(pin["url"], "hooks.example.com:443");
        assert_eq!(pin["redis_url"], "cache:6379");
        assert_eq!(
            pin["headers"]["host"]
                .as_str()
                .map(str::len),
            Some(64)
        );
        assert!(
            pin["headers"]
                .get("authorization")
                .is_none()
        );
        assert!(
            !configuration
                .to_string()
                .contains("redis-pass"),
            "{configuration}"
        );
        assert_eq!(configuration["url_secret_id"], "hook-a");
    }

    #[tokio::test]
    async fn a_save_refuses_a_referenced_url_that_is_not_a_permitted_destination() {
        let store = url_store();
        for (case, configuration) in [
            ("private address", serde_json::json!({ "url_secret_id": "private-hook" })),
            ("not a URL", serde_json::json!({ "webhook_url_secret_id": "not-a-url" })),
            ("missing secret", serde_json::json!({ "url_secret_id": "missing" })),
        ] {
            let mut sent = configuration.clone();
            let refused = pin_destination(&mut sent, None, as_store(&store))
                .await
                .unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{case}: {}", refused.1);
            assert!(
                !refused
                    .1
                    .contains("10.0.0.5/in"),
                "{case}: {}",
                refused.1
            );
            assert!(
                sent.get(PINNED_DESTINATION)
                    .is_none(),
                "{case}"
            );
        }

        let mut no_destination_reference =
            serde_json::json!({ "smtp_host": "h", "smtp_password_secret_id": "missing" });
        pin_destination(&mut no_destination_reference, None, None)
            .await
            .unwrap();
        assert!(
            no_destination_reference
                .get(PINNED_DESTINATION)
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_delivery_is_refused_when_a_referenced_destination_moved_since_the_save() {
        let store = url_store();
        let mut configuration = serde_json::json!({ "url_secret_id": "hook-a" });
        pin_destination(&mut configuration, None, as_store(&store))
            .await
            .unwrap();

        let mut resolved = configuration.clone();
        resolve_secret_references(&mut resolved, None, as_store(&store))
            .await
            .unwrap();
        verify_pinned_destination(&configuration, &resolved).unwrap();

        for (case, url) in
            [("same host, new port", "https://hooks.example.com:8443/in"), ("new host", "https://attacker.example/in")]
        {
            let moved = serde_json::json!({ "url": url });
            let error = verify_pinned_destination(&configuration, &moved)
                .unwrap_err()
                .to_string();
            assert!(error.contains("save the integration again"), "{case}: {error}");
            assert!(!error.contains("attacker"), "{case}: {error}");
        }

        let same_host_new_path = serde_json::json!({ "url": "https://hooks.example.com/in/rotated" });
        verify_pinned_destination(&configuration, &same_host_new_path).unwrap();

        let mut unpinned = configuration.clone();
        unpinned
            .as_object_mut()
            .unwrap()
            .remove(PINNED_DESTINATION);
        assert!(verify_pinned_destination(&unpinned, &resolved).is_err());
    }

    #[tokio::test]
    async fn startup_pins_saved_integrations_that_have_no_pin_yet() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let unpinned = stored("webhook", serde_json::json!({ "url_secret_id": "hook-a" }));
        let unresolvable = stored("webhook", serde_json::json!({ "url_secret_id": "missing" }));
        let inline = stored("webhook", serde_json::json!({ "url": "https://hooks.example.com/in" }));
        for integration in [&unpinned, &unresolvable, &inline] {
            storage
                .save(integration)
                .await
                .unwrap();
        }

        pin_unpinned_destinations(&storage, as_store(&url_store()), &|| true).await;

        let configuration_of = |id: String| {
            let storage = &storage;
            async move {
                storage
                    .load(&id)
                    .await
                    .unwrap()
                    .configuration
            }
        };
        assert_eq!(
            configuration_of(unpinned.id.clone()).await[PINNED_DESTINATION],
            serde_json::json!({ "url": "hooks.example.com:443" })
        );
        assert!(
            configuration_of(unresolvable.id.clone())
                .await
                .get(PINNED_DESTINATION)
                .is_none()
        );
        assert_eq!(configuration_of(inline.id.clone()).await, inline.configuration);
    }

    #[tokio::test]
    async fn a_superseded_activation_pins_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let unpinned = stored("webhook", serde_json::json!({ "url_secret_id": "hook-a" }));
        storage
            .save(&unpinned)
            .await
            .unwrap();

        pin_unpinned_destinations(&storage, as_store(&url_store()), &|| false).await;

        assert_eq!(
            storage
                .load(&unpinned.id)
                .await
                .unwrap()
                .configuration,
            unpinned.configuration
        );
    }

    #[tokio::test]
    async fn the_values_sent_are_the_ones_the_reference_check_approved() {
        let mut configuration = serde_json::json!({
            "secret_key_secret_id": "token-b",
            "headers_secret_id": { "Authorization": "id-global" },
        });

        let approved = resolve_authorized_references(&configuration, store().as_ref(), Some("tenant-b"), None, None)
            .await
            .unwrap();
        approved
            .fill(&mut configuration)
            .unwrap();

        assert_eq!(
            configuration,
            serde_json::json!({ "secret_key": "tenant-b-token", "headers": { "Authorization": "global-token" } })
        );

        let other_tenant = serde_json::json!({ "secret_key_secret_id": "token-b" });
        let refused = resolve_authorized_references(&other_tenant, store().as_ref(), Some("tenant-a"), None, None)
            .await
            .err()
            .unwrap();
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_header_reference_fails_when_headers_is_not_an_object() {
        let mut configuration =
            serde_json::json!({ "headers": "x", "headers_secret_id": { "Authorization": "id-global" } });

        let error = resolve_secret_references(&mut configuration, None, store())
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("headers_secret_id.Authorization"), "{error}");
    }

    #[tokio::test]
    async fn a_configuration_without_references_needs_no_store() {
        let mut configuration = serde_json::json!({ "url": "https://hooks.example.com" });

        resolve_secret_references(&mut configuration, None, None)
            .await
            .unwrap();
        authorize_secret_references(&configuration, None, None, None, None)
            .await
            .unwrap();

        assert_eq!(configuration, serde_json::json!({ "url": "https://hooks.example.com" }));
    }

    #[tokio::test]
    async fn saving_a_reference_checks_the_owners_tenant_and_the_tokens_scope() {
        let configuration = serde_json::json!({ "secret_key_secret_id": "token-b" });
        let store = store();
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-b".into(),
        };
        let scoped_out = PatResourceScope(Arc::new(Regex::new(r"\ATENANT:tenant-b:secrets:other\z").unwrap()));

        authorize_secret_references(&configuration, store.as_ref(), Some("tenant-b"), Some(&context), None)
            .await
            .unwrap();
        for (case, owner, scope) in
            [("other tenant", Some("tenant-a"), None), ("scoped out", Some("tenant-b"), Some(&scoped_out))]
        {
            let refused = authorize_secret_references(&configuration, store.as_ref(), owner, Some(&context), scope)
                .await
                .unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{case}");
        }
        let unavailable = authorize_secret_references(&configuration, None, None, None, None)
            .await
            .unwrap_err();
        assert_eq!(unavailable.0, StatusCode::SERVICE_UNAVAILABLE);
    }
}
