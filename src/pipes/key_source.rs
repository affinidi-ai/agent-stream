//! Where the key a model call sends comes from, and what that call bills.
//!
//! Every model call Agent Stream makes (the main call, a stream, a failover,
//! load-balancing or routed target, a Decider candidate or merger, the Judge,
//! a juror, a guard or an embedder) sends a key from one of three sources:
//!
//! - [`KeySource::Client`]: the caller's own key, taken from the request. Only
//!   the surface's primary provider's main call may send it.
//! - [`KeySource::Customer`]: a secret the surface's tenant stored.
//! - [`KeySource::Platform`]: an appliance-wide secret the operator pays for,
//!   or no key at all.
//!
//! A call on an owned key (client or customer) is the account's own spend with
//! its provider, so it bills nothing: `billed_cost` is zero while `cost` keeps
//! the catalog price. A platform call bills its cost. Only the label ever
//! leaves this module; key material never reaches a log, a metric or a header.

use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::pipes::types::llm::OverridePolicy;

/// The source of the key one model call sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeySource {
    /// The caller's own key, from the request.
    Client,
    /// A secret the surface's tenant stored.
    Customer,
    /// The operator's key (or no key).
    Platform,
}

impl KeySource {
    /// The label sent in headers and stored in metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Customer => "customer",
            Self::Platform => "platform",
        }
    }

    /// Whether the key belongs to the account (the caller's or the tenant's
    /// own), so the provider bills the account directly.
    pub fn owned(self) -> bool {
        matches!(self, Self::Client | Self::Customer)
    }

    /// What a call that cost `cost` at its priced rate bills the account.
    pub fn billed_cost(
        self,
        cost: f64,
    ) -> f64 {
        if self.owned() {
            0.0
        } else {
            cost
        }
    }

    /// The source of a call that sent credentials from two sources: the
    /// platform's whenever either is, so a call is never billed as owned while
    /// any of its credentials is the operator's.
    pub fn combine(
        self,
        other: Self,
    ) -> Self {
        match (self, other) {
            (Self::Platform, _) | (_, Self::Platform) => Self::Platform,
            (Self::Client, Self::Client) => Self::Client,
            _ => Self::Customer,
        }
    }
}

/// Model calls counted by the source of the key each one sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySourceCounts {
    #[serde(default)]
    pub client: u64,
    #[serde(default)]
    pub customer: u64,
    #[serde(default)]
    pub platform: u64,
}

impl KeySourceCounts {
    /// One call on a key from `source`.
    pub fn one(source: KeySource) -> Self {
        let mut counts = Self::default();
        counts.record(source);
        counts
    }

    /// Count one more call on a key from `source`.
    pub fn record(
        &mut self,
        source: KeySource,
    ) {
        match source {
            KeySource::Client => self.client += 1,
            KeySource::Customer => self.customer += 1,
            KeySource::Platform => self.platform += 1,
        }
    }

    /// Fold another set of counts into this one.
    pub fn add(
        &mut self,
        other: Self,
    ) {
        self.client += other.client;
        self.customer += other.customer;
        self.platform += other.platform;
    }

    pub fn total(&self) -> u64 {
        self.client + self.customer + self.platform
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// The one source every counted call used, `None` when none was counted or
    /// the calls used keys from more than one source.
    pub fn sole(&self) -> Option<KeySource> {
        match (self.client > 0, self.customer > 0, self.platform > 0) {
            (true, false, false) => Some(KeySource::Client),
            (false, true, false) => Some(KeySource::Customer),
            (false, false, true) => Some(KeySource::Platform),
            _ => None,
        }
    }
}

/// A key one model call sends, and where it came from.
#[derive(Clone)]
pub struct CallKey {
    pub value: String,
    pub source: KeySource,
}

impl std::fmt::Debug for CallKey {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("CallKey")
            .field("value", &"[redacted]")
            .field("source", &self.source)
            .finish()
    }
}

/// Whether a model call may send the caller's own key. Its `Debug` never
/// prints the key.
#[derive(Clone, Copy)]
pub enum CallerKey<'a> {
    /// Every call except the surface's primary provider's main call: an
    /// auxiliary stage (Judge, juror, Decider, guard, embedder) or a call to any
    /// other provider (a failover, load-balancing or routed target, a Decider
    /// candidate or merger). It sends its own stored key.
    NotOffered,
    /// The surface's primary provider's main call. `key` is the caller's key
    /// from the request (`None` when the request carried none) and `policy` the
    /// surface's `api_key` override policy.
    Offered { key: Option<&'a str>, policy: Option<&'a OverridePolicy> },
}

impl std::fmt::Debug for CallerKey<'_> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::NotOffered => f.write_str("NotOffered"),
            Self::Offered { key, policy } => f
                .debug_struct("Offered")
                .field("key", &key.map(|_| "[redacted]"))
                .field("policy", policy)
                .finish(),
        }
    }
}

/// The credentials a request carried for its upstream, as the HTTP handler
/// resolved them. Only the surface's primary provider's main call may send any
/// of them. Its `Debug` never prints a value.
#[derive(Clone, Default)]
pub struct CallerCredentials {
    /// The request's `Authorization` header as received: the token identity
    /// pass-through (`forward_caller_token`) forwards, validated by the
    /// surface's `jwt_bearer` source auth.
    pub authorization: Option<String>,
    /// The `x-agent-stream-upstream-authorization` header: a distinct token
    /// identity pass-through forwards in preference to `authorization`.
    pub upstream_authorization: Option<String>,
    /// The caller's own provider key, offered under the surface's `api_key`
    /// override policy. Taken only from a header the front door did not
    /// consume, and never equal to the front-door credential.
    pub provider_key: Option<String>,
}

impl std::fmt::Debug for CallerCredentials {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let shown = |value: &Option<String>| {
            value
                .as_ref()
                .map(|_| "[redacted]")
        };
        f.debug_struct("CallerCredentials")
            .field("authorization", &shown(&self.authorization))
            .field("upstream_authorization", &shown(&self.upstream_authorization))
            .field("provider_key", &shown(&self.provider_key))
            .finish()
    }
}

impl CallerCredentials {
    /// The token identity pass-through (`forward_caller_token`) sends upstream:
    /// the caller's distinct upstream token when it sent one, else its
    /// front-door bearer token.
    pub fn forwarded_token(&self) -> Option<&str> {
        forwardable_bearer(
            self.upstream_authorization
                .as_deref(),
        )
        .or_else(|| forwardable_bearer(self.authorization.as_deref()))
    }
}

/// The trimmed, non-empty bearer token in a header value.
fn forwardable_bearer(header: Option<&str>) -> Option<&str> {
    header
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// The bearer token in an `Authorization` header value, if it carries one.
pub fn bearer_token(header: Option<&str>) -> Option<&str> {
    header
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
}

/// Resolve the key one model call sends: the single decision every model call
/// makes. `stored` resolves the call's own stored key (see
/// [`crate::secrets::SurfaceSecrets::resolve_key`]); it is only awaited when
/// that key is the one sent.
///
/// The caller's key is sent only when it is [`CallerKey::Offered`] and the
/// policy admits it: `client_wins` sends it and never a stored key,
/// `inject_if_missing` sends it when present and the stored key otherwise, and
/// `gateway_wins` (the default) always sends the stored key.
pub async fn resolve_call_key<'a, F, Fut, E>(
    caller: CallerKey<'a>,
    stored: F,
) -> Result<Option<CallKey>, E>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<CallKey>, E>>,
{
    let client = |key: &str| CallKey {
        value: key.to_string(),
        source: KeySource::Client,
    };
    match caller {
        CallerKey::NotOffered => stored().await,
        CallerKey::Offered { key, policy } => match policy {
            Some(OverridePolicy::ClientWins) => Ok(key.map(client)),
            Some(OverridePolicy::InjectIfMissing) => match key {
                Some(key) => Ok(Some(client(key))),
                None => stored().await,
            },
            Some(OverridePolicy::GatewayWins) | None => stored().await,
        },
    }
}

/// The source of a call's credentials: its key's and its extra upstream
/// headers' combined (see [`KeySource::combine`]: the platform's whenever any
/// of them is the operator's), else whichever one it sends, else the
/// platform's.
pub fn call_key_source(
    key: Option<KeySource>,
    headers: Option<KeySource>,
) -> KeySource {
    match (key, headers) {
        (Some(key), Some(headers)) => key.combine(headers),
        (key, headers) => key
            .or(headers)
            .unwrap_or(KeySource::Platform),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(source: KeySource) -> Result<Option<CallKey>, ()> {
        Ok(Some(CallKey {
            value: "stored".to_string(),
            source,
        }))
    }

    async fn pick(
        caller: CallerKey<'_>,
        stored_source: Option<KeySource>,
    ) -> Option<(String, KeySource)> {
        resolve_call_key(caller, || async move {
            match stored_source {
                Some(source) => stored(source),
                None => Ok(None),
            }
        })
        .await
        .unwrap()
        .map(|k| (k.value, k.source))
    }

    fn offered<'a>(
        key: Option<&'a str>,
        policy: Option<&'a OverridePolicy>,
    ) -> CallerKey<'a> {
        CallerKey::Offered { key, policy }
    }

    #[tokio::test]
    async fn a_call_not_offered_the_callers_key_sends_its_stored_key_under_every_policy() {
        assert_eq!(
            pick(CallerKey::NotOffered, Some(KeySource::Customer)).await,
            Some(("stored".to_string(), KeySource::Customer))
        );
        assert_eq!(
            pick(CallerKey::NotOffered, Some(KeySource::Platform)).await,
            Some(("stored".to_string(), KeySource::Platform))
        );
        assert_eq!(pick(CallerKey::NotOffered, None).await, None);
    }

    #[tokio::test]
    async fn the_primary_main_call_follows_the_api_key_policy() {
        let client_wins = OverridePolicy::ClientWins;
        let inject = OverridePolicy::InjectIfMissing;
        let gateway = OverridePolicy::GatewayWins;

        assert_eq!(
            pick(offered(Some("sk-caller"), Some(&client_wins)), Some(KeySource::Platform)).await,
            Some(("sk-caller".to_string(), KeySource::Client))
        );
        assert_eq!(
            pick(offered(None, Some(&client_wins)), Some(KeySource::Platform)).await,
            None,
            "client_wins never falls back to a stored key"
        );
        assert_eq!(
            pick(offered(Some("sk-caller"), Some(&inject)), Some(KeySource::Platform)).await,
            Some(("sk-caller".to_string(), KeySource::Client))
        );
        assert_eq!(
            pick(offered(None, Some(&inject)), Some(KeySource::Customer)).await,
            Some(("stored".to_string(), KeySource::Customer))
        );
        assert_eq!(
            pick(offered(Some("sk-caller"), Some(&gateway)), Some(KeySource::Platform)).await,
            Some(("stored".to_string(), KeySource::Platform))
        );
        assert_eq!(
            pick(offered(Some("sk-caller"), None), Some(KeySource::Platform)).await,
            Some(("stored".to_string(), KeySource::Platform)),
            "no policy means the stored key"
        );
    }

    #[tokio::test]
    async fn a_stored_key_is_not_resolved_when_the_callers_key_wins() {
        let client_wins = OverridePolicy::ClientWins;
        let resolved = resolve_call_key(offered(Some("sk-caller"), Some(&client_wins)), || async {
            Err::<Option<CallKey>, &str>("the stored key was resolved")
        })
        .await;
        assert_eq!(
            resolved
                .unwrap()
                .map(|k| k.source),
            Some(KeySource::Client)
        );
    }

    #[test]
    fn an_owned_key_bills_nothing_and_a_platform_key_bills_its_cost() {
        assert_eq!(KeySource::Client.billed_cost(1.25), 0.0);
        assert_eq!(KeySource::Customer.billed_cost(1.25), 0.0);
        assert_eq!(KeySource::Platform.billed_cost(1.25), 1.25);
    }

    #[test]
    fn credentials_from_the_platform_make_the_whole_call_platform() {
        assert_eq!(KeySource::Customer.combine(KeySource::Platform), KeySource::Platform);
        assert_eq!(KeySource::Platform.combine(KeySource::Client), KeySource::Platform);
        assert_eq!(KeySource::Customer.combine(KeySource::Customer), KeySource::Customer);
        assert_eq!(KeySource::Client.combine(KeySource::Client), KeySource::Client);
        assert_eq!(call_key_source(None, None), KeySource::Platform);
        assert_eq!(call_key_source(None, Some(KeySource::Customer)), KeySource::Customer);
    }

    #[test]
    fn an_owned_key_beside_an_operator_header_is_a_platform_call() {
        assert_eq!(call_key_source(Some(KeySource::Client), Some(KeySource::Platform)), KeySource::Platform);
        assert_eq!(call_key_source(Some(KeySource::Customer), Some(KeySource::Platform)), KeySource::Platform);
        assert_eq!(call_key_source(Some(KeySource::Platform), Some(KeySource::Customer)), KeySource::Platform);
        assert_eq!(call_key_source(Some(KeySource::Customer), Some(KeySource::Customer)), KeySource::Customer);
        assert_eq!(call_key_source(Some(KeySource::Client), None), KeySource::Client);
    }

    #[test]
    fn counts_add_and_name_their_sole_source() {
        let mut counts = KeySourceCounts::one(KeySource::Customer);
        assert_eq!(counts.sole(), Some(KeySource::Customer));
        counts.add(KeySourceCounts::one(KeySource::Customer));
        assert_eq!(counts.total(), 2);
        assert_eq!(counts.sole(), Some(KeySource::Customer));
        counts.record(KeySource::Platform);
        assert_eq!(counts.sole(), None);
        assert_eq!(KeySourceCounts::default().sole(), None);
        assert!(KeySourceCounts::default().is_empty());
    }

    #[test]
    fn labels_serialize_lowercase_and_keys_never_print() {
        assert_eq!(serde_json::to_value(KeySource::Customer).unwrap(), serde_json::json!("customer"));
        assert_eq!(KeySource::Client.as_str(), "client");
        let key = CallKey {
            value: "sk-secret-value".to_string(),
            source: KeySource::Client,
        };
        assert!(!format!("{key:?}").contains("sk-secret-value"));
    }

    #[test]
    fn a_caller_key_never_prints() {
        let policy = OverridePolicy::ClientWins;
        let offered = offered(Some("sk-caller-secret"), Some(&policy));
        let printed = format!("{offered:?}");
        assert!(!printed.contains("sk-caller-secret"), "{printed}");
        assert!(printed.contains("[redacted]") && printed.contains("ClientWins"), "{printed}");
        assert_eq!(format!("{:?}", CallerKey::NotOffered), "NotOffered");
    }

    #[test]
    fn a_bearer_header_yields_its_token() {
        assert_eq!(bearer_token(Some("Bearer sk-1")), Some("sk-1"));
        assert_eq!(bearer_token(Some("Bearer ")), None);
        assert_eq!(bearer_token(Some("Basic abc")), None);
        assert_eq!(bearer_token(None), None);
    }

    #[test]
    fn the_forwarded_token_prefers_the_upstream_token() {
        let caller = |authorization: Option<&str>, upstream: Option<&str>| CallerCredentials {
            authorization: authorization.map(str::to_string),
            upstream_authorization: upstream.map(str::to_string),
            provider_key: None,
        };
        assert_eq!(caller(Some("Bearer front"), Some("Bearer upstream")).forwarded_token(), Some("upstream"));
        assert_eq!(caller(Some("Bearer front"), None).forwarded_token(), Some("front"));
        assert_eq!(caller(Some("Bearer front"), Some("Bearer  ")).forwarded_token(), Some("front"));
        assert_eq!(caller(Some("Bearer  padded "), None).forwarded_token(), Some("padded"));
        assert_eq!(caller(Some("Basic abc"), None).forwarded_token(), None);
        assert_eq!(caller(None, None).forwarded_token(), None);
    }
}
