//! The provider's signed tokens. The ID token check (OpenID Connect Core 1.0
//! section 3.1.3.7): the signature against the provider's published keys, then
//! the issuer, audience, authorized party, expiry, issue time, nonce and
//! subject. The logout token check (Back-Channel Logout 1.0 section 2.6): the
//! same signature, issuer and audience, then its type, issue time, event,
//! subject or session, and a `jti` never seen before.

use dashmap::DashMap;
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header};
use serde_json::{Map, Value};

use super::config::OidcConfig;
use crate::auth::session::OidcSessionBinding;
use crate::jwt_bearer::JwksClient;
use crate::jwt_bearer::errors::JwtBearerError;

/// The JWKS cache entry the provider's keys are kept under.
const JWKS_CACHE_KEY: &str = "oidc-login";
/// Clock skew allowed on `exp` and `iat`.
const LEEWAY_SECS: u64 = 60;
/// The longest `sub`, `sid` or `jti` accepted.
const MAX_IDENTIFIER_CLAIM_LEN: usize = 255;
/// How old a logout token without `exp` may be.
const LOGOUT_TOKEN_MAX_AGE_SECS: i64 = 5 * 60;
/// The event a logout token must carry.
const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// Most logout token ids remembered at once; at the cap the one that would be
/// forgotten soonest is dropped.
const MAX_SEEN_LOGOUT_TOKENS: usize = 10_000;

/// A verified ID token: the account it names, the provider's session id when
/// it gives one, and all its claims.
#[derive(Debug)]
pub struct VerifiedIdToken {
    pub subject: String,
    pub sid: Option<String>,
    pub claims: Map<String, Value>,
}

/// Why an ID token or a logout token was not accepted. The detail names the check that failed,
/// for the log; it never contains the token.
#[derive(Debug)]
pub enum TokenFailure {
    /// The provider's published keys could not be fetched.
    KeysUnavailable(String),
    /// The token did not pass a check.
    Invalid(String),
}

impl std::fmt::Display for TokenFailure {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::KeysUnavailable(detail) | Self::Invalid(detail) => f.write_str(detail),
        }
    }
}

/// A verified logout token: what it signs out, and its `jti`.
#[derive(Debug)]
pub struct VerifiedLogoutToken {
    pub target: LogoutTarget,
    pub jti: String,
}

/// What a verified logout token signs out: one provider session (`sid`), or
/// every session of one account (`sub`).
#[derive(Debug, PartialEq, Eq)]
pub struct LogoutTarget {
    pub subject: Option<String>,
    pub sid: Option<String>,
}

impl LogoutTarget {
    /// Whether a session bound to `binding` is one this logout ends: the same
    /// issuer, and the same `sid` (and `sub`, when the token gives both), or,
    /// for a token with only `sub`, the same account. A session whose ID token
    /// had no `sid` cannot be told apart from the account's other provider
    /// sessions, so a token with `sid` ends it when its `sub` names the account.
    pub fn matches(
        &self,
        issuer: &str,
        binding: &OidcSessionBinding,
    ) -> bool {
        let same_account = self
            .subject
            .as_ref()
            .is_some_and(|subject| subject == &binding.subject);
        binding.issuer == issuer
            && match (&self.sid, &binding.sid) {
                (Some(sid), Some(bound)) => {
                    sid == bound
                        && self
                            .subject
                            .as_ref()
                            .is_none_or(|subject| subject == &binding.subject)
                }
                (Some(_), None) | (None, _) => same_account,
            }
    }
}

/// Logout token ids already used, each kept until its token would have
/// expired, so a captured logout token cannot be replayed.
#[derive(Default)]
pub struct SeenLogoutTokens {
    ids: DashMap<String, i64>,
}

impl SeenLogoutTokens {
    /// Record `jti` until `until` (a Unix time). False when it is already recorded.
    fn remember(
        &self,
        jti: &str,
        until: i64,
        now: i64,
    ) -> bool {
        self.ids
            .retain(|_, kept_until| *kept_until > now);
        if self.ids.len() >= MAX_SEEN_LOGOUT_TOKENS {
            // Collect the key first so no shard lock is held across the remove.
            let soonest = self
                .ids
                .iter()
                .min_by_key(|entry| *entry.value())
                .map(|entry| entry.key().clone());
            if let Some(key) = soonest {
                self.ids.remove(&key);
            }
        }
        match self
            .ids
            .entry(jti.to_string())
        {
            dashmap::Entry::Occupied(_) => false,
            dashmap::Entry::Vacant(slot) => {
                slot.insert(until);
                true
            }
        }
    }

    /// Forget `jti`, so the provider can send its logout token again.
    pub fn forget(
        &self,
        jti: &str,
    ) {
        self.ids.remove(jti);
    }
}

/// Verify an ID token from the token endpoint, issued for the sign-in whose
/// nonce is `expected_nonce`.
pub async fn verify_id_token(
    token: &str,
    config: &OidcConfig,
    jwks: &JwksClient,
    jwks_uri: &str,
    expected_nonce: &str,
) -> Result<VerifiedIdToken, TokenFailure> {
    let (_, claims) = signed_claims(token, config, jwks, jwks_uri, &["exp", "iss", "aud", "sub"]).await?;
    check_claims(&claims, config, expected_nonce, chrono::Utc::now().timestamp()).map_err(TokenFailure::Invalid)?;
    Ok(VerifiedIdToken {
        subject: string_claim(&claims, "sub").unwrap_or_default(),
        sid: string_claim(&claims, "sid"),
        claims,
    })
}

/// Verify a logout token the provider posted, and record its `jti` so it
/// works once.
pub async fn verify_logout_token(
    token: &str,
    config: &OidcConfig,
    jwks: &JwksClient,
    jwks_uri: &str,
    seen: &SeenLogoutTokens,
) -> Result<VerifiedLogoutToken, TokenFailure> {
    let (header, claims) = signed_claims(token, config, jwks, jwks_uri, &["iss", "aud"]).await?;
    if let Some(typ) = &header.typ {
        let typ = typ.to_ascii_lowercase();
        if typ != "logout+jwt" && typ != "application/logout+jwt" {
            return Err(TokenFailure::Invalid(format!("typ is {typ}, not logout+jwt")));
        }
    }
    let now = chrono::Utc::now().timestamp();
    let (target, jti, remember_until) = check_logout_claims(&claims, now).map_err(TokenFailure::Invalid)?;
    if !seen.remember(&jti, remember_until, now) {
        return Err(TokenFailure::Invalid("jti was already used".to_string()));
    }
    Ok(VerifiedLogoutToken { target, jti })
}

/// Check the header's algorithm against `id_token_signing_algs`, the signature
/// against the provider's keys, `iss`, `aud`, `exp` when present, and that the
/// registered claims in `required` are present. Returns the header and claims.
async fn signed_claims(
    token: &str,
    config: &OidcConfig,
    jwks: &JwksClient,
    jwks_uri: &str,
    required: &[&str],
) -> Result<(Header, Map<String, Value>), TokenFailure> {
    let header = decode_header(token).map_err(|e| TokenFailure::Invalid(format!("unreadable header: {e}")))?;
    if !config
        .id_token_signing_algs
        .contains(&header.alg)
    {
        return Err(TokenFailure::Invalid(format!("algorithm {:?} is not in id_token_signing_algs", header.alg)));
    }
    let jwk = jwks
        .get_key(
            JWKS_CACHE_KEY,
            jwks_uri,
            header
                .kid
                .as_deref()
                .unwrap_or_default(),
        )
        .await
        .map_err(|e| match e {
            JwtBearerError::KeyNotFound(_) => TokenFailure::Invalid(format!("no published key matches: {e}")),
            _ => TokenFailure::KeysUnavailable(format!("signing key unavailable: {e}")),
        })?;
    if let Some(key_alg) = &jwk.alg
        && key_alg
            .parse::<Algorithm>()
            .ok()
            != Some(header.alg)
    {
        return Err(TokenFailure::Invalid(format!("the signing key is for {key_alg}, not {:?}", header.alg)));
    }
    if jwk
        .key_use
        .as_deref()
        .is_some_and(|key_use| key_use != "sig")
    {
        return Err(TokenFailure::Invalid("the signing key is not published for signatures".to_string()));
    }
    let key = crate::jwt_bearer::validator::decoding_key_from_jwk(&jwk)
        .map_err(|e| TokenFailure::Invalid(format!("signing key unusable: {e}")))?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[&config.client_id]);
    validation.set_required_spec_claims(required);
    validation.leeway = LEEWAY_SECS;
    let claims = decode::<Map<String, Value>>(token, &key, &validation)
        .map_err(|e| TokenFailure::Invalid(format!("{e}")))?
        .claims;
    Ok((header, claims))
}

fn string_claim(
    claims: &Map<String, Value>,
    name: &str,
) -> Option<String> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// An optional claim that, when present, must be a string of 1 to 255
/// characters.
fn short_string_claim(
    claims: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, String> {
    match claims.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() && value.len() <= MAX_IDENTIFIER_CLAIM_LEN => {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(format!("{name} must be a string of 1 to {MAX_IDENTIFIER_CLAIM_LEN} characters")),
    }
}

/// The logout token checks `jsonwebtoken` does not make. Returns what to sign
/// out, the `jti`, and until when to remember it.
fn check_logout_claims(
    claims: &Map<String, Value>,
    now: i64,
) -> Result<(LogoutTarget, String, i64), String> {
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or("iat is missing")?;
    if issued_at > now + LEEWAY_SECS as i64 {
        return Err("iat is in the future".to_string());
    }
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_i64);
    if expires_at.is_none() && issued_at < now - LOGOUT_TOKEN_MAX_AGE_SECS {
        return Err("a token without exp is more than 5 minutes old".to_string());
    }
    if claims.contains_key("nonce") {
        return Err("a logout token must not carry a nonce".to_string());
    }
    if !claims
        .get("events")
        .and_then(Value::as_object)
        .and_then(|events| events.get(BACKCHANNEL_LOGOUT_EVENT))
        .is_some_and(Value::is_object)
    {
        return Err("events does not hold the back-channel logout event".to_string());
    }
    let target = LogoutTarget {
        subject: short_string_claim(claims, "sub")?,
        sid: short_string_claim(claims, "sid")?,
    };
    if target.subject.is_none() && target.sid.is_none() {
        return Err("neither sub nor sid is present".to_string());
    }
    let jti = short_string_claim(claims, "jti")?.ok_or("jti is missing")?;
    let remember_until = expires_at.unwrap_or(issued_at + LOGOUT_TOKEN_MAX_AGE_SECS) + LEEWAY_SECS as i64;
    Ok((target, jti, remember_until))
}

/// The checks `jsonwebtoken` does not make: `iat`, `azp`, `nonce` and the
/// shape of `sub`.
fn check_claims(
    claims: &Map<String, Value>,
    config: &OidcConfig,
    expected_nonce: &str,
    now: i64,
) -> Result<(), String> {
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or("iat is missing")?;
    if issued_at > now + LEEWAY_SECS as i64 {
        return Err("iat is in the future".to_string());
    }

    let several_audiences = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|audiences| audiences.len() > 1);
    match claims.get("azp") {
        Some(Value::String(azp)) if azp == &config.client_id => {}
        Some(_) => return Err("azp is not this client".to_string()),
        None if several_audiences => return Err("azp is missing for a token with several audiences".to_string()),
        None => {}
    }

    if claims
        .get("nonce")
        .and_then(Value::as_str)
        != Some(expected_nonce)
    {
        return Err("nonce does not match this sign-in".to_string());
    }

    if short_string_claim(claims, "sub")?.is_none() {
        return Err(format!("sub must be a string of 1 to {MAX_IDENTIFIER_CLAIM_LEN} characters"));
    }
    short_string_claim(claims, "sid").map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::test_support::{
        CLIENT_ID, KEY_A_KID, KEY_B_KID, KEY_B_PEM, StubProvider, config_for, id_token_claims, sign,
    };
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    async fn verify(
        provider: &StubProvider,
        token: &str,
    ) -> Result<VerifiedIdToken, String> {
        let config = config_for(&provider.issuer);
        verify_id_token(token, &config, &provider.jwks_client(), &provider.jwks_uri(), "nonce-1")
            .await
            .map_err(|failure| failure.to_string())
    }

    #[tokio::test]
    async fn a_token_signed_by_the_provider_is_accepted() {
        let provider = StubProvider::start().await;
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let verified = verify(&provider, &token)
            .await
            .unwrap();

        assert_eq!(verified.subject, "user-1");
        assert_eq!(verified.claims["org_id"], "org_123");
    }

    #[tokio::test]
    async fn a_token_signed_by_another_key_is_refused() {
        let provider = StubProvider::start().await;
        let forged = sign(KEY_B_PEM, Some(KEY_A_KID), &id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &forged)
            .await
            .unwrap_err();

        assert!(refused.contains("InvalidSignature"), "{refused}");
    }

    #[tokio::test]
    async fn a_token_with_an_unsigned_or_symmetric_algorithm_is_refused() {
        let provider = StubProvider::start().await;
        let claims = id_token_claims(&provider.issuer, "nonce-1");
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&claims).unwrap(),
        );
        let unsigned = format!("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{payload}.");
        assert!(
            verify(&provider, &unsigned)
                .await
                .unwrap_err()
                .contains("unreadable header"),
            "alg none is not even a known algorithm"
        );

        let hs256 = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"the-client-secret"),
        )
        .unwrap();
        assert!(
            verify(&provider, &hs256)
                .await
                .unwrap_err()
                .contains("HS256 is not in id_token_signing_algs")
        );
    }

    #[tokio::test]
    async fn a_key_published_for_another_algorithm_is_refused() {
        let provider = StubProvider::start().await;
        provider.set_jwks(json!({ "keys": [provider.jwk_a_with_alg("ES384")] }));
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &token)
            .await
            .unwrap_err();

        assert!(refused.contains("the signing key is for ES384"), "{refused}");
    }

    #[tokio::test]
    async fn a_key_published_for_encryption_is_refused() {
        let provider = StubProvider::start().await;
        let mut key = provider.jwk_a_with_alg("ES256");
        key["use"] = json!("enc");
        provider.set_jwks(json!({ "keys": [key] }));
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &token)
            .await
            .unwrap_err();

        assert!(refused.contains("not published for signatures"), "{refused}");
    }

    #[tokio::test]
    async fn keys_that_cannot_be_fetched_are_told_apart_from_a_token_that_does_not_verify() {
        let provider = StubProvider::start().await;
        let config = config_for(&provider.issuer);
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let unavailable = verify_id_token(
            &token,
            &config,
            &provider.jwks_client(),
            &format!("{}/no-such-jwks", provider.issuer),
            "nonce-1",
        )
        .await
        .unwrap_err();
        assert!(matches!(unavailable, TokenFailure::KeysUnavailable(_)), "{unavailable:?}");

        let unknown_key = sign(KEY_B_PEM, Some(KEY_B_KID), &id_token_claims(&provider.issuer, "nonce-1"));
        let invalid = verify_id_token(&unknown_key, &config, &provider.jwks_client(), &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap_err();
        assert!(matches!(invalid, TokenFailure::Invalid(_)), "{invalid:?}");
    }

    #[tokio::test]
    async fn an_unknown_key_id_refetches_the_keys_once_so_rotation_works() {
        let provider = StubProvider::start().await;
        let config = config_for(&provider.issuer);
        let jwks = provider.jwks_client();
        let first = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));
        verify_id_token(&first, &config, &jwks, &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap();

        provider.rotate_to_key_b();
        let rotated = sign(KEY_B_PEM, Some(KEY_B_KID), &id_token_claims(&provider.issuer, "nonce-1"));
        verify_id_token(&rotated, &config, &jwks, &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap();

        assert_eq!(provider.jwks_fetches(), 2, "one fetch at first use, one for the new key id");
    }

    #[tokio::test]
    async fn the_standard_claims_are_checked() {
        let provider = StubProvider::start().await;
        let now = chrono::Utc::now().timestamp();
        for (change, expected) in [
            (json!({ "iss": "https://other.example" }), "InvalidIssuer"),
            (json!({ "aud": "another-client" }), "InvalidAudience"),
            (json!({ "exp": now - 120 }), "ExpiredSignature"),
            (json!({ "sub": null }), "sub"),
        ] {
            let mut claims = id_token_claims(&provider.issuer, "nonce-1");
            for (name, value) in change.as_object().unwrap() {
                if value.is_null() {
                    claims
                        .as_object_mut()
                        .unwrap()
                        .remove(name);
                } else {
                    claims[name] = value.clone();
                }
            }
            let refused = verify(&provider, &provider.id_token(claims))
                .await
                .unwrap_err();
            assert!(refused.contains(expected), "{change}: {refused}");
        }
    }

    fn checked(change: Value) -> Result<(), String> {
        let config = config_for("https://idp.example.com");
        let mut claims = id_token_claims("https://idp.example.com", "nonce-1");
        for (name, value) in change.as_object().unwrap() {
            if value.is_null() {
                claims
                    .as_object_mut()
                    .unwrap()
                    .remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        let claims = claims
            .as_object()
            .unwrap()
            .clone();
        check_claims(&claims, &config, "nonce-1", chrono::Utc::now().timestamp())
    }

    #[test]
    fn the_nonce_must_be_this_sign_ins() {
        assert!(checked(json!({})).is_ok());
        for nonce in [json!("nonce-2"), json!(null), json!(7)] {
            assert!(
                checked(json!({ "nonce": nonce }))
                    .unwrap_err()
                    .contains("nonce"),
                "{nonce}"
            );
        }
    }

    #[test]
    fn several_audiences_need_this_client_as_the_authorized_party() {
        assert!(
            checked(json!({ "aud": [CLIENT_ID, "other"] }))
                .unwrap_err()
                .contains("azp is missing")
        );
        assert!(checked(json!({ "aud": [CLIENT_ID, "other"], "azp": CLIENT_ID })).is_ok());
        assert!(checked(json!({ "aud": [CLIENT_ID] })).is_ok(), "one audience needs no azp");
        assert!(
            checked(json!({ "azp": "other" }))
                .unwrap_err()
                .contains("azp is not this client")
        );
    }

    #[test]
    fn the_token_must_not_be_issued_in_the_future() {
        let now = chrono::Utc::now().timestamp();
        assert!(checked(json!({ "iat": now + 30 })).is_ok(), "within the leeway");
        assert!(
            checked(json!({ "iat": now + 600 }))
                .unwrap_err()
                .contains("future")
        );
        assert!(
            checked(json!({ "iat": null }))
                .unwrap_err()
                .contains("iat is missing")
        );
    }

    #[test]
    fn the_subject_must_be_a_short_non_empty_string() {
        assert!(checked(json!({ "sub": "" })).is_err());
        assert!(checked(json!({ "sub": "x".repeat(256) })).is_err());
        assert!(checked(json!({ "sub": 42 })).is_err());
        assert!(checked(json!({ "sub": "x".repeat(255) })).is_ok());
    }

    fn binding(sid: Option<&str>) -> OidcSessionBinding {
        OidcSessionBinding {
            issuer: "https://idp.example.com".to_string(),
            subject: "user-1".to_string(),
            sid: sid.map(str::to_string),
        }
    }

    fn target(
        subject: Option<&str>,
        sid: Option<&str>,
    ) -> LogoutTarget {
        LogoutTarget {
            subject: subject.map(str::to_string),
            sid: sid.map(str::to_string),
        }
    }

    #[test]
    fn a_logout_by_sid_ends_that_provider_session_and_by_sub_every_session_of_the_account() {
        let issuer = "https://idp.example.com";
        let by_sid = target(None, Some("s1"));
        assert!(by_sid.matches(issuer, &binding(Some("s1"))));
        assert!(!by_sid.matches(issuer, &binding(Some("s2"))));
        assert!(!by_sid.matches(issuer, &binding(None)), "a session without a sid is not this one");

        let both = target(Some("user-1"), Some("s1"));
        assert!(both.matches(issuer, &binding(Some("s1"))));
        assert!(!both.matches(issuer, &binding(Some("s2"))));
        assert!(both.matches(issuer, &binding(None)), "a session without a sid, of that account");
        assert!(!target(Some("user-2"), Some("s1")).matches(issuer, &binding(None)));
        assert!(!target(Some("user-2"), Some("s1")).matches(issuer, &binding(Some("s1"))), "sub must agree too");

        let by_sub = target(Some("user-1"), None);
        assert!(by_sub.matches(issuer, &binding(Some("s1"))));
        assert!(by_sub.matches(issuer, &binding(None)));
        assert!(!target(Some("user-2"), None).matches(issuer, &binding(None)));

        assert!(!by_sub.matches("https://other.example", &binding(None)), "another provider's session");
        assert!(!target(None, None).matches(issuer, &binding(Some("s1"))));
    }

    #[test]
    fn a_logout_token_id_works_once_until_it_would_have_expired() {
        let seen = SeenLogoutTokens::default();
        assert!(seen.remember("jti-1", 1_000, 900));
        assert!(!seen.remember("jti-1", 1_000, 950), "replayed");
        assert!(seen.remember("jti-1", 2_000, 1_000), "forgotten once its token expired");
        assert!(seen.remember("jti-2", 2_000, 1_000));
    }

    #[test]
    fn at_the_cap_the_token_id_forgotten_soonest_makes_room() {
        let seen = SeenLogoutTokens::default();
        for index in 0..MAX_SEEN_LOGOUT_TOKENS {
            assert!(seen.remember(&format!("jti-{index}"), 10_000 + index as i64, 0));
        }
        assert!(seen.remember("newest", 50_000, 0));
        assert_eq!(seen.ids.len(), MAX_SEEN_LOGOUT_TOKENS);
        assert!(seen.remember("jti-0", 50_000, 0), "the soonest to expire was dropped");
        assert!(!seen.remember("jti-9999", 50_000, 0));
    }

    fn logout_checked(change: Value) -> Result<(LogoutTarget, String, i64), String> {
        let mut claims = crate::auth::oidc::test_support::logout_claims("https://idp.example.com", "s1");
        for (name, value) in change.as_object().unwrap() {
            if value.is_null() {
                claims
                    .as_object_mut()
                    .unwrap()
                    .remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        check_logout_claims(claims.as_object().unwrap(), chrono::Utc::now().timestamp())
    }

    #[test]
    fn a_logout_token_must_carry_the_event_a_subject_or_session_and_an_id() {
        let (target, jti, _) = logout_checked(json!({})).unwrap();
        assert_eq!(
            target,
            LogoutTarget {
                subject: Some("user-1".into()),
                sid: Some("s1".into())
            }
        );
        assert!(!jti.is_empty());

        for (change, expected) in [
            (json!({ "events": null }), "events"),
            (json!({ "events": { "http://schemas.openid.net/event/other": {} } }), "events"),
            (json!({ "events": { BACKCHANNEL_LOGOUT_EVENT: true } }), "events"),
            (json!({ "nonce": "n" }), "nonce"),
            (json!({ "sub": null, "sid": null }), "neither sub nor sid"),
            (json!({ "sid": "" }), "sid"),
            (json!({ "jti": null }), "jti is missing"),
            (json!({ "iat": null }), "iat is missing"),
            (json!({ "iat": chrono::Utc::now().timestamp() + 600 }), "future"),
        ] {
            let refused = logout_checked(change.clone()).unwrap_err();
            assert!(refused.contains(expected), "{change}: {refused}");
        }
        assert!(logout_checked(json!({ "sub": null })).is_ok(), "sid alone");
        assert!(logout_checked(json!({ "sid": null })).is_ok(), "sub alone");
    }

    #[test]
    fn a_logout_token_without_exp_must_be_recent() {
        let now = chrono::Utc::now().timestamp();
        let (_, _, remember_until) = logout_checked(json!({ "exp": null, "iat": now - 60 })).unwrap();
        assert_eq!(remember_until, now - 60 + LOGOUT_TOKEN_MAX_AGE_SECS + LEEWAY_SECS as i64);

        let refused = logout_checked(json!({ "exp": null, "iat": now - 600 })).unwrap_err();
        assert!(refused.contains("more than 5 minutes old"), "{refused}");
        assert!(logout_checked(json!({ "iat": now - 600 })).is_ok(), "an old token with exp in the future");
    }

    #[test]
    fn a_logout_token_id_is_remembered_for_as_long_as_the_leeway_still_accepts_the_token() {
        let now = chrono::Utc::now().timestamp();
        let (_, _, remember_until) = logout_checked(json!({ "exp": now - 30 })).unwrap();
        assert_eq!(remember_until, now - 30 + LEEWAY_SECS as i64);
    }

    async fn verify_logout(
        provider: &StubProvider,
        token: &str,
        seen: &SeenLogoutTokens,
    ) -> Result<LogoutTarget, String> {
        verify_logout_failure(provider, token, seen)
            .await
            .map(|verified| verified.target)
            .map_err(|failure| failure.to_string())
    }

    async fn verify_logout_failure(
        provider: &StubProvider,
        token: &str,
        seen: &SeenLogoutTokens,
    ) -> Result<VerifiedLogoutToken, TokenFailure> {
        let config = config_for(&provider.issuer);
        verify_logout_token(token, &config, &provider.jwks_client(), &provider.jwks_uri(), seen).await
    }

    #[tokio::test]
    async fn a_signed_logout_token_is_accepted_once() {
        let provider = StubProvider::start().await;
        let seen = SeenLogoutTokens::default();
        let token = crate::auth::oidc::test_support::sign_logout(&crate::auth::oidc::test_support::logout_claims(
            &provider.issuer,
            "s1",
        ));

        assert_eq!(
            verify_logout(&provider, &token, &seen)
                .await
                .unwrap()
                .sid
                .as_deref(),
            Some("s1")
        );
        assert!(
            verify_logout(&provider, &token, &seen)
                .await
                .unwrap_err()
                .contains("jti was already used")
        );
    }

    #[tokio::test]
    async fn an_id_token_or_a_forged_or_misaddressed_token_is_not_a_logout_token() {
        let provider = StubProvider::start().await;
        let seen = SeenLogoutTokens::default();
        let claims = crate::auth::oidc::test_support::logout_claims(&provider.issuer, "s1");

        let id_token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));
        assert!(
            verify_logout(&provider, &id_token, &seen)
                .await
                .unwrap_err()
                .contains("typ is jwt")
        );

        let mut untyped_with_nonce = claims.clone();
        untyped_with_nonce["nonce"] = json!("nonce-1");
        let mut header = Header::new(Algorithm::ES256);
        header.typ = None;
        header.kid = Some(KEY_A_KID.to_string());
        let token = jsonwebtoken::encode(
            &header,
            &untyped_with_nonce,
            &EncodingKey::from_ec_pem(crate::auth::oidc::test_support::KEY_A_PEM.as_bytes()).unwrap(),
        )
        .unwrap();
        assert!(
            verify_logout(&provider, &token, &seen)
                .await
                .unwrap_err()
                .contains("nonce")
        );

        let forged = sign(KEY_B_PEM, Some(KEY_A_KID), &claims);
        assert!(
            verify_logout(&provider, &forged, &seen)
                .await
                .unwrap_err()
                .contains("InvalidSignature")
        );

        let mut misaddressed = claims.clone();
        misaddressed["aud"] = json!("another-client");
        let token = crate::auth::oidc::test_support::sign_logout(&misaddressed);
        assert!(
            verify_logout(&provider, &token, &seen)
                .await
                .unwrap_err()
                .contains("InvalidAudience")
        );
    }

    #[tokio::test]
    async fn a_signed_logout_token_inside_the_exp_leeway_is_accepted_once() {
        let provider = StubProvider::start().await;
        let seen = SeenLogoutTokens::default();
        let mut claims = crate::auth::oidc::test_support::logout_claims(&provider.issuer, "s1");
        claims["exp"] = json!(chrono::Utc::now().timestamp() - 30);
        let token = crate::auth::oidc::test_support::sign_logout(&claims);

        assert!(
            verify_logout(&provider, &token, &seen)
                .await
                .is_ok()
        );
        assert!(
            verify_logout(&provider, &token, &seen)
                .await
                .unwrap_err()
                .contains("jti was already used")
        );
    }

    #[tokio::test]
    async fn a_forgotten_logout_token_id_can_be_sent_again() {
        let provider = StubProvider::start().await;
        let seen = SeenLogoutTokens::default();
        let token = crate::auth::oidc::test_support::sign_logout(&crate::auth::oidc::test_support::logout_claims(
            &provider.issuer,
            "s1",
        ));

        let verified = verify_logout_failure(&provider, &token, &seen)
            .await
            .unwrap();
        seen.forget(&verified.jti);
        assert!(
            verify_logout(&provider, &token, &seen)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_logout_token_type_is_logout_jwt_with_or_without_its_media_type_prefix() {
        let provider = StubProvider::start().await;
        let seen = SeenLogoutTokens::default();
        let claims = crate::auth::oidc::test_support::logout_claims(&provider.issuer, "s1");
        let typed = |typ: &str| {
            let mut header = Header::new(Algorithm::ES256);
            header.typ = Some(typ.to_string());
            header.kid = Some(KEY_A_KID.to_string());
            let mut claims = claims.clone();
            claims["jti"] = json!(uuid::Uuid::new_v4().to_string());
            jsonwebtoken::encode(
                &header,
                &claims,
                &EncodingKey::from_ec_pem(crate::auth::oidc::test_support::KEY_A_PEM.as_bytes()).unwrap(),
            )
            .unwrap()
        };

        assert!(
            verify_logout(&provider, &typed("application/logout+jwt"), &seen)
                .await
                .is_ok()
        );
        assert!(
            verify_logout(&provider, &typed("secevent+jwt"), &seen)
                .await
                .unwrap_err()
                .contains("not logout+jwt")
        );
    }

    #[tokio::test]
    async fn a_logout_token_whose_keys_cannot_be_fetched_is_unchecked_rather_than_invalid() {
        let provider = StubProvider::start().await;
        provider.set_jwks(json!("not a key set"));
        let token = crate::auth::oidc::test_support::sign_logout(&crate::auth::oidc::test_support::logout_claims(
            &provider.issuer,
            "s1",
        ));

        let failure = verify_logout_failure(&provider, &token, &SeenLogoutTokens::default())
            .await
            .unwrap_err();
        assert!(matches!(failure, TokenFailure::KeysUnavailable(_)), "{failure:?}");
    }

    #[test]
    fn an_id_token_sid_must_be_short_when_present() {
        assert!(checked(json!({ "sid": "s1" })).is_ok());
        assert!(checked(json!({ "sid": "" })).is_err());
        assert!(checked(json!({ "sid": 7 })).is_err());
    }
}
