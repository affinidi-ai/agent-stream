//! `oidc.json`: the one OpenID provider the dashboard signs in with, the
//! client registered there, and how the provider's claims become a user and a
//! role. Read and checked once at startup; any problem stops startup.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use jsonwebtoken::Algorithm;
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;
use url::Url;

use crate::auth::types::UserRole;

/// Where a client secret may come from. A secret written into the file itself
/// (`string://` or no prefix) is refused, so `oidc.json` never holds one.
const SECRET_REFERENCE_PREFIXES: &[&str] = &["env://", "file://", "aws_secrets://", "aws_parameter_store://"];

/// ID token signing algorithms that may be allowed. `none` and the `HS*`
/// family are never among them: an `HS*` token is signed with the client
/// secret, which proves nothing about the provider.
const ALLOWED_SIGNING_ALGS: &[Algorithm] = &[
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::EdDSA,
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcFile {
    #[serde(default = "default_label")]
    label: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    redirect_uri: String,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default = "default_signing_algs")]
    id_token_signing_algs: Vec<String>,
    #[serde(default)]
    claims: ClaimNames,
    #[serde(default)]
    required_claims: BTreeMap<String, Vec<RawClaimValue>>,
    role_mapping: RoleMappingFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleMappingFile {
    claim: String,
    values: BTreeMap<String, UserRole>,
    #[serde(default = "default_unmapped")]
    unmapped: String,
}

fn default_label() -> String {
    "SSO".to_string()
}

fn default_scopes() -> Vec<String> {
    ["openid", "profile", "email"]
        .map(String::from)
        .to_vec()
}

fn default_signing_algs() -> Vec<String> {
    vec!["ES256".to_string()]
}

fn default_unmapped() -> String {
    "deny".to_string()
}

/// How the client authenticates at the provider's token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    #[default]
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenEndpointAuthMethod {
    /// The method's name in `oidc.json` and in the provider's discovery document.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }
}

/// Which ID token claim fills each profile field. Profile fields are display
/// data only: none of them identifies the person.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClaimNames {
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

impl Default for ClaimNames {
    fn default() -> Self {
        Self {
            username: "preferred_username".to_string(),
            email: "email".to_string(),
            first_name: "given_name".to_string(),
            last_name: "family_name".to_string(),
        }
    }
}

/// How `oidc.json` marks a value as a regular expression: `regex:<pattern>`.
/// An explicit marker, because ordinary values such as email addresses are
/// full of characters (`.`, `+`) that mean something in a pattern.
const REGEX_PREFIX: &str = "regex:";

/// The longest compiled pattern accepted, in bytes of compiled program.
const MAX_PATTERN_SIZE: usize = 1 << 20;

/// A claim value as `oidc.json` writes it in `required_claims`.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawClaimValue {
    String(String),
    Bool(bool),
}

/// A value from `oidc.json` that a claim value is compared with: a string or a
/// boolean, each matching only its own type exactly (so `true` does not match
/// the string `"true"`), or a `regex:` pattern that must match the whole of a
/// string value.
#[derive(Debug, Clone)]
pub enum ValueMatcher {
    Exact(String),
    Bool(bool),
    Regex(regex::Regex),
}

impl PartialEq for ValueMatcher {
    fn eq(
        &self,
        other: &Self,
    ) -> bool {
        match (self, other) {
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Regex(a), Self::Regex(b)) => a.as_str() == b.as_str(),
            _ => false,
        }
    }
}

impl ValueMatcher {
    /// A string from `oidc.json`: a pattern when it starts with `regex:`,
    /// otherwise an exact value. The pattern is anchored to the whole value.
    pub(crate) fn from_text(
        field: &str,
        text: &str,
    ) -> Result<Self, String> {
        let Some(pattern) = text.strip_prefix(REGEX_PREFIX) else {
            return Ok(Self::Exact(text.to_string()));
        };
        let build = |pattern: &str| {
            regex::RegexBuilder::new(pattern)
                .size_limit(MAX_PATTERN_SIZE)
                .build()
                .map_err(|e| format!("{field}: {text} is not a usable regular expression: {e}"))
        };
        // Compiled alone first: a pattern such as `a)|(b` would otherwise close
        // the anchoring group and match part of a value.
        build(pattern)?;
        build(&format!("^(?:{pattern})$")).map(Self::Regex)
    }

    /// Whether a claim value from a token matches.
    pub fn matches(
        &self,
        value: &Value,
    ) -> bool {
        match (self, value) {
            (Self::Bool(expected), Value::Bool(actual)) => expected == actual,
            (_, Value::String(actual)) => self.matches_str(actual),
            _ => false,
        }
    }

    /// Whether a string claim value matches.
    pub fn matches_str(
        &self,
        value: &str,
    ) -> bool {
        match self {
            Self::Exact(expected) => expected == value,
            Self::Regex(pattern) => pattern.is_match(value),
            Self::Bool(_) => false,
        }
    }
}

/// Which values of one claim grant which role, and what an account with no
/// mapped value gets: a role, or no access (`None`).
#[derive(Debug)]
pub struct RoleMapping {
    pub claim: String,
    pub values: Vec<(ValueMatcher, UserRole)>,
    pub unmapped: Option<UserRole>,
}

/// The resolved client secret. Its `Debug` output never shows the value.
pub struct ClientSecret(pub(super) String);

impl ClientSecret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str("ClientSecret(<redacted>)")
    }
}

/// A checked `oidc.json`, with its client secret resolved.
#[derive(Debug)]
pub struct OidcConfig {
    pub label: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: ClientSecret,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub redirect_uri: Url,
    pub scopes: Vec<String>,
    pub id_token_signing_algs: Vec<Algorithm>,
    pub claims: ClaimNames,
    pub required_claims: BTreeMap<String, Vec<ValueMatcher>>,
    pub role_mapping: RoleMapping,
}

impl OidcConfig {
    /// Read, check and resolve `oidc.json`.
    pub async fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("Failed to read OIDC config file: {}", e))?;
        Self::from_json(&content).await
    }

    pub(crate) async fn from_json(content: &str) -> Result<Self, String> {
        let file: OidcFile =
            serde_json::from_str(content).map_err(|e| format!("Failed to parse OIDC config JSON: {}", e))?;
        let checked = check(file)?;
        let client_id = resolve_client_id(&checked.client_id).await?;
        let client_secret = resolve_client_secret(&checked.client_secret_reference).await?;
        if checked
            .required_claims
            .is_empty()
        {
            warn!(
                issuer = %checked.issuer,
                "oidc.json has no required_claims: every account at the OpenID provider can sign in"
            );
        }
        Ok(Self {
            label: checked.label,
            issuer: checked.issuer,
            client_id,
            client_secret,
            token_endpoint_auth_method: checked.token_endpoint_auth_method,
            redirect_uri: checked.redirect_uri,
            scopes: checked.scopes,
            id_token_signing_algs: checked.id_token_signing_algs,
            claims: checked.claims,
            required_claims: checked.required_claims,
            role_mapping: checked.role_mapping,
        })
    }

    /// The provider's discovery document address (OpenID Connect Discovery
    /// 1.0 section 4: one trailing `/` of the issuer is dropped first).
    pub fn discovery_url(&self) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            self.issuer
                .strip_suffix('/')
                .unwrap_or(&self.issuer)
        )
    }
}

/// Everything in the file but the secret, checked.
struct CheckedFile {
    label: String,
    issuer: String,
    client_id: String,
    client_secret_reference: String,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    redirect_uri: Url,
    scopes: Vec<String>,
    id_token_signing_algs: Vec<Algorithm>,
    claims: ClaimNames,
    required_claims: BTreeMap<String, Vec<ValueMatcher>>,
    role_mapping: RoleMapping,
}

fn check(file: OidcFile) -> Result<CheckedFile, String> {
    let label = non_empty("label", file.label)?;
    let issuer_url = provider_url("issuer", &file.issuer)?;
    if issuer_url.query().is_some() {
        return Err("issuer must not have a query".to_string());
    }
    let client_id = non_empty("client_id", file.client_id)?;
    if !SECRET_REFERENCE_PREFIXES
        .iter()
        .any(|prefix| {
            file.client_secret
                .starts_with(prefix)
        })
    {
        return Err(format!(
            "client_secret must be a secret reference starting with {}",
            SECRET_REFERENCE_PREFIXES.join(", ")
        ));
    }
    let redirect_uri = provider_url("redirect_uri", &file.redirect_uri)?;
    if !file
        .scopes
        .iter()
        .any(|scope| scope == "openid")
    {
        return Err("scopes must include openid".to_string());
    }
    let id_token_signing_algs = signing_algs(&file.id_token_signing_algs)?;
    for (field, claim) in [
        ("claims.username", &file.claims.username),
        ("claims.email", &file.claims.email),
        ("claims.first_name", &file.claims.first_name),
        ("claims.last_name", &file.claims.last_name),
    ] {
        if claim.trim().is_empty() {
            return Err(format!("{field} must not be empty"));
        }
    }
    let required_claims = required_claims(file.required_claims)?;
    let role_mapping = role_mapping(file.role_mapping)?;
    Ok(CheckedFile {
        label,
        issuer: file.issuer,
        client_id,
        client_secret_reference: file.client_secret,
        token_endpoint_auth_method: file.token_endpoint_auth_method,
        redirect_uri,
        scopes: file.scopes,
        id_token_signing_algs,
        claims: file.claims,
        required_claims,
        role_mapping,
    })
}

fn required_claims(file: BTreeMap<String, Vec<RawClaimValue>>) -> Result<BTreeMap<String, Vec<ValueMatcher>>, String> {
    file.into_iter()
        .map(|(claim, allowed)| {
            if claim.trim().is_empty() {
                return Err("required_claims has an empty claim name".to_string());
            }
            if allowed.is_empty() {
                return Err(format!("required_claims.{claim} must list at least one allowed value"));
            }
            let field = format!("required_claims.{claim}");
            let allowed = allowed
                .into_iter()
                .map(|value| match value {
                    RawClaimValue::String(text) => ValueMatcher::from_text(&field, &text),
                    RawClaimValue::Bool(value) => Ok(ValueMatcher::Bool(value)),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((claim, allowed))
        })
        .collect()
}

fn non_empty(
    field: &str,
    value: String,
) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(value)
}

/// Parse an address the provider or the browser is sent to, and refuse one
/// that is not `https` (see [`transport_problem`]), has a fragment, or carries
/// user information.
fn provider_url(
    field: &str,
    raw: &str,
) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| format!("{field} is not an absolute URL"))?;
    if let Some(problem) = transport_problem(&url) {
        return Err(format!("{field} {problem}"));
    }
    if url.fragment().is_some() {
        return Err(format!("{field} must not have a fragment"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{field} must not contain user information"));
    }
    Ok(url)
}

/// Why a provider address cannot be used, if it cannot. Tokens are trusted
/// partly because they arrive over TLS, so every address is `https`. A debug
/// build also accepts `http` to a loopback host, for a provider running on the
/// same machine during development; a release build never does.
pub(crate) fn transport_problem(url: &Url) -> Option<&'static str> {
    match url.scheme() {
        "https" => None,
        "http" if cfg!(debug_assertions) && is_loopback(url) => None,
        _ => Some("must start with https://"),
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn signing_algs(names: &[String]) -> Result<Vec<Algorithm>, String> {
    if names.is_empty() {
        return Err("id_token_signing_algs must list at least one algorithm".to_string());
    }
    names
        .iter()
        .map(|name| {
            Algorithm::from_str(name)
                .ok()
                .filter(|algorithm| ALLOWED_SIGNING_ALGS.contains(algorithm))
                .ok_or_else(|| format!("id_token_signing_algs: {name} is not an allowed ID token signing algorithm"))
        })
        .collect()
}

fn role_mapping(file: RoleMappingFile) -> Result<RoleMapping, String> {
    if file.claim.trim().is_empty() {
        return Err("role_mapping.claim must not be empty".to_string());
    }
    if file.values.is_empty() {
        return Err("role_mapping.values must map at least one value to a role".to_string());
    }
    let unmapped = match file.unmapped.as_str() {
        "deny" => None,
        "administrator" => Some(UserRole::Administrator),
        "poweruser" => Some(UserRole::PowerUser),
        "user" => Some(UserRole::User),
        other => {
            return Err(format!("role_mapping.unmapped must be deny, administrator, poweruser or user, not {other}"));
        }
    };
    let values = file
        .values
        .into_iter()
        .map(|(text, role)| Ok((ValueMatcher::from_text("role_mapping.values", &text)?, role)))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(RoleMapping {
        claim: file.claim,
        values,
        unmapped,
    })
}

/// Resolve a secret reference to its trimmed, non-empty value. The `file://`
/// loader keeps a file's trailing newline, which no client credential has.
async fn resolve_reference(
    field: &str,
    reference: &str,
) -> Result<String, String> {
    let value = crate::config::loaders::load(reference)
        .await
        .map_err(|e| format!("{field} could not be resolved: {}", e))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field} resolved to an empty value"));
    }
    Ok(value.to_string())
}

/// The client id is not secret (the provider shows it in every sign-in
/// address), so it may be written in the file, or given as a secret reference
/// to keep it beside the client secret.
async fn resolve_client_id(client_id: &str) -> Result<String, String> {
    if SECRET_REFERENCE_PREFIXES
        .iter()
        .any(|prefix| client_id.starts_with(prefix))
    {
        resolve_reference("client_id", client_id).await
    } else {
        Ok(client_id.to_string())
    }
}

async fn resolve_client_secret(reference: &str) -> Result<ClientSecret, String> {
    resolve_reference("client_secret", reference)
        .await
        .map(ClientSecret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn valid_file() -> Value {
        json!({
            "label": "Example IdP",
            "issuer": "https://idp.example.com",
            "client_id": "agent-stream",
            "client_secret": "file://SECRET_FILE",
            "redirect_uri": "https://stream.example.com/api/oidc/callback",
            "required_claims": { "org_id": ["org_123"] },
            "role_mapping": {
                "claim": "roles",
                "values": { "admin": "administrator", "member": "user" }
            }
        })
    }

    fn with(
        mut file: Value,
        path: &[&str],
        value: Value,
    ) -> Value {
        let (last, parents) = path.split_last().unwrap();
        let mut target = &mut file;
        for key in parents {
            target = target.get_mut(*key).unwrap();
        }
        target[*last] = value;
        file
    }

    /// Load `file` with its `file://SECRET_FILE` reference pointing at a file
    /// holding `secret`.
    async fn load_with_secret(
        file: Value,
        secret: &str,
    ) -> Result<OidcConfig, String> {
        let secret_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret_file.path(), secret).unwrap();
        let json = file.to_string().replace(
            "SECRET_FILE",
            secret_file
                .path()
                .to_str()
                .unwrap(),
        );
        OidcConfig::from_json(&json).await
    }

    async fn load(file: Value) -> Result<OidcConfig, String> {
        load_with_secret(file, " s3cret\n").await
    }

    #[tokio::test]
    async fn a_valid_file_loads_with_its_defaults() {
        let config = load(valid_file())
            .await
            .unwrap();

        assert_eq!(config.label, "Example IdP");
        assert_eq!(config.client_secret.expose(), "s3cret", "the resolved secret is trimmed");
        assert_eq!(config.token_endpoint_auth_method, TokenEndpointAuthMethod::ClientSecretBasic);
        assert_eq!(config.scopes, ["openid", "profile", "email"]);
        assert_eq!(config.id_token_signing_algs, [Algorithm::ES256]);
        assert_eq!(config.claims.username, "preferred_username");
        assert_eq!(config.role_mapping.unmapped, None, "an unmapped account is refused by default");
        assert!(
            config
                .role_mapping
                .values
                .contains(&(ValueMatcher::Exact("admin".to_string()), UserRole::Administrator))
        );
        assert!(!format!("{config:?}").contains("s3cret"), "the secret never reaches Debug output");
    }

    #[tokio::test]
    async fn the_client_id_may_be_written_in_the_file_or_referenced() {
        let config = load(valid_file())
            .await
            .unwrap();
        assert_eq!(config.client_id, "agent-stream", "a plain value is used as written");

        let config = load(with(valid_file(), &["client_id"], json!("file://SECRET_FILE")))
            .await
            .unwrap();
        assert_eq!(config.client_id, "s3cret", "a reference is resolved and trimmed, never sent as written");

        let refused = load(with(valid_file(), &["client_id"], json!("env://AS_TEST_OIDC_UNSET_CLIENT_ID")))
            .await
            .unwrap_err();
        assert!(refused.contains("client_id could not be resolved"), "{refused}");
    }

    #[tokio::test]
    async fn a_secret_written_into_the_file_is_refused() {
        for secret in ["string://s3cret", "s3cret"] {
            let refused = load(with(valid_file(), &["client_secret"], json!(secret)))
                .await
                .unwrap_err();
            assert!(refused.contains("secret reference"), "{secret}: {refused}");
        }
    }

    #[tokio::test]
    async fn a_secret_that_resolves_to_nothing_is_refused() {
        let refused = load(with(valid_file(), &["client_secret"], json!("env://AS_TEST_OIDC_UNSET_SECRET")))
            .await
            .unwrap_err();
        assert!(refused.contains("client_secret could not be resolved"), "{refused}");

        let refused = load_with_secret(valid_file(), " \n")
            .await
            .unwrap_err();
        assert!(refused.contains("empty"), "{refused}");
    }

    #[tokio::test]
    async fn only_asymmetric_signing_algorithms_are_allowed() {
        for alg in ["none", "HS256", "HS512", "XX1"] {
            let refused = load(with(valid_file(), &["id_token_signing_algs"], json!(["ES256", alg])))
                .await
                .unwrap_err();
            assert!(refused.contains(alg), "{alg}: {refused}");
        }
        let refused = load(with(valid_file(), &["id_token_signing_algs"], json!([])))
            .await
            .unwrap_err();
        assert!(refused.contains("at least one"), "{refused}");

        let config = load(with(valid_file(), &["id_token_signing_algs"], json!(["RS256", "PS256", "EdDSA"])))
            .await
            .unwrap();
        assert_eq!(config.id_token_signing_algs, [Algorithm::RS256, Algorithm::PS256, Algorithm::EdDSA]);
    }

    #[tokio::test]
    async fn the_role_mapping_must_name_known_roles() {
        let refused = load(with(valid_file(), &["role_mapping", "values"], json!({ "admin": "owner" })))
            .await
            .unwrap_err();
        assert!(refused.contains("owner"), "{refused}");

        let refused = load(with(valid_file(), &["role_mapping", "values"], json!({ "admin": "Administrator" })))
            .await
            .unwrap_err();
        assert!(refused.contains("Administrator"), "role names are exact: {refused}");

        let refused = load(with(valid_file(), &["role_mapping", "values"], json!({})))
            .await
            .unwrap_err();
        assert!(refused.contains("at least one value"), "{refused}");

        let refused = load(with(valid_file(), &["role_mapping", "unmapped"], json!("guest")))
            .await
            .unwrap_err();
        assert!(refused.contains("guest"), "{refused}");

        let refused = load(with(valid_file(), &["role_mapping", "claim"], json!(" ")))
            .await
            .unwrap_err();
        assert!(refused.contains("role_mapping.claim"), "{refused}");

        let config = load(with(valid_file(), &["role_mapping", "unmapped"], json!("user")))
            .await
            .unwrap();
        assert_eq!(config.role_mapping.unmapped, Some(UserRole::User));
    }

    #[tokio::test]
    async fn a_misspelt_field_stops_startup_rather_than_being_ignored() {
        let mut file = valid_file();
        let binding = file
            .as_object_mut()
            .unwrap()
            .remove("required_claims")
            .unwrap();
        file["required_claim"] = binding;

        let refused = load(file).await.unwrap_err();
        assert!(refused.contains("required_claim"), "{refused}");
    }

    #[tokio::test]
    async fn the_issuer_and_redirect_uri_must_be_https() {
        for (field, value, expected) in [
            ("issuer", "http://idp.example.com", "must start with https://"),
            ("issuer", "https://idp.example.com?tenant=1", "must not have a query"),
            ("issuer", "https://idp.example.com#top", "must not have a fragment"),
            ("issuer", "idp.example.com", "not an absolute URL"),
            ("redirect_uri", "http://stream.example.com/api/oidc/callback", "must start with https://"),
            ("redirect_uri", "https://user:pw@stream.example.com/api/oidc/callback", "user information"),
        ] {
            let refused = load(with(valid_file(), &[field], json!(value)))
                .await
                .unwrap_err();
            assert!(refused.contains(expected), "{field}={value}: {refused}");
        }
    }

    #[test]
    fn plain_http_is_accepted_only_to_this_machine_in_a_debug_build() {
        let local = Url::parse("http://127.0.0.1:8080").unwrap();
        let remote = Url::parse("http://idp.example.com").unwrap();

        assert_eq!(transport_problem(&local).is_none(), cfg!(debug_assertions));
        assert!(transport_problem(&remote).is_some());
        assert!(transport_problem(&Url::parse("ftp://127.0.0.1").unwrap()).is_some());
    }

    #[tokio::test]
    async fn scopes_must_include_openid_and_lists_must_not_be_empty() {
        let refused = load(with(valid_file(), &["scopes"], json!(["profile", "email"])))
            .await
            .unwrap_err();
        assert!(refused.contains("openid"), "{refused}");

        let refused = load(with(valid_file(), &["required_claims"], json!({ "org_id": [] })))
            .await
            .unwrap_err();
        assert!(refused.contains("required_claims.org_id"), "{refused}");

        let refused = load(with(valid_file(), &["claims"], json!({ "username": "" })))
            .await
            .unwrap_err();
        assert!(refused.contains("claims.username"), "{refused}");
    }

    #[tokio::test]
    async fn a_required_claim_may_allow_strings_and_booleans_but_nothing_else() {
        let config = load(with(
            valid_file(),
            &["required_claims"],
            json!({ "org_id": ["org_123"], "email_verified": [true, "true"] }),
        ))
        .await
        .unwrap();
        assert_eq!(
            config.required_claims["email_verified"],
            [ValueMatcher::Bool(true), ValueMatcher::Exact("true".to_string())]
        );
        assert_eq!(config.required_claims["org_id"], [ValueMatcher::Exact("org_123".to_string())]);

        for value in [json!([123]), json!([null]), json!([{"org": "org_123"}]), json!("org_123")] {
            let refused = load(with(valid_file(), &["required_claims"], json!({ "org_id": value })))
                .await
                .unwrap_err();
            assert!(refused.contains("Failed to parse OIDC config JSON"), "{value}: {refused}");
        }
    }

    #[tokio::test]
    async fn a_regex_value_is_compiled_at_startup_and_anything_else_is_exact() {
        let config = load(with(
            valid_file(),
            &["role_mapping", "values"],
            json!({ "regex:.*@affinidi\\.com": "poweruser", "adam.l@affinidi.com": "administrator" }),
        ))
        .await
        .unwrap();
        let (pattern, role) = config
            .role_mapping
            .values
            .iter()
            .find(|(matcher, _)| matches!(matcher, ValueMatcher::Regex(_)))
            .unwrap();
        assert_eq!(role, &UserRole::PowerUser);
        assert!(pattern.matches_str("someone@affinidi.com"));
        assert!(
            config
                .role_mapping
                .values
                .contains(&(ValueMatcher::Exact("adam.l@affinidi.com".to_string()), UserRole::Administrator)),
            "a value with dots is still exact"
        );

        let config = load(with(valid_file(), &["required_claims"], json!({ "email": ["regex:.*@affinidi\\.com"] })))
            .await
            .unwrap();
        assert!(config.required_claims["email"][0].matches_str("x@affinidi.com"));
        assert!(!config.required_claims["email"][0].matches_str("x@affinidi.com.evil.example"), "the whole value");

        let config = load(with(valid_file(), &["required_claims"], json!({ "email": ["regex:a|b"] })))
            .await
            .unwrap();
        assert!(config.required_claims["email"][0].matches_str("b"));
        assert!(!config.required_claims["email"][0].matches_str("ab"), "an alternation stays anchored");

        for (path, value) in [
            (&["role_mapping", "values"][..], json!({ "regex:(unclosed": "user" })),
            (&["required_claims"][..], json!({ "email": ["regex:[a-"] })),
            (&["required_claims"][..], json!({ "email": ["regex:x)|(.*"] })),
        ] {
            let refused = load(with(valid_file(), path, value))
                .await
                .unwrap_err();
            assert!(refused.contains("is not a usable regular expression"), "{refused}");
        }
    }

    #[tokio::test]
    async fn the_discovery_address_drops_one_trailing_slash_of_the_issuer() {
        let config = load(with(valid_file(), &["issuer"], json!("https://tenant.auth.example/")))
            .await
            .unwrap();
        assert_eq!(config.issuer, "https://tenant.auth.example/", "the issuer is kept exactly as written");
        assert_eq!(config.discovery_url(), "https://tenant.auth.example/.well-known/openid-configuration");

        let config = load(with(valid_file(), &["issuer"], json!("https://id.example/realms/example")))
            .await
            .unwrap();
        assert_eq!(config.discovery_url(), "https://id.example/realms/example/.well-known/openid-configuration");
    }

    #[tokio::test]
    async fn the_client_authentication_method_is_basic_or_post() {
        let config = load(with(valid_file(), &["token_endpoint_auth_method"], json!("client_secret_post")))
            .await
            .unwrap();
        assert_eq!(config.token_endpoint_auth_method, TokenEndpointAuthMethod::ClientSecretPost);

        let refused = load(with(valid_file(), &["token_endpoint_auth_method"], json!("private_key_jwt")))
            .await
            .unwrap_err();
        assert!(refused.contains("private_key_jwt"), "{refused}");
    }
}
