use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use openssl::rsa::Rsa;
use serde_json::{Value, json};

const KEY_ID: &str = "bdd-jwt-key";

struct BddRsaKey {
    private_pem: Vec<u8>,
    modulus: String,
}

fn bdd_rsa_key() -> &'static BddRsaKey {
    static KEY: OnceLock<BddRsaKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let rsa = Rsa::generate(2048).expect("BDD RSA key should generate");
        BddRsaKey {
            private_pem: rsa
                .private_key_to_pem()
                .expect("BDD RSA key should export"),
            modulus: URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
        }
    })
}

pub fn static_jwks_source() -> Value {
    json!({
        "type": "static",
        "jwks": [{
            "kty": "RSA",
            "kid": KEY_ID,
            "use": "sig",
            "alg": "RS256",
            "n": bdd_rsa_key().modulus,
            "e": "AQAB"
        }]
    })
}

pub fn signed_token(
    issuer: &str,
    audience: &str,
) -> String {
    signed_token_for(issuer, audience, "bdd-caller")
}

/// A valid token for `subject`, so scenarios can tell callers apart.
pub fn signed_token_for(
    issuer: &str,
    audience: &str,
    subject: &str,
) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KEY_ID.to_string());
    let claims = json!({
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": SystemTime::now().duration_since(UNIX_EPOCH).expect("clock should follow epoch").as_secs() + 3600
    });
    encode(&header, &claims, &EncodingKey::from_rsa_pem(&bdd_rsa_key().private_pem).expect("BDD RSA key should parse"))
        .expect("BDD JWT should encode")
}

pub fn invalid_token(
    issuer: &str,
    audience: &str,
) -> String {
    format!("{}x", signed_token(issuer, audience))
}
