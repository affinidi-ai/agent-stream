"use strict";

const crypto = require("crypto");
const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

// Identity / credential minting for the caller flavors:
//   - email : a plain email string sent in the X-Caller-Email header.
//   - jwt   : an RS256 JWT whose `sub` claim names the member (Subject identity),
//             verified by the appliance against a static JWK strategy. The signer
//             can also embed arbitrary claims (email / name / groups / tid) so the
//             enrolment drill can exercise claim-based member auto-provisioning.
//   - apikey: an ApiKeyProvider secret presented in X-Api-Key, the member being
//             identified by the key's server-assigned key_id.
//   - mtls  : a client certificate presented via the forwarded-client-cert header
//             (the testkit is its own tiny CA — see makeMtlsPki), used by the
//             enrolment drill to exercise mTLS auto-provisioning without a real
//             TLS handshake. The appliance must trust the runner as a forwarded
//             proxy (see tests/appliance/config/managed.config.toml [tls.client_auth]).
//
// The JWT signing key is generated fresh per run; its public half is published
// to the appliance as a static JWK verification strategy during setup.

const ISSUER = "https://testkit.local/issuer";
// Every token carries this audience and every testkit JWT Surface accepts it:
// a Surface with no accepted audience refuses every token.
const AUDIENCE = "https://testkit.local/agent-stream";

function base64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function generateRsaKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const kid = `testkit-${crypto.randomBytes(6).toString("hex")}`;
  // Node exports an RSA public key directly as a JWK (kty/n/e).
  const jwk = publicKey.export({ format: "jwk" });
  const publicJwk = {
    kty: "RSA",
    use: "sig",
    kid,
    alg: "RS256",
    n: jwk.n,
    e: jwk.e,
  };
  return { privateKey, kid, publicJwk };
}

// Sign a compact RS256 JWT for the given subject.
function signJwt(privateKey, kid, subject, { audience = AUDIENCE, claims } = {}) {
  const header = { alg: "RS256", typ: "JWT", kid };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISSUER,
    sub: subject,
    iat: now,
    nbf: now - 5,
    exp: now + 3600,
    jti: crypto.randomBytes(8).toString("hex"),
  };
  payload.aud = audience;
  // Extra claims (email / name / groups / tid) drive claim-based provisioning
  // and team-assignment rules. They never override the registered claims above.
  if (claims && typeof claims === "object") {
    for (const [k, v] of Object.entries(claims)) {
      if (!(k in payload)) payload[k] = v;
    }
  }
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput), privateKey);
  return `${signingInput}.${base64url(signature)}`;
}

// Build a fresh signer bound to a generated keypair + the published strategy.
function makeJwtSigner() {
  const { privateKey, kid, publicJwk } = generateRsaKeypair();
  return {
    issuer: ISSUER,
    audience: AUDIENCE,
    publicJwk,
    sign(subject) {
      return signJwt(privateKey, kid, subject);
    },
    // Sign a token carrying additional claims (used by the enrolment drill).
    signWithClaims(subject, claims) {
      return signJwt(privateKey, kid, subject, { claims });
    },
  };
}

// ── mTLS PKI (openssl-backed) ────────────────────────────────────────────────
//
// The enrolment drill presents a client certificate through the forwarded-cert
// header, so it needs a throwaway CA plus a CA-signed client leaf. Node has no
// built-in X.509 issuance, so we shell out to the `openssl` CLI. Everything is
// written to a fresh temp dir and read back as PEM strings.

// True when the `openssl` CLI is callable. mTLS enrolment is skipped (or fails,
// per policy) when it is not.
function opensslAvailable() {
  try {
    execFileSync("openssl", ["version"], { stdio: ["ignore", "ignore", "ignore"] });
    return true;
  } catch {
    return false;
  }
}

// Generate a self-signed CA and a client leaf signed by it. The client leaf
// carries CN=<cn>, the TLS Client Authentication EKU, and (when supplied) an
// email SubjectAltName so both the subject-CN and email-SAN provisioning
// bindings can be exercised. Returns the three PEM blobs as strings.
function makeMtlsPki({ cn, email }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "testkit-mtls-"));
  const p = (f) => path.join(dir, f);
  const run = (args) => execFileSync("openssl", args, { stdio: ["ignore", "ignore", "pipe"] });
  try {
    // Self-signed CA (short-lived — a throwaway per run).
    run([
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", p("ca.key"), "-out", p("ca.pem"),
      "-days", "2", "-subj", "/CN=Testkit mTLS CA",
    ]);
    // Client key + CSR.
    run([
      "req", "-newkey", "rsa:2048", "-nodes",
      "-keyout", p("client.key"), "-out", p("client.csr"),
      "-subj", `/CN=${cn}`,
    ]);
    // Extensions: client-auth EKU + optional email SAN.
    const ext = [
      "extendedKeyUsage = clientAuth",
      email ? `subjectAltName = email:${email}` : "",
    ]
      .filter(Boolean)
      .join("\n");
    fs.writeFileSync(p("ext.cnf"), `${ext}\n`);
    // Sign the client leaf with the CA.
    run([
      "x509", "-req", "-in", p("client.csr"),
      "-CA", p("ca.pem"), "-CAkey", p("ca.key"), "-CAcreateserial",
      "-out", p("client.pem"), "-days", "2", "-extfile", p("ext.cnf"),
    ]);
    return {
      caPem: fs.readFileSync(p("ca.pem"), "utf8"),
      clientCertPem: fs.readFileSync(p("client.pem"), "utf8"),
      clientKeyPem: fs.readFileSync(p("client.key"), "utf8"),
    };
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort temp cleanup
    }
  }
}

module.exports = { makeJwtSigner, makeMtlsPki, opensslAvailable, ISSUER, AUDIENCE };
