use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use openssl::pkey::PKey;
use openssl::x509::X509;
use samael::crypto::{CertificateDer, Crypto, CryptoProvider};
use samael::schema::{Assertion, Conditions, Response};
use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;
use tracing::info;

use crate::auth::auth_config::SamlConfig;

/// How long an SP-initiated AuthnRequest stays outstanding, waiting for a
/// matching response's InResponseTo.
const AUTHN_REQUEST_TTL: Duration = Duration::minutes(5);

/// Clock skew tolerance applied to assertion NotBefore/NotOnOrAfter checks.
const CLOCK_SKEW: Duration = Duration::seconds(180);

/// Hard cap on outstanding SP-initiated AuthnRequests. `/saml/login` is public
/// and unauthenticated, so without a ceiling a flood of login initiations grows
/// `pending_requests` without bound (only expired entries are pruned). This
/// bounds memory to at most this many live ids; at the cap the entry closest to
/// expiry is evicted to make room, so a new login still proceeds. The request
/// rate on `/saml/login` is limited per client by `auth::throttle`.
const MAX_PENDING_REQUESTS: usize = 10_000;

/// Upper bound on a decoded SAML response before it is parsed. A legitimate
/// Entra assertion is a few KB; this leaves generous headroom while capping the
/// unauthenticated, pre-trust XML that reaches the parsers at `/saml/acs`.
const MAX_SAML_RESPONSE_BYTES: usize = 512 * 1024;

/// SAML Service Provider implementation
pub struct SamlService {
    /// SAML configuration
    config: SamlConfig,

    /// SHA-256 thumbprints of the trusted IdP signing cert(s), used to pin the
    /// certificate embedded in the response signature.
    idp_cert_thumbprints: Vec<String>,

    /// The same trusted IdP signing cert(s) in DER, as the verification key
    /// bound to the signature context. More than one because Entra publishes a
    /// rollover bundle; a response need only verify under one of them.
    idp_cert_ders: Vec<CertificateDer>,

    /// SP private key for signing requests (if sign_requests = true)
    sp_key: Option<PKey<openssl::pkey::Private>>,

    /// SP certificate (if sign_requests = true)
    sp_cert: Option<X509>,

    /// IDs of outstanding SP-initiated AuthnRequests, keyed to their
    /// expiry, so a response's InResponseTo can be matched and consumed
    /// (single-use) against a request this service actually sent.
    pending_requests: DashMap<String, DateTime<Utc>>,
}

impl SamlService {
    /// Create a new SAML service
    pub fn new(config: SamlConfig) -> Result<Self> {
        // Load IdP certificate
        let idp_cert_pem = fs::read_to_string(&config.idp_cert_path)
            .with_context(|| format!("Failed to read IdP certificate from {}", config.idp_cert_path))?;

        // Pin EVERY certificate in the configured PEM, not just the first.
        // `xmlsec1 --trusted-pem` trusts all certs in the file, so the pinning
        // thumbprint set must cover all of them too — otherwise, when the IdP
        // (Entra) publishes a second/rolled signing cert in the same bundle,
        // xmlsec1 would accept a response the pin check then rejects, breaking
        // login on key rollover with no auto-recovery.
        let idp_certs = X509::stack_from_pem(idp_cert_pem.as_bytes()).context("Failed to parse IdP certificate(s)")?;
        let idp_cert_thumbprints: Vec<String> = idp_certs
            .iter()
            .filter_map(cert_sha256_thumbprint)
            .collect();
        if idp_cert_thumbprints.is_empty() {
            anyhow::bail!("Could not compute a SHA-256 thumbprint for any IdP signing certificate");
        }
        let idp_cert_ders: Vec<CertificateDer> = idp_certs
            .iter()
            .filter_map(|cert| cert.to_der().ok())
            .map(CertificateDer::from)
            .collect();
        if idp_cert_ders.is_empty() {
            anyhow::bail!("Could not encode any IdP signing certificate as DER");
        }

        // Refuse to offer SAML at all on a host whose libxmlsec1 does not
        // behave, rather than discovering it on the first login.
        ensure_verifier()?;

        // Load SP signing credentials if request signing is enabled
        let (sp_key, sp_cert) = if config.sign_requests {
            let key_path = config
                .sp_key_path
                .as_ref()
                .context("sp_key_path required when sign_requests = true")?;
            let cert_path = config
                .sp_cert_path
                .as_ref()
                .context("sp_cert_path required when sign_requests = true")?;

            // Load private key
            let key_pem = fs::read_to_string(key_path)
                .with_context(|| format!("Failed to read SP private key from {}", key_path))?;
            let key = PKey::private_key_from_pem(key_pem.as_bytes()).context("Failed to parse SP private key")?;

            // Load certificate
            let cert_pem = fs::read_to_string(cert_path)
                .with_context(|| format!("Failed to read SP certificate from {}", cert_path))?;
            let cert = X509::from_pem(cert_pem.as_bytes()).context("Failed to parse SP certificate")?;

            info!("Loaded SP signing credentials for SAML request signing");
            (Some(key), Some(cert))
        } else {
            (None, None)
        };

        Ok(Self {
            config,
            idp_cert_thumbprints,
            idp_cert_ders,
            sp_key,
            sp_cert,
            pending_requests: DashMap::new(),
        })
    }

    /// A service that can only start logins: no IdP certificate is loaded and
    /// nothing verifies, so route tests do not run the verifier self-test.
    #[cfg(test)]
    pub(crate) fn for_route_tests(config: SamlConfig) -> Self {
        Self {
            config,
            idp_cert_thumbprints: Vec::new(),
            idp_cert_ders: Vec::new(),
            sp_key: None,
            sp_cert: None,
            pending_requests: DashMap::new(),
        }
    }

    /// Generate SP metadata XML
    pub fn generate_metadata(&self) -> Result<String> {
        // Include certificate in metadata if signing is enabled
        let cert_section = if let Some(cert) = &self.sp_cert {
            let cert_der = cert
                .to_der()
                .context("Failed to convert certificate to DER")?;
            let cert_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_der);
            format!(
                r#"
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>"#,
                cert_b64
            )
        } else {
            String::new()
        };

        // Create SP metadata with certificate if available
        let metadata = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="{}" WantAssertionsSigned="true">{}
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{}" index="0" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>"#,
            self.config.sp_entity_id, self.config.sign_requests, cert_section, self.config.sp_acs_url
        );

        Ok(metadata)
    }

    /// Create an authentication request (for SP-initiated flow). Returns the
    /// redirect URL and the request id, so the caller can bind the initiating
    /// browser to this request via a correlation cookie and cross-check it at
    /// the ACS.
    pub fn create_authn_request(&self) -> Result<(String, String)> {
        use uuid::Uuid;

        // Generate unique request ID and timestamp
        let request_id = format!("_{}", Uuid::new_v4());
        let issue_instant = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let now = Utc::now();
        self.pending_requests
            .retain(|_, expiry| *expiry > now);
        // Bound memory on the public, unauthenticated login endpoint. At the
        // cap, evict the entry closest to expiry (it would lapse soonest anyway)
        // rather than refusing the new request — so a flood cannot both exhaust
        // memory AND lock every legitimate user out of login. This caps
        // memory, not request rate; `auth::throttle` limits the rate per client.
        if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
            // Collect the victim key first so no DashMap shard lock is held
            // across the subsequent remove (avoids self-deadlock).
            let victim = self
                .pending_requests
                .iter()
                .min_by_key(|entry| *entry.value())
                .map(|entry| entry.key().clone());
            if let Some(key) = victim {
                self.pending_requests
                    .remove(&key);
            }
        }
        self.pending_requests
            .insert(request_id.clone(), now + AUTHN_REQUEST_TTL);

        // Create AuthnRequest XML
        let authn_request = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>{}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"#,
            request_id, issue_instant, self.config.idp_sso_url, self.config.sp_acs_url, self.config.sp_entity_id
        );

        // Sign the request if signing is enabled
        let final_request = if self.config.sign_requests {
            self.sign_authn_request(&authn_request)?
        } else {
            authn_request
        };

        // Deflate and base64 encode
        use flate2::Compression;
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(final_request.as_bytes())
            .context("Failed to deflate AuthnRequest")?;
        let deflated = encoder
            .finish()
            .context("Failed to finish deflating")?;

        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &deflated);
        let encoded_url = urlencoding::encode(&encoded);

        // Create redirect URL
        let redirect_url = format!("{}?SAMLRequest={}", self.config.idp_sso_url, encoded_url);

        info!("Created SAML AuthnRequest (signed: {})", self.config.sign_requests);
        Ok((redirect_url, request_id))
    }

    /// Sign an AuthnRequest XML
    fn sign_authn_request(
        &self,
        xml: &str,
    ) -> Result<String> {
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;

        let key = self
            .sp_key
            .as_ref()
            .context("SP private key not loaded")?;
        let cert = self
            .sp_cert
            .as_ref()
            .context("SP certificate not loaded")?;

        // Calculate SHA-256 digest of the canonicalized XML
        let mut signer = Signer::new(MessageDigest::sha256(), key).context("Failed to create signer")?;
        signer
            .update(xml.as_bytes())
            .context("Failed to update signer")?;
        let signature = signer
            .sign_to_vec()
            .context("Failed to sign")?;

        let signature_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signature);
        let cert_der = cert
            .to_der()
            .context("Failed to convert certificate to DER")?;
        let cert_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_der);

        // Insert signature into XML after <Issuer> element (correct SAML position)
        let signed_xml = xml.replace(
            "</saml:Issuer>",
            &format!(
                r#"</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue/>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>{}</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>{}</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>"#,
                signature_b64, cert_b64
            ),
        );

        Ok(signed_xml)
    }

    /// Validate a SAML response and extract assertions.
    ///
    /// `expected_in_response_to` is the AuthnRequest id carried in the
    /// initiating browser's correlation cookie; the response must answer THAT
    /// request, not merely any outstanding one, so a response cannot be
    /// completed in a different browser than the one that began the login.
    pub fn validate_response(
        &self,
        saml_response: &str,
        expected_in_response_to: Option<&str>,
    ) -> Result<Assertion> {
        info!("Validating SAML response");

        // Reject an oversized payload BEFORE allocating the decoded buffer.
        // base64 inflates by ~4/3, so bound the encoded input generously; the
        // exact decoded-length check below is the authoritative one.
        if saml_response.len() > MAX_SAML_RESPONSE_BYTES.saturating_mul(2) {
            anyhow::bail!("SAML response exceeds the maximum permitted size");
        }

        // Decode base64 response
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(saml_response)
            .context("Failed to decode SAML response")?;

        let response_xml = String::from_utf8(decoded).context("Failed to parse SAML response as UTF-8")?;

        // Bound the untrusted payload and reject DOCTYPE/ENTITY declarations
        // before any XML parser (quick_xml here, libxml2 via xmlsec1 below)
        // touches it. `/saml/acs` is public and pre-trust; this fails closed on
        // oversized documents and on internal/external entity definitions
        // (defence-in-depth against entity-expansion DoS and parser-differential
        // surprises), independent of parser defaults.
        if response_xml.len() > MAX_SAML_RESPONSE_BYTES {
            anyhow::bail!("SAML response exceeds the maximum permitted size");
        }
        if response_xml.contains("<!DOCTYPE") || response_xml.contains("<!ENTITY") {
            anyhow::bail!("SAML response contains a disallowed DOCTYPE/ENTITY declaration");
        }

        // Reject a response carrying more than one Assertion element before
        // any of it is trusted: xmlsec1 (below) verifies that *a* signature
        // in the document is cryptographically valid, but the struct
        // deserializer further down simply takes whichever Assertion sits at
        // Response.assertion. A second, unsigned or falsely-signed Assertion
        // planted elsewhere in the tree — the classic XML Signature Wrapping
        // attack — would otherwise let a forged assertion be trusted while
        // the original, genuinely-signed one is what gets verified.
        reject_multiple_assertions(&response_xml)?;

        // A SAML signature only ever references elements inside the same
        // document. xmlsec's default reference-URI policy is permissive, so
        // without this gate a `<ds:Reference URI="file:///…">` would be
        // dereferenced while computing digests (blind local-file read / read
        // amplification), on the public, pre-trust `/saml/acs` path.
        reject_external_reference_uris(&response_xml)?;

        // Verify the IdP's XML-DSig signature, and pin the signing certificate
        // to the trusted IdP cert, before trusting any content in the response.
        self.verify_signing_cert_pinned(&response_xml)?;
        self.verify_response_signature(&response_xml)?;

        let response: Response = quick_xml::de::from_str(&response_xml).context("Failed to parse SAML response XML")?;

        // Validate response
        self.validate_response_structure(&response)?;

        // Browser binding: the response must answer the AuthnRequest that THIS
        // browser started (the id in its correlation cookie), not merely any
        // outstanding request. Fails closed when the cookie is absent, so an
        // injected response cannot be completed cross-browser.
        let expected_in_response_to = expected_in_response_to
            .context("Missing SAML correlation cookie; start login at the SAML login endpoint in this browser")?;
        if response
            .in_response_to
            .as_deref()
            != Some(expected_in_response_to)
        {
            anyhow::bail!("SAML response does not match this browser's outstanding AuthnRequest");
        }

        // The Response@InResponseTo is not covered by the assertion signature,
        // so capture it here to cross-check against the *signed* assertion's
        // SubjectConfirmationData below.
        let response_in_response_to = response
            .in_response_to
            .clone();

        // Extract and validate assertion (assertion is Option<Assertion>)
        let assertion = response
            .assertion
            .context("No assertion found in SAML response")?;

        // Assertion must itself carry a signature.
        self.verify_assertion_signature(&assertion)?;

        // Validate assertion conditions
        self.validate_assertion_conditions(&assertion)?;

        // Bind the signed assertion to THIS request and this SP. The outer
        // Response@InResponseTo is attacker-controllable (unsigned); only the
        // bearer SubjectConfirmationData inside the signed assertion proves the
        // assertion was minted for the request we sent. Without this, a genuine
        // signed victim assertion could be wrapped in a Response quoting a
        // different outstanding request id and accepted (assertion injection /
        // XML Signature Wrapping of the response envelope).
        check_subject_confirmation(
            &assertion,
            response_in_response_to.as_deref(),
            &self.config.sp_acs_url,
            Utc::now(),
        )?;

        info!("SAML response validated successfully");
        Ok(assertion)
    }

    /// Validate response structure
    fn validate_response_structure(
        &self,
        response: &Response,
    ) -> Result<()> {
        check_response_structure(response, &self.config.sp_acs_url, &self.pending_requests, Utc::now())
    }

    /// Ensure the assertion carries a signature. Cryptographic verification of
    /// the response's XML-DSig signature is performed in `validate_response`.
    fn verify_assertion_signature(
        &self,
        assertion: &Assertion,
    ) -> Result<()> {
        if assertion.signature.is_none() {
            anyhow::bail!("Assertion is not signed");
        }
        Ok(())
    }

    /// Validate assertion conditions
    fn validate_assertion_conditions(
        &self,
        assertion: &Assertion,
    ) -> Result<()> {
        let conditions = assertion
            .conditions
            .as_ref()
            .context("No conditions in assertion")?;

        check_assertion_conditions(conditions, Utc::now(), &self.config.sp_entity_id)
    }

    /// Extract user attributes from assertion
    pub fn extract_attributes(
        &self,
        assertion: &Assertion,
    ) -> Result<HashMap<String, String>> {
        let mut attributes = HashMap::new();

        // attribute_statements is Option<Vec<AttributeStatement>>
        if let Some(statements) = &assertion.attribute_statements
            && let Some(attribute_statement) = statements.first()
        {
            for attr in &attribute_statement.attributes {
                // Use 'values' instead of 'attribute_values' per samael API
                if let Some(attr_value) = attr.values.first() {
                    // AttributeValue has a 'value: Option<String>' field
                    // attr.name is also Option<String>
                    if let (Some(name), Some(text)) = (&attr.name, &attr_value.value) {
                        attributes.insert(name.clone(), text.clone());
                    }
                }
            }
        }

        // Also extract NameID if present
        if let Some(subject) = &assertion.subject
            && let Some(name_id) = &subject.name_id
        {
            attributes.insert("NameID".to_string(), name_id.value.clone());
        }

        Ok(attributes)
    }

    /// Get configuration
    pub fn config(&self) -> &SamlConfig {
        &self.config
    }

    /// Verify the response's XML-DSig signature against the trusted IdP signing
    /// key(s). Entra publishes a rollover bundle, so a response is accepted when
    /// it verifies under any one of them.
    fn verify_response_signature(
        &self,
        xml: &str,
    ) -> Result<()> {
        ensure_verifier()?;

        let mut last_error = None;
        for der in &self.idp_cert_ders {
            match verify_xml_signature(der, xml) {
                Ok(()) => return Ok(()),
                Err(e) => last_error = Some(e),
            }
        }
        match last_error {
            Some(e) => Err(e).context("XML signature verification failed"),
            None => anyhow::bail!("No trusted IdP signing certificate is configured"),
        }
    }

    /// Ensure the certificate embedded in the response signature is one of the
    /// trusted IdP signing certs (pinning).
    ///
    /// `verify_response_signature` binds the trusted key onto the signature
    /// context, so an attacker's KeyInfo certificate is already ignored. This
    /// stays as the check that also covers the rollover bundle: it names which
    /// of the configured certs the IdP actually signed with.
    fn verify_signing_cert_pinned(
        &self,
        xml: &str,
    ) -> Result<()> {
        use base64::Engine;
        let embedded: Vec<String> = extract_cert_b64s(xml)
            .into_iter()
            .filter_map(|b64| {
                base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .ok()
            })
            .filter_map(|der| X509::from_der(&der).ok())
            .filter_map(|cert| cert_sha256_thumbprint(&cert))
            .collect();
        if embedded.is_empty() {
            anyhow::bail!("SAML response has no embedded signing certificate");
        }
        if embedded.iter().any(|tp| {
            self.idp_cert_thumbprints
                .contains(tp)
        }) {
            Ok(())
        } else {
            anyhow::bail!(
                "SAML response signed by an untrusted certificate (got {embedded:?}, trusted {:?})",
                self.idp_cert_thumbprints
            )
        }
    }
}

/// Reject a SAML response that does not contain exactly one `Assertion`
/// element anywhere in the document (see the XSW comment at the call site).
fn reject_multiple_assertions(xml: &str) -> Result<()> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    let mut count = 0usize;
    loop {
        match reader
            .read_event()
            .context("Failed to scan SAML response for Assertion elements")?
        {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"Assertion" => {
                count += 1;
            }
            _ => {}
        }
    }

    if count != 1 {
        anyhow::bail!(
            "SAML response must contain exactly one Assertion element, found {count} (possible XML Signature Wrapping attack)"
        );
    }
    Ok(())
}

/// Reject a SAML response carrying a signature reference that points outside
/// the document. Only an empty URI (the whole document) and a same-document
/// fragment (`#id`) are permitted — the equivalent of xmlsec1's
/// `--enabled-reference-uris empty,same-doc` and
/// `--enabled-key-info-reference-uris empty,same-doc`, which libxmlsec1 does
/// not apply by default when driven in-process. `Reference` covers the signed
/// content; `RetrievalMethod` and `KeyInfoReference` are the KeyInfo children
/// that name a URI.
fn reject_external_reference_uris(xml: &str) -> Result<()> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    loop {
        let event = reader
            .read_event()
            .context("Failed to scan SAML response for signature references")?;
        let element = match event {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => e,
            _ => continue,
        };
        let name = element.local_name();
        if !matches!(name.as_ref(), b"Reference" | b"RetrievalMethod" | b"KeyInfoReference") {
            continue;
        }
        for attr in element.attributes() {
            let attr = attr.context("Failed to parse a signature reference attribute")?;
            if attr.key.local_name().as_ref() != b"URI" {
                continue;
            }
            let uri = String::from_utf8_lossy(attr.value.as_ref()).into_owned();
            if !uri.is_empty() && !uri.starts_with('#') {
                anyhow::bail!("SAML response signature references a URI outside the document: {uri}");
            }
        }
    }
    Ok(())
}

/// Enforce a `Response`'s Status, Destination and InResponseTo. All three
/// fields are required (fail closed) — a forged response could otherwise
/// bypass any one check simply by omitting it. Matching InResponseTo
/// consumes the pending request, so a captured response cannot be replayed
/// against a second `/saml/acs` POST, and an unsolicited (IdP-initiated)
/// response is rejected outright since this service only drives SP-initiated
/// login.
fn check_response_structure(
    response: &Response,
    sp_acs_url: &str,
    pending_requests: &DashMap<String, DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<()> {
    let status = response
        .status
        .as_ref()
        .context("SAML response missing Status")?;
    let code_value = status
        .status_code
        .value
        .as_ref()
        .context("SAML response missing StatusCode value")?;
    if code_value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
        anyhow::bail!("SAML authentication failed: {}", code_value);
    }

    let destination = response
        .destination
        .as_ref()
        .context("SAML response missing Destination")?;
    if destination != sp_acs_url {
        anyhow::bail!("Invalid destination in SAML response");
    }

    let in_response_to = response
        .in_response_to
        .as_ref()
        .context("SAML response missing InResponseTo (unsolicited responses are not accepted)")?;
    match pending_requests.remove(in_response_to) {
        Some((_, expiry)) if expiry > now => {}
        Some(_) => anyhow::bail!("SAML response's AuthnRequest has expired"),
        None => {
            anyhow::bail!("SAML response does not match an outstanding AuthnRequest (possible replay)")
        }
    }

    Ok(())
}

/// Enforce an assertion's `Conditions`: NotBefore/NotOnOrAfter (within
/// `CLOCK_SKEW`) and audience restriction against `sp_entity_id`. Both
/// NotOnOrAfter and AudienceRestriction are required — a forged or replayed
/// assertion could otherwise bypass either check simply by omitting it.
fn check_assertion_conditions(
    conditions: &Conditions,
    now: DateTime<Utc>,
    sp_entity_id: &str,
) -> Result<()> {
    if let Some(not_before) = conditions.not_before
        && now < not_before - CLOCK_SKEW
    {
        anyhow::bail!("Assertion is not yet valid (NotBefore: {})", not_before);
    }

    let not_on_or_after = conditions
        .not_on_or_after
        .context("Assertion conditions missing NotOnOrAfter")?;
    if not_on_or_after + CLOCK_SKEW < now {
        anyhow::bail!("Assertion has expired (NotOnOrAfter: {})", not_on_or_after);
    }

    let audience_restrictions = conditions
        .audience_restrictions
        .as_ref()
        .context("Assertion conditions missing AudienceRestriction")?;
    if audience_restrictions.is_empty() {
        anyhow::bail!("Assertion conditions missing AudienceRestriction");
    }
    // SAML core: multiple <AudienceRestriction> elements are ANDed — the
    // assertion is valid only if EVERY restriction is satisfied — while
    // multiple <Audience> within one restriction are ORed. This SP must appear
    // in each restriction; an outer `any` (OR across restrictions) would accept
    // an assertion that another restriction explicitly scopes away from us.
    let valid_audience = audience_restrictions
        .iter()
        .all(|restriction| {
            restriction
                .audience
                .iter()
                .any(|a| a == sp_entity_id)
        });
    if !valid_audience {
        anyhow::bail!("Invalid audience in assertion");
    }

    Ok(())
}

/// SAML Web-Browser-SSO bearer method URN.
const BEARER_METHOD: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// Enforce the assertion's bearer `SubjectConfirmationData` per the SAML 2.0
/// Web Browser SSO profile: at least one `SubjectConfirmation` with
/// `Method="…:bearer"` whose `SubjectConfirmationData` (a) quotes an
/// `InResponseTo` equal to the request this response answers, (b) is addressed
/// to this SP's ACS via `Recipient`, and (c) is still within `NotOnOrAfter`.
/// This binds the *signed* assertion to the outstanding request and to us, so a
/// captured assertion cannot be replayed or wrapped into a different response.
fn check_subject_confirmation(
    assertion: &Assertion,
    expected_in_response_to: Option<&str>,
    sp_acs_url: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    let expected_in_response_to =
        expected_in_response_to.context("SAML response missing InResponseTo for subject confirmation")?;

    let subject = assertion
        .subject
        .as_ref()
        .context("Assertion missing Subject")?;
    let confirmations = subject
        .subject_confirmations
        .as_ref()
        .context("Assertion Subject missing SubjectConfirmation")?;

    if !bearer_confirmation_present(confirmations, expected_in_response_to, sp_acs_url, now) {
        anyhow::bail!(
            "Assertion has no valid bearer SubjectConfirmationData (InResponseTo/Recipient/NotOnOrAfter) for this request"
        );
    }

    Ok(())
}

/// True iff at least one bearer `SubjectConfirmation` binds the assertion to
/// this request (`InResponseTo`), this SP (`Recipient`), and is unexpired
/// (`NotOnOrAfter`, within `CLOCK_SKEW`).
fn bearer_confirmation_present(
    confirmations: &[samael::schema::SubjectConfirmation],
    expected_in_response_to: &str,
    sp_acs_url: &str,
    now: DateTime<Utc>,
) -> bool {
    confirmations.iter().any(|c| {
        if c.method.as_deref() != Some(BEARER_METHOD) {
            return false;
        }
        let Some(data) = c
            .subject_confirmation_data
            .as_ref()
        else {
            return false;
        };
        data.in_response_to.as_deref() == Some(expected_in_response_to)
            && data.recipient.as_deref() == Some(sp_acs_url)
            && data
                .not_on_or_after
                .is_some_and(|nooa| now <= nooa + CLOCK_SKEW)
    })
}

/// Verify an XML digital signature in-process with libxmlsec1, registering the
/// SAML `ID` attribute so the enveloped Assertion/Response reference resolves.
/// The trusted certificate is bound onto the signature context as the
/// verification key, so the certificate carried in the document's `KeyInfo` is
/// never consulted. `Ok` means the signature is cryptographically valid and was
/// produced with that key.
fn verify_xml_signature(
    idp_cert_der: &CertificateDer,
    xml: &str,
) -> Result<()> {
    Crypto::verify_signed_xml(xml, idp_cert_der, Some("ID")).map_err(|e| anyhow::anyhow!("{e}"))
}

/// A signed probe document and the certificates that must and must not verify
/// it. Generated out-of-band by `probes/generate.py` with an independent
/// signer, never by the library under test.
const PROBE_SIGNED: &str = include_str!("probes/signed.xml");
const PROBE_BAD_SIGNATURE: &str = include_str!("probes/bad-signature.xml");
const PROBE_TAMPERED_CONTENT: &str = include_str!("probes/tampered-content.xml");
const PROBE_SIGNER_CERT_DER: &[u8] = include_bytes!("probes/signer-cert.der");
const PROBE_OTHER_CERT_DER: &[u8] = include_bytes!("probes/other-cert.der");

/// Result of the one-time verifier self-test, cached for the process lifetime.
static VERIFIER_SELF_TEST: OnceLock<Result<(), String>> = OnceLock::new();

/// Prove that this host's libxmlsec1 both accepts a valid signature and
/// rejects the three ways one can be invalid, before any SAML response is
/// trusted. A silently permissive XML-DSig stack would otherwise turn
/// `/saml/acs` into an unauthenticated login for anyone; failing closed here
/// means such a host serves no SAML at all.
///
/// The residual caveat is that a sufficiently broken libxmlsec1 aborts the
/// process rather than returning an error, which no in-process check can
/// convert into a clean failure; the build-time link guard
/// (`make verify-xml-libs`) is the mitigation for that.
fn ensure_verifier() -> Result<()> {
    let outcome = VERIFIER_SELF_TEST.get_or_init(run_verifier_self_test);
    match outcome {
        Ok(()) => Ok(()),
        Err(e) => anyhow::bail!("SAML signature verification is not usable on this host: {e}"),
    }
}

fn run_verifier_self_test() -> Result<(), String> {
    let signer = CertificateDer::from(PROBE_SIGNER_CERT_DER.to_vec());
    let other = CertificateDer::from(PROBE_OTHER_CERT_DER.to_vec());

    let probes: [(&str, &str, &CertificateDer, bool); 4] = [
        ("valid signature", PROBE_SIGNED, &signer, true),
        ("forged signature value", PROBE_BAD_SIGNATURE, &signer, false),
        ("tampered signed content", PROBE_TAMPERED_CONTENT, &signer, false),
        ("untrusted signing key", PROBE_SIGNED, &other, false),
    ];

    for (name, xml, cert, should_verify) in probes {
        let verified = verify_xml_signature(cert, xml).is_ok();
        if verified != should_verify {
            return Err(format!(
                "self-test probe '{name}' {} unexpectedly",
                if verified {
                    "verified"
                } else {
                    "failed to verify"
                }
            ));
        }
    }

    info!("SAML XML signature verifier self-test passed");
    Ok(())
}

/// SHA-256 thumbprint (`XX:XX:…`) of a certificate.
fn cert_sha256_thumbprint(cert: &X509) -> Option<String> {
    cert.digest(openssl::hash::MessageDigest::sha256())
        .ok()
        .map(|d| {
            d.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        })
}

/// Extract every base64 `X509Certificate` payload embedded in the XML.
fn extract_cert_b64s(xml: &str) -> Vec<String> {
    let marker = "X509Certificate>";
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(marker) {
        let after = &rest[i + marker.len()..];
        match after.find('<') {
            Some(end) => {
                let candidate: String = after[..end]
                    .split_whitespace()
                    .collect();
                if !candidate.is_empty() {
                    out.push(candidate);
                }
                rest = &after[end..];
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use samael::schema::{AudienceRestriction, Status, StatusCode, SubjectConfirmation, SubjectConfirmationData};

    const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    fn bearer_scd(
        in_response_to: Option<&str>,
        recipient: Option<&str>,
        not_on_or_after: Option<DateTime<Utc>>,
    ) -> SubjectConfirmation {
        SubjectConfirmation {
            method: Some(BEARER.to_string()),
            name_id: None,
            subject_confirmation_data: Some(SubjectConfirmationData {
                not_before: None,
                not_on_or_after,
                recipient: recipient.map(str::to_string),
                in_response_to: in_response_to.map(str::to_string),
                address: None,
                content: None,
            }),
        }
    }

    #[test]
    fn subject_confirmation_accepts_matching_bearer() {
        let now = Utc::now();
        let c = vec![bearer_scd(Some("req-1"), Some(ACS_URL), Some(now + Duration::minutes(5)))];
        assert!(bearer_confirmation_present(&c, "req-1", ACS_URL, now));
    }

    #[test]
    fn subject_confirmation_rejects_wrapped_assertion_different_request() {
        // The XSW case: a genuine victim assertion (SCD InResponseTo = the
        // victim's request) wrapped in a response quoting the attacker's own
        // outstanding request id must NOT confirm.
        let now = Utc::now();
        let c = vec![bearer_scd(Some("victim-req"), Some(ACS_URL), Some(now + Duration::minutes(5)))];
        assert!(!bearer_confirmation_present(&c, "attacker-req", ACS_URL, now));
    }

    #[test]
    fn subject_confirmation_rejects_wrong_recipient() {
        let now = Utc::now();
        let c = vec![bearer_scd(Some("req-1"), Some("https://evil.example/acs"), Some(now + Duration::minutes(5)))];
        assert!(!bearer_confirmation_present(&c, "req-1", ACS_URL, now));
    }

    #[test]
    fn subject_confirmation_rejects_expired_and_missing_nooa() {
        let now = Utc::now();
        let expired = vec![bearer_scd(Some("req-1"), Some(ACS_URL), Some(now - Duration::hours(1)))];
        assert!(!bearer_confirmation_present(&expired, "req-1", ACS_URL, now));
        let missing = vec![bearer_scd(Some("req-1"), Some(ACS_URL), None)];
        assert!(!bearer_confirmation_present(&missing, "req-1", ACS_URL, now));
    }

    #[test]
    fn subject_confirmation_rejects_non_bearer_method() {
        let now = Utc::now();
        let mut c = bearer_scd(Some("req-1"), Some(ACS_URL), Some(now + Duration::minutes(5)));
        c.method = Some("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key".to_string());
        assert!(!bearer_confirmation_present(&[c], "req-1", ACS_URL, now));
    }

    #[test]
    fn audience_and_semantics_rejects_when_one_restriction_excludes_sp() {
        // Two AudienceRestriction elements are ANDed: [sp-entity] AND [other].
        // The old outer `any` accepted this; the fix requires every restriction
        // to name this SP, so it must now be rejected.
        let now = Utc::now();
        let c = Conditions {
            not_before: None,
            not_on_or_after: Some(now + Duration::minutes(5)),
            audience_restrictions: Some(vec![
                AudienceRestriction {
                    audience: vec!["sp-entity".to_string()],
                },
                AudienceRestriction {
                    audience: vec!["someone-else".to_string()],
                },
            ]),
            one_time_use: None,
            proxy_restriction: None,
        };
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    #[test]
    fn audience_and_semantics_accepts_when_all_restrictions_include_sp() {
        let now = Utc::now();
        let c = Conditions {
            not_before: None,
            not_on_or_after: Some(now + Duration::minutes(5)),
            audience_restrictions: Some(vec![
                AudienceRestriction {
                    audience: vec!["sp-entity".to_string(), "x".to_string()],
                },
                AudienceRestriction {
                    audience: vec!["sp-entity".to_string()],
                },
            ]),
            one_time_use: None,
            proxy_restriction: None,
        };
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_ok());
    }

    const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
    const ACS_URL: &str = "https://sp.example/saml/acs";

    fn conditions(
        not_before: Option<DateTime<Utc>>,
        not_on_or_after: Option<DateTime<Utc>>,
        audience: Option<Vec<String>>,
    ) -> Conditions {
        Conditions {
            not_before,
            not_on_or_after,
            audience_restrictions: audience.map(|a| vec![AudienceRestriction { audience: a }]),
            one_time_use: None,
            proxy_restriction: None,
        }
    }

    #[test]
    fn accepts_conditions_within_window_and_matching_audience() {
        let now = Utc::now();
        let c = conditions(
            Some(now - Duration::minutes(1)),
            Some(now + Duration::minutes(1)),
            Some(vec!["sp-entity".to_string()]),
        );
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_ok());
    }

    #[test]
    fn rejects_expired_assertion() {
        let now = Utc::now();
        let c = conditions(None, Some(now - Duration::minutes(10)), Some(vec!["sp-entity".to_string()]));
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    #[test]
    fn rejects_assertion_not_yet_valid() {
        let now = Utc::now();
        let c = conditions(
            Some(now + Duration::minutes(10)),
            Some(now + Duration::minutes(20)),
            Some(vec!["sp-entity".to_string()]),
        );
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    #[test]
    fn rejects_missing_not_on_or_after() {
        let now = Utc::now();
        let c = conditions(None, None, Some(vec!["sp-entity".to_string()]));
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    #[test]
    fn rejects_missing_audience_restriction() {
        let now = Utc::now();
        let c = conditions(None, Some(now + Duration::minutes(5)), None);
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    #[test]
    fn rejects_wrong_audience() {
        let now = Utc::now();
        let c = conditions(None, Some(now + Duration::minutes(5)), Some(vec!["someone-else".to_string()]));
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    fn response_with(
        status_code: Option<&str>,
        destination: Option<&str>,
        in_response_to: Option<&str>,
    ) -> Response {
        Response {
            id: "resp-1".to_string(),
            in_response_to: in_response_to.map(str::to_string),
            version: "2.0".to_string(),
            issue_instant: Utc::now(),
            destination: destination.map(str::to_string),
            consent: None,
            issuer: None,
            signature: None,
            status: status_code.map(|v| Status {
                status_code: StatusCode { value: Some(v.to_string()) },
                status_message: None,
                status_detail: None,
            }),
            encrypted_assertion: None,
            assertion: None,
        }
    }

    #[test]
    fn accepts_matching_pending_request_and_consumes_it() {
        let now = Utc::now();
        let pending = DashMap::new();
        pending.insert("req-1".to_string(), now + Duration::minutes(5));
        let response = response_with(Some(SUCCESS), Some(ACS_URL), Some("req-1"));

        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_ok());
        // Replaying the same response must fail now that the request is consumed.
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_unknown_in_response_to() {
        let pending = DashMap::new();
        let response = response_with(Some(SUCCESS), Some(ACS_URL), Some("unknown"));
        assert!(check_response_structure(&response, ACS_URL, &pending, Utc::now()).is_err());
    }

    #[test]
    fn rejects_expired_pending_request() {
        let now = Utc::now();
        let pending = DashMap::new();
        pending.insert("req-1".to_string(), now - Duration::seconds(1));
        let response = response_with(Some(SUCCESS), Some(ACS_URL), Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_missing_in_response_to() {
        let pending = DashMap::new();
        let response = response_with(Some(SUCCESS), Some(ACS_URL), None);
        assert!(check_response_structure(&response, ACS_URL, &pending, Utc::now()).is_err());
    }

    #[test]
    fn rejects_missing_status() {
        let now = Utc::now();
        let pending = DashMap::new();
        pending.insert("req-1".to_string(), now + Duration::minutes(5));
        let response = response_with(None, Some(ACS_URL), Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_failure_status_code() {
        let now = Utc::now();
        let pending = DashMap::new();
        pending.insert("req-1".to_string(), now + Duration::minutes(5));
        let response =
            response_with(Some("urn:oasis:names:tc:SAML:2.0:status:Requester"), Some(ACS_URL), Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_missing_destination() {
        let now = Utc::now();
        let pending = DashMap::new();
        pending.insert("req-1".to_string(), now + Duration::minutes(5));
        let response = response_with(Some(SUCCESS), None, Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_wrong_destination() {
        let now = Utc::now();
        let pending = DashMap::new();
        pending.insert("req-1".to_string(), now + Duration::minutes(5));
        let response = response_with(Some(SUCCESS), Some("https://evil.example/acs"), Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn extracts_embedded_certificates() {
        let xml = "<ds:X509Certificate>AAAB\n  BBBB</ds:X509Certificate><X509Certificate>CCCC</X509Certificate>";
        assert_eq!(extract_cert_b64s(xml), vec!["AAABBBBB".to_string(), "CCCC".to_string()]);
    }

    #[test]
    fn extracts_nothing_when_no_certificate_present() {
        assert!(extract_cert_b64s("<samlp:Response>no certs</samlp:Response>").is_empty());
    }

    #[test]
    fn accepts_response_with_exactly_one_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion ID="a1"></saml:Assertion>
        </samlp:Response>"#;
        assert!(reject_multiple_assertions(xml).is_ok());
    }

    #[test]
    fn rejects_response_with_no_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>"#;
        assert!(reject_multiple_assertions(xml).is_err());
    }

    #[test]
    fn rejects_response_with_a_second_wrapped_assertion() {
        // Simulates an XML Signature Wrapping attempt: a genuine signed
        // Assertion alongside a second, forged one planted elsewhere in the
        // tree (e.g. inside an Extensions wrapper).
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion ID="forged"></saml:Assertion>
            <samlp:Extensions>
                <saml:Assertion ID="genuine"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature></saml:Assertion>
            </samlp:Extensions>
        </samlp:Response>"#;
        assert!(reject_multiple_assertions(xml).is_err());
    }

    #[test]
    fn rejects_response_with_self_closing_second_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion ID="a1"></saml:Assertion>
            <saml:Assertion ID="a2"/>
        </samlp:Response>"#;
        assert!(reject_multiple_assertions(xml).is_err());
    }

    #[test]
    fn verifier_self_test_passes() {
        ensure_verifier().expect("libxmlsec1 self-test must pass on a supported host");
    }

    #[test]
    fn verifies_the_signed_probe_and_rejects_every_invalid_variant() {
        let signer = CertificateDer::from(PROBE_SIGNER_CERT_DER.to_vec());
        let other = CertificateDer::from(PROBE_OTHER_CERT_DER.to_vec());

        assert!(verify_xml_signature(&signer, PROBE_SIGNED).is_ok());
        assert!(verify_xml_signature(&signer, PROBE_BAD_SIGNATURE).is_err());
        assert!(verify_xml_signature(&signer, PROBE_TAMPERED_CONTENT).is_err());
        assert!(verify_xml_signature(&other, PROBE_SIGNED).is_err());
    }

    #[test]
    fn accepts_same_document_reference_uris() {
        assert!(reject_external_reference_uris(PROBE_SIGNED).is_ok());
        let empty_uri =
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Reference URI=""/></ds:Signature>"#;
        assert!(reject_external_reference_uris(empty_uri).is_ok());
    }

    #[test]
    fn rejects_reference_uri_pointing_outside_the_document() {
        for uri in ["file:///etc/passwd", "https://attacker.example/x", "/etc/passwd"] {
            let xml = format!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Reference URI="{uri}"/></ds:Signature>"#
            );
            assert!(reject_external_reference_uris(&xml).is_err(), "reference URI {uri} must be rejected");
        }
    }

    #[test]
    fn rejects_retrieval_method_uri_pointing_outside_the_document() {
        let xml = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:RetrievalMethod URI="https://attacker.example/cert"/></ds:KeyInfo>"#;
        assert!(reject_external_reference_uris(xml).is_err());
    }

    #[test]
    fn rejects_key_info_reference_uri_pointing_outside_the_document() {
        let xml = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><dsig11:KeyInfoReference URI="file:///etc/passwd"/></ds:KeyInfo>"#;
        assert!(reject_external_reference_uris(xml).is_err());
    }
}
