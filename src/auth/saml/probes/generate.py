#!/usr/bin/env python3
"""Regenerate the SAML verifier self-test probe fixtures in this directory.

The appliance verifies SAML signatures in-process with libxmlsec1 (via samael).
`ensure_verifier()` replays the fixtures produced here at startup so a host whose
libxmlsec1 misbehaves gets no SAML at all. They are therefore signed by an
*independent* implementation (lxml exclusive-c14n + `cryptography` RSA-SHA256),
never by the library under test, and committed.

Re-run only if the probe set changes:

    python3 src/auth/saml/probes/generate.py

Requires: python3 with `lxml` and `cryptography`.
"""

import datetime
import hashlib
import pathlib
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from lxml import etree

HERE = pathlib.Path(__file__).resolve().parent
DS = "http://www.w3.org/2000/09/xmldsig#"

TEMPLATE = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_probe_response" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>urn:agent-stream:saml:probe:idp</saml:Issuer>
  <saml:Assertion ID="_probe_assertion" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>urn:agent-stream:saml:probe:idp</saml:Issuer>
    <saml:Subject>
      <saml:NameID>probe@agent-stream.invalid</saml:NameID>
    </saml:Subject>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_probe_assertion">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue/>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue/>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate/>
        </ds:X509Data>
      </ds:KeyInfo>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>
"""


def make_cert(common_name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    not_before = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=36500))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def exc_c14n(node):
    return etree.tostring(node, method="c14n", exclusive=True, with_comments=False)


def sign(template, key, cert):
    root = etree.fromstring(template.encode())
    assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    signature = assertion.find(f"{{{DS}}}Signature")

    # Reference digest: enveloped-signature transform, then exclusive c14n.
    # Only the Signature element is removed — its tail whitespace is part of
    # the signed content, and lxml's remove() would take it along.
    payload = etree.fromstring(etree.tostring(assertion))
    payload_signature = payload.find(f"{{{DS}}}Signature")
    tail = payload_signature.tail or ""
    previous = payload_signature.getprevious()
    if previous is not None:
        previous.tail = (previous.tail or "") + tail
    else:
        payload.text = (payload.text or "") + tail
    payload.remove(payload_signature)
    digest = hashlib.sha256(exc_c14n(payload)).digest()

    signed_info = signature.find(f"{{{DS}}}SignedInfo")
    signed_info.find(f".//{{{DS}}}DigestValue").text = _b64(digest)

    sig_value = key.sign(exc_c14n(signed_info), padding.PKCS1v15(), hashes.SHA256())
    signature.find(f"{{{DS}}}SignatureValue").text = _b64(sig_value)
    signature.find(f".//{{{DS}}}X509Certificate").text = _b64(
        cert.public_bytes(serialization.Encoding.DER)
    )

    return etree.tostring(root, xml_declaration=False).decode()


def _b64(raw):
    import base64

    return base64.b64encode(raw).decode()


def main():
    signer_key, signer_cert = make_cert("agent-stream-saml-probe")
    _, other_cert = make_cert("agent-stream-saml-probe-other")

    (HERE / "signer-cert.der").write_bytes(
        signer_cert.public_bytes(serialization.Encoding.DER)
    )
    (HERE / "other-cert.der").write_bytes(
        other_cert.public_bytes(serialization.Encoding.DER)
    )

    signed = sign(TEMPLATE, signer_key, signer_cert)
    (HERE / "signed.xml").write_text(signed)

    # Flip one base64 character of the SignatureValue: the reference digest
    # still matches, so only RSA verification can reject this one.
    match = re.search(r"(<ds:SignatureValue>)(.*?)(</ds:SignatureValue>)", signed, re.S)
    body = match.group(2)
    index = next(i for i, c in enumerate(body) if c.isalnum())
    flipped = body[:index] + ("B" if body[index] == "A" else "A") + body[index + 1 :]
    (HERE / "bad-signature.xml").write_text(
        signed[: match.start(2)] + flipped + signed[match.end(2) :]
    )

    # Alter signed content: the RSA signature over SignedInfo is still intact,
    # so only the reference digest can reject this one.
    (HERE / "tampered-content.xml").write_text(
        signed.replace("probe@agent-stream.invalid", "attacker@agent-stream.invalid")
    )

    print(f"Regenerated probe fixtures in {HERE}")


if __name__ == "__main__":
    main()
