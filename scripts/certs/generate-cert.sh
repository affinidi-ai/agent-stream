#!/bin/bash
# Generate a self-signed TLS certificate for local Agent Stream development

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

CERT_DIR="config/certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
DAYS=365

# Create directory if it doesn't exist
mkdir -p "$CERT_DIR"

echo "Generating self-signed TLS certificate..."
echo "This certificate is for TESTING ONLY and should not be used in production."
echo ""

# Create a config file for SAN (Subject Alternative Names)
cat > "$CERT_DIR/openssl.cnf" <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = localhost
O = Agent Stream (development)
C = US

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = host.docker.internal
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate the certificate with SAN
openssl req -x509 -newkey rsa:4096 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days $DAYS \
  -nodes \
  -config "$CERT_DIR/openssl.cnf" \
  -extensions v3_req

echo ""
echo "Certificate generated successfully!"
echo "  Certificate: $CERT_FILE"
echo "  Private Key: $KEY_FILE"
echo "  Config: $CERT_DIR/openssl.cnf"
echo "  Valid for: $DAYS days"
echo ""
echo "To trust this certificate on your system:"
echo ""
echo "macOS:"
echo "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERT_FILE"
echo ""
echo "Linux:"
echo "  sudo cp $CERT_FILE /usr/local/share/ca-certificates/agent-stream.crt"
echo "  sudo update-ca-certificates"
echo ""
echo "Windows:"
echo "  Import $CERT_FILE into 'Trusted Root Certification Authorities'"
echo ""
echo "For clients, you can also skip verification (TESTING ONLY):"
echo "  curl -k https://localhost:8443/..."
echo "  or pass --cacert $CERT_FILE to curl"
echo ""
