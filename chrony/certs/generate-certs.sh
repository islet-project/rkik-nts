#!/bin/bash

# Generate private key and X.509 self-signed certificate for chrony NTS
# with Subject Alternative Names for the specified IP addresses

set -e

# Configuration
KEY_FILE="server.key"
CERT_FILE="server.crt"
DAYS_VALID=365

# Generate private key (RSA 2048 bits)
echo "Generating private key..."
openssl genrsa -out "$KEY_FILE" 2048

# Generate self-signed certificate with SANs
echo "Generating self-signed certificate..."
openssl req -new -x509 \
    -key "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days "$DAYS_VALID" \
    -subj "/CN=chrony-nts-server" \
    -addext "subjectAltName=IP:192.168.10.1,IP:192.168.97.1"

echo "Certificate and key generated successfully:"
echo "  Key:  $KEY_FILE"
echo "  Cert: $CERT_FILE"

# Display certificate information
echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_FILE" -noout -text | grep -A 1 "Subject Alternative Name"
