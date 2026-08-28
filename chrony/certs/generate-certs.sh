#!/bin/bash

set -e

KEY_FILE="nts-devel.key"
CERT_FILE="nts-devel.crt"
DAYS_VALID=$((365*5))

# Generate private key (RSA 2048 bits)
echo "Generating private key..."
openssl genrsa -out "$KEY_FILE" 2048

# Generate self-signed certificate for the purposes of Islet/AVF development
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
