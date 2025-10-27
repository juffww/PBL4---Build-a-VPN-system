#!/bin/bash

# Script tạo self-signed certificate cho VPN Server

CERT_DIR="./certs"
DAYS_VALID=365

mkdir -p "$CERT_DIR"

echo "[*] Generating VPN Server TLS Certificate..."

# Generate private key (2048-bit RSA)
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Generate self-signed certificate
openssl req -new -x509 -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days $DAYS_VALID \
    -subj "/C=VN/ST=DaNang/L=DaNang/O=VPNServer/CN=vpn.local"

# Set appropriate permissions
chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

echo "[✓] Certificate generated successfully!"
echo "    Private Key: $CERT_DIR/server.key"
echo "    Certificate: $CERT_DIR/server.crt"
echo ""
echo "Usage: ./vpn_server --cert $CERT_DIR/server.crt --key $CERT_DIR/server.key"