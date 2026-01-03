#!/bin/bash
# Generate test TLS certificates for SEPP
# Run this script from the docker/rust/configs/tls directory

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Generating CA key and certificate..."
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=NextGCore/CN=NextGCore CA"

echo "Generating SEPP1 key and certificate..."
openssl genrsa -out sepp1.key 2048
openssl req -new -key sepp1.key -out sepp1.csr \
    -subj "/C=US/ST=State/L=City/O=NextGCore/CN=sepp1.localdomain"
openssl x509 -req -days 365 -in sepp1.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out sepp1.crt

echo "Generating SEPP2 key and certificate..."
openssl genrsa -out sepp2.key 2048
openssl req -new -key sepp2.key -out sepp2.csr \
    -subj "/C=US/ST=State/L=City/O=NextGCore/CN=sepp2.localdomain"
openssl x509 -req -days 365 -in sepp2.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out sepp2.crt

echo "Cleaning up CSR files..."
rm -f sepp1.csr sepp2.csr

echo "Done! Generated certificates:"
ls -la *.crt *.key
