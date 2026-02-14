#!/bin/bash
# NextGCore TLS Certificate Generation Script (G36)
#
# Generates self-signed CA and NF certificates for SBI TLS.
# Creates certificates for all 5GC network functions.
#
# Usage:
#   ./generate-certs.sh                    # Generate all certs in ./certs/
#   ./generate-certs.sh /custom/output/dir # Generate in custom directory
#
# Output structure:
#   certs/
#     ca.crt           - Root CA certificate
#     ca.key           - Root CA private key
#     nrf.crt, nrf.key - NRF certificate + key
#     amf.crt, amf.key - AMF certificate + key
#     ... (one per NF)

set -euo pipefail

CERTS_DIR="${1:-./certs}"
DAYS_VALID=3650  # 10 years

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== NextGCore TLS Certificate Generator ===${NC}"
echo "Output directory: $CERTS_DIR"
echo "Validity: $DAYS_VALID days"
echo ""

# Create certs directory
mkdir -p "$CERTS_DIR"

# ============================================================================
# Step 1: Generate Root CA
# ============================================================================
echo -e "${GREEN}[1/3] Generating Root CA...${NC}"

if [ -f "$CERTS_DIR/ca.key" ] && [ -f "$CERTS_DIR/ca.crt" ]; then
    echo -e "${YELLOW}Root CA already exists, skipping...${NC}"
else
    # Generate CA private key
    openssl genrsa -out "$CERTS_DIR/ca.key" 4096

    # Generate CA certificate
    openssl req -new -x509 -days $DAYS_VALID \
        -key "$CERTS_DIR/ca.key" \
        -out "$CERTS_DIR/ca.crt" \
        -subj "/C=US/ST=California/L=San Francisco/O=NextG/OU=5GC/CN=NextGCore Root CA"

    echo -e "${GREEN}Root CA created: ca.crt, ca.key${NC}"
fi

# ============================================================================
# Step 2: Generate NF certificates
# ============================================================================
echo ""
echo -e "${GREEN}[2/3] Generating NF certificates...${NC}"

NF_LIST="nrf ausf udm udr pcf nssf bsf amf smf upf"

for nf in $NF_LIST; do
    if [ -f "$CERTS_DIR/${nf}.key" ] && [ -f "$CERTS_DIR/${nf}.crt" ]; then
        echo -e "${YELLOW}  ${nf}: already exists, skipping${NC}"
        continue
    fi

    # Generate NF private key
    openssl genrsa -out "$CERTS_DIR/${nf}.key" 2048

    # Generate certificate signing request (CSR)
    openssl req -new \
        -key "$CERTS_DIR/${nf}.key" \
        -out "$CERTS_DIR/${nf}.csr" \
        -subj "/C=US/ST=California/L=San Francisco/O=NextG/OU=5GC/CN=${nf}.nextgcore.local"

    # Create SAN configuration for this NF
    cat > "$CERTS_DIR/${nf}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${nf}.nextgcore.local
DNS.2 = nextgcore-${nf}
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = 172.23.0.1
EOF

    # Sign certificate with CA
    openssl x509 -req -days $DAYS_VALID \
        -in "$CERTS_DIR/${nf}.csr" \
        -CA "$CERTS_DIR/ca.crt" \
        -CAkey "$CERTS_DIR/ca.key" \
        -CAcreateserial \
        -out "$CERTS_DIR/${nf}.crt" \
        -extfile "$CERTS_DIR/${nf}.ext"

    # Clean up CSR and extension file
    rm -f "$CERTS_DIR/${nf}.csr" "$CERTS_DIR/${nf}.ext"

    echo -e "${GREEN}  ${nf}: certificate created${NC}"
done

# ============================================================================
# Step 3: Set permissions
# ============================================================================
echo ""
echo -e "${GREEN}[3/3] Setting permissions...${NC}"

chmod 600 "$CERTS_DIR"/*.key
chmod 644 "$CERTS_DIR"/*.crt

# ============================================================================
# Summary
# ============================================================================
echo ""
echo -e "${GREEN}=== Certificate generation complete ===${NC}"
echo ""
echo "Root CA:"
echo "  Certificate: $CERTS_DIR/ca.crt"
echo "  Private key: $CERTS_DIR/ca.key"
echo ""
echo "NF certificates:"
for nf in $NF_LIST; do
    echo "  ${nf}: $CERTS_DIR/${nf}.crt, $CERTS_DIR/${nf}.key"
done
echo ""
echo "To use in docker-compose:"
echo "  1. Mount certs directory as volume"
echo "  2. Set TLS_ENABLED=true"
echo "  3. Point TLS_CERT, TLS_KEY, TLS_CA to mounted paths"
echo ""
