#!/usr/bin/env bash
# generate-dev-certs.sh — Generate self-signed dev TLS certificates for NextGCore SBI
#
# Generates:
#   ca.crt / ca.key          — Self-signed root CA (dev only, 10-year validity)
#   <nf>.crt / <nf>.key      — Per-NF server certificates signed by the CA
#
# Usage:
#   ./generate-dev-certs.sh           # Generate for all NFs
#   ./generate-dev-certs.sh --clean   # Remove existing certs and regenerate
#
# After generation, enable TLS:
#   TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
#
# WARNING: These certificates are for local development only.
#          Never use them in production.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- Config ----------------------------------------------------------------
DAYS=3650          # 10 years for dev certs
KEY_BITS=2048
COUNTRY="US"
ORG="NextGCore Dev"
# All NF SANs on the Docker network (or 127.0.0.1 for local)
SAN_IPS="127.0.0.1,172.23.0.1,172.23.0.10,172.23.0.11,172.23.0.12,172.23.0.13,172.23.0.14,172.23.0.15,172.23.0.16,172.23.0.17,172.23.0.18,172.23.0.19"
SAN_DNS="localhost,nrf,ausf,udm,udr,pcf,nssf,bsf,amf,smf,upf,scp,sepp"
# ---------------------------------------------------------------------------

NF_LIST=(
    nrf ausf udm udr pcf nssf bsf amf smf upf
    scp sepp lmf mbsmf nsacf ee pin nwdaf dccf
)

if [[ "${1:-}" == "--clean" ]]; then
    echo "Removing existing certificates..."
    rm -f ca.crt ca.key ca.srl *.crt *.key *.csr *.ext
fi

if [[ -f ca.crt ]]; then
    echo "CA certificate already exists (use --clean to regenerate)"
else
    echo "==> Generating CA key and self-signed certificate"
    openssl genrsa -out ca.key ${KEY_BITS} 2>/dev/null
    openssl req -new -x509 -days ${DAYS} \
        -key ca.key \
        -out ca.crt \
        -subj "/C=${COUNTRY}/O=${ORG}/CN=NextGCore Dev CA" \
        -extensions v3_ca \
        -addext "basicConstraints=critical,CA:TRUE"
    echo "   CA certificate: ca.crt"
    echo "   CA private key: ca.key"
fi

generate_nf_cert() {
    local NF="$1"
    if [[ -f "${NF}.crt" ]]; then
        echo "   ${NF}.crt already exists (skipping)"
        return
    fi

    # Write SAN extension config
    cat > "${NF}.ext" <<EXTEOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
[alt_names]
DNS.1 = ${NF}
DNS.2 = localhost
$(IFS=','; idx=3; for dns in ${SAN_DNS//,/ }; do echo "DNS.${idx} = ${dns}"; ((idx++)); done)
$(IFS=','; idx=1; for ip in ${SAN_IPS//,/ }; do echo "IP.${idx} = ${ip}"; ((idx++)); done)
EXTEOF

    openssl genrsa -out "${NF}.key" ${KEY_BITS} 2>/dev/null
    openssl req -new \
        -key "${NF}.key" \
        -out "${NF}.csr" \
        -subj "/C=${COUNTRY}/O=${ORG}/CN=${NF}.nextgcore.local"
    openssl x509 -req -days ${DAYS} \
        -in "${NF}.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${NF}.crt" \
        -extfile "${NF}.ext" \
        -extensions v3_req 2>/dev/null
    rm -f "${NF}.csr" "${NF}.ext"
    echo "   ${NF}.crt (signed by CA)"
}

echo ""
echo "==> Generating per-NF certificates"
for NF in "${NF_LIST[@]}"; do
    generate_nf_cert "${NF}"
done

# Clean up CA serial file
rm -f ca.srl

echo ""
echo "==> Certificate summary:"
echo "    CA:          ca.crt  (trust anchor)"
for NF in "${NF_LIST[@]}"; do
    if [[ -f "${NF}.crt" ]]; then
        EXPIRY=$(openssl x509 -noout -enddate -in "${NF}.crt" 2>/dev/null | cut -d= -f2)
        echo "    ${NF}:  ${NF}.crt  (expires: ${EXPIRY})"
    fi
done

echo ""
echo "==> To enable TLS:"
echo "    TLS_ENABLED=true SBI_SCHEME=https docker compose up -d"
echo ""
echo "    To verify NRF TLS:"
echo "    openssl s_client -connect localhost:7777 -CAfile certs/ca.crt -verify_return_error < /dev/null"
