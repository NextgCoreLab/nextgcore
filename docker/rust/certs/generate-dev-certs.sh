#!/usr/bin/env bash
# generate-dev-certs.sh — Generate the dev SBI PKI for NextGCore
#
# Generates:
#   ca.crt / ca.key          — Self-signed root CA (dev only, 10-year validity)
#   <nf>.crt / <nf>.key      — Per-NF TLS client+server certificates signed by the CA
#
# Each NF certificate follows the NF TLS client and server certificate profile
# of TS 33.310 §6.1.3c.3 (Table 6.1.3c.3-1), so the NRF can verify who is
# registering (TS 33.501 §13.1.0, §5.9.2.2; nextgcore #1611, #1617):
#   - subjectAltName URI-ID  urn:uuid:<nfInstanceId>   (from nf-identities.txt)
#   - RFC 9310 NFTypes       <nfType>                  (from nf-identities.txt)
#   - subjectAltName DNS-IDs and IPs of this NF only (and loopback)
#   - keyUsage               critical, digitalSignature
#   - extendedKeyUsage       serverAuth, clientAuth (an NF is both)
#   - subjectKeyIdentifier / authorityKeyIdentifier (RFC 5280 method 1)
#   - validity               3 years or less
#
# Usage:
#   ./generate-dev-certs.sh                 # Generate into this directory
#   ./generate-dev-certs.sh --out DIR       # Generate into DIR
#   ./generate-dev-certs.sh --clean [...]   # Remove existing certs first
#   ./generate-dev-certs.sh --ids FILE      # Use another identity table
#
# Re-running keeps the CA and every NF certificate that already carries the
# URN and NFTypes its table entry names. A certificate that does not (one
# issued before #1617, or for an ID that has since changed) is re-issued:
# keeping it would leave that NF unable to prove its identity to the NRF.
#
# WARNING: These certificates are for local development only.
#          Never use them in production.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OUT_DIR="$SCRIPT_DIR"
IDS_FILE="$SCRIPT_DIR/nf-identities.txt"
CLEAN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean) CLEAN=1; shift ;;
        --out)   OUT_DIR="${2:?--out needs a directory}"; shift 2 ;;
        --ids)   IDS_FILE="${2:?--ids needs a file}"; shift 2 ;;
        -h|--help) sed -n '2,31p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
[[ -f "$IDS_FILE" ]] || { echo "identity table not found: $IDS_FILE" >&2; exit 1; }
mkdir -p "$OUT_DIR"
IDS_FILE="$(cd "$(dirname "$IDS_FILE")" && pwd)/$(basename "$IDS_FILE")"
cd "$OUT_DIR"

# ---- Config ----------------------------------------------------------------
CA_DAYS=3650       # dev root CA
DAYS=1095          # NF certificates: "3 years or less" (TS 33.310 Table 6.1.3c.3-1)
KEY_BITS=2048
COUNTRY="US"
# Subject O is the home domain name (TS 33.310 Table 6.1.3c.3-1, TS 23.003
# §28.2); the shipped configs use PLMN 999/70.
HOME_DOMAIN="${HOME_DOMAIN:-5gc.mnc070.mcc999.3gppnetwork.org}"
# RFC 9310 id-pe-nftype
NFTYPES_OID="1.3.6.1.5.5.7.1.34"
# ---------------------------------------------------------------------------

# name -> nfType / nfInstanceId / addresses, from the identity table.
declare -A NF_TYPE NF_ID NF_IPS
NF_LIST=()
while read -r name type id ips rest; do
    [[ -z "${name:-}" || "$name" == \#* ]] && continue
    if [[ -z "${ips:-}" || -n "${rest:-}" ]]; then
        echo "malformed line in $IDS_FILE: $name ${type:-} ${id:-} ${ips:-} ${rest:-}" >&2; exit 1
    fi
    if ! [[ "$name" =~ ^[a-z0-9-]+$ ]]; then
        echo "$name: a cert name is lower-case letters, digits and -" >&2; exit 1
    fi
    if ! [[ "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
        echo "$name: $id is not a lower-case UUID version 4 (TS 29.571 §5.3.2)" >&2; exit 1
    fi
    if ! [[ "$type" =~ ^[A-Z0-9_]{1,32}$ ]]; then
        echo "$name: $type is not an NF type (RFC 9310: IA5String, 1-32 characters)" >&2; exit 1
    fi
    if [[ -n "${NF_ID[$name]:-}" ]]; then
        echo "$name appears twice in $IDS_FILE" >&2; exit 1
    fi
    NF_TYPE[$name]="$type"
    NF_ID[$name]="$id"
    NF_IPS[$name]="$ips"
    NF_LIST+=("$name")
done < "$IDS_FILE"
[[ ${#NF_LIST[@]} -gt 0 ]] || { echo "no NF in $IDS_FILE" >&2; exit 1; }

if [[ "$CLEAN" == 1 ]]; then
    echo "Removing existing certificates..."
    rm -f ca.crt ca.key ca.srl ./*.crt ./*.key ./*.csr ./*.ext
fi

if [[ -f ca.crt && -f ca.key ]]; then
    echo "CA certificate already exists (use --clean to regenerate)"
else
    echo "==> Generating CA key and self-signed certificate"
    # A config file rather than -addext, which OpenSSL 1.0.x lacks.
    cat > ca.ext <<EXTEOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
C = ${COUNTRY}
O = ${HOME_DOMAIN}
CN = NextGCore Dev CA
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EXTEOF
    openssl genrsa -out ca.key ${KEY_BITS} 2>/dev/null
    openssl req -new -x509 -days ${CA_DAYS} -sha256 \
        -key ca.key \
        -out ca.crt \
        -config ca.ext
    rm -f ca.ext
    echo "   CA certificate: ca.crt"
    echo "   CA private key: ca.key"
fi

# The DER of the NFTypes payload naming exactly one type:
# SEQUENCE { IA5String <nfType> }, as lower-case hex.
nf_types_der_hex() {
    local t="$1"
    printf '30%02x16%02x' $(( ${#t} + 2 )) ${#t}
    printf '%s' "$t" | od -An -v -tx1 | tr -d ' \n'
}

# The subjectAltName of <nf>.crt as `openssl x509 -text` prints it.
expected_san() {
    local NF="$1" ip san
    san="URI:urn:uuid:${NF_ID[$NF]}, DNS:${NF}, DNS:nextgcore-${NF}, DNS:localhost, IP Address:127.0.0.1"
    if [[ "${NF_IPS[$NF]}" != "-" ]]; then
        for ip in ${NF_IPS[$NF]//,/ }; do san+=", IP Address:${ip}"; done
    fi
    printf '%s' "$san"
}

# Whether <nf>.crt was issued by the current CA and already carries the
# identity its table entry names.
cert_is_current() {
    local NF="$1" text der_hex
    [[ -f "${NF}.crt" && -f "${NF}.key" ]] || return 1
    openssl verify -CAfile ca.crt "${NF}.crt" >/dev/null 2>&1 || return 1
    text="$(openssl x509 -in "${NF}.crt" -noout -text 2>/dev/null)" || return 1
    # The subjectAltName must be exactly this NF's (see generate_nf_cert).
    [[ "$(grep -A1 "Subject Alternative Name" <<<"$text" | tail -1 | sed 's/^ *//')" \
        == "$(expected_san "$NF")" ]] || return 1
    grep -q "TLS Web Client Authentication" <<<"$text" || return 1
    der_hex="$(openssl x509 -in "${NF}.crt" -outform DER | od -An -v -tx1 | tr -d ' \n')"
    [[ "$der_hex" == *"$(nf_types_der_hex "${NF_TYPE[$NF]}")"* ]] || return 1
}

generate_nf_cert() {
    local NF="$1" idx ip
    if cert_is_current "$NF"; then
        echo "   ${NF}.crt already current (skipping)"
        return
    fi
    if [[ -f "${NF}.crt" ]]; then
        echo "   ${NF}.crt lacks urn:uuid:${NF_ID[$NF]} / NFTypes ${NF_TYPE[$NF]}, or another CA issued it: re-issuing"
    fi

    {
        cat <<EXTEOF
[v3_nf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = @alt_names
${NFTYPES_OID} = ASN1:SEQUENCE:nf_types
[nf_types]
nfType.1 = IA5STRING:${NF_TYPE[$NF]}
[alt_names]
URI.1 = urn:uuid:${NF_ID[$NF]}
DNS.1 = ${NF}
DNS.2 = nextgcore-${NF}
DNS.3 = localhost
IP.1 = 127.0.0.1
EXTEOF
        # Only this NF's own addresses: a certificate naming every NF's
        # address would let any NF pass as any other NF's server.
        idx=2
        if [[ "${NF_IPS[$NF]}" != "-" ]]; then
            for ip in ${NF_IPS[$NF]//,/ }; do
                echo "IP.${idx} = ${ip}"; idx=$((idx + 1))
            done
        fi
    } > "${NF}.ext"

    openssl genrsa -out "${NF}.key" ${KEY_BITS} 2>/dev/null
    # A CN-ID, when present, must be one of the subjectAltName values (TS 33.310
    # §6.1.3c.3 NOTE); DNS.1 is the NF's service name.
    openssl req -new \
        -key "${NF}.key" \
        -out "${NF}.csr" \
        -subj "/C=${COUNTRY}/O=${HOME_DOMAIN}/CN=${NF}"
    openssl x509 -req -days ${DAYS} -sha256 \
        -in "${NF}.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${NF}.crt" \
        -extfile "${NF}.ext" \
        -extensions v3_nf 2>/dev/null
    rm -f "${NF}.csr" "${NF}.ext"
    cert_is_current "$NF" || { echo "${NF}.crt was issued without its identity" >&2; exit 1; }
    echo "   ${NF}.crt (urn:uuid:${NF_ID[$NF]}, NFTypes ${NF_TYPE[$NF]})"
}

echo ""
echo "==> Generating per-NF certificates"
for NF in "${NF_LIST[@]}"; do
    generate_nf_cert "${NF}"
done

rm -f ca.srl

echo ""
echo "==> Certificate summary ($(pwd)):"
echo "    CA:          ca.crt  (trust anchor)"
for NF in "${NF_LIST[@]}"; do
    EXPIRY=$(openssl x509 -noout -enddate -in "${NF}.crt" 2>/dev/null | cut -d= -f2)
    echo "    ${NF}:  ${NF}.crt  ${NF_TYPE[$NF]} urn:uuid:${NF_ID[$NF]}  (expires: ${EXPIRY})"
done
echo ""
echo "    To verify an NRF that serves TLS:"
echo "    openssl s_client -connect localhost:7777 -CAfile ca.crt -verify_return_error < /dev/null"
