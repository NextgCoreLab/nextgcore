# SBI TLS Certificates — Development Setup

This directory holds TLS certificates for securing the SBI (Service Based Interface) between 5G Core NFs.

> **Warning**: These are **development-only** self-signed certificates. Do not use in production.

## Quick Start

```bash
# 1. Generate CA + per-NF certificates
./generate-dev-certs.sh

# 2. Start the stack with TLS enabled
TLS_ENABLED=true SBI_SCHEME=https docker compose up -d

# 3. Verify NRF TLS endpoint
openssl s_client -connect localhost:7777 \
    -CAfile certs/ca.crt \
    -verify_return_error < /dev/null
```

## What Gets Generated

| File | Purpose |
|------|---------|
| `ca.crt` | Root CA certificate (trust anchor for all NFs) |
| `ca.key` | Root CA private key (**never share**) |
| `<nf>.crt` | Per-NF server certificate (signed by CA) |
| `<nf>.key` | Per-NF private key (**never share**) |

NF certificates cover: nrf, ausf, udm, udr, pcf, nssf, bsf, amf, smf, upf, scp, sepp, lmf, mbsmf, nsacf, ee, pin, nwdaf, dccf

All certificates include SANs for `localhost`, Docker network IPs (172.23.0.x), and per-NF DNS names.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_ENABLED` | `false` | Set to `true` to pass `--tls` flag to NF binaries |
| `SBI_SCHEME` | `http` | Set to `https` for TLS SBI URLs |

## Certificate Renewal

Certificates have a 10-year validity (development only).  To regenerate:

```bash
./generate-dev-certs.sh --clean
docker compose down && docker compose up -d
```

## Production TLS

For production deployments, replace self-signed certificates with:
- Certificates from an internal PKI (e.g., cert-manager in K8s)
- Certificates per 3GPP TS 33.310 (Network Domain Security)
- TLS 1.3 with ECDSA P-256 or P-384 for SBI (TS 33.501 §13.2)

See `../../deploy/helm/` for K8s TLS configuration using cert-manager.
