# SBI TLS Certificates — Development PKI

This directory holds the generator for the TLS certificates that secure the SBI
(Service Based Interface) between the 5G Core NFs of the shipped stacks.

> **Warning**: These are **development-only** certificates from a self-signed
> CA. Do not use them in production.

## Quick Start

```bash
# Generate the CA and one certificate per NF into this directory
./generate-dev-certs.sh

# Or somewhere else
./generate-dev-certs.sh --out /tmp/nextgcore-certs

# Inspect one
openssl x509 -in amf.crt -noout -text
```

## What Gets Generated

| File | Purpose |
|------|---------|
| `ca.crt` | Root CA certificate (trust anchor for all NFs) |
| `ca.key` | Root CA private key (**never share**) |
| `<nf>.crt` | Per-NF TLS client and server certificate, signed by the CA |
| `<nf>.key` | Per-NF private key (**never share**) |

The NFs, their NF types, NF instance IDs and addresses come from
[`nf-identities.txt`](nf-identities.txt). Each NF certificate follows the NF TLS
client and server certificate profile of TS 33.310 §6.1.3c.3:

| Field | Value |
|-------|-------|
| Subject | `C=US, O=5gc.mnc070.mcc999.3gppnetwork.org, CN=<nf>` (override the home domain with `HOME_DOMAIN`) |
| subjectAltName | `URI:urn:uuid:<nfInstanceId>`, `DNS:<nf>`, `DNS:nextgcore-<nf>`, `DNS:localhost`, `IP:127.0.0.1`, plus the NF's addresses from the table |
| NFTypes (RFC 9310, 1.3.6.1.5.5.7.1.34) | `<nfType>` |
| keyUsage | critical, digitalSignature |
| extendedKeyUsage | serverAuth, clientAuth (an NF is both) |
| subjectKeyIdentifier / authorityKeyIdentifier | RFC 5280 method (1) |
| Validity | 3 years (the CA: 10 years) |

The URN and the NFTypes are what the NRF checks a registrant against:
NFRegister, NFUpdate and NFDeregister must name the nfInstanceId and nfType of
the caller's verified client certificate, or they are refused
`400 INVALID_CLIENT` (#1611). TS 33.310 §6.1.3c.3 NOTE 1a: without the URN, "the
identity of the NF instance can not be securely validated".

So **an NF must register with the nfInstanceId its certificate names**. The
compose stacks pin each NF's ID with `NEXTGCORE_<TYPE>_INSTANCE_ID` (see
`src/libs/nextgcore-sbi/src/nf_instance_id.rs`); an unpinned NF generates a
random UUID at start that no certificate names.
[`check-nf-identities.py`](check-nf-identities.py) (run in CI) fails when a
compose file pins an ID other than the table's.

Each certificate names only its own NF in its DNS and IP SANs (plus loopback),
so one NF's certificate cannot pass as another NF's server identity.

The private keys keep the default file mode, so the non-root `nextgcore` user
in the containers can read them through the bind mount.

## Re-running

Re-running keeps the CA and every NF certificate that already carries the
identity its table row names. A certificate that does not (one issued before
#1617, or for a changed ID or type) is re-issued, and the script says so.
`--clean` removes everything and starts over.

## Production TLS

For production, issue the certificates from the operator's PKI (TS 33.310
§6.1.3c: CMPv2 or ACME) with the same profile: in particular the
`urn:uuid:<nfInstanceId>` URI SAN, the RFC 9310 NFTypes extension, and the
nfInstanceId the NF actually registers.
