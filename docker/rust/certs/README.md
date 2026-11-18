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

# Single dev host whose NFs dial each other on loopback (WARNs, see below)
./generate-dev-certs.sh --loopback

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
| subjectAltName | `URI:urn:uuid:<nfInstanceId>`, `DNS:<nf>`, `DNS:nextgcore-<nf>`, plus the NF's addresses from the table (`DNS:localhost`, `IP:127.0.0.1` only with `--loopback`) |
| NFTypes (RFC 9310, 1.3.6.1.5.5.7.1.34) | `<nfType>` |
| keyUsage | critical, digitalSignature |
| extendedKeyUsage | serverAuth, clientAuth (an NF is both) |
| subjectKeyIdentifier / authorityKeyIdentifier | RFC 5280 method (1) |
| Validity | 3 years (the CA: 10 years) |
| cRLDistributionPoints | **absent** (see "Known deviations") |

The CA is `basicConstraints = critical, CA:TRUE, pathlen:0`: it signs NF
certificates and cannot certify a sub-CA.

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
compose file pins an ID other than the table's, when a service with a
certificate volume configures any nfInstanceId but its certificate's (in its
environment, command or bind-mounted files) or does not name its pair with
`NEXTGCORE_NRF_TLS_*`, and when a service other than `sbi-tls` mounts this
directory or the `sbi_pki` volume.

Each certificate names only its own NF in its DNS and IP SANs, so one NF's
certificate cannot pass as another NF's server identity.

### Loopback

By default no certificate names `localhost` or `127.0.0.1`. Every certificate
naming them would let any NF's certificate pass as the server of any peer
addressed by loopback, which is the impersonation the per-NF SANs remove.
A client on the same host dials the NF by a name its certificate carries
(`DNS:<nf>`), or, for the NRF, sets `NEXTGCORE_NRF_TLS_SERVER_NAME=nrf` to
verify the NRF's certificate against that name while dialling `127.0.0.1`.
`--loopback` restores the loopback SANs on every certificate for a single dev
host, and prints a WARN. Switching it on or off re-issues the certificates.

### Private keys

Every `*.key` is written `0600` (and a key kept from an earlier run is
tightened to `0600`). A container whose user is not the key's owner cannot read
it through a bind mount: the deployment must give the key to the container's
user (for example a copy owned by that user, or a Kubernetes Secret with
`defaultMode`/`fsGroup`), rather than widening the file mode.

The compose stacks do not bind-mount this directory into any NF. Their one-shot
`sbi-tls` service runs [`compose-tls-init.sh`](compose-tls-init.sh) as root:
it issues the PKI into the `sbi_pki` volume (only that service mounts it, so
the CA key stays there) and copies into each NRF client's own volume
`tls-<name>` its `ca.crt`, `<name>.crt` (`0444`) and `<name>.key` (`0400`,
owned by the uid that container runs as: the image's `nextgcore` user, or the
uid `SBI_TLS_OWNERS` names for a nextgsim sidecar that drops to its own). Each
NF mounts only its own volume, read-only, at `/etc/nextgcore/certs`, so no NF
container can read another NF's key.

The Kubernetes deployments (`k8s/deploy.sh`, `deploy/eks/deploy-eks.sh`) do
the same with Secrets: [`k8s/nf-tls-secrets.sh`](../../../k8s/nf-tls-secrets.sh)
issues the PKI into a private temporary directory, deleted on exit (the CA key
never enters the cluster), and creates one Secret per `nf-tls-<name>` the pods
mount: `ca.crt`, `<name>.crt`, `<name>.key`, named `nf-tls-<name>-<version>`
after its CA (the first 16 hex digits of the sha256 of `ca.crt`). The pod mounts it read-only
at `/etc/nextgcore/certs` with `defaultMode: 0440` and `fsGroup`, so the
image's non-root user reads it; root-run nextgsim sidecars that drop to their
own uid get it `0400` and hand the key to that uid. `nf-tls-ca` holds `ca.crt`
only, for a client that only discovers. A re-run keeps the newest complete,
current version (each certificate chains, matches its key, names its row and is
valid 30 more days). Otherwise it creates a whole new version beside the old
one, which it never modifies: a failed or interrupted issue leaves the running
pods on their CA, and its partial version is never used. The deploy scripts
point the manifests at the version in force (`--stamp`: `secretName` and the
`nextg.io/nf-tls-ca` annotation), so applying them rolls the NRF and its clients
together. Older versions are left in place, unreferenced; nothing deletes them.
`check-nf-identities.py --k8s` checks every rendered kustomization.

Certificates (`*.crt`, `ca.crt`) are public and written `0644`, so any
container user can read them through a bind mount.

## Re-running

Re-running keeps the CA and every NF certificate that already carries the
identity its table row names. A certificate that does not (one issued before
#1617, or for a changed ID or type) is re-issued, and the script says so.
`--clean` removes everything and starts over.

## Known deviations from TS 33.310 Table 6.1.3c.3-1

- **cRLDistributionPoints** is "Mandatory: TRUE" in the profile and is not
  issued. This dev PKI has no CRL and revokes nothing, so a distribution point
  would name a URL that serves nothing. Do not copy this profile as conformant:
  an operator PKI must carry the extension.

## Production TLS

For production, issue the certificates from the operator's PKI (TS 33.310
§6.1.3c: CMPv2 or ACME) with the same profile: in particular the
`urn:uuid:<nfInstanceId>` URI SAN, the RFC 9310 NFTypes extension, and the
nfInstanceId the NF actually registers.
