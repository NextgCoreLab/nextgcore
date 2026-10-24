# NextGCore Rust Docker Deployment

This directory contains the Docker Compose stacks, per-NF configs and E2E scripts for the NextGCore Rust network functions and the nextgsim RAN simulators.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Building Images](#building-images)
- [Deployment Options](#deployment-options)
- [Configuration](#configuration)
- [Network Architecture](#network-architecture)
- [Validation](#validation)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)

## Prerequisites

- Docker 24.0+ with BuildKit support
- Docker Compose v2.20+
- 8 GB RAM for the health-gated 5GC containers; 12-16 GB to keep all 26 `docker-compose.yml` containers running (see [CI.md](CI.md))
- >= 25 GB free disk (the preflight refuses to build below that; 60 GB recommended)
- `curl` and `jq` for validation scripts

### Verify Prerequisites

```bash
# Check Docker version
docker --version

# Check Docker Compose version
docker compose version

# Verify BuildKit is enabled
docker buildx version
```

## Quick Start

### Deploy 5G Core (5GC)

```bash
cd docker/rust

# One command: disk preflight -> build -> full matched-sim E2E
# (UE registration -> PDU session -> data-plane ping). Exit 0 = all green.
./e2e.sh

# Or bring the stack up manually and follow key logs
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml logs -f amf gnb ue
```

### Deploy EPC (4G LTE)

```bash
cd docker/rust

# Build the NF images (build.sh compiles both workspaces, including nextgsim's
# lte-enb and lte-ue, into ./binaries)
./build.sh

# build.sh does not package the LTE eNB/UE images; build them as CI does
mkdir -p ../../../nextgsim/binaries
cp binaries/lte-enb binaries/lte-ue ../../../nextgsim/binaries/
docker build -f ../../../nextgsim/Dockerfile.enb-local -t nextgsim-lte-enb:latest ../../../nextgsim
docker build -f ../../../nextgsim/Dockerfile.lte-ue-local -t nextgsim-lte-ue:latest ../../../nextgsim

# Deploy
docker compose -f docker-compose-epc.yml up -d

# Verify deployment: health, then a real LTE attach and a 0%-loss ping
docker compose -f docker-compose-epc.yml ps
./epc-attach-check.sh 10.45.0.1 20

# Idle mode as well (#956): S1 release, mobile-originated and network-triggered
# SERVICE REQUEST. Needs an eNB with a user-inactivity release and LTE paging
# (nextgsim #350, #351); off by default until then.
EPC_IDLE_MODE=1 ./epc-attach-check.sh 10.45.0.1 20

# View logs
docker compose -f docker-compose-epc.yml logs -f
```

> **Scope of the EPC stage — a real LTE attach and a 0%-loss ping (#303).**
> The compose file now carries nextgsim's LTE eNB (`enb`, 172.24.0.50) and UE
> (`lte-ue`), built from nextgsim's `Dockerfile.enb-local` /
> `Dockerfile.lte-ue-local` (nextgsim #186). The nightly stage first asserts what
> it always did — the seven NFs healthy, both PFCP associations (Sxa SGW-C ↔
> SGW-U, Sxb PGW-C ↔ PGW-U, from both ends) and the PGW-C's S5/S8 socket
> serving — and then `epc-attach-check.sh`:
>
> 1. S1 Setup accepted by the MME;
> 2. the UE at EMM-REGISTERED with its default EPS bearer activated on the
>    **same EBI** at the UE and the MME, and a non-zero PDN address;
> 3. 20 ICMP echoes from the bearer's TUN to the PGW-U SGi address
>    `10.45.0.1` with 0% loss — UE → eNB → S1-U → SGW-U → S5-U → PGW-U and back.
>
> The subscriber (IMSI 999700000000001, TS 35.208 K/OPc, APN `internet`) is
> seeded by the same `docs/assets/webui/mongo-init.js` the 5G compose uses. The
> `lte-ue` service needs `NET_ADMIN` and `/dev/net/tun` for the bearer's TUN;
> the eNB needs only the host `sctp` module (S1-MME is an outbound kernel SCTP
> association). Not exercised: dedicated bearers, handover, idle mode/paging,
> IPv6 PDN, and egress beyond the PGW-U. History: `specs/epc-e2e-scope.md` (#328) and
> `specs/epc-pgw-container.md` (#380).

### 5GC and EPC together

The two stacks are separate compose files on separate networks
(`172.23.0.0/24` and `172.24.0.0/24`) and can run side by side:

```bash
cd docker/rust
./build.sh
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose-epc.yml up -d
```

## Building Images

### Build Script Options

```bash
./build.sh [--skip-rust] [--no-preflight]

Options:
  --skip-rust      Reuse the binaries already in ./binaries and only rebuild the
                   Docker images (fast iteration; no recompile).
  --no-preflight   Skip the disk preflight (preflight.sh). Not recommended.

build.sh compiles BOTH workspaces (nextgcore + nextgsim) inside a Rust builder
container (Dockerfile.builder), extracts binaries to ./binaries, then builds one
slim image per NF (Dockerfile.core + Dockerfile.nf) plus the gNB/UE images. It
always builds every NF; there are no tag/registry/push/parallel/multi-arch/per-NF
flags.
```

### Build Examples

```bash
# Full build: compile both workspaces + build every NF/gNB/UE image
./build.sh

# Fast re-image without recompiling (reuse ./binaries)
./build.sh --skip-rust
```

### Multi-architecture images

`build-multiarch.sh` builds linux/amd64 and linux/arm64 images with Buildx:

```bash
./build-multiarch.sh                                   # local platform only
./build-multiarch.sh --platform linux/amd64,linux/arm64
./build-multiarch.sh --push <registry> --platform linux/amd64,linux/arm64
```

## Deployment Options

### Docker Compose Files

| File | Description |
|------|-------------|
| `docker-compose.yml` | Matched-sim E2E: MongoDB + 20 5GC NFs + nextgsim gNB/UE + Prometheus/Grafana/Jaeger (no EPC) |
| `docker-compose-epc.yml` | EPC (4G): MME, SGW-C, SGW-U, PGW-C, PGW-U, HSS, PCRF + nextgsim LTE eNB/UE. The PGW-C/PGW-U are `smfd`/`upfd` in their EPC roles (#380) |
| `docker-compose.oauth2.yml` | Overlay: OAuth2 SBI enforcement (`./e2e.sh --overlay oauth2`) |
| `docker-compose.kernel-sctp.yml` | Overlay: native kernel-SCTP N2 (`./e2e.sh --overlay kernel-sctp`) |
| `docker-compose.features.yml` | Overlay: Rel-17/18 feature harness (`./e2e.sh --overlay features`) |

### Starting a subset

`docker-compose.yml` has no profiles: `docker compose up -d` starts every
service, including SCP and SEPP. Start a subset by naming services, as the CI
E2E does:

```bash
docker compose up -d mongodb nrf
docker compose up -d ausf udm udr pcf nssf bsf
docker compose up -d amf smf upf gnb ue
```

## Configuration

### Environment Variables

The compose files set each NF's environment inline. `docker/rust/.env` (gitignored) holds the one secret compose needs, `GRAFANA_ADMIN_PASSWORD`.
Common ones:

| Variable | Description | Default |
|----------|-------------|---------|
| `GRAFANA_ADMIN_PASSWORD` | Grafana `admin` password. **Required**: `docker compose` refuses to start without it (#837); put `GRAFANA_ADMIN_PASSWORD=...` in `docker/rust/.env` (gitignored) | none |
| `RUST_LOG` | Log filter for every NF (env_logger syntax, e.g. `info,nextgcore_amfd=debug`). When set and not blank it replaces the NF's `--log-level` entirely; unset, `--log-level` applies to all targets (#691) | `info` |
| `NEXTGCORE_SBI_PROFILE` | SBI security profile for amf/smf/ausf/udm; the compose files set `dev` (h2c, no mTLS) | `production` when unset |
| `NEXTGCORE_SBI_OAUTH2_REQUIRE` | Force OAuth2 enforcement on an NF's SBI server (the `oauth2` overlay sets it) | unset |

`TLS_ENABLED` and `SBI_SCHEME`, set in the compose file's common block, are not
read by any NF. SBI TLS comes from an NF's `--tls --tls-cert --tls-key` flags or
from the `production` SBI profile; see the
[configuration overview](../../docs-book/src/configuration/overview.md).

#### Rel-17/18 Feature Knobs

These tune the integrated Rel-17/18 features (set on the relevant NF container):

| Variable | NF | Description | Default |
|----------|----|-------------|---------|
| `REDCAP_SESS_AMBR_DL_BPS` | smf | RedCap session-AMBR downlink cap (Rel-17) | `150000000` (150 Mbps) |
| `REDCAP_SESS_AMBR_UL_BPS` | smf | RedCap session-AMBR uplink cap | `50000000` (50 Mbps) |
| `AMF_SNPN_ALLOWED_NIDS` | amf | Comma-separated served SNPN NIDs; a UE NID not in this list is rejected (5GMM #75). Unset = accept any NID (Rel-17, TS 23.501 §5.30) | _(unset)_ |
| `AMF_UAV_GEOFENCE` | amf | UAV geofence `min_lat,max_lat,min_lon,max_lon,min_alt,max_alt`; a tracking report outside it is denied (Rel-18, TS 23.256) | `0,0,0,0,0,120` (0-120 m ceiling) |
| `PCF_UAV_DNN` | pcf | DNN that triggers UAV policy authorization | `uav` |

Notes:
- **XR 5QI** (Rel-18) needs no env var: a PDU session on an XR DNN (`xr`/`xr-cloud`/`xr-gaming` → 5QI 82, `xr-split` → 84, `xr-haptic` → 85) makes the SMF install a dedicated GBR XR QER and the UPF mark it EF/AF41. The DNN reaches the SMF via the UE's UL NAS Transport DNN IE.
- **MINT** (Rel-18) needs no env var; the secondary SUPI(s) the UE registers must exist in the subscriber DB.
- See `nextgsim/docs/configuration.md` for the matching UE-side config knobs and `config/features/` for ready-to-run per-feature example configs.

### Configuration Files

Configuration files are mounted from `configs/` directory:

```
configs/
├── 5gc/                    # 5G Core configurations
│   ├── amf.yaml
│   ├── smf.yaml
│   ├── upf.yaml
│   ├── nrf.yaml
│   ├── ausf.yaml
│   ├── udm.yaml
│   ├── udr.yaml
│   ├── pcf.yaml
│   ├── nssf.yaml
│   ├── bsf.yaml
│   ├── nsacf.yaml, nwdaf.yaml, lmf.yaml, mbsmf.yaml, ees.yaml, pin.yaml, dccf.yaml, ucmf.yaml
│   ├── *-oauth2.yaml      # variants for the oauth2 overlay (nrf, udr, bsf, nssf, nsacf)
│   └── hnet/              # Home network keys
├── epc/                    # EPC configurations
│   ├── mme.yaml
│   ├── hss.yaml
│   ├── pcrf.yaml
│   ├── sgwc.yaml
│   ├── sgwu.yaml
│   ├── pgwc.yaml          # smfd as PGW-C
│   ├── pgwu.yaml          # upfd as PGW-U
│   └── freeDiameter/      # Diameter configurations
├── scp.yaml               # SCP configuration
├── sepp1.yaml             # SEPP1 configuration
├── sepp2.yaml             # SEPP2 configuration
├── observability/         # Prometheus / tracing
└── tls/                   # TLS certificates
```

### NSACF Slice Quotas

`configs/5gc/nsacf.yaml` provisions per-slice admission limits at startup:

```yaml
nsacf:
  slice_quotas:
    - sst: 1
      # sd: optional (hex); omit for an SST-wide quota
      max_ues: 1000            # omit -> that count is not NSAC-subject (uncapped)
      max_pdu_sessions: 2000
```

Each entry maps to an S-NSSAI `{sst, sd?}`; NSACF admits UEs / PDU sessions up to
`max_ues` / `max_pdu_sessions` (TS 29.536). An absent limit means that count is
uncapped for the slice; an S-NSSAI with no matching quota entry is treated as
not-NSAC-subject (`SLICE_NOT_FOUND`). The other advanced NFs (`nwdaf.yaml`,
`lmf.yaml`, `mbsmf.yaml`, `ees.yaml`, `pin.yaml`, `dccf.yaml`, `ucmf.yaml`) also
live under `configs/5gc/`.

### Custom Configuration

Mount custom configuration files:

```yaml
services:
  amf:
    volumes:
      - ./my-configs/amf.yaml:/etc/nextgcore/amf.yaml:ro
```

## Network Architecture

### 5G Core Network (172.23.0.0/24)

```
┌─────────────────────────────────────────────────────────────────┐
│                        5G Core Network                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐     │
│  │   NRF   │    │  AUSF   │    │   UDM   │    │   UDR   │     │
│  │ .0.10   │    │ .0.11   │    │ .0.12   │    │ .0.20   │     │
│  └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘     │
│       │              │              │              │           │
│       └──────────────┴──────────────┴──────────────┘           │
│                          │ SBI                                  │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐     │
│  │   PCF   │    │  NSSF   │    │   BSF   │    │   SCP   │     │
│  │ .0.13   │    │ .0.14   │    │ .0.15   │    │ .0.37   │     │
│  └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘     │
│       │              │              │              │           │
│       └──────────────┴──────────────┴──────────────┘           │
│                          │                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    AMF (.0.5)                            │   │
│  │         NGAP: 38412 (SCTP over UDP), SBI: 7777          │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    SMF (.0.4)                            │   │
│  │              PFCP: 8805/udp, SBI: 7777                  │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │ N4 (PFCP)                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    UPF (.0.7)                            │   │
│  │         GTP-U: 2152/udp, PFCP: 8805/udp                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### EPC Network (172.24.0.0/24)

```
┌─────────────────────────────────────────────────────────────────┐
│                        EPC Network                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    HSS (.0.8)                            │   │
│  │                 Diameter: 3868                           │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │ S6a                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    MME (.0.5)                            │   │
│  │       S1AP: 36412 (kernel SCTP), GTP-C: 2123            │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            │ S11                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   SGW-C (.0.3)                           │   │
│  │              GTP-C: 2123, PFCP: 8805                    │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                 Sxa        │        S5/S8-C (GTP-C: 2123)      │
│        ┌───────────────────┴───────────────────┐               │
│  ┌─────────────────────────┐   ┌───────────────────────────┐   │
│  │      SGW-U (.0.6)        │   │      PGW-C (.0.4)          │   │
│  │       GTP-U: 2152        │   │  GTP-C: 2123, PFCP: 8805   │   │
│  └───────────┬─────────────┘   └─────────────┬─────────────┘   │
│              │  S5/S8-U (GTP-U: 2152)        │ Sxb (PFCP)      │
│              │      ┌────────────────────────┘                 │
│  ┌───────────┴──────┴──────────────────────────────────────┐   │
│  │                   PGW-U (.0.7)                           │   │
│  │        GTP-U: 2152, PFCP: 8805, SGi via `epctun`        │   │
│  │             UE pool 10.45.0.0/16 (gw .0.1)              │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   PCRF (.0.9)                            │   │
│  │                 Diameter: 3868                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  PGW-C and PGW-U are `nextgcore-smfd`/`nextgcore-upfd` in their │
│  EPC roles (TS 23.401 4.2.1 combined SGW/PGW; TS 29.244 5.2.6). │
│  Dedicated instances, NOT the 5GC's smf/upf -- the two networks │
│  have no route between them and an S5-U F-TEID must carry an    │
│  address the SGW-U can reach. See specs/epc-pgw-container.md.   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Port Mappings

| Service | Protocol | Port | Description |
|---------|----------|------|-------------|
| NRF | HTTP/2 | 7777 | SBI interface |
| AMF | SCTP/UDP | 38412 | NGAP (N2). `docker-compose.yml` publishes 38412/**udp** (default userspace SCTP-over-UDP); real kernel SCTP (proto 132) only via the `kernel-sctp` overlay |
| AMF | HTTP/2 | 7777 | SBI interface |
| SMF | UDP | 8805 | PFCP (N4 to UPF) |
| SMF | HTTP/2 | 7777 | SBI interface |
| UPF | UDP | 2152 | GTP-U (N3 to gNB) |
| UPF | UDP | 8805 | PFCP (N4 to SMF) |
| MME | SCTP | 36412 | S1AP (to eNB). Kernel SCTP only: mmed is built with `--features kernel-sctp` and needs the host `sctp` module |
| PGW-C | UDP | 2123 | GTPv2-C (S5/S8-C, from SGW-C). TS 29.274 §4.1 fixes the port. On-network only — not published to the host, since nothing outside the `epc` bridge speaks S5/S8 |
| PGW-C | UDP | 8805 | PFCP (Sxb/N4 to PGW-U). On-network only |
| PGW-U | UDP | 2152 | GTP-U (S5/S8-U, to SGW-U). On-network only |
| PGW-U | UDP | 8805 | PFCP (Sxb/N4 to PGW-C). On-network only |
| HSS | TCP | 3868 | Diameter (S6a) |
| MongoDB | TCP | 27017 | Database |
| Prometheus | TCP | 9090 | Metrics |
| Grafana | TCP | 3000 | Dashboards, on 127.0.0.1 only. Login `admin` with the password you set as `GRAFANA_ADMIN_PASSWORD` |
| Jaeger | TCP | 16686 | Tracing UI |

## Validation

### One-command E2E (recommended)

```bash
# Disk preflight -> build -> full matched-sim E2E (reg + PDU session + ping).
# Exit 0 = all assertions green, 1 = test failure, 2 = infra/preflight refusal.
./e2e.sh

# Re-run without recompiling Rust / with an overlay / keeping the stack up
./e2e.sh --quick
./e2e.sh --overlay oauth2        # or: kernel-sctp, features
./e2e.sh --keep
```

### UE flows (the nightly 0.2.0 gate)

Against a running stack (e.g. after `./e2e.sh --keep`), `ue-flow-check.sh`
drives nextgsim's real gNB and UE through the flows the nightly CI gates:

```bash
./ue-flow-check.sh paging         # downlink data pages a CM-IDLE UE; Service Request; ping
./ue-flow-check.sh idle-uplink    # uplink from CM-IDLE; the triggering packet is not lost
./ue-flow-check.sh deregister     # UE-initiated de-registration, re-registration, ping
./ue-flow-check.sh network-rereg  # UDM REREGISTRATION_REQUIRED; prompt re-registration; ping
./ue-flow-check.sh all            # all of the above, with a second paging round
```

Each prints one `PASS: <scenario>` or `FAIL: <scenario> -- <why>` line and exits
non-zero on failure.

The preflight (`preflight.sh`) refuses to build with < 25 GB free disk and
trims the BuildKit cache (`docker builder prune --keep-storage=20GB`) — see
hazard #269 (Docker image-store wipe under disk pressure). On failure, per-NF
`docker logs` are captured under `artifacts/` before teardown. CI runner
requirements and artifact layout: [CI.md](CI.md).

### End-to-End Tests

```bash
# Full baseline E2E: build + deploy + UE registration → PDU session → GTP-U ping
./e2e-test.sh                 # add --no-build to reuse images, --keep to leave the stack up

# Rel-17/18 feature E2E (assumes a built stack is up, e.g. after ./e2e-test.sh --keep)
./feature-e2e-test.sh                       # all scenarios
./feature-e2e-test.sh redcap xr uav-allow   # selected scenarios
```

`feature-e2e-test.sh` drives each integrated Rel-17/18 feature with a dedicated UE/gNB
config (under `../../../nextgsim/config/features/`) via the `docker-compose.features.yml` overlay and
asserts the exact per-NF log signatures. Scenarios: `redcap`, `xr`, `uav-allow`,
`uav-deny`, `mint`, `snpn-accept`, `snpn-reject`. It recreates only the containers each
scenario needs and scopes log assertions per-scenario; pass `--down` to tear down after.

### Manual Validation

```bash
# Check container status
docker compose ps

# Check NRF health
curl http://localhost:7777/nnrf-nfm/v1/nf-instances

# Check MongoDB
docker exec nextgcore-mongodb mongosh --eval "db.adminCommand('ping')"

# Check UPF TUN interface
docker exec nextgcore-upf ip link show ogstun
```

## Troubleshooting

### Common Issues

#### Containers Not Starting

```bash
# Check logs
docker compose logs [service_name]

# Check resource usage
docker stats

# Verify images exist
docker images | grep nextgcore
```

#### NFs Not Registering with NRF

```bash
# Check NRF is accessible
curl -v http://localhost:7777/nnrf-nfm/v1/nf-instances

# Check NF logs for registration errors
docker logs nextgcore-amf 2>&1 | grep -i "register\|nrf"

# Verify network connectivity (compose names the network <project>_core)
docker network inspect rust_core
```

#### MongoDB Connection Issues

```bash
# Check MongoDB status
docker logs nextgcore-mongodb

# Test connection
docker exec nextgcore-mongodb mongosh --eval "db.adminCommand('ping')"

# Check database
docker exec nextgcore-mongodb mongosh nextgcore --eval "db.subscribers.count()"
```

#### UPF TUN Interface Issues

```bash
# Check TUN device
docker exec nextgcore-upf ip link show ogstun

# Check capabilities
docker inspect nextgcore-upf | grep -A5 "CapAdd"

# Check IP forwarding
docker exec nextgcore-upf sysctl net.ipv4.ip_forward
```

### Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f amf

# Last 100 lines
docker compose logs --tail=100 amf

# With timestamps
docker compose logs -t amf
```

### Cleanup

```bash
# Stop services
docker compose down

# Stop and remove volumes
docker compose down -v

# Remove all NextGCore images
docker images | grep nextgcore | awk '{print $3}' | xargs docker rmi

# Full cleanup
docker compose down -v --rmi all
```

## Advanced Usage

### CI

`.github/workflows/ci.yml` runs this directory's build and E2E nightly and on
demand: see [CI.md](CI.md) and [docs/ci-and-release.md](../../docs/ci-and-release.md).

### Production Deployment

For production deployments:

1. Enable TLS for SBI interfaces
2. Use external MongoDB with authentication
3. Configure proper network segmentation
4. Set up monitoring with Prometheus/Grafana
5. Configure log aggregation
6. Use secrets management for credentials

For SBI TLS, set `NEXTGCORE_SBI_PROFILE=production` and mount certificates
(amf/smf/ausf/udm), or start the other SBI NFs with `--tls --tls-cert --tls-key`.

### Kubernetes Deployment

- `k8s/` — Kind manifests with `deploy.sh`, `e2e-test.sh`, `teardown.sh`
- `deploy/helm/nextgcore/` — Helm chart for the 5GC control plane
- `deploy/eks/` — EKS deployment with the nextgsim gNB/UE

## License

NextGCore is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

## Support

- [GitHub Issues](https://github.com/NextgCoreLab/nextgcore/issues)
