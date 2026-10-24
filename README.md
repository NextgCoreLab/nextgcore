# NextGCore - Pure Rust 5G/LTE Core Network

NextGCore is a Rust implementation of a 5G/LTE mobile core network, derived from the Open5GS project. It provides a 5G Standalone (SA) core and a 4G EPC, validated end-to-end against the companion [nextgsim](https://github.com/NextgCoreLab/nextgsim) gNB/UE and eNB/UE simulators: 5G registration, PDU session, paging, Service Request and de-registration with user-plane pings, and LTE attach with a ping through the default bearer. It is a research/interop implementation, not a production-certified core.

## Key Features

- **Rust** - every NF is Rust. The default build still compiles one C library, `aws-lc-sys` (the rustls crypto provider), so a C compiler and `cmake` are needed; the optional kernel-SCTP backend also needs `libsctp`
- **Cross-Platform** - Build for Linux (x86_64, ARM64), macOS, and more
- **Two SCTP backends** - userspace SCTP over UDP (`sctp-proto`, the default, which nextgsim speaks) and native Linux kernel SCTP for a standard RAN (`--features kernel-sctp`; the AMF selects it with `--sctp-backend kernel`, and the MME's S1-MME is kernel SCTP only)
- **Generated ASN.1 codecs** - NGAP, S1AP, NRPPa, LPP, NR RRC and LTE RRC are compiled from the 3GPP ASN.1 by [NextgCoreLab/asn1-codegen](https://github.com/NextgCoreLab/asn1-codegen) (`src/libs/nextgcore-*-gen`); each crate's `asn/PROVENANCE.md` names the spec version
- **Async/Await** - Modern async runtime using Tokio
- **Container-Ready** - Docker Compose for 5GC and EPC, Kind manifests, a Helm chart, and an EKS deployment (`deploy/eks`)
- **28 network functions** - 23 5GC/Rel-17+ NFs and 5 EPC NFs (see [Network Functions](#network-functions))
- **Rel-17/18 features** - RedCap reduced-AMBR, XR delay-critical GBR 5QI (82-85), SNPN NID authorization, MINT/disaster-roaming multi-SUPI, and UAV geofence authorization wired end-to-end (see `docker/rust/README.md` → Rel-17/18 Feature Knobs / End-to-End Tests)

## New in 0.2.0

Since 0.1.0 (2026-07-02); see [CHANGELOG.md](CHANGELOG.md) for the full list.

- **Generated codecs.** NGAP, S1AP, NRPPa and LPP traffic in amfd, smfd, mbsmfd, mmed and lmfd is encoded and decoded by codecs generated from the 3GPP ASN.1, pinned to NextgCoreLab/asn1-codegen v0.1.0. The hand-written S1AP, NRPPa, LPP, E1AP, F1AP and XnAP codecs are deleted. The hand-written NGAP crates (`nextgcore-ngap` and the `nextgcore-asn1c` APER engine under it) are still in the tree; deleting them is tracked in #417.
- **A real LTE attach.** The EPC stage attaches nextgsim's LTE UE through its eNB to mmed, with SGW-C/SGW-U and a PGW-C/PGW-U (`smfd`/`upfd` in their EPC roles), and pings through the default bearer.
- **Paging and Service Request.** CM-IDLE UEs are paged on downlink data, and a Service Request from CM-IDLE or CM-CONNECTED re-activates the user plane.
- **EPS-5GS interworking over N26.** Idle-mode context transfer and connected-mode handover in both directions (Forward Relocation, Relocation Cancel, data-forwarding tunnels), with the AMF and the MME each as source and target. Off by default: set `AMF_N26_INTERWORKING` / `MME_N26_INTERWORKING`. The nightly E2E does not run a handover yet.
- **RACS.** A new NF, `nextgcore-ucmfd` (UCMF, TS 29.673/29.675), transcodes UE radio capabilities between TS 38.331 and TS 36.331; the AMF uses it over Nucmf.
- **Deployment.** `deploy/eks` selects what to deploy with `PROFILE=<name>` (`profiles/5g` ships; `epc` and `6g` profiles are being added), checks UE-to-internet traffic with `e2e-internet.sh`, and recovers from a pod restart without manual restarts of its peers.
- **CI.** A nightly cross-repo E2E gates the UE flows (paging, idle uplink, de-registration, UDM-triggered re-registration) and LTE attach, records the validated (nextgcore, nextgsim) commit pair, and `release.yml` releases only such a pair. Fuzz targets for NGAP, S1AP, NRPPa, LPP, NAS, GTP, PFCP and Diameter build on every PR (`src/fuzz`).

## Quickstart

### Option 1: Docker (Recommended)

The fastest way to deploy a complete 5G core:

```bash

# Clone the repo for 5G/LTE Core Network 
git clone https://github.com/NextgCoreLab/nextgcore.git

# Clone the repo for UE/gNB Simulator
git clone https://github.com/NextgCoreLab/nextgsim.git

# Go to directory containing Docker yamls and configurations for deploying the NextGCore Rust implementation.
cd nextgcore/docker/rust

# Build all images (compiles both workspaces in a builder container)
# This step will show a warning - "WARN[0000] No services to build" - which can be ignored. 
docker compose -f docker-compose.yml build

# Start the 5G core
docker compose -f docker-compose.yml up -d

# Verify all services are running
docker ps --filter "name=nextgcore-" --format "table {{.Names}}\t{{.Status}}"

# Check AMF logs
docker logs nextgcore-amf 2>&1 | tail -20
```

Expected output:
```
nextgcore-amf       Up 2 minutes (healthy)
nextgcore-smf       Up 2 minutes (healthy)
nextgcore-upf       Up 2 minutes (healthy)
...
```

### Option 2: Build from Source

```bash
# Prerequisites: the toolchain pinned in src/rust-toolchain.toml (Rust 1.95.0,
# installed by rustup automatically), a C compiler and cmake.
cd src
cargo build --release

# Every NF takes -c <config>. The configs under docker/rust/configs/ bind the
# compose network's 172.23.0.0/24 addresses; copy and edit them for a host run.
./target/release/nextgcore-nrfd -c ../docker/rust/configs/5gc/nrf.yaml &
./target/release/nextgcore-amfd -c ../docker/rust/configs/5gc/amf.yaml &
./target/release/nextgcore-smfd -c ../docker/rust/configs/5gc/smf.yaml &
./target/release/nextgcore-upfd -c ../docker/rust/configs/5gc/upf.yaml &
```

Run `<binary> --help` for an NF's flags.

### Option 3: Watch the nextgsim UE register

`docker/rust/docker-compose.yml` already runs nextgsim's gNB (`nextgsim-gnb`) and
UE (`nextgsim-ue`) next to the core, so after Option 1:

```bash
docker logs nextgsim-ue 2>&1 | grep "Registration Accept"
docker exec nextgsim-ue ping -c 3 -I uesimtun0 10.45.0.1
```

For the 4G EPC with nextgsim's LTE eNB and UE, use `docker-compose-epc.yml`
(see [docker/rust/README.md](docker/rust/README.md)).

## Network Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NextGCore 5G Core Network                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────── Control Plane ───────────────────────────┐    │
│  │                                                                     │    │
│  │   ┌─────┐    ┌──────┐    ┌─────┐    ┌─────┐    ┌──────┐             │    │
│  │   │ NRF │◄──►│ AUSF │◄──►│ UDM │◄──►│ UDR │◄──►│  DB  │             │    │
│  │   └──┬──┘    └──────┘    └─────┘    └─────┘    └──────┘             │    │
│  │      │                                                              │    │
│  │      │ SBI (HTTP/2)                                                 │    │
│  │      ▼                                                              │    │
│  │   ┌─────┐    ┌──────┐    ┌─────┐    ┌─────┐                         │    │
│  │   │ AMF │◄──►│ NSSF │◄──►│ PCF │◄──►│ BSF │                         │    │
│  │   └──┬──┘    └──────┘    └─────┘    └─────┘                         │    │
│  │      │                                                              │    │
│  └──────┼──────────────────────────────────────────────────────────────┘    │
│         │ NGAP (N2)                        │ N11                            │
│         ▼                                  ▼                                │
│   ┌──────────┐                      ┌──────────┐                            │
│   │   gNB    │                      │   SMF    │                            │
│   │ (RAN)    │                      └────┬─────┘                            │
│   └────┬─────┘                           │ N4 (PFCP)                        │
│        │                                 ▼                                  │
│        │ GTP-U (N3)              ┌──────────────┐                           │
│        └────────────────────────►│     UPF      │──────► Internet           │
│                                  │ (User Plane) │       (N6)                │
│                                  └──────────────┘                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Docker Deployment

### Container IP Addresses

| Service | IP Address | Ports |
|---------|------------|-------|
| MongoDB | 172.23.0.2 | 27017 |
| NRF | 172.23.0.10 | 7777 (SBI) |
| AUSF | 172.23.0.11 | 7777 (SBI) |
| UDM | 172.23.0.12 | 7777 (SBI) |
| PCF | 172.23.0.13 | 7777 (SBI), 9090 (metrics) |
| NSSF | 172.23.0.14 | 7777 (SBI) |
| BSF | 172.23.0.15 | 7777 (SBI) |
| UDR | 172.23.0.20 | 7777 (SBI) |
| **AMF** | **172.23.0.5** | **38412 (NGAP, SCTP over UDP)**, 7777 (SBI) |
| SMF | 172.23.0.4 | 8805 (PFCP), 7777 (SBI) |
| **UPF** | **172.23.0.7** | **2152 (GTP-U)**, 8805 (PFCP) |
| NWDAF, EES, LMF, MB-SMF, NSACF, PIN, DCCF, SCP, SEPP | 172.23.0.30-38 | SBI |
| UCMF | 172.23.0.39 | 7777 (SBI) |
| gNB / UE (nextgsim) | 172.23.0.100 / .101 | |
| Prometheus / Grafana / Jaeger | 172.23.0.200-202 | 9090 / 3000 / 16686 |

`docker/rust/configs/5gc/README.md` lists every NF's address.

### Docker Compose Files

| File | Description |
|------|-------------|
| `docker-compose.yml` | 20 5GC NFs + MongoDB + nextgsim gNB/UE + Prometheus/Grafana/Jaeger (recommended) |
| `docker-compose-epc.yml` | 4G EPC (MME, HSS, PCRF, SGW-C, SGW-U, PGW-C, PGW-U) + nextgsim LTE eNB/UE |
| `docker-compose.features.yml` | Rel-17/18 feature-knobs overlay |
| `docker-compose.oauth2.yml` | SBI OAuth2 token-enforcement overlay |
| `docker-compose.kernel-sctp.yml` | Native kernel-SCTP N2 overlay |

### Environment Variables

```bash
RUST_BACKTRACE=1        # Enable backtraces for debugging
RUST_LOG=info           # Log filter for every NF; overrides --log-level
                        # (every NF but smfd takes --log-level)
```

Per-NF environment variables are documented in the
[configuration reference](https://nextgcorelab.github.io/nextgcore/book/configuration/overview.html)
(`docs-book/src/configuration/`).

## Project Structure

```
nextgcore/
├── src/                # Cargo workspace root
│   ├── bins/           # 28 NF daemons (nextgcore-<nf>d) + nextgcore-webui
│   ├── libs/           # 23 shared library crates, 6 of them generated ASN.1 codecs (*-gen)
│   ├── tests/          # Mock-based flow tests (nextgcore-integration-tests)
│   ├── fuzz/           # cargo-fuzz targets (own workspace)
│   └── vendor/         # patched sctp-proto
├── docker/rust/        # Docker Compose stacks, configs, E2E scripts
├── k8s/                # Kind manifests and scripts
├── deploy/helm/        # Helm chart (5GC control plane)
├── deploy/eks/         # EKS deployment (PROFILE=<name>)
├── docs/               # GitHub Pages site, OpenAPI specs, design notes
├── docs-book/          # mdBook sources (built into docs/book/)
└── webui/              # Node.js subscriber-management WebUI
```

## Network Functions

### 5G Core (5GC)

| NF | Description | 3GPP Spec |
|----|-------------|-----------|
| **NRF** | Network Repository Function - Service discovery | TS 29.510 |
| **AUSF** | Authentication Server Function - UE authentication | TS 29.509 |
| **UDM** | Unified Data Management - Subscriber data | TS 29.503 |
| **UDR** | Unified Data Repository - Data storage | TS 29.504 |
| **PCF** | Policy Control Function - QoS policies | TS 29.507 |
| **NSSF** | Network Slice Selection Function | TS 29.531 |
| **BSF** | Binding Support Function - PCF binding | TS 29.521 |
| **AMF** | Access and Mobility Management Function | TS 29.518 |
| **SMF** | Session Management Function | TS 29.502 |
| **UPF** | User Plane Function - Data forwarding | TS 29.244 |
| **NSACF** | Network Slice Admission Control Function | TS 29.536 |
| **NWDAF** | Network Data Analytics Function | TS 29.520 |
| **LMF** | Location Management Function | TS 29.572 |
| **EES** | Edge Enabler Server | TS 29.558 |
| **MBSMF** | MBS Session Management Function | TS 29.532 |
| **PIN** | Personal IoT Network server | TS 23.542 |
| **DCCF** | Data Collection Coordination Function | TS 23.288 |
| **NEF** | Network Exposure Function | TS 29.522, TS 29.122 |
| **EASDF** | Edge Application Server Discovery Function | TS 23.548 |
| **TSCTSF** | Time Sensitive Communication and Time Synchronization Function | TS 23.501 §5.27-5.28 |
| **UCMF** | UE radio Capability Management Function (RACS) | TS 29.673, TS 29.675 |

### Evolved Packet Core (EPC)

| NF | Description |
|----|-------------|
| **HSS** | Home Subscriber Server |
| **PCRF** | Policy and Charging Rules Function |
| **MME** | Mobility Management Entity |
| **SGW-C** | Serving Gateway Control Plane |
| **SGW-U** | Serving Gateway User Plane |

The PGW-C and PGW-U are `nextgcore-smfd` and `nextgcore-upfd` in their EPC
roles (`docker/rust/configs/epc/pgwc.yaml`, `pgwu.yaml`).

### Optional Components

| NF | Description |
|----|-------------|
| **SCP** | Service Communication Proxy |
| **SEPP** | Security Edge Protection Proxy |

## Configuration

### AMF Configuration

Excerpt of `docker/rust/configs/5gc/amf.yaml`:

```yaml
amf:
  sbi:
    server:
      - address: 172.23.0.5
        port: 7777
    client:
      nrf:
        - uri: http://172.23.0.10:7777
  ngap:
    server:
      - address: 172.23.0.5
        port: 38412
  guami:
    - plmn_id:
        mcc: 999
        mnc: 70
      amf_id:
        region: 2
        set: 1
  tai:
    - plmn_id:
        mcc: 999
        mnc: 70
      tac: 1
  plmn_support:
    - plmn_id:
        mcc: 999
        mnc: 70
      s_nssai:
        - sst: 1
```

### UPF Configuration

Excerpt of `docker/rust/configs/5gc/upf.yaml`:

```yaml
upf:
  pfcp:
    server:
      - address: 172.23.0.7
        port: 8805
  gtpu:
    server:
      - address: 172.23.0.7
        port: 2152
  session:
    - subnet: 10.45.0.0/16
      gateway: 10.45.0.1
      dev: ogstun
```

Every NF's keys, flags and environment variables are in the
[configuration reference](docs-book/src/configuration/overview.md).

## Testing

### Unit Tests

```bash
cd src
cargo test
```

### End-to-End (matched-sim)

The one-command matched-sim E2E runs our nextgsim gNB+UE against our 5G core
(no Open5GS): disk preflight -> build -> full registration + PDU session
+ user-plane ping through the GTP-U tunnel (UE gets 10.45.0.2 on `uesimtun0`).
See `docker/rust/CI.md`.

```bash
cd docker/rust
./e2e.sh            # preflight -> build -> E2E  (exit 0/1/2)
./e2e.sh --quick    # reuse prebuilt binaries (fast re-run)
./e2e.sh --overlay features   # baseline + Rel-17/18 feature harness
./ue-flow-check.sh all        # paging, idle uplink, de-registration, UDM re-registration
                              # (against a running stack, e.g. after ./e2e.sh --keep)
```

The nightly CI runs the same flows, plus the OAuth2 overlay and the EPC LTE
attach (`epc-attach-check.sh`); see [docs/ci-and-release.md](docs/ci-and-release.md).

### Protocol Conformance

The generated codecs are compiled from these ASN.1 versions (from each crate's
`asn/PROVENANCE.md`):

| Protocol | Spec | Version |
|---|---|---|
| NGAP | TS 38.413 | V17.9.0 |
| S1AP | TS 36.413 | V19.2.0 |
| NRPPa | TS 38.455 | V19.2.0 |
| LPP | TS 37.355 | V19.3.0 |
| NR RRC | TS 38.331 | V19.3.0 |
| LTE RRC | TS 36.331 | V19.4.0 |

The hand-written protocols cite their specs in doc comments: NAS (TS 24.501 /
TS 24.301), SBI (TS 29.500 series), PFCP (TS 29.244), GTP (TS 29.274 / TS 29.281),
Diameter (RFC 6733, TS 29.272 / 29.212).

## Development

### Building

```bash
cd src

# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Build specific NF
cargo build --release -p nextgcore-amfd
```

### Cross-Compilation

```bash
# Add target
rustup target add aarch64-unknown-linux-gnu

# Build for ARM64 Linux
cargo build --release --target aarch64-unknown-linux-gnu
```

### Code Quality

```bash
# Format code
cargo fmt

# Run lints (CI also checks every feature: --all-features --all-targets)
cargo clippy --workspace --all-targets

# Check for security vulnerabilities
cargo audit
```

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — release notes and version history
- [docs/ci-and-release.md](docs/ci-and-release.md) — CI pipeline (GitHub Actions jobs) and the release process
- [docs/sba-transport-evaluation.md](docs/sba-transport-evaluation.md) — HTTP/2 vs HTTP/3 SBI transport benchmark and evaluation (non-normative 6G research)
- [docs/isac-sensing-pipeline.md](docs/isac-sensing-pipeline.md) — ISAC sensing data pipeline design note (non-normative 6G research)
- [docs/intent-driven-policy-loop.md](docs/intent-driven-policy-loop.md) — intent-driven closed-loop policy design note (non-normative 6G research)
- [docs/network-state-snapshot.md](docs/network-state-snapshot.md) — aggregate network-state snapshot / digital-twin export design note (non-normative 6G research)
- [docs/nwdaf-inference.md](docs/nwdaf-inference.md) — NWDAF analytics inference abstraction and ONNX-subset backend design note (non-normative 6G research)
- [docs/slice-sla-observe.md](docs/slice-sla-observe.md) — observe-only slice-SLA assurance loop design note (non-normative research)
- [docker/rust/CI.md](docker/rust/CI.md) — the one-command matched-sim end-to-end suite (`e2e.sh`)
- [docs-book/](docs-book/src/SUMMARY.md) — the mdBook: getting started, per-NF configuration reference, call flows ([published](https://nextgcorelab.github.io/nextgcore/book/))
- [deploy/eks/README.md](deploy/eks/README.md) — EKS deployment; [deploy/helm/nextgcore/README.md](deploy/helm/nextgcore/README.md) — Helm chart
- [src/fuzz/README.md](src/fuzz/README.md) — fuzz targets
- [docs/](docs/) — per-component gap analyses and architecture notes

## Contributing

We welcome contributions! Here's how to get started:

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/NextgCoreLab/nextgcore.git
cd nextgcore

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build and test
cd src
cargo build
cargo test
```

### Contribution Guidelines

1. **Fork the repository** and create a feature branch
2. **Follow Rust conventions**: Use `cargo fmt` and `cargo clippy`
3. **Write tests**: All new features should include tests
4. **Update documentation**: Keep README and doc comments current
5. **Sign commits**: Use `git commit -s` for DCO sign-off

### Pull Request Process

1. Ensure all tests pass: `cargo test --workspace`
2. Run lints: `cargo clippy --workspace --all-targets`
3. Format code: `cargo fmt --all`
4. Update CHANGELOG.md if applicable
5. Submit PR with clear description of changes

### Areas for Contribution

- **Network Functions**: Enhance existing NF implementations
- **Protocol Support**: Add missing 3GPP procedures
- **Performance**: Profiling and optimization
- **Testing**: More unit and integration tests
- **Documentation**: Tutorials, architecture docs
- **Cross-Platform**: Test on different architectures

### Reporting Issues

Use GitHub Issues for:
- Bug reports (include logs and reproduction steps)
- Feature requests
- Documentation improvements

## WebUI

Two subscriber-management front ends ship, and neither has a default account
(TS 33.117 §4.2.3.4.2.2; issue #118):

- **Node.js WebUI** (`webui/`, port 9999 by default, `PORT` to change). Create
  the first admin with `node server/bin/create-admin.js <username>`; the password
  is read from the terminal or `WEBUI_ADMIN_PASSWORD`, at least 12 characters.
  It needs a `SECRET_KEY` of at least 32 characters (no fallback) and listens
  on `127.0.0.1` unless `WEBUI_BIND_ADDR` says otherwise; the container's
  `HOSTNAME` is never used. The `docker/webui` image therefore needs
  `-e WEBUI_BIND_ADDR=0.0.0.0` to be reachable through its published port.
  Set it only when the container sits on a private network, and publish to
  loopback (`-p 127.0.0.1:9999:9999`) with an SSH tunnel for remote access,
  never on all interfaces.
- **`nextgcore-webui`** (Rust, `src/bins/nextgcore-webui`). Listens on
  `127.0.0.1:3000` by default (`--listen`, `--port`) and requires an API token
  (`--api-token-file` or `NEXTGCORE_WEBUI_API_TOKEN`); `--tls-cert`/`--tls-key`
  for HTTPS, `--insecure-dev` only for local development.

Both read and write the `nextgcore` MongoDB database the UDR uses.

## Key Dependencies

- **tokio** - Async runtime
- **hyper** / **h2** - HTTP/2 for SBI
- **rustls** - TLS for SBI
- **serde** / **serde_yaml** - Configuration parsing
- **log** / **env_logger** - Logging
- **sctp-proto** - Userspace SCTP (patched copy in `src/vendor/sctp-proto`)
- **asn1-codecs** / **asn1-compiler** - generated ASN.1 codecs ([NextgCoreLab/asn1-codegen](https://github.com/NextgCoreLab/asn1-codegen))
- **mongodb** - Subscriber database

## References

### 3GPP Specifications

- [TS 23.501](https://www.3gpp.org/DynaReport/23501.htm) - System Architecture
- [TS 23.502](https://www.3gpp.org/DynaReport/23502.htm) - Procedures
- [TS 29.500](https://www.3gpp.org/DynaReport/29500.htm) - SBI Framework
- [TS 38.413](https://www.3gpp.org/DynaReport/38413.htm) - NGAP
- [TS 29.244](https://www.3gpp.org/DynaReport/29244.htm) - PFCP

### Related Projects

- [Open5GS](https://open5gs.org/) - Original C implementation
- [nextgsim](https://github.com/NextgCoreLab/nextgsim) - Companion UE/gNB and LTE UE/eNB simulator

## Troubleshooting

### Common Issues

**AMF not accepting gNB connections**
```bash
# Check AMF is listening on NGAP port
docker logs nextgcore-amf | grep "NGAP server listening"
# Should show: "NGAP server listening on 172.23.0.5:38412 (...)" with the SCTP backend in brackets
```

**UPF not forwarding traffic**
```bash
# Verify UPF has TUN interface
docker exec nextgcore-upf ip addr show
# Verify IP forwarding
docker exec nextgcore-upf sysctl net.ipv4.ip_forward
```

**MongoDB connection issues**
```bash
# Check MongoDB health
docker logs nextgcore-mongodb
# Verify connectivity
docker exec nextgcore-amf ping -c 1 172.23.0.2
```

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details.
