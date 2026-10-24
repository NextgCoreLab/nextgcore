# Getting Started

NextGCore is a 5G Core Network implemented in Rust, with a 3GPP Rel-15 baseline and selected Rel-16/17/18 features (RACS, MBS, NSACF, LMF positioning, RedCap, XR QoS, SNPN, MINT, UAV Service-level-AA per TS 23.256), plus a 4G EPC and EPS-5GS interworking over N26. 6G/Rel-20 items (ISAC, FL, PQC, semantic comms) are **non-normative research prototypes** — no frozen Rel-20 Stage-3 specs exist. End-to-end validation runs against the project's own matched RAN simulators (nextgsim gNB/UE and LTE eNB/UE); it is **not third-party certified**.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.95.0, pinned by `src/rust-toolchain.toml` (rustup installs it) | Build toolchain |
| C/C++ compiler, cmake | any recent | `aws-lc-sys`, the C crypto library under rustls |
| libsctp-dev | any | only for `--features kernel-sctp` (amfd, mmed) |
| Docker + Compose v2 | Engine ≥ 24, Compose ≥ 2.20 | E2E testing |

```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential cmake pkg-config
sudo apt-get install -y libsctp-dev        # kernel-SCTP builds only

# macOS (Homebrew)
brew install cmake
```

The generated codec crates need a lot of compiler memory (about 9.4 GB of rustc RSS for
the NR RRC codec with debuginfo), so give a full `cargo test --workspace` 16 GB or more.

## Build from Source

The Cargo workspace root is **`nextgcore/src/`**, not the repository root:

```bash
git clone https://github.com/NextgCoreLab/nextgcore.git
cd nextgcore/src

cargo build --workspace --release   # all 28 NF binaries + webui
ls target/release/nextgcore-*

cargo build -p nextgcore-amfd       # or build a single NF
```

Run the test suite from the same directory:

```bash
cargo test --workspace                 # all tests
cargo test -p nextgcore-amfd           # single NF
cargo test --workspace -- --nocapture  # with log output
```

## Docker Compose

The Docker E2E stack lives in `docker/rust/`:

```bash
cd nextgcore/docker/rust
docker compose up -d      # 5GC + matched RAN simulator + observability
docker compose ps         # expect 26 containers
bash e2e-test.sh          # run the E2E suite
```

Overlay compose files extend the baseline stack:

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Baseline 5GC + simulator |
| `docker-compose.oauth2.yml` | OAuth2 enforcement on SBI |
| `docker-compose.kernel-sctp.yml` | Native kernel-SCTP N2 transport |
| `docker-compose.features.yml` | Rel-17/18 feature harness |
| `docker-compose-epc.yml` | 4G/EPC stack with nextgsim's LTE eNB and UE (separate stack, not an overlay) |

## One-Command E2E

`e2e.sh` chains disk preflight → image build → matched-sim E2E run (the project's own gNB/UE against its own 5GC) → artifact capture on failure, with a clean exit code for CI:

```bash
cd nextgcore/docker/rust
bash e2e.sh                        # preflight + full build + baseline E2E
bash e2e.sh --quick                # reuse existing binaries
bash e2e.sh --overlay oauth2       # OAuth2 enforcement overlay
bash e2e.sh --overlay kernel-sctp  # native kernel SCTP N2
bash e2e.sh --overlay features     # baseline + Rel-17/18 feature harness
bash e2e.sh --keep                 # leave the stack running afterwards
bash e2e.sh --no-build             # images already built
bash e2e.sh --artifacts DIR        # failure-artifact directory (default: artifacts/)
```

Exit codes: `0` all passed, `1` test assertion failure, `2` infrastructure failure (preflight refusal, build, startup). On failure, logs of every `nextgcore-*`/`nextgsim-*` container are saved to the artifacts directory before teardown.

`e2e-test.sh` runs the suite directly against an existing stack and accepts `--no-build`, `--keep`, `--no-preflight`, and `--overlay NAME`. Typical iteration loop:

```bash
bash e2e-test.sh --no-build --keep   # skip rebuild, keep containers for debugging
```

The 0.2.0 UE flows the nightly CI gates run against a stack left up with `--keep`:

```bash
bash ue-flow-check.sh all          # paging, idle uplink, de-registration, UDM re-registration
```

For the EPC, after `docker compose -f docker-compose-epc.yml up -d`:

```bash
bash epc-attach-check.sh 10.45.0.1 20   # S1 Setup, LTE attach, 20 pings through the default bearer
```

A multi-UE stress test is also available:

```bash
bash test-multi-ue.sh                # 5 UEs (default)
bash test-multi-ue.sh --ue-count 10
```

## Kubernetes

Kind manifests, scripts and a kind config live in `k8s/`; the Helm chart is in
`deploy/helm/nextgcore/` and the EKS deployment in `deploy/eks/` (see their READMEs):

```bash
cd nextgcore/k8s
bash deploy.sh                     # deploy the stack
kubectl get pods -n nextg-system   # verify pods are running
bash e2e-test.sh                   # run the E2E suite against the cluster

kubectl port-forward -n nextg-system svc/jaeger 16686:16686   # traces
```

Every NF exposes Prometheus metrics on port 9090 (`/metrics`); monitoring assets are under `k8s/monitoring/` and `docker/rust/monitoring/`. `teardown.sh` removes the deployment.

## Where Configs Live

Per-NF YAML configs for the Docker stack are under `docker/rust/configs/`:

```
docker/rust/configs/
├── 5gc/            # per-NF YAML (amf.yaml, smf.yaml, upf.yaml, ...)
├── epc/            # 4G/EPC NF configs
├── observability/  # Prometheus / tracing configs
├── scp.yaml, sepp1.yaml, sepp2.yaml
└── tls/            # SBI TLS material (see also docker/rust/certs/)
```

Kubernetes configuration lives in `k8s/base/` and `k8s/manifests/`. NFs log at `info` by default, tunable via `--log-level` or `RUST_LOG`, which overrides it (see the [configuration overview](configuration/overview.md)).

## Next Steps

- Read the [Contributing guide](contributing.md) for the style gate (`cargo fmt --all`, `cargo clippy --workspace --all-targets`, `cargo check --all-features`, `cargo audit`) and the PR process.
- Protocol code cites its 3GPP spec in doc comments (e.g. `//! TS 23.501 §5.15`); key references are TS 23.501/23.502 (architecture/procedures), TS 29.xxx (SBI), TS 38.331 (NR RRC), and TS 38.413 (NGAP).
- Remember the validation caveat: green E2E means the suite passes against the matched simulator — it is not a conformance certification.
