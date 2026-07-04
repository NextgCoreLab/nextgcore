# Getting Started

NextGCore is a 5G Core Network implemented in Rust, targeting 3GPP Rel-15 with selected Rel-17/18 features (MBS, NSACF, LMF positioning, RedCap, XR QoS, SNPN, MINT, UAV Service-level-AA per TS 23.256), plus 4G/EPC interworking. 6G/Rel-20 items (ISAC, FL, PQC, semantic comms) are **non-normative research prototypes** — no frozen Rel-20 Stage-3 specs exist. End-to-end validation runs against the project's own matched RAN simulator (nextgsim gNB/UE); it is **not third-party certified**.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | stable (≥ 1.75) | Build toolchain |
| protobuf-compiler | ≥ 3.21 | Protobuf codegen |
| clang / libclang-dev | any | LLVM bindings |
| libssl-dev | any | TLS support |
| cmake | ≥ 3.16 | FFI build scripts |
| Docker + docker-compose | ≥ 24 | E2E testing |

```bash
# Ubuntu/Debian
sudo apt-get install -y pkg-config libssl-dev cmake protobuf-compiler clang

# macOS (Homebrew)
brew install protobuf cmake openssl
```

## Build from Source

The Cargo workspace root is **`nextgcore/src/`**, not the repository root:

```bash
git clone https://github.com/NextgCoreLab/nextgcore.git
cd nextgcore/src

cargo build --workspace --release   # all 24 NF binaries + webui
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
docker compose ps         # expect 25 containers
bash e2e-test.sh          # run the E2E suite
```

Overlay compose files extend the baseline stack:

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Baseline 5GC + simulator |
| `docker-compose.oauth2.yml` | OAuth2 enforcement on SBI |
| `docker-compose.kernel-sctp.yml` | Native kernel-SCTP N2 transport |
| `docker-compose.features.yml` | Rel-17/18 feature harness |
| `docker-compose-epc.yml` | 4G/EPC stack |

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

A multi-UE stress test is also available:

```bash
bash test-multi-ue.sh                # 5 UEs (default)
bash test-multi-ue.sh --ue-count 10
```

## Kubernetes

Kubernetes manifests, Helm assets, and a kind config live in `k8s/`:

```bash
cd nextgcore/k8s
bash deploy.sh                     # deploy the stack
kubectl get pods -n nextgcore      # verify pods are running
bash e2e-test.sh                   # run the E2E suite against the cluster

kubectl port-forward svc/jaeger 16686:16686   # traces
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

Kubernetes configuration lives in `k8s/base/` and `k8s/manifests/`. NFs log at `info` by default, tunable via `RUST_LOG`.

## Next Steps

- Read `CONTRIBUTING.md` for the style gate (`cargo fmt --all`, `cargo clippy --workspace -- -D warnings`, `cargo audit`) and the PR process.
- Protocol code cites its 3GPP spec in doc comments (e.g. `//! TS 23.501 §5.15`); key references are TS 23.501/23.502 (architecture/procedures), TS 29.xxx (SBI), TS 38.331 (NR RRC), and TS 38.413 (NGAP).
- Remember the validation caveat: green E2E means the suite passes against the matched simulator — it is not a conformance certification.
