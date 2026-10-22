# Contributing to NextGCore

NextGCore is a research-faithful 5G Core and 4G EPC implementation in Rust: a Rel-15 baseline with selected Rel-16/17/18 features (RACS, MBS, NSACF, LMF positioning, RedCap, XR QoS, SNPN, MINT, UAV). 6G/Rel-20 items (ISAC, FL, PQC, semantic, agent-native) are non-normative prototypes — no frozen Rel-20 3GPP specs exist.

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

The Docker builder image (`docker/rust/Dockerfile.builder`) installs a superset
(`protobuf-compiler`, `clang`, `libssl-dev`, ...) because it also builds nextgsim.

The generated codec crates (`nextgcore-*-gen`) are memory-hungry to compile: the
NR RRC codec alone peaks at about 9.4 GB of rustc RSS with debuginfo, so give
`cargo test --workspace` 16 GB or more, or set `CARGO_PROFILE_TEST_DEBUG=0`
as CI does.

## Building

The workspace root is `nextgcore/src/` (not `nextgcore/`):

```bash
cd nextgcore/src
cargo build --workspace            # debug
cargo build --workspace --release  # release
```

To build a single NF binary:

```bash
cargo build -p nextgcore-amfd
```

## Testing

```bash
cd nextgcore/src
cargo test --workspace                          # all tests
cargo test -p nextgcore-amfd                    # single NF
cargo test --workspace -- --nocapture           # with log output
```

`src/tests` (`nextgcore-integration-tests`) runs flow tests against mock NFs.
The end-to-end tests against the real binaries need Docker:

```bash
cd nextgcore/docker/rust
./e2e.sh                     # preflight -> build -> registration, PDU session, ping
./e2e.sh --keep && ./ue-flow-check.sh all   # paging, idle uplink, de/re-registration
```

Multi-UE stress test:

```bash
bash test-multi-ue.sh               # 5 UEs (default)
bash test-multi-ue.sh --ue-count 10 # 10 UEs
```

## Code Style

All code must pass `cargo fmt` and `cargo clippy`:

```bash
cd nextgcore/src
cargo fmt --all
cargo clippy --workspace --all-targets
cargo check --workspace --all-features --all-targets
```

CI fails on clippy **errors**; warnings are reported but do not fail the job.
Do not add new warnings to the code you touch.

Pre-commit checklist:
- [ ] `cargo fmt --all -- --check` — no formatting changes
- [ ] `cargo clippy --workspace --all-targets` — no errors, no new warnings
- [ ] `cargo check --workspace --all-features --all-targets` — every feature compiles
- [ ] `cargo test --workspace` — all tests pass
- [ ] `cd fuzz && cargo clippy --locked --bins -- -D warnings` — if you touched a decoder the fuzz targets call
- [ ] `cargo audit` — no unpatched advisories

Tests that touch process-global state (an NF context, an environment
variable) must take the lock declared beside that global, so the default
parallel `cargo test` cannot race them.

## Security Auditing

```bash
cargo install cargo-audit
cd nextgcore/src
cargo audit
```

## Project Layout

```
nextgcore/
├── src/                     # Workspace root
│   ├── bins/                # 28 NF binaries + webui
│   │   ├── nextgcore-amfd/  # AMF
│   │   ├── nextgcore-smfd/  # SMF (also the EPC PGW-C)
│   │   ├── nextgcore-upfd/  # UPF (also the EPC PGW-U)
│   │   └── ...
│   ├── libs/                # 23 shared libraries
│   │   ├── nextgcore-core/        # Core types, state store
│   │   ├── nextgcore-sbi/         # HTTP/2 SBI client + server, OAuth2, TLS
│   │   ├── nextgcore-crypt/       # 5G cryptography (SUCI, AKA, PQC)
│   │   ├── nextgcore-metrics/     # Prometheus + OpenTelemetry
│   │   ├── nextgcore-*-gen/       # NGAP, S1AP, NRPPa, LPP, NR RRC, LTE RRC codecs generated from the 3GPP ASN.1
│   │   └── ...
│   ├── tests/               # Mock-based flow tests
│   ├── fuzz/                # cargo-fuzz targets (own workspace)
│   └── vendor/sctp-proto/   # patched sctp-proto
├── k8s/                     # Kind manifests
├── deploy/                  # Helm chart, EKS deployment
├── docker/rust/             # Docker Compose E2E stacks
├── docs/                    # Pages site, OpenAPI specs, design notes
└── docs-book/               # mdBook sources
```

## 3GPP Specification References

Each file includes a doc comment referencing the 3GPP TS number and section (e.g. `//! TS 23.501 §5.15`). When adding new protocol logic, always cite the relevant spec:

- **TS 23.501** — 5G system architecture
- **TS 23.502** — 5G procedures
- **TS 29.xxx** — SBI service definitions
- **TS 38.331** — NR RRC
- **TS 38.413** — NGAP; **TS 36.413** — S1AP
- **TS 24.501 / TS 24.301** — 5GS / EPS NAS

Generated codecs are rebuilt from the ASN.1 in each `nextgcore-*-gen/asn/`;
the version and source are recorded in that directory's `PROVENANCE.md`. Do not
hand-edit generated code; change the schema or the compiler
([NextgCoreLab/asn1-codegen](https://github.com/NextgCoreLab/asn1-codegen),
pinned by rev in `src/Cargo.toml`).

## Commit Messages

Follow conventional commits:

```
feat(smf): add MBS multicast session context (TS 23.247)
fix(amf): release SMF session on UE context release
test(upf): add SDF filter 5-tuple matching unit tests
```

- **Never** include `Co-Authored-By: Claude` or any AI attribution
- Sign commits: `Signed-off-by: Your Name <email>`

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Implement your change with tests
4. Ensure all CI checks pass
5. Open a PR with a description referencing the 3GPP TS item

## NF Implementation Standards

Each NF binary must:
- Register with NRF on startup (via `nextgcore-sbi` NF management), and
  deregister on shutdown
- Expose `/metrics` (Prometheus, port 9090)
- Respond to SIGTERM with graceful shutdown
- Log at `info` level by default, configurable via `--log-level` and `RUST_LOG`
  (13 NFs honour `RUST_LOG` today; #691 tracks the rest)
- Have ≥ 1 unit test per public function

## License

AGPL-3.0. See [LICENSE](https://github.com/NextgCoreLab/nextgcore/blob/main/LICENSE).
