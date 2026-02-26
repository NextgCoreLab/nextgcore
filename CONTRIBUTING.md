# Contributing to NextGCore

NextGCore is a 5G Core Network implementation in Rust targeting 3GPP Rel-15 through Rel-20 (6G research).

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | stable (≥1.75) | Build toolchain |
| protobuf-compiler | ≥3.21 | Protobuf codegen |
| clang / libclang-dev | any | LLVM bindings |
| libssl-dev | any | TLS support |
| cmake | ≥3.16 | FFI build scripts |
| Docker + docker-compose | ≥24 | E2E testing |

```bash
# Ubuntu/Debian
sudo apt-get install -y pkg-config libssl-dev cmake protobuf-compiler clang

# macOS (Homebrew)
brew install protobuf cmake openssl
```

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

Integration / E2E tests require Docker:

```bash
cd nextgcore/docker/rust
docker compose up -d
bash e2e-test.sh
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
cargo clippy --workspace -- -D warnings
```

Pre-commit checklist:
- [ ] `cargo fmt --all` — no formatting changes
- [ ] `cargo clippy --workspace -- -D warnings` — zero warnings
- [ ] `cargo test --workspace` — all tests pass
- [ ] `cargo audit` — no unpatched advisories

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
│   ├── bins/                # 22 NF binaries
│   │   ├── nextgcore-amfd/  # AMF
│   │   ├── nextgcore-smfd/  # SMF
│   │   ├── nextgcore-upfd/  # UPF
│   │   └── ...              # (all 22 NFs)
│   ├── libs/                # Shared libraries
│   │   ├── ogs-core/        # Core types
│   │   ├── ogs-sbi/         # HTTP/2 SBI client + server
│   │   ├── ogs-crypt/       # 5G cryptography (SUCI, AKA, PQC)
│   │   ├── ogs-metrics/     # Prometheus + OpenTelemetry
│   │   └── ...
│   └── tests/               # Integration tests
├── k8s/                     # Kubernetes manifests + Helm
├── docker/rust/             # Docker Compose E2E stack
└── docs/                    # OpenAPI specs, architecture docs
```

## 3GPP Specification References

Each file includes a doc comment referencing the 3GPP TS number and section (e.g. `//! TS 23.501 §5.15`). When adding new protocol logic, always cite the relevant spec:

- **TS 23.501** — 5G system architecture
- **TS 23.502** — 5G procedures
- **TS 29.xxx** — SBI service definitions
- **TS 38.331** — NR RRC
- **TS 38.413** — NGAP

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
2. Create a feature branch from `initial_commit`
3. Implement your change with tests
4. Ensure all CI checks pass
5. Open a PR with a description referencing the 3GPP TS item

## NF Implementation Standards

Each NF binary must:
- Register with NRF on startup (via `ogs-sbi` NF management)
- Expose `/metrics` (Prometheus, port 9090)
- Respond to SIGTERM with graceful shutdown
- Log at `info` level by default, configurable via `RUST_LOG`
- Have ≥ 1 unit test per public function

## License

Apache-2.0. See [LICENSE](LICENSE).
