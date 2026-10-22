# NextGCore Rust Integration Tests

This crate (`nextgcore-integration-tests`, one `[[test]]` target named
`integration`) holds flow-level tests that run against **mock network
functions** (`integration/common/nf_mock.rs`, `MockEnvironment`), not against
the real NF binaries. They check message sequencing and state bookkeeping for
each flow. Tests that drive the real daemons over the wire are the Docker E2E
stages in `docker/rust/` (see `docker/rust/CI.md` and `docs/ci-and-release.md`).

## Test Categories (`integration/`)

| Module | Covers |
|---|---|
| `registration/` | 5G registration through the AMF, 4G attach through the MME |
| `session/` | PDU session establishment (SMF/UPF), EPS bearer activation (MME/SGW-C/SGW-U) |
| `inter_nf/` | SBI between 5G NFs, Diameter between EPC NFs, GTP-C/GTP-U |
| `pfcp/` | N4 association and session establishment/modification/deletion |
| `handover/` | X2/S1, Xn/N2 and inter-RAT handover sequences, failure and recovery |
| `slicing/` | S-NSSAI selection at registration, per-slice sessions and QoS |
| `volte/` | IMS registration, MO/MT call setup, QCI 1/5 dedicated bearers |
| `property/` | proptest strategies over the mocked message sequences |

## Prerequisites

None for the flow tests above. `integration/common/mongodb.rs` has a
`testcontainers` MongoDB helper; its own self-test is skipped when `docker info`
fails.

## Running Tests

```bash
cd src
cargo test -p nextgcore-integration-tests                      # everything in this crate
cargo test -p nextgcore-integration-tests --test integration registration
cargo test -p nextgcore-integration-tests --test integration -- --nocapture
```

## Writing New Tests

1. Add test functions to the matching module.
2. Use `MockEnvironment` / `TestContext` for NF set-up and `TestSubscriber` for
   subscriber provisioning.
3. Assert on captured messages (`MessageCapture`) rather than on log output.
