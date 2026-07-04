# MME Configuration

The MME (Mobility Management Entity, `nextgcore-mmed`) is the 4G/EPS control-plane anchor of the dual 5G+4G core, ported from the C reference `src/mme/`. Its crate implements the protocol logic for five EPC interfaces: S1AP toward eNBs (APER-encoded via the `nextgcore-s1ap` codec per TS 36.413, as cited in `s1ap_build.rs`), NAS EMM/ESM toward UEs (cause codes and bitrate/APN-AMBR encodings per TS 24.301, per code comments) with NAS integrity/ciphering EIA0–EIA3/EEA0–EEA3 (`nas_security.rs`), S11 GTPv2-C toward the SGW-C (`s11_build.rs`/`s11_handler.rs`), S6a Diameter toward the HSS (Application ID 16777251; AIR/ULR/CLR/IDR/PUR grouped-AVP wire format per TS 29.272 §7.3.x, per code comments in `fd_path.rs`), plus SGsAP toward the MSC/VLR (`sgsap_build.rs`) and SBc-AP warning-message handling (TS 29.168 / TS 23.041, as cited in `sbc_message.rs`).

Configuration is nominally split between a YAML file (default path `/etc/nextgcore/mme.yaml`, overridable with `-c/--config`) and command-line flags — but unlike most NextGCore NFs, **this daemon currently parses no YAML at all**. The crate contains no `#[derive(Deserialize)]` config structs and no file reads; `MmeApp::init` in `src/bins/nextgcore-mmed/src/main.rs` receives the config path as `_config_path` and ignores it. All runtime knobs that exist come from the four CLI flags, one environment variable, and hardcoded defaults in `context.rs`.

> **Honesty note:** `nextgcore-mmed` is a protocol-logic port, not yet a wired daemon. The message builders, decoders, state machines (`MmeFsm`/`EmmFsm`/`EsmFsm`/`S1apFsm`/`SgsapFsm`), and NAS security functions are real and unit-tested — including proptest state-machine property tests and a 128-EIA2 check against TS 33.401 Annex C.2 Test Set 2, per code comments — but the binary's main loop only sleeps in 100 ms ticks (the code comment reads "In a real implementation, this would: 1. Poll for S1AP messages from eNBs…"). No SCTP/UDP socket is bound anywhere in the crate: `gtp_open` just sets a flag, and the S6a Diameter client is created in deferred-connect mode and never connected from `main`. The MME is **not** exercised by the 84/84 docker E2E suite (that suite covers the 5GC); validation is in-crate unit and property tests only, not third-party certification.

## Example configuration

From `nextgcore/docker/rust/configs/epc/mme.yaml` (mounted by `docker-compose-epc.yml`, which runs the daemon as `-c /etc/nextgcore/mme.yaml` at `172.24.0.5` and publishes `36412/sctp`):

```yaml
# NextGCore MME Configuration for Docker EPC Deployment
# Rust implementation

logger:
  file:
    path: /var/log/nextgcore/mme.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

mme:
  freeDiameter: /etc/freeDiameter/mme.conf
  s1ap:
    server:
      - address: 172.24.0.5
  gtpc:
    server:
      - address: 172.24.0.5
    client:
      sgwc:
        - address: 172.24.0.3
      smf:
        - address: 172.24.0.4
  metrics:
    server:
      - address: 172.24.0.5
        port: 9090
  gummei:
    - plmn_id:
        mcc: 999
        mnc: 70
      mme_gid: 2
      mme_code: 1
  tai:
    - plmn_id:
        mcc: 999
        mnc: 70
      tac: 1
  security:
    integrity_order: [EIA2, EIA1, EIA0]
    ciphering_order: [EEA0, EEA1, EEA2]
  network_name:
    full: NextGCore
    short: Next
  mme_name: nextgcore-mme0
```

## YAML parameters

**None.** The daemon deserializes no YAML fields: there are no `#[derive(Deserialize)]` structs in `src/bins/nextgcore-mmed/src/` and no `serde`/`std::fs` usage in the crate. The values an operator would expect to set in YAML are instead hardcoded defaults in `MmeContext::new()` (`src/bins/nextgcore-mmed/src/context.rs`):

| Setting (in-memory field) | Hardcoded value | Notes |
|---|---|---|
| `s1ap_port` | `36412` | S1AP port constant; no listener is actually bound. |
| `sgsap_port` | `29118` | SGsAP port constant; no listener is actually bound. |
| `relative_capacity` | `255` | RelativeMMECapacity advertised in S1 Setup Response builders. |
| `mme_ue_s1ap_id` | starts at `1` | Wraps back to 1 on reaching the invalid value `0xffffffff`. |
| `served_gummei`, `served_tai`, `integrity_order`, `ciphering_order`, `network_name`, `mme_name`, timers (`t3402`/`t3412`/`t3423`) | empty / `Default` | `MmeContext` has fields for all of these, but nothing populates them from the YAML file. |

### Parsed-but-inert / decorative YAML fields

Because the config file is never read, **every field in the shipped `mme.yaml` is decorative** for this daemon: `logger.*`, `global.max.*`, `mme.freeDiameter`, `mme.s1ap.server`, `mme.gtpc.server/client`, `mme.metrics.server`, `mme.gummei`, `mme.tai`, `mme.security.integrity_order/ciphering_order`, `mme.network_name`, and `mme.mme_name`. The file documents the intended deployment shape (its keys mirror the `MmeContext` fields above) but changing it has no effect on the running binary.

The same applies to the freeDiameter configs: `docker-compose-epc.yml` mounts `configs/epc/freeDiameter/` (containing `mme.conf`, `hss.conf`, `pcrf.conf`) at `/etc/freeDiameter:ro`, and the YAML points at `/etc/freeDiameter/mme.conf`, but the daemon never opens these files. The S6a stack is pure Rust (`nextgcore-diameter`); its `DiameterConfig` would be supplied programmatically to `mme_fd_init_async()`, which `main` does not call.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-mmed/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/mme.yaml` | Configuration file path. Logged at startup, then **ignored** (`init` takes it as `_config_path`). |
| `-l, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); unrecognized values fall back to `info`. |
| `--no-color` | flag | off | Parsed but never referenced after parsing — has no effect. |
| `-d, --daemon` | flag | off | Parsed but never referenced after parsing — has no effect. |

## Behavior notes

- **The config file is logged, not loaded.** Startup prints `Configuration: <path>`, then initializes the global `MmeContext` (a `OnceLock` singleton) purely from hardcoded defaults. Operators cannot currently change GUMMEI/TAI, security algorithm order, or peer addresses without recompiling.
- **S6a is deferred-connect and never connected by `main`.** `mme_fd_init()` only initializes client state; `mme_fd_init_async(config, hss_addr)` plus `mme_fd_connect()` (which retries the HSS connection 3 times via `connect_with_retry(3)`) exist in `fd_path.rs` but are not invoked from the binary's startup path. HSS-initiated CLR/IDR polling (`TS 29.272 §7.2.7/7.2.9` mandatory-AVP checks, per code comments) is implemented in the same module.
- **Environment variables:** the only one this binary reads is `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://jaeger:4317`) for OpenTelemetry trace export at startup. Note that `RUST_LOG` is **not** honored — logging uses `env_logger::Builder::new().filter_level(...)` without parsing the environment, so the level comes solely from `-l/--log-level`. The `RUST_LOG: info` set in `docker-compose-epc.yml` is therefore inert for the MME.
- **Docker publishes `36412/sctp`, but nothing listens.** The compose file's port mapping and the `kill -0 1` healthcheck both succeed because the process stays alive in its sleep loop, not because S1AP is serviceable.
- **Built-in capacity constants** (`context.rs`): max 8 served GUMMEIs, 16 supported TAs, 6 PLMNs per MME, 4 sessions and 8 bearers per UE, EPS bearer IDs 5–15. GUTI space is 256 MME group IDs × 256 MME codes per MME.
- **What is real and tested:** S1AP APER decode/dispatch including S1 handover paths (TS 36.413, per code comments), UE paging identity index `IMSI mod 1024` (TS 36.304 §7.1, per code comment), byte-level NAS builders with TAI-list encoding (TS 24.301 §9.9.3.33, per code comment), GTPv2-C S11 builders with TS 23.003 APN label encoding, SBc-AP/ETWS message codecs (TS 23.041), and proptest-based FSM equivalence tests (`property_tests.rs`) — all as library logic exercised by `cargo test`, not over the wire by this binary.
