# BSF Configuration

The BSF (Binding Support Function, `nextgcore-bsfd`) stores and serves PCF binding information so that policy consumers (e.g. an AF or NEF via PCF) can find the PCF that owns a given PDU session, UE, or MBS session. It serves the `Nbsf_Management` API (TS 29.521, as cited throughout the daemon's source comments): `/nbsf-management/v1/pcfBindings` (PDU-session bindings, full POST/GET/PATCH/DELETE plus query-based discovery), `/nbsf-management/v1/pcf-ue-bindings` (UE-policy bindings, TS 29.521 §4.2.2.3/§4.2.4.3 per code comments), and `/nbsf-management/v1/pcf-mbs-bindings` (MBS-session bindings, TS 29.521 §4.2.2.4/§4.2.4.4 per code comments). The `Nbsf_Management` Subscribe/Unsubscribe sub-resource (`pcfBindings/.../subscriptions`) is a deliberate stub that returns **501 Not Implemented**. Routing and handlers live in `bsf_sbi_request_handler` in `src/bins/nextgcore-bsfd/src/lib.rs` — since the Wave-6 H1 lib-targetization, `main.rs` is a thin wrapper around `nextgcore_bsfd::run()`.

Configuration is split between a YAML file (default path `/etc/nextgcore/bsf.yaml`, overridable with `-c/--config`; the docker deployment passes `-c /etc/nextgcore/bsf.yaml`) and command-line flags. Unusually for this codebase, the YAML SBI `server` entry **overrides** the CLI `--sbi-addr`/`--sbi-port` (so the NRF NFProfile advertises a routable endpoint instead of `0.0.0.0`, per the code comment); everything else — TLS flags, session capacity, log level — is CLI-only. The only environment variable the binary reads is `OTEL_EXPORTER_OTLP_ENDPOINT`.

> **Honesty note:** BSF behavior is validated by this project's own unit tests and matched-simulator Docker E2E runs (84/84 as of 2026-07-02), not by third-party conformance certification. Known gaps visible in the source: `Nbsf_Management` subscriptions are a 501 stub (`bsfd-13`); the `--tls` flag does **not** enable TLS on the actual HTTP/2 listener (it only flips the advertised URI scheme in the legacy NF-instance metadata built in `sbi_path.rs`); the MongoDB persistence layer (`bsf_bindings` collection) is best-effort and the daemon never initializes a MongoDB connection itself — no `nextgcore_mongoc_init`/`nextgcore_dbi_init` call exists in this crate, so in the standalone binary bindings live in memory only; and `sbi_path.rs` still contains legacy placeholder helpers (`bsf_sbi_send_request`/`bsf_sbi_discover_and_send` return a hardcoded transaction ID).

## Example configuration

From `nextgcore/docker/rust/configs/5gc/bsf.yaml`:

```yaml
# BSF (Binding Support Function) Configuration
# Docker container configuration for 5G Core deployment

logger:
  file:
    path: /var/log/nextgcore/bsf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

bsf:
  sbi:
    server:
      - address: 172.23.0.15
        port: 7777
    client:
      nrf:
        - uri: http://172.23.0.10:7777
    # TLS configuration (G36: SBI TLS)
    # Enable: TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
    tls:
      enabled: false
      cert: /etc/nextgcore/certs/bsf.crt
      key: /etc/nextgcore/certs/bsf.key
      ca: /etc/nextgcore/certs/ca.crt
      min_version: "1.2"
```

An OAuth2-enforcing variant (`bsf-oauth2.yaml`, used via `docker-compose.oauth2.yml`) is identical except it adds:

```yaml
bsf:
  sbi:
    oauth2:
      require: true
```

## YAML parameters

These are the fields actually deserialized by the daemon (`#[derive(Deserialize)]` structs `BsfYaml`/`BsfSection`/`SbiYaml`/`SbiServerYaml`/`SbiClientYaml`/`NrfClientYaml`/`SbiOauth2Yaml` in `src/bins/nextgcore-bsfd/src/lib.rs`). Only the **first** entry of each list (`server`, `client.nrf`) is read.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `bsf.sbi.server[0].address` | string | absent → CLI `--sbi-addr` (`0.0.0.0`) | Bind **and** advertised SBI address. When present it overrides the CLI value so the NRF NFProfile advertises a reachable endpoint instead of `0.0.0.0` (per code comment). |
| `bsf.sbi.server[0].port` | u16 | absent → CLI `--sbi-port` (`7777`) | Bind and advertised SBI port; overrides the CLI value when present. |
| `bsf.sbi.client.nrf[0].uri` | string | absent → CLI `--nrf-uri` (unset → no NRF registration) | NRF base URI, seeded into the global SBI context for NF registration, heartbeat, and (when OAuth2 is on) token issuance/JWKS. `uri` is a **required** field of the list entry — if an `nrf` entry omits it, deserialization of the whole file fails and is silently ignored (the parse is wrapped in `if let Ok(...)`), leaving the BSF unregistered. |
| `bsf.sbi.oauth2.require` | bool | `false` | SBI OAuth2 bearer-token enforcement. When `true`, incoming requests must carry an NRF-issued token whose audience includes `BSF`, verified against the NRF JWKS (TS 33.501 §13.4.1 per code comment); with no NRF URI configured the server fails closed with 503 (per code comment). Also installs a process-wide OAuth2 client so outbound SBI calls attach tokens. Unlike NSACF, there is **no** CLI override flag for this knob. |

### Parsed-but-inert / decorative YAML fields

The daemon deserializes only the fields above; unknown YAML keys are silently ignored by serde. In particular, in the shipped example files:

- **`logger.file.path` and `logger.level` are inert.** The log level comes solely from the CLI flag `-e/--log-level` (default `info`). Note that `RUST_LOG` has *no* effect either — `init_logging` builds a fresh `env_logger::Builder::new()` without reading the environment. Logs go to stderr; no file sink is wired (see `--log-file` below).
- **`global.max.ue` / `global.max.peer` are inert.** No `global` section exists in the deserialize structs; session capacity is the CLI flag `--max-sess`.
- **`bsf.sbi.tls.*` (`enabled`/`cert`/`key`/`ca`/`min_version`) is inert.** No `tls` field exists in `SbiYaml`. TLS-related knobs are the CLI flags `--tls`/`--tls-cert`/`--tls-key` — and even those only affect the advertised scheme (see Behavior notes). The `TLS_ENABLED`/`SBI_SCHEME` variables mentioned in the YAML comment, and the `TLS_CERT`/`TLS_KEY` environment variables set by `docker-compose.yml`, are not read by this binary.

## Command-line flags

Runtime knobs with real defaults from the clap `Args` struct in `src/bins/nextgcore-bsfd/src/lib.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/bsf.yaml` | Configuration file path. A missing file is tolerated (logged at debug); a malformed file is silently ignored. |
| `-l, --log-file` | path | unset | Parsed but **never used** — `init_logging` wires no file sink; logging goes to stderr. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); unrecognized values fall back to `info`. |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Stub: logs "would send SIGTERM to running instance" and exits without signaling anything. |
| `--sbi-addr` | string | `0.0.0.0` | SBI server bind address; **overridden** by `bsf.sbi.server[0].address` when the YAML provides one. |
| `--sbi-port` | u16 | `7777` | SBI server port; **overridden** by `bsf.sbi.server[0].port` when present. |
| `--tls` | flag | off | Sets `tls_enabled` in the legacy context config; switches the advertised URI scheme to `https` but does not enable TLS on the HTTP/2 listener (see Behavior notes). |
| `--tls-cert` | path | unset | TLS certificate path (stored in the legacy context config only). |
| `--tls-key` | path | unset | TLS key path (stored in the legacy context config only). |
| `--nrf-uri` | string | unset | NRF URI fallback when `bsf.sbi.client.nrf` is absent. With neither set, NRF registration is skipped and the BSF runs standalone. |
| `--max-sess` | usize | `1024` | Maximum number of PDU-session bindings in the context pool. |

## Behavior notes

- **Create/validation semantics** (`POST /nbsf-management/v1/pcfBindings`): mandatory `dnn` + `snssai` (TS 29.521 PcfBinding, per code comment), at least one UE address (`ipv4Addr`/`ipv6Prefix`/`macAddr48` — MAC-only Ethernet bindings are valid), and at least one PCF address (`pcfFqdn`, non-empty `pcfIpEndPoints`, or `pcfDiamHost`+`pcfDiamRealm`; `bsfd-05`), each violation returning 400 `MANDATORY_IE_MISSING`. When the `--max-sess` pool (default 1024) is full, creation fails with 400 / `SYSTEM_FAILURE`. Success is 201 with a `Location` header; PDU-session binding IDs are numeric (a non-numeric ID on DELETE yields 400 `INVALID_BINDING_ID`), while UE/MBS binding IDs are UUIDs.
- **Feature negotiation and duplicate detection**: the BSF advertises `suppFeat` `0x6` — BindingUpdate + SamePcf, not MultiUeAddr (TS 29.521 Table 5.8-1 per code comment) — and echoes the negotiated intersection per session. With SamePcf negotiated and `paraCom` present, a duplicate `dnn`+`snssai`+`supi` binding is rejected 403 `EXISTING_BINDING_INFO_FOUND` with `pcfSmFqdn`/`pcfSmIpEndPoints` extensions; MBS binding creation likewise rejects a duplicate `mbsSessionId` with 403.
- **Discovery semantics**: `GET /pcfBindings` requires a UE-address query parameter (TS 29.521 §4.2.4.2 per code comment) — SUPI/GPSI/DNN-only queries get 400 `MANDATORY_QUERY_PARAM_MISSING`; no match returns **204** (not 404); multiple matches return 400 `MULTIPLE_BINDING_INFO_FOUND`. MBS discovery uses the `mbs-session-id` query parameter (TS 29.521 §4.2.4.4 per code comment), accepting legacy `mbsSessionId` leniently. PATCH bodies must be `application/merge-patch+json` (TS 29.521 §5.2 per code comment); `application/json` and an absent Content-Type are accepted leniently, anything else is 415.
- **Binding TTL**: every PDU-session binding arms an expiry timer — from the RFC 3339 `expiry` attribute when supplied (invalid values are rejected 400), otherwise the default TTL of **3600 s** (`timer::defaults::BINDING_EXPIRY` in `src/bins/nextgcore-bsfd/src/timer.rs`). The event loop removes expired bindings, and expired-but-unswept bindings are excluded from GET/discovery.
- **NRF registration and load reporting**: the BSF PUTs an NFProfile (`nfType: BSF`, service `nbsf-management`, `allowedNfTypes: PCF/SMF/SCP`, `heartBeatTimer: 10`) to `/nnrf-nfm/v1/nf-instances/{id}` and, on success, spawns a heartbeat worker every **5 s** that PATCHes a live `/load` gauge computed as bindings vs. `--max-sess` capacity (TS 29.510 §5.2.2.3.2 per code comment). Registration failure is non-fatal ("will operate without NRF"). Quirk: passing `--nrf-uri` on the CLI additionally triggers a second, legacy registration with a separate random NF instance ID from `bsf_sbi_open` (`sbi_path.rs`); the YAML-configured URI only drives the main registration path.
- **Environment variables**: the only one read is `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://jaeger:4317`) for the OpenTelemetry OTLP exporter. `RUST_LOG` is not honored, and MongoDB persistence has no URI source in this binary at all — the `bsf_bindings` upsert/delete/load calls are best-effort no-ops (failures logged at debug) unless some in-process embedder initializes the shared DBI layer first.
