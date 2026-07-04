# NSSF Configuration

The NSSF (Network Slice Selection Function, `nextgcore-nssfd`) selects the network slice instances to serve a UE, determines the allowed NSSAI and its mapping to subscribed S-NSSAIs, and determines the AMF Set for a UE, per TS 29.531 (as cited in the daemon's source comments). It serves the `Nnssf_NSSelection` v2 API (`GET /nnssf-nsselection/v2/network-slice-information`, with dedicated handlers for the registration, PDU-session, and UE-Configuration-Update scenarios) and the `Nnssf_NSSAIAvailability` v1 API (`/nnssf-nssaiavailability/v1/nssai-availability/{nfId}` PUT/PATCH/DELETE, store-level OPTIONS, and `.../subscriptions` POST/PATCH/DELETE with availability-change notifications).

Configuration is split between a YAML file (default path `/etc/nextgcore/nssf.yaml`, overridable with `-c/--config`) and command-line flags, plus two environment variables (`NEXTGCORE_NSSF_STATE_FILE`, `OTEL_EXPORTER_OTLP_ENDPOINT`). Unusually for this codebase, the YAML `nssf.sbi.server` address/port **overrides** the CLI `--sbi-addr`/`--sbi-port` flags — per the code comment, so the NRF NFProfile advertises a routable endpoint instead of `0.0.0.0`.

> **Honesty note:** NSSF behavior is validated by this project's own unit tests and matched-simulator docker E2E only, not by third-party conformance certification. Two stances are explicitly non-strict by design (documented in code comments as matched-sim back-compat): availability updates are **default-allow** — any non-empty NF Id is treated as authorized without an NRF lookup, and with no `supported_snssai_list` configured every reported S-NSSAI is accepted. The NSSF advertises `supportedFeatures: "1"` and does not advertise the REROUTE capability (TS 29.531 §6.1.6.3 per code comment). The `-k/--kill` flag is a stub (logs and exits), and the TLS flags are not wired into the actual HTTP/2 listener (see below).

## Example configuration

From `nextgcore/docker/rust/configs/5gc/nssf.yaml`:

```yaml
# NSSF (Network Slice Selection Function) Configuration
# Docker container configuration for 5G Core deployment

logger:
  file:
    path: /var/log/nextgcore/nssf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

nssf:
  sbi:
    server:
      - address: 172.23.0.14
        port: 7777
    client:
      nrf:
        - uri: http://172.23.0.10:7777
      nsi:
        - uri: http://172.23.0.10:7777
          s_nssai:
            sst: 1
    # TLS configuration (G36: SBI TLS)
    # Enable: TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
    tls:
      enabled: false
      cert: /etc/nextgcore/certs/nssf.crt
      key: /etc/nextgcore/certs/nssf.key
      ca: /etc/nextgcore/certs/ca.crt
      min_version: "1.2"
```

An OAuth2-enforcing variant (`nssf-oauth2.yaml`, used via `docker-compose.oauth2.yml`) is identical except it adds:

```yaml
nssf:
  sbi:
    oauth2:
      require: true
```

## YAML parameters

These are the fields actually deserialized by the daemon (`#[derive(Deserialize)]` structs `NssfYaml`/`NssfSection`/`SbiYaml`/`SbiServerYaml`/`SbiClientYaml`/`NrfClientYaml`/`SbiOauth2Yaml`/`SnssaiYaml` in `src/bins/nextgcore-nssfd/src/main.rs`).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `nssf.sbi.server[].address` | string | absent → CLI `--sbi-addr` (`0.0.0.0`) | SBI bind/advertised address. Only the **first** list entry is read; when present it **overrides** the CLI flag so the NRF NFProfile advertises a reachable endpoint (per code comment). |
| `nssf.sbi.server[].port` | u16 | absent → CLI `--sbi-port` (`7777`) | SBI port; same first-entry-only, overrides-CLI semantics. |
| `nssf.sbi.client.nrf[].uri` | string | absent → **no NRF registration** | NRF base URI (only the first list entry is used). Absent means the daemon skips NRF registration/heartbeat/discovery entirely and runs standalone — there is **no** CLI fallback for the NRF URI in this binary. `uri` is mandatory inside an entry (non-`Option` field). |
| `nssf.sbi.oauth2.require` | bool | `false` | SBI OAuth2 bearer-token enforcement. When `true`, incoming requests must carry an NRF-issued token whose audience includes `NSSF`, verified against the NRF JWKS (TS 33.501 §13.4.1 per code comment); with no NRF URI configured the server fails closed (503). Outbound SBI calls (including availability notifications to AMFs) attach tokens. No CLI override exists for this knob. |
| `nssf.amf_set_id` | string | absent | Target AMF Set for AMF re-selection, emitted as `targetAmfSet` (TS 29.531 §5.2.2.2.2 step 2a per code comment). CLI `--target-amf-set` overrides the YAML value. When neither is set, registration responses derive a syntactically valid fallback from the UE's serving-PLMN TAI: `<mcc>-<mnc>-01-001`. |
| `nssf.supported_snssai_list` | list | absent → **no restriction (allow-all)** | Optional explicit set of S-NSSAIs supported in this PLMN (TS 29.531 §6.2.3.2.3.1 per code comment). When present, an NSSAIAvailability PUT/PATCH reporting an S-NSSAI outside the set is rejected with 403 `SNSSAI_NOT_SUPPORTED`. Absent means allow-all (matched-sim back-compat), **not** an empty set. |
| `nssf.supported_snssai_list[].sst` | u8 | **required** | Slice/Service Type of the S-NSSAI. |
| `nssf.supported_snssai_list[].sd` | string | absent (no SD) | Slice Differentiator as a hex string. The reserved value `FFFFFF` (and any non-hex string) is treated as "no SD". |

### Parsed-but-inert / decorative YAML fields

Unknown YAML keys are silently ignored by serde. In the shipped example file:

- **`logger.file.path` and `logger.level` are inert.** The log level comes solely from the CLI flag `-e/--log-level`; `init_logging` builds `env_logger::Builder::new()` with an explicit filter, so even `RUST_LOG` is not consulted, and no file logging is wired (see `--log-file` below).
- **`global.max.ue` / `global.max.peer` are inert** — no `global` section exists in the deserialize structs; the only pool cap is CLI `--max-nf`.
- **`nssf.sbi.client.nsi[]` (uri, s_nssai) is inert.** `SbiClientYaml` only has an `nrf` field; NSI-to-NRF mappings are not provisioned from YAML.
- **`nssf.sbi.tls.*` (enabled/cert/key/ca/min_version) is inert.** TLS is CLI-flag-only, and even those flags only populate a legacy config (next section).

Note this differs from some sibling NFs: `nssf.sbi.server[]` **is** read here (and wins over the CLI flags), and there is no `--nrf-uri` CLI fallback.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-nssfd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/nssf.yaml` | Configuration file path. |
| `-l, --log-file` | path | unset | **Parsed but never used** — no file-logging sink is wired; logs go to the `env_logger` default (stderr). |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; unknown values fall back to `info`). |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Stub: logs "would send SIGTERM to running instance" and exits without signalling anything. |
| `--sbi-addr` | string | `0.0.0.0` | SBI bind address — **overridden** by `nssf.sbi.server[0].address` when the YAML sets it. |
| `--sbi-port` | u16 | `7777` | SBI port — overridden by `nssf.sbi.server[0].port`. |
| `--tls` | flag | off | Recorded in the legacy `SbiServerConfig` (`sbi_path.rs`) only; the actual HTTP/2 listener in `main.rs` is built without TLS, so the SBI server always speaks cleartext HTTP/2. |
| `--tls-cert` | path | unset | Same caveat as `--tls`. |
| `--tls-key` | path | unset | Same caveat as `--tls`. |
| `--max-nf` | usize | `512` | Maximum NSI entries and home contexts in the context pools; also the denominator of the NRF `/load` gauge. |
| `--target-amf-set` | string | unset | Target AMF Set (format `<MCC>-<MNC>-<RegionId>-<SetId>`, TS 29.531 `targetAmfSet` per code comment). Overrides YAML `nssf.amf_set_id`. |
| `--state-file` | path | unset | JSON snapshot file for NSSAI-availability subscriptions and availability data. Precedence: `--state-file`, then `NEXTGCORE_NSSF_STATE_FILE`; with neither set (or an empty value) state is purely in-memory and lost on restart. |

## Behavior notes

- **NRF registration is one-shot, heartbeat carries a real load gauge.** At startup the NSSF PUTs an NFProfile (`heartBeatTimer: 10`, services `nnssf-nsselection` v2 and `nnssf-nssaiavailability` v1, `allowedNfTypes` AMF/SCP/NSSF) to `/nnrf-nfm/v1/nf-instances/{uuid}`. On failure it logs a warning and **operates without NRF** — there is no registration retry loop. On success a heartbeat worker runs every 5 seconds and PATCHes a `/load` gauge computed as NSI count × 100 / `--max-nf`, clamped to 0–100 (TS 29.510 §5.2.2.3.2 per code comment). H-NSSF instances are also discovered from the NRF once at startup; a failure there is "will retry on demand".
- **Availability-update admission is default-allow.** 403 `NOT_AUTHORIZED` is returned only for a missing/empty NF Id (deliberately no NRF authorization lookup, per code comment); 403 `SNSSAI_NOT_SUPPORTED` only when `supported_snssai_list` is configured *and* a reported S-NSSAI falls outside it. Success returns 200 with `authorizedNssaiAvailabilityData` — or **204 No Content when no supported S-NSSAIs remain** after the update (TS 29.531 §6.2.3.2.3.1 per code comment). Availability PATCH requires `Content-Type: application/json-patch+json` (else 415, RFC 6902 / TS 29.531 §6.2 per code comment) and is applied to a clone, committed only if the patched document re-validates.
- **Notifications are fire-and-forget.** Availability changes spawn one Tokio task per matching subscription, POSTing `NssfEventNotification` with bounded timeouts (2 s connect, 3 s request); delivery failures are logged, never retried, and the AMF whose own update caused the change is excluded (it gets the data in its direct response).
- **State persistence is per-mutation, not shutdown-only.** With a state file configured, subscriptions and availability documents are atomically rewritten on every add/update/delete and reloaded at startup; a corrupt or missing file is logged and skipped, starting empty.
- **Config parse errors are silent.** The YAML is parsed with `if let Ok(...)`: a type mismatch anywhere (e.g. a non-numeric `sst`) silently discards the *entire* `nssf` section and the daemon proceeds on CLI defaults — check the startup log for the expected "NRF URI configured" / "Target AMF Set configured" lines.
- **Environment variables:** `NEXTGCORE_NSSF_STATE_FILE` (state-file path; lower precedence than `--state-file`) and `OTEL_EXPORTER_OTLP_ENDPOINT` (OpenTelemetry OTLP exporter endpoint, default `http://jaeger:4317`). `RUST_LOG` is **not** honored by this binary.
