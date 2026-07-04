# AUSF Configuration

The AUSF (Authentication Server Function, `nextgcore-ausfd`) runs primary UE authentication — both 5G-AKA and EAP-AKA' (RFC 5448/9048) — deriving KAUSF/KSEAF and confirming results to the UDM, per TS 33.501 and TS 29.509 (as cited in the daemon's source comments). Its SBI router (`ausf_sbi_request_handler` in `src/bins/nextgcore-ausfd/src/app.rs`) serves the `Nausf_UEAuthentication` API (`POST /nausf-auth/v1/ue-authentications`, `PUT .../{authCtxId}/5g-aka-confirmation`, `POST .../{authCtxId}/eap-session`, `DELETE .../{authCtxId}`) plus the Wave-6 F-03 producer services `Nausf_SoRProtection` (`POST /nausf-sorprotection/v1/{supi}/ue-sor`) and `Nausf_UPUProtection` (`POST /nausf-upuprotection/v1/{supi}/ue-upu`), both TS 29.509 per code comments (the vendored `specs/TS29509_Nausf_SoRProtection.yaml` / `TS29509_Nausf_UPUProtection.yaml` are referenced from `sor_protection.rs` / `upu_protection.rs`).

Configuration is split between a YAML file (default path `/etc/nextgcore/ausf.yaml`, overridable with `-c/--config`) and command-line flags, with a precedence quirk worth knowing: when the YAML lists an SBI server entry, its address/port **override** the `--sbi-addr`/`--sbi-port` CLI flags (the code comment explains this is so the NRF NFProfile advertises a routable endpoint instead of `0.0.0.0`). The YAML carries only the SBI endpoint, the NRF URI, and the OAuth2 knob; everything else (log level, UE capacity, TLS flags) is CLI-only. A few environment variables are also read — see the behavior notes. Since the Wave-6 H1 lib split, `main.rs` is a thin wrapper around `nextgcore_ausfd::run()`; all logic including the clap `Args` struct lives in `src/bins/nextgcore-ausfd/src/app.rs`.

> **Honesty note:** AUSF behavior is validated by this project's own unit tests, in-crate strict-peer integration tests (the lib-target exists precisely so peer NF crates can drive the real `ausf_sbi_request_handler` in-process), and the matched-simulator docker E2E suite (84/84 as of 2026-07-02) — not by third-party conformance certification. Known bespoke/non-normative points, all documented in code comments: the consumer-PLMN entitlement check (`extract_consumer_plmns`) decodes the OAuth2 JWT payload **without signature verification** and is default-permissive for token-less peers; the `--tls*` CLI flags and the YAML `tls:` block are not wired to the live HTTP/2 server (see below), so all shipped deployments serve plain HTTP; and the registered NFProfile is a simplified subset of TS 29.510.

## Example configuration

From `nextgcore/docker/rust/configs/5gc/ausf.yaml`:

```yaml
# AUSF (Authentication Server Function) Configuration
# Docker container configuration for 5G Core deployment

logger:
  file:
    path: /var/log/nextgcore/ausf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

ausf:
  sbi:
    server:
      - address: 172.23.0.11
        port: 7777
    client:
      nrf:
        - uri: http://172.23.0.10:7777
    # TLS configuration (G36: SBI TLS)
    # Enable: TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
    tls:
      enabled: false
      cert: /etc/nextgcore/certs/ausf.crt
      key: /etc/nextgcore/certs/ausf.key
      ca: /etc/nextgcore/certs/ca.crt
      min_version: "1.2"
  security:
    pqc:
      enabled: false
      prefer_pqc: false
```

There is no `ausf-oauth2.yaml` variant (despite a code comment mentioning one): the OAuth2 compose overlay (`docker-compose.oauth2.yml`) enables enforcement for the AUSF via the `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` environment variable instead.

## YAML parameters

These are the fields actually deserialized by the daemon (`#[derive(Deserialize)]` structs `AusfYaml`/`AusfSection`/`SbiYaml`/`SbiServerYaml`/`SbiClientYaml`/`NrfClientYaml` in `src/bins/nextgcore-ausfd/src/app.rs`), plus one knob read via a raw `serde_yaml::Value` scan. If the file is missing, or fails to parse as `AusfYaml`, the daemon silently proceeds on CLI defaults (`if let Ok(...)` — a malformed file is not an error).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `ausf.sbi.server[].address` | string | absent → CLI `--sbi-addr` (`0.0.0.0`) | SBI bind **and** NRF-advertised address. Only the **first** list entry is read; when present it overrides the CLI flag. |
| `ausf.sbi.server[].port` | u16 | absent → CLI `--sbi-port` (`7777`) | SBI bind/advertised port. First entry only; overrides the CLI flag. |
| `ausf.sbi.client.nrf[].uri` | string | absent → **no NRF** | NRF base URI seeded into the SBI context for NF registration, heartbeat, discovery, and (when OAuth2 is on) token/JWKS. First entry only. If absent, NRF registration and discovery are skipped entirely — the AUSF "will operate without NRF". |
| `ausf.sbi.oauth2.require` | bool | `false` | SBI OAuth2 enforcement (Wave-6 H8; TS 33.501 §13.4.1, TS 29.510 §5.4.2 per code comment). Not part of the typed structs: `oauth2_required()` re-reads the file as a raw YAML value, root-key agnostic (true iff **any** top-level section sets `sbi.oauth2.require: true`). When on, incoming requests need an NRF-issued Bearer token with audience `AUSF` and outbound Nudm calls attach tokens. The `NEXTGCORE_SBI_OAUTH2_REQUIRE` env var, **when set to any value**, wins in both directions. |

### Parsed-but-inert / decorative YAML fields

Unknown YAML keys are silently ignored by serde. In the shipped `ausf.yaml`, the following blocks are decorative:

- **`logger.file.path` and `logger.level` are inert.** The log level comes solely from the CLI flag `-e/--log-level`; `init_logging` builds an `env_logger::Builder::new()` with `filter_level`, so even `RUST_LOG` (which the docker compose sets) is not consulted by this daemon. Nothing writes to the YAML's log-file path.
- **`global.max.ue` / `global.max.peer` are inert.** The auth-context pool capacity comes from the CLI flag `--max-ue` (default `1024` — the example's matching `1024` is coincidence, not causation). `max.peer` is read by nothing in this binary.
- **`ausf.sbi.tls.*` (enabled/cert/key/ca/min_version) is inert.** More honestly: even the CLI `--tls`/`--tls-cert`/`--tls-key` flags only populate the legacy `SbiServerConfig` consumed by the `ausf_sbi_open()` logging shim (`sbi_path.rs`, marked inert by the "ausfd-10" note). The live HTTP/2 server is built from `nextgcore_sbi::server::SbiServerConfig::new(addr)` with no TLS fields set, so the served endpoint is plain HTTP regardless.
- **`ausf.security.pqc.*` is inert.** No PQC code path exists in this binary.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-ausfd/src/app.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/ausf.yaml` | Configuration file path (docker passes exactly `-c /etc/nextgcore/ausf.yaml`). |
| `-l, --log-file` | path | unset | Accepted but **not wired** — `init_logging` never reads it; logs go to stdout/stderr. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); unrecognized values fall back to `info`. |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Stub: logs "would send SIGTERM to running instance" and exits 0 without signaling anything. |
| `--sbi-addr` | string | `0.0.0.0` | SBI bind address — **overridden** by `ausf.sbi.server[0].address` when the YAML sets it. |
| `--sbi-port` | u16 | `7777` | SBI port — **overridden** by `ausf.sbi.server[0].port` when the YAML sets it. |
| `--tls` | flag | off | Feeds only the inert legacy `ausf_sbi_open` config; the live HTTP/2 server ignores it (see above). |
| `--tls-cert` | path | unset | Same caveat as `--tls`. |
| `--tls-key` | path | unset | Same caveat as `--tls`. |
| `--max-ue` | usize | `1024` | Capacity of the in-memory authentication-context pool. |

## Behavior notes

- **Admission/rejection on `Nausf_UEAuthentication`:** a malformed or non-5G `servingNetworkName` → 403 `SERVING_NETWORK_NOT_AUTHORIZED` (TS 33.501 §6.1.2, TS 29.509 §6.1.7.3 per code comments); a null/absent `resStar` in the 5G-AKA confirmation → 200 with `AUTHENTICATION_FAILURE` while present-but-bad hex → 400 (TS 29.509 §6.1.6.2.6/§6.1.6.2.8 per code comments); `kseaf`/`supi` appear in responses only on success (and `supi` only when the original identity was a SUCI). Pool exhaustion at `--max-ue` yields a **400** "Failed to allocate UE context" (cause `INTERNAL_ERROR`), not a 5xx. Unmatched routes get 405; the API version path segment is not validated.
- **NRF registration is best-effort, no retry loop:** with an NRF URI configured, the AUSF PUTs a NFProfile (`/nnrf-nfm/v1/nf-instances/{uuid}`) advertising `nausf-auth`, `nausf-sorprotection`, and `nausf-upuprotection` with `allowedNfTypes` [AMF, UDM, SCP] and `heartBeatTimer: 10`; on success a heartbeat worker runs every 5 s, PATCHing a real load gauge (auth contexts vs `--max-ue`, TS 29.510 §5.2.2.3.2 per code comment). On failure it logs a warning and continues without NRF.
- **UDM resolution order:** startup discovery via `/nnrf-disc` (target `UDM`, service `nudm-ueau`, failure = "will retry on demand"); per-request, cached discovery results win, else the `UDM_SBI_ADDR`/`UDM_SBI_PORT` env fallback (port defaults to `7777`; the docker compose sets `172.23.0.12:7777`). An unreachable UDM turns `POST /ue-authentications` into a 503 `UDM_UNAVAILABLE`.
- **SoR/UPU are fail-closed** (per the module-header invariants in `sor_protection.rs`/`upu_protection.rs`): no per-SUPI KAUSF anchor (no completed primary authentication) → 404 `CONTEXT_NOT_FOUND`, never a MAC over a zero key; counter about to wrap → 503 `COUNTER_WRAP` with the counter not consumed (TS 33.501 §14.1.3/§6.14.2.3 per code comments); anything not encodable byte-exactly → 400.
- **No state files — everything is in-memory.** A restart loses all auth contexts and the SoR/UPU anchors/counters. `DELETE .../{authCtxId}` zeroizes the context's KAUSF/KSEAF/XRES* (TS 33.501 §6.1.4.1a per code comment) but deliberately keeps the per-SUPI anchor store so SoR/UPU keep working afterwards (TS 33.501 §6.14.1 per code comment).
- **Environment variables** read by this binary: `NEXTGCORE_SBI_OAUTH2_REQUIRE` (checked *before* the YAML; truthy = `1`/`true`/`TRUE`/`yes` — any other set value forces OAuth2 **off** even if the YAML says `true`), `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP trace exporter, default `http://jaeger:4317`), and `UDM_SBI_ADDR`/`UDM_SBI_PORT` (UDM fallback only — NRF discovery results take precedence). With OAuth2 enabled but no NRF URI configured, the server fails closed and 503s every request (per the code comment referencing `nextgcore-sbi` `server.rs`).
