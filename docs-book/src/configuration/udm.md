# UDM Configuration

The UDM (Unified Data Management, `nextgcore-udmd`) is the subscriber-data front-end of the core: it manages UE context registrations, serves subscription data, and generates 5G authentication vectors, backed by the UDR over `Nudr_DataRepository`. Its SBI router (`udm_sbi_request_handler` in `src/bins/nextgcore-udmd/src/app.rs`) serves four services: `Nudm_UECM` (`/nudm-uecm/v1` — AMF 3GPP/non-3GPP-access and SMF registrations, TS 29.503 §5.3.3 per code comments), `Nudm_SDM` (`/nudm-sdm/v1` — am-data, sm-data, smf-select-data, nssai, sdm-subscriptions, and SoR/UPU acknowledgements, TS 29.503 §5.2.2.6 per code comments), `Nudm_UEAU` (`/nudm-ueau/v1` — `generate-auth-data` with 5G-AKA/EAP-AKA' per TS 33.501 §6.1.2 as cited in the daemon source, plus `auth-events`), and `Nudm_EE` (`/nudm-ee/v1` — event-exposure subscriptions, TS 29.503 §5.5 per code comments). SUCI deconcealment (SIDF role) is implemented in `context.rs` per TS 33.501 §6.12 as cited in the source, and Steering-of-Roaming / UE-Parameters-Update injection into am-data goes through the AUSF's protection services (TS 33.501 §6.14.2.1 / §6.15.2.1 per code comments).

Configuration is split between a YAML file (default path `/etc/nextgcore/udm.yaml`, overridable with `-c/--config`) and command-line flags, with a small set of environment variables on top. Unlike some NFs, the UDM's YAML `sbi.server` entry *overrides* the CLI bind address/port so the NRF NFProfile advertises a routable endpoint instead of `0.0.0.0` (per the inline comment in `app.rs`). If the config file is missing the daemon logs at debug level and runs on pure CLI defaults; a YAML file that fails to deserialize is silently ignored.

> **Honesty note:** UDM behavior is validated by this project's own unit tests and matched-simulator docker E2E runs (84/84 as of 2026-07-02), not by third-party conformance certification. Several routes are honest stubs: `ue-context-in-smf-data` GET, `id-translation-result` GET, and `sdm-subscriptions` PATCH return **501 NOT_IMPLEMENTED**; `Nudm_EE` subscription PATCH returns 204 on an existing subscription *without applying the JSON-Patch* (deferred, per code comment). Notification-driven UPU delivery (post-registration `Nudm_SDM_Notification`) is explicitly deferred — only the am-data-attribute UPU path exists. The `-k/--kill` flag and the TLS flags are also stubs (see below).

## Example configuration

From `nextgcore/docker/rust/configs/5gc/udm.yaml`:

```yaml
# UDM (Unified Data Management) Configuration
# Docker container configuration for 5G Core deployment

logger:
  file:
    path: /var/log/nextgcore/udm.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

udm:
  hnet:
    - id: 1
      scheme: 1
      key: /etc/nextgcore/hnet/curve25519-1.key
    - id: 2
      scheme: 2
      key: /etc/nextgcore/hnet/secp256r1-2.key
  sbi:
    server:
      - address: 172.23.0.12
        port: 7777
    client:
      nrf:
        - uri: http://172.23.0.10:7777
    # TLS configuration (G36: SBI TLS)
    # Enable: TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
    tls:
      enabled: false
      cert: /etc/nextgcore/certs/udm.crt
      key: /etc/nextgcore/certs/udm.key
      ca: /etc/nextgcore/certs/ca.crt
      min_version: "1.2"
```

## YAML parameters

These are the fields actually deserialized by the daemon (`#[derive(Deserialize)]` structs `UdmYaml`/`UdmSection`/`SbiYaml`/`SbiServerYaml`/`SbiClientYaml`/`NrfClientYaml`/`HnetYaml`/`SorYaml`/`UpuYaml` in `src/bins/nextgcore-udmd/src/app.rs`), plus one knob (`sbi.oauth2.require`) read by a separate untyped `serde_yaml::Value` scan in `oauth2_required()`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `udm.sbi.server[].address` | string | absent → CLI `--sbi-addr` (`0.0.0.0`) | Only the **first** list entry is read. Overrides the CLI bind address and becomes the address advertised in the NRF NFProfile. |
| `udm.sbi.server[].port` | u16 | absent → CLI `--sbi-port` (`7777`) | First entry only; overrides the CLI SBI port. |
| `udm.sbi.client.nrf[].uri` | string | absent → **no NRF registration** | First entry only; seeds the NRF URI in the shared SBI context. If absent, NRF registration is skipped entirely (debug log) and the UDM operates without NRF. |
| `udm.sbi.oauth2.require` | bool | `false` | SBI OAuth2 enforcement (Wave-6 H8; TS 33.501 §13.4.1, TS 29.510 §5.4.2 per code comments). Read via a raw YAML scan that is root-key agnostic (true iff *any* top-level section sets `sbi.oauth2.require: true`). The env var `NEXTGCORE_SBI_OAUTH2_REQUIRE` takes precedence over the YAML. When on, incoming requests must carry an NRF-issued Bearer token with audience `UDM` (verified against the NRF JWKS; fails closed with 503 when no NRF URI is configured, per code comment) and outbound SBI calls attach tokens. |
| `udm.hnet[].id` | u8 | **required** per entry | Home-network key identifier for SUCI deconcealment (TS 33.501 §6.12 per code comment); matched against the SUCI's key id. |
| `udm.hnet[].scheme` | u8 | **required** per entry | Protection scheme: `1` = Profile A (ECIES X25519), `2` = Profile B (ECIES P-256), per the `deconceal_suci` doc comment in `context.rs`. A key whose scheme mismatches the SUCI's scheme is rejected. |
| `udm.hnet[].key` | string | **required** per entry | Either a 64-hex-char private key inline, or a **path to a file containing 64 hex chars** (not PEM, despite the `.key` extension in the example). A key that fails to load logs a warning and every SUCI using that key id is rejected. |
| `udm.allow_null_scheme` | bool | `true` (context default `AtomicBool::new(true)`; YAML applied only when present) | udmd-11: gate for null-scheme SUCIs. When `false`, null-scheme SUCIs are rejected at deconcealment; `imsi-` passthrough is always allowed. |
| `udm.sor.steering` | array of JSON objects | absent/empty → **no SoR injection**, am-data passthrough is byte-identical | Wave-6 F-04: TS 29.509 `SteeringContainer` as a `SteeringInfo[]` array (`{plmnId: {mcc, mnc}, accessTechList: [..]}`; quote `mcc`/`mnc` as strings, per the struct doc comment). The AUSF performs the TS 24.501 §9.11.3.51 wire encoding per code comment. |
| `udm.sor.ack_ind` | bool | `true` (`unwrap_or(true)`) | Request UE acknowledgement (`SorInfo.ackInd`). |
| `udm.upu.data` | array of JSON objects | absent/empty → **no UPU injection**, am-data passthrough is byte-identical | Wave-6 F-05: TS 29.509 `UpuData[]` entries (`{routingId}`, `{defaultConfNssai: [..]}`, `{secPacket}`, …, per the struct doc comment). The AUSF performs the TS 24.501 §9.11.3.53A wire encoding and MAC per code comment. |
| `udm.upu.ack_ind` | bool | `true` (`unwrap_or(true)`) | Request UE acknowledgement (`UpuInfo.upuAckInd`). |

### Parsed-but-inert / decorative YAML fields

Unknown YAML keys are silently ignored by serde. In the shipped `udm.yaml`:

- **`logger.file.path` and `logger.level` are inert.** The log level comes from the CLI flag `-e/--log-level` (default `info`); `init_logging()` never opens a log file (see the CLI table — even `-l/--log-file` is inert).
- **`global.max.ue` and `global.max.peer` are inert.** Context capacities come from the CLI flags `--max-ue` (default `1024`) and `--max-sess` (default `4096`); the example's `ue: 1024` merely coincides with the CLI default.
- **`udm.sbi.tls.*` (`enabled`/`cert`/`key`/`ca`/`min_version`) is entirely inert.** `SbiYaml` has no `tls` field, and even the CLI TLS flags only populate a legacy placeholder config (see behavior notes).

Everything else in the shipped example (`udm.hnet[]`, `udm.sbi.server[]`, `udm.sbi.client.nrf[]`) is genuinely read.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-udmd/src/app.rs` (the binary's `main.rs` is a thin wrapper around `nextgcore_udmd::run`):

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/udm.yaml` | Configuration file path. |
| `-l, --log-file` | path | unset | **Parsed but unused** — `init_logging()` never references it; logging goes to stderr via `env_logger`. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else falls back to `info`). |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | **Stub**: logs "would send SIGTERM to running instance" and exits; does not actually signal anything. |
| `--sbi-addr` | string | `0.0.0.0` | SBI bind address — **overridden** by `udm.sbi.server[0].address` when present in the YAML. |
| `--sbi-port` | u16 | `7777` | SBI port — **overridden** by `udm.sbi.server[0].port` when present in the YAML. |
| `--tls` | flag | off | Stored only in the legacy `SbiServerConfig` placeholder (affects its reported URI scheme); the real HTTP/2 listener is built from `NextgcoreSbiServerConfig::new(addr)` with no TLS wiring, so **the actual SBI socket is always plaintext**. |
| `--tls-cert` | path | unset | Same placeholder-only caveat as `--tls`. |
| `--tls-key` | path | unset | Same placeholder-only caveat as `--tls`. |
| `--max-ue` | usize | `1024` | UE context pool capacity (also the denominator of the NRF load gauge). |
| `--max-sess` | usize | `4096` | Session context pool capacity. |

## Behavior notes

- **NRF registration and load-reporting heartbeat.** When an NRF URI is configured, the UDM PUTs an NFProfile advertising the `nudm-sdm`, `nudm-uecm`, and `nudm-ueau` services (note: `nudm-ee` is served but *not* advertised), `allowedNfTypes` `[AMF, SMF, AUSF, PCF, SCP]`, and `heartBeatTimer: 10`. On success it spawns a heartbeat worker every 5 s that PATCHes a real `/load` gauge — registered UEs as a percentage of `--max-ue`, clamped 0–100 (TS 29.510 §5.2.2.3.2 per code comment). Registration failure is non-fatal: the UDM logs a warning and operates without NRF.
- **Hard UDR dependency with env-var fallback.** All subscription data, authentication material, and UECM persistence go to the UDR via `Nudr_DataRepository`. UDR selection uses NRF discovery-cache instances first, then falls back to `UDR_SBI_ADDR`/`UDR_SBI_PORT` (port default `7777`); with neither available, SDM/UEAU requests answer **503**. The AUSF client for SoR/UPU protection follows the same pattern: the AUSF that authenticated the UE first, then any cached AUSF, then `AUSF_SBI_ADDR`/`AUSF_SBI_PORT` (port default `7777`), failing closed (withholding `sorInfo`/`upuInfo`) on any AUSF failure since TS 33.501 defines no unprotected delivery path, per code comments.
- **Auth-vector admission is strict.** `generate-auth-data` rejects: missing `servingNetworkName`/`ausfInstanceId` (400 `MANDATORY_IE_MISSING`), malformed serving-network names (403 `SERVING_NETWORK_NOT_AUTHORIZED`, anti-bidding-down per TS 33.501 §6.1.2 code comment), SUCI deconcealment failure (403 `AUTHENTICATION_REJECTED`), unknown subscribers (404 `USER_NOT_FOUND`), auth methods other than `5G_AKA`/`EAP_AKA_PRIME` (501), and subscriptions whose AMF separation bit is unset (403, TS 33.102 Annex H per code comment).
- **SQN replay protection gates AV issuance.** After Milenage AV generation the SQN is advanced per TS 33.102 Annex C.3.2 (per code comment) and PATCHed to the UDR. A UDR 5xx or transport failure makes the UDM **refuse to issue the AV** (503) to prevent SQN replay; other non-success statuses (e.g. 404 in the matched sim) degrade with a warning and the AV is issued anyway.
- **SoR/UPU acks are MAC-verified, single-use.** When an am-data response carried a protected SoR/UPU payload, the expected XMAC-I_UE is pinned; the UE's ack MAC is compared constant-time and a match yields 204 *and clears the pin* (a replayed ack is rejected). Mismatch or missing MAC → 400 (`SOR_MAC_FAILURE`/`UPU_MAC_FAILURE`/`MANDATORY_IE_MISSING`); a MAC with nothing outstanding → 400 `UNEXPECTED_MESSAGE`. A plain ack with nothing outstanding stays 204 (backward-compatible with the matched sim, which never sends acks, per code comment). `ueNotReachable: true` is recorded without a MAC check.
- **Environment variables** read by this binary: `NEXTGCORE_SBI_OAUTH2_REQUIRE` (`1`/`true`/`TRUE`/`yes` = on; checked *before* and overriding the YAML `sbi.oauth2.require`), `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP tracing endpoint, default `http://jaeger:4317`), and the peer fallbacks `UDR_SBI_ADDR`/`UDR_SBI_PORT` and `AUSF_SBI_ADDR`/`AUSF_SBI_PORT` used only when NRF discovery yields no instance.
