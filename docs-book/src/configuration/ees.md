# EES Configuration

The EES (Edge Enabler Server, `nextgcore-eesd`) is an Edge Enabler Layer entity per TS 23.558 / TS 24.558 / TS 29.558 — **not** an NRF-discoverable 5GC NF (there is no `nfType "EES"` in TS 29.510, per the daemon's module doc comment). It self-registers toward the Edge Configuration Server (ECS) over EDGE-6 instead of the NRF, and serves twelve `eees-*` service APIs with the `{apiRoot}/<apiName>/<apiVersion>` layout (router in `src/bins/nextgcore-eesd/src/main.rs`, TS section numbers as cited in its route comments): `eees-easregistration` (TS 29.558 §5.2, EAS registration CRUD with PUT full-replace and RFC 7396 PATCH), `eees-easdiscovery` (TS 24.558 §5.3, `request-discovery` plus discovery-change subscriptions), `eees-eecregistration` (TS 24.558 §5.2), `eees-appctxtreloc` (TS 24.558 §5.5, Determine/Initiate/Declare), `eees-eel-acr` (TS 29.558 §5.11), `eees-acrstatus-update` (TS 29.558 §5.12), `eees-cea` (TS 29.558 Common EAS Announcement, single `POST /declare` custom operation), `eees-appclientinformation` (TS 29.558 §8.4), `eees-acrmgntevent` (TS 29.558 §5.8), `eees-eeccontextreloc` (TS 29.558 §8.7.2, push/pull on `/eec-contexts` only), `eees-acr-param` (TS 29.558 ACR Parameter Information, `POST /send-acrparamsinfo`), and `eees-acrevents` (TS 24.558 §6.4, subscribe/notify). Anything else — including the legacy bespoke `nees-*` paths — falls through to 404.

Configuration is unusual for this project: the binary accepts a `-c/--config` flag (default path `/etc/nextgcore/ees.yaml`), but **the daemon never opens or parses that file** — `args.config` appears only in a unit-test assertion, and the only file `main.rs` ever reads is the OAuth2 JWKS (`--oauth2-jwks-file`). Every runtime knob is a CLI flag, plus two environment variables (`RUST_LOG` and `OTEL_EXPORTER_OTLP_ENDPOINT`). The shared `nextgcore-app` config layer is a declared dependency but is not called from any `nextgcore-eesd` source file.

> **Honesty note:** EES behavior is validated by this project's own unit tests and matched-simulator Docker E2E only, not by third-party conformance certification. Several pieces are explicitly stubbed or deferred in the source: there is no live ECS peer in this stack (without `--ecs-uri` the EDGE-6 registration request is built, logged, and skipped), full CAPIF onboarding (AEF credential exchange) is deferred — token verification uses an out-of-band JWKS file instead — and UE location/identifier exposure (eesd-09/10, NEF path) plus SessionWithQoS/TIE are deferred per the module doc comments. The `EESProfile`/`EESRegistration` structures sent to the ECS are documented in code as TS 29.558 §8 *subsets*.

## Example configuration

From `nextgcore/docker/rust/configs/5gc/ees.yaml` (mounted read-only to `/etc/nextgcore/ees.yaml` by `docker-compose.yml`):

```yaml
# EES (Edge Enabler Server) Configuration
logger:
  level: info

ees:
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.31
        port: 7777
  nrf:
    uri: http://172.23.0.10:7777
```

The docker deployment does its real configuration on the command line: `command: ["--sbi-addr", "172.23.0.31", "--sbi-port", "7777", "--nrf-uri", "http://172.23.0.10:7777"]`. Note that `--nrf-uri` is a flag the current `Args` struct no longer defines — the `--ecs-uri` doc comment states it "Replaces the former `--nrf-uri`" (eesd-01 removed NRF self-registration) — so the shipped compose command line is stale relative to the current binary.

## YAML parameters

**None.** The daemon defines no `#[derive(Deserialize)]` configuration struct and never reads the file named by `-c/--config`. All `Deserialize` structs in this crate are SBI message bodies (`types.rs`, `services.rs`, `acr.rs`, `acrevents.rs`, `eec.rs`, `ecs_registration.rs`), not configuration. If you need to change the bind address, port, capacity, ECS URI, or OAuth2 keys, use the command-line flags below — editing `ees.yaml` has no effect on `nextgcore-eesd`.

### Parsed-but-inert / decorative YAML fields

Since the YAML file is never parsed, **every** field in the shipped example is decorative:

- **`logger.level` is inert.** The log level comes from the CLI flag `-e/--log-level` (default `info`) or `RUST_LOG`.
- **`ees.sbi.server[]` (address/advertise/port) is inert.** The SBI bind address and port come from `--sbi-addr`/`--sbi-port`; the same values are what the EES advertises in its ECS-registration `EndPoint`.
- **`ees.nrf.uri` is inert and doubly stale.** The EES does not register with the NRF at all (eesd-01); the ECS apiRoot is `--ecs-uri`, a CLI flag only.

The file exists for visual consistency with the other NF configs and to satisfy the compose volume mount.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-eesd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/ees.yaml` | Configuration file path. **Accepted but never read** by the daemon. |
| `-l, --log-file` | path | unset | Log file path. **Parsed but never consumed** — logging goes through `env_logger` regardless. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`). `RUST_LOG` takes precedence when set. |
| `-m, --no-color` | flag | off | Disable color output. **Parsed but never consumed.** |
| `--sbi-addr` | string | `0.0.0.0` | SBI server bind address; also placed in the `EESRegistration` endpoint sent to the ECS. |
| `--sbi-port` | u16 | `7814` | SBI server port (docker deployments pass `7777`). |
| `--tls` | flag | off | Enable TLS on the SBI server. |
| `--tls-cert` | path | `/etc/nextgcore/tls/server.crt` (when `--tls`) | TLS certificate file. |
| `--tls-key` | path | `/etc/nextgcore/tls/server.key` (when `--tls`) | TLS private key file. |
| `--max-eas` | usize | `512` | Capacity cap, applied **per resource family** (see behavior notes). |
| `--ecs-uri` | string | unset | ECS apiRoot for EES self-registration over EDGE-6 (TS 29.558 §9.1 per code comment). When unset, the registration request is built and logged but skipped. |
| `--ees-id` | string | fresh `ees-<UUIDv4>` per start | EES identifier advertised to the ECS (`eesId`). |
| `--oauth2-jwks-file` | path | unset | JSON JWKS used to verify OAuth2 access tokens (CAPIF/NRF issuer). When unset, **every protected operation fails closed with 401** (authorization is mandatory, TS 29.558 §6 per code comment). |
| `--callback-max-attempts` | u32 | `3` | Max delivery attempts per notification callback, including the first (clamped to ≥ 1); exhausting the budget drops the notification. |
| `--callback-backoff-ms` | u64 | `1000` | Base backoff between callback retries; a `Retry-After` response header takes precedence (RFC 9110 §10.2.3 per code comment). |
| `--callback-timeout-secs` | u64 | `5` | Per-attempt callback request timeout. |

## Behavior notes

- **OAuth2 is fail-closed and per-operation** (eesd-08, `auth.rs`): every `eees-*` route runs `require_oauth2` *before* method dispatch. No JWKS configured, or a missing/invalid/expired bearer → 401; a valid token whose space-delimited `scope` lacks the per-API scope (the scope string equals the apiName, e.g. `eees-easregistration`) → 403 `INSUFFICIENT_SCOPE`. The shipped docker-compose command passes no `--oauth2-jwks-file`, so in that deployment every protected EES operation answers 401; `main.rs` logs a startup warning to that effect.
- **ECS, not NRF**: with `--ecs-uri` set, the EES POSTs an `EESRegistration` to `{ecsApiRoot}/eecs-eesregistration/v1/registrations` and, on 200/201, spawns a refresh task that PUTs the resource every 60 s. A failed initial POST is logged (`will operate without ECS`) and **not retried**; without `--ecs-uri` the daemon runs standalone.
- **Capacity and rejection**: the single `--max-eas` value caps each resource family independently in `context.rs` — EAS registrations, EEC registrations, discovery subscriptions, AC-information subscriptions, ACR-management-event subscriptions, ACR-events subscriptions, and stored EEC contexts. On exhaustion, create handlers return **507** with cause `INSUFFICIENT_RESOURCES`. Mandatory-IE violations return 400 `MANDATORY_IE_MISSING`; malformed JSON returns 400 `INVALID_MSG_FORMAT`; changing an immutable `easId`/`eecId` on update returns 403 `MODIFICATION_NOT_ALLOWED`.
- **Registration lifecycle** (eesd-12): a sweep every 30 s (`LIFECYCLE_SWEEP_INTERVAL_SECS`) drops expired EAS/EEC registrations; an EEC registration created without `expTime` is minted one 3600 s out (`DEFAULT_EEC_REG_LIFETIME_SECS` in `eec.rs`). All state is in-memory only — there is no state file, and the context is cleared on shutdown.
- **Notification callbacks** (D6, `notifier.rs`): every subscription callback is POSTed to its `notificationDestination` through a bounded queue (default capacity 1024; a full queue drops the newest with a warning) with bounded retry per the `--callback-*` flags; `suppFeat` negotiation echoes the hex-AND of the consumer's mask with `EES_SUPPORTED_FEATURES = 0x1` (`types.rs`).
- **Environment variables**: `RUST_LOG` overrides `-e/--log-level` (the `env_logger` builder uses the flag only as the default filter), and `OTEL_EXPORTER_OTLP_ENDPOINT` sets the OpenTelemetry OTLP exporter endpoint, defaulting to `http://jaeger:4317` when unset. These are the only env vars read by this binary's sources.
