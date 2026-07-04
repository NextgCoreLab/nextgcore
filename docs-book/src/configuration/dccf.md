# DCCF Configuration

The DCCF (Data Collection Co-ordination Function, `nextgcore-dccfd`) is a Rel-17 optional NF, per TS 23.288 §6.7 as cited in the daemon's source comments, that brokers network data between producers (AMF, SMF, PCF, etc.) and analytics consumers (NWDAF, ADRF). It serves two SBI APIs, both routed in `dccf_request_handler` in `src/bins/nextgcore-dccfd/src/main.rs`: `Ndccf_DataManagement` (TS 29.574 §5.2 per code comment — `POST/GET/DELETE /ndccf-datamanagement/v1/subscriptions[/{id}]` plus an inbound `POST /ndccf-datamanagement/v1/notify` that fans data out to subscribers) and `Ndccf_ContextDocument` (TS 29.574 §5.3 per code comment — `POST/GET/DELETE /ndccf-contextdocument/v1/contexts[/{id}]`). A `/healthz` endpoint answers `{"status":"ok"}` to any HTTP method.

Configuration is split between a YAML file (default path `/etc/nextgcore/dccf.yaml`, overridable with `-c/--config`), command-line flags, and environment variables — but for this daemon the split is extreme: **the YAML file carries exactly one live knob** (`sbi.oauth2.require`). Everything operational — bind address/port, NRF URI, TLS, the subscription cap — comes from CLI flags, and the docker deployment passes them explicitly (`--sbi-addr 172.23.0.36 --sbi-port 7777 --nrf-uri http://172.23.0.10:7777` in `docker-compose.yml`).

> **Honesty note:** DCCF behavior is validated by this project's own unit tests (including an in-crate OAuth2 enforcement triplet) and the matched-simulator docker E2E only — not by third-party conformance certification. Several behaviors are bespoke: subscription creation reads only `notifyUri` from the request body (event filters are ignored), notification fan-out goes to *every* subscriber with a callback URI rather than matching subscriptions to events, and the fan-out wraps the producer's payload in a NextGCore-specific `{"data": "<body>"}` envelope that is not a normative TS 29.574 notification shape.

## Example configuration

From `nextgcore/docker/rust/configs/5gc/dccf.yaml`:

```yaml
# DCCF (Data Collection Co-ordination Function) Configuration
logger:
  level: info

dccf:
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.36
        port: 7777
  nrf:
    uri: http://172.23.0.10:7777
  max_subscriptions: 4096
```

There is no OAuth2 YAML variant for DCCF; the OAuth2 overlay (`docker-compose.oauth2.yml`) enables enforcement via the environment variable `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` instead.

## YAML parameters

Unlike most NextGCore NFs, `nextgcore-dccfd` defines **no `#[derive(Deserialize)]` config structs at all**. The only code that reads the config file is the function `oauth2_required()` in `src/bins/nextgcore-dccfd/src/main.rs`, which parses the whole file as an untyped `serde_yaml::Value` and probes a single path. It is root-key agnostic: the knob is honored if *any* top-level section (conventionally `dccf:`) contains it.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `dccf.sbi.oauth2.require` | bool | `false` | SBI OAuth2 bearer-token enforcement (Wave-6 H8; TS 33.501 §13.4.1 and TS 29.510 §5.4.2 per code comments). When enabled, incoming requests must carry an NRF-issued token whose audience includes `DCCF`, verified against the NRF JWKS; with no NRF URI configured the server fails closed (503, per code comment). A missing, unreadable, or unparseable YAML file yields `false`. The environment variable `NEXTGCORE_SBI_OAUTH2_REQUIRE` is checked *first* and, when set to any value, decides the outcome in both directions (see Behavior notes). |

That is the complete list — no other YAML field influences the daemon.

### Parsed-but-inert / decorative YAML fields

Every other field in the shipped example file is decorative; since the file is only probed for `sbi.oauth2.require`, all other keys are silently ignored:

- **`logger.level` is inert.** The log level comes from the CLI flag `-e/--log-level` (default `info`) or `RUST_LOG`, not the YAML.
- **`dccf.sbi.server[]` (address/advertise/port) is inert.** The SBI bind address and port come from `--sbi-addr`/`--sbi-port`; the docker deployment passes them on the command line.
- **`dccf.nrf.uri` is inert.** The NRF URI comes exclusively from `--nrf-uri` (default `http://127.0.0.1:7777`); the docker deployment passes `--nrf-uri http://172.23.0.10:7777` explicitly.
- **`dccf.max_subscriptions` is inert.** The subscription cap comes from `--max-subscriptions`; the YAML value `4096` merely mirrors the CLI default.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-dccfd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/dccf.yaml` | Configuration file path (read only for the OAuth2 knob). |
| `-l, --log-file` | path | unset | **Parsed but unused** — declared in `Args` yet never referenced by the binary; logging goes to stderr via `env_logger`. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`). Overridden by `RUST_LOG` when set. |
| `-m, --no-color` | flag | off | **Parsed but unused** — declared in `Args` yet never referenced by the binary. |
| `--sbi-addr` | string | `0.0.0.0` | SBI server bind address; also advertised as the NF's `ipv4Addresses` in the NRF registration. |
| `--sbi-port` | u16 | `7816` | SBI server port ("TS 29.574 default: 7816" per code comment); docker deployments pass `7777`. |
| `--tls` | flag | off | Enable TLS on the SBI server. Takes effect only if **both** `--tls-cert` and `--tls-key` are also given; otherwise it is silently ignored. |
| `--tls-cert` | path | unset | TLS certificate file (no built-in default path). |
| `--tls-key` | path | unset | TLS private key file (no built-in default path). |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | NRF base URI for NF registration, heartbeats, and (when OAuth2 is on) JWKS/token endpoints. |
| `--max-subscriptions` | usize | `4096` | Maximum concurrent data-management subscriptions held in the in-memory context. |

## Behavior notes

- **Environment variables and precedence.** `NEXTGCORE_SBI_OAUTH2_REQUIRE` is consulted before the YAML: if the variable is set at all, it alone decides — `1`/`true`/`TRUE`/`yes` (after trim) enables enforcement, any other value disables it *even if the YAML says `require: true`*. `OTEL_EXPORTER_OTLP_ENDPOINT` sets the OpenTelemetry OTLP exporter endpoint (default `http://jaeger:4317`). `RUST_LOG` overrides `-e/--log-level` (the flag is only `env_logger`'s fallback filter).
- **Silent drop at capacity.** When the subscription table is full (`--max-subscriptions`), `POST /ndccf-datamanagement/v1/subscriptions` still returns **201 Created** with a fresh `subscriptionId` — the handler discards the capacity-check result, the daemon logs `subscription capacity exhausted`, and the subscription is *not* stored. A subsequent `GET` on the returned ID yields 404.
- **Fan-out is fire-and-forget.** `POST /ndccf-datamanagement/v1/notify` returns 204 immediately; the body is then POSTed asynchronously (one spawned task per target) to every subscriber that registered a non-empty `notifyUri`, wrapped as `{"data": "<original body>"}`. Delivery failures are only logged (`warn`), never retried, and there is no per-subscription event matching.
- **NRF registration is best-effort, no retry.** At startup the DCCF `PUT`s an NFProfile (`nfType: DCCF`, one `ndccf-datamanagement` v1 service, `allowedNfTypes: NWDAF/AMF/SMF/PCF`, `heartBeatTimer: 10`) to `/nnrf-nfm/v1/nf-instances/{id}`. On failure it logs a warning and keeps serving without NRF. On success it spawns a heartbeat worker every **5 s** that PATCHes a real `/load` gauge — the active subscription count saturated at 100 (TS 29.510 §5.2.2.3.2 per code comment; "honest subscription-count proxy — no fabricated CPU numbers").
- **No persistence.** Subscriptions and analytics contexts live only in an in-memory `Mutex`-guarded context (`src/bins/nextgcore-dccfd/src/context.rs`); there is no state file, so all registrations are lost on restart. `DELETE` of a missing subscription returns 404, but `DELETE` of a missing analytics context returns 204.
- **OAuth2 is inbound-only in practice.** With enforcement on, the server rejects missing or wrong-audience Bearer tokens with 401 before the handler runs (covered by in-crate tests). An outbound `OAuth2Client` is also installed, but no outbound call in this binary actually attaches a token — the accessor is marked `#[allow(dead_code)]` and the fan-out client never invokes `with_oauth2`.
