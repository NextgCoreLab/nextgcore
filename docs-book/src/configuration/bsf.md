# BSF Configuration

The BSF (Binding Support Function, `nextgcore-bsfd`) stores and serves PCF binding information so that policy consumers (e.g. an AF or NEF via PCF) can find the PCF that owns a given PDU session, UE, or MBS session. It serves the `Nbsf_Management` API (TS 29.521, as cited throughout the daemon's source comments): `/nbsf-management/v1/pcfBindings` (PDU-session bindings, full POST/GET/PATCH/DELETE plus query-based discovery), `/nbsf-management/v1/pcf-ue-bindings` (UE-policy bindings, TS 29.521 §4.2.2.3/§4.2.4.3 per code comments), and `/nbsf-management/v1/pcf-mbs-bindings` (MBS-session bindings, TS 29.521 §4.2.2.4/§4.2.4.4 per code comments). It also serves `/nbsf-management/v1/subscriptions` (event Subscribe/Unsubscribe/Notify, TS 29.521 §4.2.6–§4.2.8) — new in #98, which removed the `bsfd-13` 501 stub that sat on `pcfBindings/.../subscriptions`, a path the spec does not define, while the spec's own top-level resource was unrouted and answered 405. Routing and handlers live in `bsf_sbi_request_handler` in `src/bins/nextgcore-bsfd/src/lib.rs` — since the Wave-6 H1 lib-targetization, `main.rs` is a thin wrapper around `nextgcore_bsfd::run()`.

Configuration is split between a YAML file (default path `/etc/nextgcore/bsf.yaml`, overridable with `-c/--config`; the docker deployment passes `-c /etc/nextgcore/bsf.yaml`) and command-line flags. Unusually for this codebase, the YAML SBI `server` entry **overrides** the CLI `--sbi-addr`/`--sbi-port` (so the NRF NFProfile advertises a routable endpoint instead of `0.0.0.0`, per the code comment); everything else — TLS flags, session capacity, log level — is CLI-only. The only environment variable the binary reads is `OTEL_EXPORTER_OTLP_ENDPOINT`.

> **Honesty note:** BSF behavior is validated by this project's own unit tests and matched-simulator Docker E2E runs (84/84 as of 2026-07-02), not by third-party conformance certification. Known gaps visible in the source: the `--tls` flag does **not** enable TLS on the actual HTTP/2 listener (it only flips the advertised URI scheme in the legacy NF-instance metadata built in `sbi_path.rs`); the daemon is **memory-only** by decision — bindings and subscriptions do not survive a restart, see [Durability](#durability-bsfd-is-a-memory-only-nf); and `sbi_path.rs` still contains legacy placeholder helpers (`bsf_sbi_send_request`/`bsf_sbi_discover_and_send` return a hardcoded transaction ID).

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
- **Event subscriptions and notifications** (#98, TS 29.521 §4.2.6–§4.2.8). `POST /nbsf-management/v1/subscriptions` creates a subscription (201 + `Location`), `PUT /subscriptions/{subId}` replaces it (200; 404 when unknown) and `DELETE` removes it (204; 404 when unknown). `BsfSubscription` requires **four** members — `events`, `notifUri`, `notifCorreId` and `supi` — and a `notifUri` that is not an absolute `http(s)` URI is refused at ingress rather than failing silently at every notification.
  - On PCF-binding **register** and **deregister** (both PDU-session and UE bindings) the BSF POSTs a `BsfNotification` to each matching subscriber. The `notifCorreId` + `eventNotifs` form is emitted, so both members are always present — `BsfNotification`'s `oneOf` is satisfied by neither branch if `eventNotifs` appears without `notifCorreId`. The notification carries the binding identity (`pcfForPduSessInfos` or `pcfForUeInfo`), not just an id, so a consumer can tell **which** PCF now serves the session — the point of a PCF watching for a binding created by a different PCF.
  - Matching is **per-SUPI**, because `supi` is a required member of the subscription: a binding for another UE, an event the subscription did not request, a binding with no SUPI, and an expired subscription all match nothing.
  - Only the four events this BSF can actually observe are reportable (`PCF_PDU_SESSION_BINDING_REGISTRATION`/`_DEREGISTRATION`, `PCF_UE_BINDING_REGISTRATION`/`_DEREGISTRATION`). `SNSSAI_DNN_BINDING_*` has no producer here, so a subscription naming only those is refused rather than accepted and never fired; an **unrecognised** token alongside a reportable one is accepted, since `BsfEvent` is an `anyOf`.
  - Delivery is fire-and-forget per subscriber with bounded timeouts, so a subscriber that is down adds no latency to binding CRUD.
- **Spec-clean binding responses** (#98). `PcfBinding` responses no longer carry the bespoke `expiry` attribute — TS 29.521 defines `expiry` on the **subscription** resource, not on `PcfBinding`, so emitting it made every binding response fail strict schema validation. The value is still honoured for the TTL timer below. `GET /pcfBindings/{bindingId}` is likewise no longer served: the spec defines only `DELETE` and `PATCH` there, so it answers 405 with an `Allow: DELETE, PATCH` header. Discovery via `GET /pcfBindings?...` is unaffected, and a PATCH response already returns the updated representation.
- **Binding TTL**: every PDU-session binding arms an expiry timer — from the RFC 3339 `expiry` attribute when supplied (invalid values are rejected 400), otherwise the default TTL of **3600 s** (`timer::defaults::BINDING_EXPIRY` in `src/bins/nextgcore-bsfd/src/timer.rs`). The event loop removes expired bindings, and expired-but-unswept bindings are excluded from GET/discovery.
- **NRF registration and load reporting**: the BSF PUTs an NFProfile (`nfType: BSF`, service `nbsf-management`, `allowedNfTypes: PCF/SMF/SCP`, `heartBeatTimer: 10`) to `/nnrf-nfm/v1/nf-instances/{id}` and, on success, spawns a heartbeat worker every **5 s** that PATCHes a live `/load` gauge computed as bindings vs. `--max-sess` capacity (TS 29.510 §5.2.2.3.2 per code comment). Registration failure is non-fatal ("will operate without NRF"). Quirk: passing `--nrf-uri` on the CLI additionally triggers a second, legacy registration with a separate random NF instance ID from `bsf_sbi_open` (`sbi_path.rs`); the YAML-configured URI only drives the main registration path.
- **Environment variables**: the only one read is `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://jaeger:4317`) for the OpenTelemetry OTLP exporter. `RUST_LOG` is not honored, and MongoDB persistence has no URI source in this binary at all — the `bsf_bindings` upsert/delete/load calls are best-effort no-ops (failures logged at debug) unless some in-process embedder initializes the shared DBI layer first.

## Durability: bsfd is a memory-only NF

**Decided deliberately, not by omission.** Every resource this BSF holds — PDU-session bindings, UE
bindings, MBS bindings and event subscriptions — lives in process memory and is **lost when the daemon
restarts**. There is no state file and no database connection: the `bsf_bindings` MongoDB helpers exist in
`context.rs` but the daemon never calls `nextgcore_mongoc_init` / `nextgcore_dbi_init`, so every
upsert/delete/load is a best-effort no-op that logs at debug. A source guard
(`bsfd_is_declared_memory_only` in `context.rs`) fails the build's test suite if a future change initialises
the DBI layer without updating this section, so this statement cannot quietly stop being true.

### What a consumer must do

After a BSF restart, a consumer must:

1. **re-register its bindings.** A `GET /pcfBindings?ipv4Addr=…` for a session registered before the restart
   returns **204** (no match), which is the same answer as "never registered" — deliberately, because it is
   the truth. The PCF or SMF that owns the binding is the only party that can restore it.
2. **re-subscribe.** A `POST /nbsf-management/v1/subscriptions` from before the restart is gone, and no
   notification will be delivered for it. `DELETE` on its `{subId}` answers 404.

Nothing is silently degraded: there is no path that returns a stale binding or accepts a notification
subscription it will not honour.

### Why restoring bindings would be *worse* than losing them

This is the reason the memory-only posture is a decision rather than a gap to be filled later.

A TS 29.521 binding is a **live** association between a UE's PDU session and the PCF currently serving it.
While the BSF is down, that association can change: the session can be released, or a different PCF can take
it over. A restored binding therefore asserts a fact that may no longer hold — and a consumer that reads it
is told **the wrong PCF**, which is worse than being told nothing, because "nothing" makes it re-discover
while a wrong answer makes it send policy traffic to a PCF that does not serve the session.

Restoring subscriptions **alone** would be worse still, and is specifically not done: a subscriber that
survived a restart while its bindings did not would either be notified about nothing at all, or — if the
sweep treated absent bindings as removed — be told bindings "deregistered" that were simply never restored.
That is a fabricated event, which is the failure this project treats as most serious.

### What would have to change to make it durable

Recorded so the option stays open and costed, rather than being rediscovered:

1. **bindings first, subscriptions with them** — never subscriptions alone, for the reason above.
2. a URI source for the DBI layer (there is none in this binary today: no config key, no environment
   variable) plus a `nextgcore_dbi_init` call on the startup path, and a decision about whether a database
   that is unreachable at boot is fatal or degrades to memory-only;
3. a **recovery-time** answer for the staleness above — most plausibly writing `recoveryTime` on each
   binding and refusing to serve a restored binding whose owning PCF has not reconfirmed it, which is a
   protocol addition rather than a storage change;
4. the durable-snapshot hazards this project has already paid for elsewhere: restore **before** the SBI
   listener accepts, persist removals as well as inserts, and never resurrect a deleted record.
