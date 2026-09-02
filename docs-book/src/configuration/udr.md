# UDR Configuration

The UDR (Unified Data Repository, `nextgcore-udrd`) stores and serves subscriber data to the UDM, policy data to the PCF, and exposure/application data, per TS 29.504 and TS 29.505 (as cited in the daemon's source comments). It serves a single SBI service, `Nudr_DataRepository` (`/nudr-dr/v1/...`) — the request router in `udr_sbi_request_handler` returns 404 for any other service name. Under `nudr-dr` it implements the `subscription-data` tree (authentication-subscription, authentication-status, provisioned-data `am-data`/`smf-selection-subscription-data`/`sm-data` incl. the combined GET with `dataset-names` and the `fields` partial-retrieval parameter per TS 29.504 §6.1.4.2 code comments, context-data `amf-3gpp-access` and `smf-registrations`, and `subs-to-notify`), the `policy-data/ues/{supi}` tree (`am-data`, `sm-data`, `ue-policy-set` — TS 29.519 shapes per code comments), and the `exposure-data` and `application-data` trees (`pfds` per TS 29.551 code comment, `influenceData`, plus their `subs-to-notify` subscriptions).

Configuration is split between a YAML file (default path `/etc/nextgcore/udr.yaml`, overridable with `-c/--config`), command-line flags, and environment variables. The YAML file is the source for the MongoDB URI, the advertised/bind SBI address and port (which, unlike most NFs, **override** the CLI flags when present), the NRF URI, and OAuth2 enforcement; logging, TLS, and state-file persistence are CLI-flag (or env-var) territory. Two environment variables provide fallbacks: `DB_URI` (when the YAML has no `db_uri`) and `NEXTGCORE_UDR_STATE_FILE` (when `--state-file` is not given).

> **Honesty note:** UDR behavior is validated by this project's own unit tests and matched-simulator docker E2E runs, not by third-party conformance certification. The non-subscriber resource trees (context-data, exposure-data, application-data, policy provisioning, subscriptions) are a bespoke in-memory store with an optional JSON snapshot file — not a real database backend; only the subscriber data path goes to MongoDB. Resource shapes mirror TS 29.504/29.505/29.519 terminology as documented in code comments. A legacy ported-C handler/state-machine path (`nudr_handler.rs`, `udr_sm.rs`) exists in the crate but is explicitly *not wired* to the live SBI server (udrd-09 per the `lib.rs` comment).

## Example configuration

From `nextgcore/docker/rust/configs/5gc/udr.yaml`:

```yaml
# UDR (Unified Data Repository) Configuration
# Docker container configuration for 5G Core deployment

db_uri: mongodb://172.23.0.2/nextgcore

logger:
  file:
    path: /var/log/nextgcore/udr.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

udr:
  sbi:
    server:
      - address: 172.23.0.20
        port: 7777
    client:
      nrf:
        - uri: http://172.23.0.10:7777
    # TLS configuration (G36: SBI TLS)
    # Enable: TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
    tls:
      enabled: false
      cert: /etc/nextgcore/certs/udr.crt
      key: /etc/nextgcore/certs/udr.key
      ca: /etc/nextgcore/certs/ca.crt
      min_version: "1.2"
```

An OAuth2-enforcing variant (`udr-oauth2.yaml`, used via `docker-compose.oauth2.yml`) is identical except it adds, under `udr.sbi`:

```yaml
udr:
  sbi:
    oauth2:
      require: true
```

Its header comment notes that NF consumers do not attach tokens yet, so the variant is for validating enforcement, not for the default E2E data-plane deployment.

## YAML parameters

These are the fields actually read by the daemon. The serde structs are `UdrYaml`/`UdrSection`/`SbiYaml`/`SbiServerYaml`/`SbiClientYaml`/`NrfClientYaml`/`SbiOauth2Yaml` in `src/bins/nextgcore-udrd/src/main.rs`; `db_uri` is *not* serde-deserialized — `parse_db_uri()` scans the file for a line starting with `db_uri:` (any indentation; the shipped files keep it top-level).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `db_uri` | string | env `DB_URI`, else `mongodb://172.23.0.2/nextgcore` | MongoDB connection URI for the subscriber database (auth subscriptions, provisioned-data). Precedence: YAML `db_uri` → `DB_URI` env var → hardcoded Docker default. Credentials are masked in logs. If MongoDB init fails the daemon warns and continues with hardcoded defaults. |
| `udr.sbi.server[]` | list | absent → CLI values used | Only the **first** entry is read; extra entries are ignored. |
| `udr.sbi.server[0].address` | string | absent → `--sbi-addr` (`0.0.0.0`) | **Overrides** the CLI bind address, and is also the address advertised in the NRF NFProfile — set here so the profile advertises a routable endpoint instead of `0.0.0.0` (per code comment). |
| `udr.sbi.server[0].port` | u16 | absent → `--sbi-port` (`7777`) | **Overrides** the CLI SBI port; used for both bind and NFProfile advertisement. |
| `udr.sbi.client.nrf[]` | list | absent → NRF registration skipped | Only the **first** entry is used. With no NRF URI the daemon logs "skipping NRF registration" and runs standalone. |
| `udr.sbi.client.nrf[0].uri` | string | required within the entry | NRF base URI for NF registration, heartbeat, and (when OAuth2 is on) JWKS fetching and token acquisition. There is **no** CLI fallback flag for the NRF URI. |
| `udr.sbi.oauth2.require` | bool | `false` | SBI OAuth2 bearer-token enforcement. When `true`, incoming requests are verified against the NRF's JWKS (fails closed if no NRF URI is configured), and a process-wide OAuth2 client is installed so outbound SBI calls attach NRF-issued Bearer tokens (Wave-6 H8 Phase A per code comment). No CLI override exists. |

## Parsed-but-inert / decorative YAML fields

The daemon deserializes only the fields above; unknown YAML keys are silently ignored by serde. In the shipped example files:

- **`logger.file.path` and `logger.level` are inert.** The log level comes only from the CLI flag `-e/--log-level` (default `info`); `init_logging` builds an `env_logger` filter directly from the flag and does not consult `RUST_LOG`. Logs always go to stderr — see the `--log-file` caveat below.
- **`global.max.ue` / `global.max.peer` are inert.** No struct deserializes the `global` section.
- **`udr.sbi.tls.*` (enabled/cert/key/ca/min_version) is inert.** `SbiYaml` has only `server`, `client`, and `oauth2` members; TLS is controlled exclusively by the CLI flags `--tls`/`--tls-cert`/`--tls-key`.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-udrd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/udr.yaml` | Configuration file path. |
| `-l, --log-file` | path | unset | **Accepted but currently unused** — `init_logging` never opens it; logging always goes to stderr. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); unrecognized values fall back to `info`. |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | **Stub**: logs "would send SIGTERM to running instance" and exits without signaling anything. |
| `--sbi-addr` | string | `0.0.0.0` | SBI server bind address. Overridden by `udr.sbi.server[0].address` when present. |
| `--sbi-port` | u16 | `7777` | SBI server port. Overridden by `udr.sbi.server[0].port` when present. |
| `--tls` | flag | off | Enable TLS on the SBI server. |
| `--tls-cert` | path | unset | TLS certificate file. |
| `--tls-key` | path | unset | TLS private key file. |
| `--state-file` | path | unset (but **set in the shipped Docker compose**, see below) | JSON snapshot file for the non-subscriber resource trees (exposure-data, application-data, smf-registrations, subs-to-notify, policy provisioning, amf-3gpp-access). Falls back to `NEXTGCORE_UDR_STATE_FILE`; empty strings are treated as unset. When neither is set the trees are in-memory only and lost on restart. |

## Behavior notes

- **Two-tier storage.** Subscriber data (authentication subscriptions, provisioned AM/SMF-selection/SM data, and derived policy defaults) is served from MongoDB via `nextgcore-dbi`; everything else lives in `data_store.rs`'s in-memory `UdrDataStore`. With a state file configured, every mutation snapshots the full store to disk (atomic temp+rename) and the file is reloaded at startup; persistence failures are logged, never propagated (best-effort durability per the doc comment).
- **NRF registration and heartbeat.** At startup the UDR PUTs an NFProfile (`nfType: UDR`, `allowedNfTypes: [UDM, PCF, AUSF, SCP]`, `heartBeatTimer: 10`, one `nudr-dr` v1 service) to `/nnrf-nfm/v1/nf-instances/{uuid}`. On success a heartbeat worker runs every 5 s and PATCHes a real `/load` gauge — the tracked-subscriber count saturated at 100 (TS 29.510 §5.2.2.3.2 per code comment). On failure it logs a warning and **operates without NRF** — there is no registration retry loop.
- **Change notifications are fire-and-forget.** `subs-to-notify` subscriptions on the subscription-data, exposure-data, influenceData, and application-data trees trigger real HTTP POSTs to the registered callback URI with a 2 s connect / 3 s request timeout; delivery failures are logged and never retried.
- **UE identifier handling** (TS 29.571 `VarUeId` forms per code comments): null-scheme SUCIs are converted to IMSI locally; syntactically valid but unprovisioned `nai-`/`gci-`/`gli-` identifiers get **404** `NOT_FOUND` (not 400); `extgroupid-` gets **501** `NOT_SUPPORTED`; anything else is **400** `INVALID_SUPI`.
- **PATCH on `authentication-subscription` stores exactly what is written** — the UDR applies the `/sequenceNumber/sqn` PatchItem verbatim with no SQN side effects; SQN advancement is the UDM/ARPF's job per the TS 33.102 Annex C.3 code comment (a previous unconditional +32 SEQ increment here was a bug, WSB-6).

## Durable state is on by default in Docker

`docker/rust/docker-compose.yml` sets `NEXTGCORE_UDR_STATE_FILE=/var/lib/nextgcore/udr-state.json`
and backs it with the `udr_state` named volume, so the resource trees survive both
`docker compose restart` and `up -d` recreating the container (issue #66).

The UDR is the most severe member of that issue: memory-only, a restart erases
every subscriber's `amf-3gpp-access` and `smf-registration` at once, and consumers
then receive authoritative-looking "not registered" answers for subscribers that
*are* registered.

Two things make enabling it safe rather than merely convenient:

* a **corrupt** snapshot is refused, not overwritten — the NF logs an error, starts
  empty, and declines to persist, so the unreadable file survives for recovery
  (see the shared-store section in [Configuration Overview](./overview.md));
* snapshots are written atomically, fsynced and `0600` — this file is keyed by
  IMSI.

**Kubernetes and Helm are not covered.** The `udr` manifest is a `Deployment` with
no volume for this, so persistence there still needs a `PersistentVolumeClaim` plus
`strategy: Recreate` (or conversion to a `StatefulSet`, as MongoDB uses). That is a
storage-topology decision rather than a config line, so it is deliberately left
out.

- **Environment variables**: `DB_URI` (MongoDB URI; read only when the YAML has no `db_uri` line), `NEXTGCORE_UDR_STATE_FILE` (state-file path; read only when `--state-file` is absent — the flag wins), and `OTEL_EXPORTER_OTLP_ENDPOINT` (OpenTelemetry OTLP exporter endpoint, default `http://jaeger:4317`).
