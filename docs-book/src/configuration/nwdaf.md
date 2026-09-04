# NWDAF Configuration

The NWDAF (Network Data Analytics Function, `nextgcore-nwdafd`) collects network data from other NFs and serves analytics to consumers (AMF, SMF, PCF, etc.), per TS 23.288 as cited in the daemon's module docs. Its SBI router serves three producer services: `Nnwdaf_AnalyticsInfo` (`GET /nnwdaf-analyticsinfo/v1/analytics` — HTTP GET with an `event-id` query parameter, TS 29.520 §4.3.2.2.2 per code comment), `Nnwdaf_EventsSubscription` (`POST /nnwdaf-eventssubscription/v1/subscriptions` plus `GET`/`PUT`/`DELETE` on `/subscriptions/{id}`), and `Nnwdaf_MLModelProvision` (`POST /nnwdaf-mlmodelprovision/v1/subscriptions` plus `PUT`/`DELETE` on `/subscriptions/{id}` — a Subscribe/Notify resource; the daemon deliberately serves no `/models` registry). It also exposes one consumer callback, `POST /nnwdaf-nfstatus-notify/v1/notify`, where the NRF delivers `Nnrf_NFManagement` NFStatusNotify bodies (TS 29.510 §5.2.2.6 per code comment) that feed the NF_LOAD analytics.

Configuration is split between a YAML file (default path `/etc/nextgcore/nwdaf.yaml`, overridable with `-c/--config`) and command-line flags — with the balance tipped much further toward flags than in most NextGCore NFs. The YAML file carries exactly **one** knob the daemon reads (OAuth2 enforcement); bind address/port, TLS, the NRF URI, subscription limits, and the NF instance ID are all CLI flags. A handful of environment variables (listed under Behavior notes) override or supplement both.

> **Honesty note:** NWDAF behavior is validated by this project's own unit tests (including strict-peer tests that run the real `nextgcore-nrfd` notify pipeline against the real NWDAF router in-process) and the matched-simulator Docker E2E — not by third-party conformance certification. Only **one** analytics event has a live data collector: `NF_LOAD`, fed by NRF NFStatusNotify (`SUPPORTED_EVENTS` in `context.rs`). Other TS 29.520 event tokens (e.g. `UE_MOBILITY`, `SLICE_LOAD_LEVEL`) are recognized but deliberately answer `204 No Content` rather than fabricating numbers, and the registered NF profile advertises only `nwdafInfo.eventIds: ["NF_LOAD"]`. The `/nnwdaf-nfstatus-notify/v1/notify` callback path is a NextGCore-chosen URI (callback URIs are consumer-chosen), not a TS 29.520 resource.

## Example configuration

From `nextgcore/docker/rust/configs/5gc/nwdaf.yaml`:

```yaml
# NWDAF (Network Data Analytics Function) Configuration
logger:
  level: info

nwdaf:
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.30
        port: 7777
  nrf:
    uri: http://172.23.0.10:7777
  analytics:
    ml_model_dir: /var/lib/nextgcore/models
```

In the OAuth2 overlay (`docker-compose.oauth2.yml`) the NWDAF is switched to enforcing mode via the environment variable `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` rather than a YAML change.

## YAML parameters

Unlike most NextGCore NFs, `nextgcore-nwdafd` defines **no** `#[derive(Deserialize)]` config structs. The only YAML access is the `oauth2_required()` function in `src/bins/nextgcore-nwdafd/src/main.rs`, which parses the whole file as an untyped `serde_yaml::Value` and extracts a single boolean. Everything else in the file is ignored (see the next section).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `nwdaf.sbi.oauth2.require` | bool | `false` | SBI OAuth2 bearer-token enforcement (Wave-6 H8; TS 33.501 §13.4.1, TS 29.510 §5.4.2 per code comments). The lookup is root-key agnostic: it is `true` iff *any* top-level YAML section sets `sbi.oauth2.require: true`. When enabled, incoming requests must carry an NRF-issued token whose audience includes `NWDAF` (verified against the NRF JWKS; unconfigured/empty NRF URI fails closed per the code comment), and an outbound OAuth2 client is installed for SBI calls. A missing, unreadable, or unparsable config file yields `false`. The environment variable `NEXTGCORE_SBI_OAUTH2_REQUIRE`, if set at all, wins outright: `1`/`true`/`TRUE`/`yes` (trimmed) enable enforcement, any other value disables it, and the YAML is never consulted. |

### Parsed-but-inert / decorative YAML fields

Everything in the shipped example except an (absent) `sbi.oauth2.require` key is decorative — the daemon never looks at it:

- **`logger.level` is inert.** The log filter comes from `RUST_LOG` (which wins, via `env_logger`'s default env) or else the CLI flag `-e/--log-level` (default `info`).
- **`nwdaf.sbi.server[]` (address/advertise/port) is inert.** The SBI bind address and port come exclusively from `--sbi-addr`/`--sbi-port`; the docker deployment passes `--sbi-addr 172.23.0.30 --sbi-port 7777` on the command line.
- **`nwdaf.nrf.uri` is inert.** The NRF URI comes exclusively from the CLI flag `--nrf-uri`; docker passes `--nrf-uri http://172.23.0.10:7777` explicitly. The YAML value exists only for visual consistency with other NF configs.
- **`nwdaf.analytics.ml_model_dir` is inert.** No code in the binary reads a model directory (or any file other than the config itself); the ML model provision service is metadata/subscription-based, not filesystem-backed.

## Command-line flags

Runtime knobs with real defaults from the clap `Args` struct in `src/bins/nextgcore-nwdafd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/nwdaf.yaml` | Configuration file path — consulted only for the OAuth2 knob above. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); `RUST_LOG` overrides it. |
| `-l, --log-file` | path | unset | **Accepted but currently unused** — the parsed value is never referenced; logs go to stderr regardless. |
| `-m, --no-color` | flag | off | **Accepted but currently unused** — the parsed value is never referenced. |
| `--sbi-addr` | string | `0.0.0.0` | SBI server bind address. Also used verbatim in the registered NFProfile `ipv4Addresses` and in the NFStatusNotify callback URI — see Behavior notes. |
| `--sbi-port` | u16 | `7815` | SBI server port (docker deployments pass `7777`). |
| `--tls` | flag | off | Enable TLS on the SBI server. |
| `--tls-cert` | path | `/etc/nextgcore/tls/server.crt` (when `--tls`) | TLS certificate file. |
| `--tls-key` | path | `/etc/nextgcore/tls/server.key` (when `--tls`) | TLS private key file. |
| `--max-subscriptions` | usize | `1024` | Capacity cap applied separately to the `Nnwdaf_EventsSubscription` pool and the `Nnwdaf_MLModelProvision` pool. |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | NRF base URI for registration, heartbeat, NFStatusSubscribe, and (when OAuth2 is on) token/JWKS. |
| `--state-file` | path | unset | JSON snapshot file for analytics and ML-provision subscriptions plus THRESHOLD edge state. Falls back to `NEXTGCORE_NWDAF_STATE_FILE` (the flag wins; an empty value is treated as unset). With neither set the NWDAF is memory-only — the shipped default. See Durable state below. |
| `--nf-instance-id` | string | unset (generates `nwdaf-<uuid4>`) | NF instance ID used for NRF registration and context init. |

## Behavior notes

- **NRF registration is best-effort, heartbeat carries a real load gauge.** Startup does a `PUT /nnrf-nfm/v1/nf-instances/{id}`; on failure it logs a warning and *operates without NRF* (no registration retry loop). On success a heartbeat worker ticks every 5 s and PATCHes the NFProfile `load` field with the live analytics-subscription count saturated at 100 (TS 29.510 §5.2.2.3.2 per code comment) — an "honest subscription-count proxy, no fabricated CPU numbers". The profile advertises `heartBeatTimer: 10`, `allowedNfTypes: [AMF, SMF, PCF, NEF, SCP]`, and `nwdafInfo.eventIds` derived from `SUPPORTED_EVENTS` (currently exactly `["NF_LOAD"]`).
- **Data collection callback uses `--sbi-addr` literally.** At startup the daemon sends an NRF NFStatusSubscribe (TS 29.510 §5.2.2.5 per code comment) with callback `http://<sbi-addr>:<sbi-port>/nnwdaf-nfstatus-notify/v1/notify`. With the default bind of `0.0.0.0` that callback URI is unroutable, so real deployments must pass a reachable address (docker passes the container IP `172.23.0.30`). Subscribe failures are non-fatal — the dispatcher tick retries/renews, and analytics simply degrade to no-data.
- **Admission/rejection semantics of the analytics query:** an unrecognized `event-id` token returns `400` with cause `INVALID_ANALYTICS_TYPE`; a recognized-but-unsupported event (anything outside `SUPPORTED_EVENTS`) returns `204 No Content` with an empty body; `NF_LOAD` with no ingested NRF data also returns `204` — after the data source deregisters, analytics deliberately "go dark" rather than serving stale or invented values. A NFStatusNotify body missing its mandatory `event` IE fails closed with `400`.
- **Subscription capacity:** both subscription pools are capped at `--max-subscriptions` (1024 each by default). At capacity, creation is refused and surfaces as a `400` (`SUBSCRIPTION_FAILED` for events subscriptions), not a 5xx.
- **Notification dispatcher:** a background task wakes every 30 s (`DEFAULT_DISPATCH_INTERVAL_SECS` in `notification_dispatcher.rs`, overridable via the `NWDAF_DISPATCH_INTERVAL_SECS` env var; unparsable values fall back to 30), computes analytics, and POSTs `Nnwdaf_EventsSubscription` notifications to all due subscribers. New subscriptions default to a 60 s repetition period, so the first notification arrives within roughly one tick.
- **Durable state (optional, off by default).** With `--state-file` or `NEXTGCORE_NWDAF_STATE_FILE` set, both subscription pools (`Nnwdaf_EventsSubscription` and `Nnwdaf_MLModelProvision`) and the THRESHOLD edge state are written to a JSON snapshot and reloaded at boot, before the SBI server accepts anything. Ingested analytics samples and the NWDAF's own NRF NFStatusSubscribe subscription are deliberately **not** persisted: the samples rebuild from NRF notifications within a tick or two, and re-subscribing at boot is safer than trusting a restored record — a stale one would make the NWDAF believe it has a collector channel it does not have, silently ending NF_LOAD collection. Three things worth knowing operationally:
  - An unreadable snapshot, or one written by a **newer** `nwdafd`, **fails startup** and is left untouched, rather than coming up empty and overwriting it. Move the file aside to start fresh.
  - Subscription create/update/delete is written synchronously, so a resource the NWDAF has acknowledged is durable. The dispatcher's per-tick bookkeeping (`last_notification_time`, `reports_sent`, the termination and ML-notified flags, threshold levels) is written **once per tick** instead of once per subscription — a full-store rewrite per counter bump would rewrite the whole file up to `--max-subscriptions` times every 30 s. A crash inside that window can repeat one notification; it cannot resurrect a deleted subscription.
  - Restoring is not capped by `--max-subscriptions`. A snapshot holding more records than the cap is restored in full and new subscriptions are refused until enough are deleted — dropping a restored subscription would 404 a consumer's live resource while the snapshot still claimed it existed.
- **Environment variables** read by this binary, with precedence: `NEXTGCORE_SBI_OAUTH2_REQUIRE` (beats the YAML OAuth2 knob whenever set), `RUST_LOG` (beats `-e/--log-level`), `NEXTGCORE_NWDAF_STATE_FILE` (loses to `--state-file`), `NWDAF_DISPATCH_INTERVAL_SECS` (default 30), and `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP tracing endpoint, default `http://jaeger:4317`; OTel init failure is non-fatal).
