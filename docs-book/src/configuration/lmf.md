# LMF Configuration

The LMF (Location Management Function, `nextgcore-lmfd`) computes UE position fixes for the 5G core, per TS 23.273 (as cited in the daemon's source comments). It serves the `Nlmf_Location` service under the apiName `nlmf-loc` (TS 29.572 §6.1.1 per code comments): `POST /nlmf-loc/v1/determine-location` (§6.1.4.2), the custom operations `cancel-location`, `location-context-transfer`, `measure-location`, `configure-up`, and `up-subscriptions` (§6.1.4 per code comments), plus a `GET /nlmf-loc/v1/capabilities` query. It also serves two Namf_Communication notify callbacks — `POST /nlmf-loc/v1/notify/n1` and `/notify/n2` (TS 29.518 §5.2.2.4 N1MessageNotify / §5.2.2.3.3 N2InfoNotify per code comments) — which complete pending positioning sessions from uplink LPP/NRPPa reports. For deferred PERIODIC location requests the LMF acts as an outbound EventNotify producer, POSTing `EventNotifyDataExt` to the request's `hgmlcCallBackURI` (TS 29.572 §6.1.5.1 per code comments); UPNotify (§6.1.5.2) is deferred. Six additional ingest routes (`measurements`, `nrppa-reports`, `nrppa-binary-reports`, `lpp-binary-reports`, `ue-locations/{supi}`) are explicitly marked in the source as **not** TS 29.572 resources and are gated behind `--debug-endpoints` (default off).

Configuration is split between a YAML file (default path `/etc/nextgcore/lmf.yaml`, overridable with `-c/--config`), command-line flags, and two environment variables. Unusually for this project, the LMF reads almost nothing from YAML: the file is probed exactly once, for the OAuth2 knob. Bind address/port, TLS, the NRF URI, the measurement-pool cap, and the debug-route gate are all CLI flags.

> **Honesty note:** LMF behavior is validated by this project's own unit tests and matched-simulator Docker E2E only — not third-party conformance certification (positioning is not on the matched-sim registration+PDU+ping path, so E2E coverage of these flows is limited). The six `--debug-endpoints` ingest routes and the `capabilities` endpoint are bespoke NextGCore extensions, not TS 29.572 resources. UPNotify and area/motion-event triggered LDR are not implemented (scoped out per code comments).

## Example configuration

From `nextgcore/docker/rust/configs/5gc/lmf.yaml`:

```yaml
# LMF (Location Management Function) Configuration
logger:
  level: info

lmf:
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.32
        port: 7777
  nrf:
    uri: http://172.23.0.10:7777
```

## YAML parameters

The LMF defines **no** `#[derive(Deserialize)]` configuration structs. The only read of the config file is the `oauth2_required()` function in `src/bins/nextgcore-lmfd/src/main.rs`, which parses the file as an untyped `serde_yaml::Value` and probes one path (the `Deserialize` structs in `nlmf.rs` are SBI message payloads, not configuration).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `lmf.sbi.oauth2.require` | bool | `false` | SBI OAuth2 bearer-token enforcement (TS 33.501 §13.4.1, TS 29.510 §5.4.2 per code comments). The probe is root-key agnostic: it is `true` iff **any** top-level YAML section carries `sbi.oauth2.require: true`. When enabled, incoming requests must carry an NRF-issued token whose audience includes `LMF` (verified against the NRF JWKS; with no NRF URI configured the server fails closed with 503, per the code comment referencing `nextgcore-sbi` server.rs), and outbound SBI calls attach tokens. An unreadable or unparseable file, or an absent field, means `false`. The environment variable `NEXTGCORE_SBI_OAUTH2_REQUIRE` is checked **first** and, when set, decides in either direction — the YAML is not consulted at all. |

### Parsed-but-inert / decorative YAML fields

Everything else in the shipped example file is decorative — unknown keys are silently ignored:

- **`logger.level` is inert.** The log level comes from the CLI flag `-e/--log-level` (default `info`), overridable by `RUST_LOG`.
- **`lmf.sbi.server[]` (address/advertise/port) is inert.** The SBI bind address and port come only from `--sbi-addr`/`--sbi-port`; the docker deployment passes them on the command line (`--sbi-addr 172.23.0.32 --sbi-port 7777`).
- **`lmf.nrf.uri` is inert.** The NRF URI comes only from the `--nrf-uri` flag (default `http://127.0.0.1:7777`). The docker deployment passes `--nrf-uri http://172.23.0.10:7777` explicitly — setting only the YAML field has no effect.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-lmfd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/lmf.yaml` | Configuration file path (probed only for `sbi.oauth2.require`). |
| `-e, --log-level` | string | `info` | Log level (env_logger filter; `RUST_LOG` takes precedence when set). |
| `-l, --log-file` | path | unset | Accepted but currently **unused** — the daemon never reads this field. |
| `-m, --no-color` | flag | off | Accepted but currently **unused**. |
| `--sbi-addr` | string | `0.0.0.0` | SBI server bind address. Also used as the advertised host for N1N2 notify callback URIs — `0.0.0.0` falls back to `127.0.0.1` (see behavior notes). |
| `--sbi-port` | u16 | `7816` | SBI server port (docker deployments pass `7777`). |
| `--tls` | flag | off | Enable TLS on the SBI server. |
| `--tls-cert` | path | `/etc/nextgcore/tls/server.crt` (when `--tls`) | TLS certificate file. |
| `--tls-key` | path | `/etc/nextgcore/tls/server.key` (when `--tls`) | TLS private key file. |
| `--max-measurements` | usize | `1024` | Maximum concurrent measurement contexts in the LMF context store. When full, new positioning sessions fail with 500 `POSITIONING_FAILED` ("measurement store exhausted"). |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | NRF base URI for registration, heartbeat, AMF discovery, and (when OAuth2 is on) token issuance/JWKS. |
| `--debug-endpoints` | bool | `false` | Enable the six bespoke/debug ingest routes (`measurements`, `nrppa-reports`, `nrppa-binary-reports`, `lpp-binary-reports`, `ue-locations`). Fail-closed by default: when disabled these paths 404 exactly like any unknown path (no route disclosure), and in particular `PUT ue-locations/{supi}` — which would inject an arbitrary client-supplied fix — is unreachable. Marked in source as "must not be enabled in production". |

## Behavior notes

- **Environment variables.** `NEXTGCORE_SBI_OAUTH2_REQUIRE` (`1`/`true`/`TRUE`/`yes` = on) overrides the YAML OAuth2 knob in both directions and is how the `docker-compose.oauth2.yml` overlay enables enforcement. `OTEL_EXPORTER_OTLP_ENDPOINT` sets the OpenTelemetry OTLP exporter endpoint (default `http://jaeger:4317`). `RUST_LOG`, when set, overrides `--log-level` via env_logger.
- **NRF registration is best-effort, no retry.** At startup the LMF PUTs an NFProfile (`nfType: LMF`, service `nlmf-loc`, `allowedNfTypes: [AMF, SCP]`, `heartBeatTimer: 10`) to `/nnrf-nfm/v1/nf-instances/{id}`. On failure it logs a warning and **operates without NRF** — and the heartbeat worker is only spawned after a successful registration. On success it heartbeats every 5 s, PATCHing a real `/load` gauge derived from the active positioning-session count saturated at 100 (TS 29.510 §5.2.2.3.2 per code comment) — no fabricated CPU numbers.
- **DetermineLocation never fabricates a fix.** A real measurement-derived fix returns 200 `LocationDataExt`; failures map per the TS 29.572 Table 6.1.7.3-1 cause table (per code comments): no discoverable serving AMF, UE not reachable, or timeout → 504 `UNREACHABLE_USER`; report received but unsolvable → 500 `POSITIONING_FAILED`; malformed `InputData`, `ecgi`+`ncgi` together, or a dangling multipart `contentId` → 400; unsupported media type → 415. A stored per-SUPI fix short-circuits the procedure only when its capture timestamp allows an honest `ageOfLocationEstimate`.
- **Response-time budget.** The handler waits `min(maxRespTime, QoS bound, 20 s hard cap)` for the positioning outcome; `responseTime: LOW_DELAY` caps the wait at 5 s and `NO_DELAY` waits not at all (`maxRespTime: 0` is rejected 504 immediately). SBI client timeouts (2 s connect / 3 s request) nest inside this cap.
- **Callback reachability.** The N1N2 notify callback base advertised to the AMF is `http://<sbi-addr>:<sbi-port>`; when `--sbi-addr` is the default `0.0.0.0` it falls back to `127.0.0.1`, so in any multi-host or container deployment you must bind to (or pass) a concretely reachable address — the docker compose passes `172.23.0.32`.
- **No state file.** All measurement contexts, positioning sessions, LDR registrations, and stored fixes live in memory and are lost on restart; periodic-LDR scheduler tasks are aborted on shutdown, and EventNotify delivery retries exactly once before auto-cancelling the deferred session (no infinite retry).
