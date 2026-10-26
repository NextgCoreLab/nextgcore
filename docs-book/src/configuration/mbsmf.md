# MB-SMF Configuration

The MB-SMF (Multicast/Broadcast Session Management Function, `nextgcore-mbsmfd`) manages MBS sessions — create, update, release — plus multicast transport resources via N4mb PFCP toward the MB-UPF and TMGI-based session identification, per TS 23.247 and TS 29.532 (as cited in the daemon's source comments). Its SBI router (`mbsmf_sbi_request_handler` in `src/bins/nextgcore-mbsmfd/src/main.rs`) serves the `Nmbsmf_MBSSession` API (`/nmbsmf-mbssession/v1/mbs-sessions` create/get/update/release, the `ContextUpdate` custom operation at `/mbs-sessions/contexts/update`, and both Status and ContextStatus subscription sub-resources, TS 29.532 §5.3.2.2–.10 per code comments) and the `Nmbsmf_TMGI` API (`/nmbsmf-tmgi/v1/tmgi` allocate/deallocate, TS 29.532 §5.2 per code comments). On the user-plane control side it drives PFCP session establishment over N4mb with T1/N1 retransmission (TS 29.244 §6.4 per code comments), and the ContextUpdate AMF path decodes/encodes real N2 MBS SM containers (TS 38.413 §9.3.5.7–.10 per code comments).

Configuration is almost entirely CLI flags and environment variables. A YAML file exists (default path `/etc/nextgcore/mbsmf.yaml`, overridable with `-c/--config`), but the daemon reads exactly one knob from it — `sbi.oauth2.require` — via an untyped `serde_yaml::Value` probe; there are **no** `#[derive(Deserialize)]` config structs in this binary. Bind address/port, TLS, session limits, and the NRF URI all come from CLI flags; the N4mb/PFCP endpoints and TMGI PLMN come from environment variables.

> **Honesty note:** MB-SMF behavior is validated by this project's own unit tests (including an in-crate strict-peer round-trip test against the live ContextUpdate handler) and the matched-simulator Docker E2E setup, not by third-party conformance certification. Some conveniences are bespoke: the `GET /nmbsmf-mbssession/v1/mbs-sessions` list endpoint returns a NextGCore-shaped JSON summary, session URIs use a local `mbs-sess-{n}` id scheme, and the optional `/activate` and `/members*` debug routes are explicitly non-spec (gated off by default so the SBI surface is exactly the TS 29.532 resource set, per the code comment).

## Example configuration

From `nextgcore/docker/rust/configs/5gc/mbsmf.yaml`:

```yaml
# MB-SMF (Multicast/Broadcast Session Management Function) Configuration
logger:
  level: info

mbsmf:
  sbi:
    server:
      - address: 0.0.0.0
        advertise: 172.23.0.33
        port: 7777
  nrf:
    uri: http://172.23.0.10:7777
```

Note that in the docker deployment the values that actually matter are passed as CLI flags: the compose service runs `--sbi-addr 172.23.0.33 --sbi-port 7777 --nrf-uri http://172.23.0.10:7777` (see `docker/rust/docker-compose.yml`).

## YAML parameters

`nextgcore-mbsmfd` defines no typed config structs. The only YAML read is in `oauth2_required()` (`src/bins/nextgcore-mbsmfd/src/main.rs`), which parses the file as a generic `serde_yaml::Value` and probes one path:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `<section>.sbi.oauth2.require` | bool | `false` | SBI OAuth2 bearer-token enforcement (Wave-6 H8; TS 33.501 §13.4.1, TS 29.510 §5.4.2 per code comments). Root-key agnostic: it is `true` iff **any** top-level YAML section (e.g. `mbsmf:`) sets `sbi.oauth2.require: true`. A missing, unreadable, or unparsable config file means `false`. The env var `NEXTGCORE_SBI_OAUTH2_REQUIRE` takes precedence: if it is set at all, its value decides (`1`/`true`/`TRUE`/`yes` after trim = on; anything else = off) and the YAML is not consulted. When enabled, the server verifies incoming Bearer tokens against the NRF JWKS with expected audience `MBSMF`, and an outbound OAuth2 client is installed; with an empty NRF URI enforcement fails closed (503, per the code comment). |

### Parsed-but-inert / decorative YAML fields

Everything else in the shipped example file is decorative for this binary — the daemon never deserializes it:

- **`logger.level` is read.** The log level is `-e/--log-level` when given, else this file's `logger.level`, else `info`; `RUST_LOG`, when set, overrides all three (#691).
- **`mbsmf.sbi.server[0]` is read (#1312).** The SBI bind is `--sbi-addr`/`--sbi-port`, else `address`/`port` here, else `127.0.0.1` and the default port. The advertised host is `--sbi-advertise`, else `NEXTGCORE_SBI_ADVERTISE`, else `advertise` here, else the bind address when it is not a wildcard; it is used in the NRF registration. A wildcard is never advertised: with a wildcard bind and nothing set to advertise, the NF does not register and logs why. A config that does not parse fails startup (#1313).
- **`mbsmf.nrf.uri` is inert.** Unlike some other NFs (e.g. NSACF, which falls back YAML→CLI), the MB-SMF takes its NRF URI only from the `--nrf-uri` flag; the docker deployment passes it on the command line and the YAML entry merely mirrors it.

> **Clock:** this NF refuses to start when the local clock reads before 2020-01-01, because its PFCP Recovery Time Stamp would be wrong. See [A set clock is required](overview.md#a-set-clock-is-required-pfcp-nfs) for the remedy on RTC-less hosts.

## Command-line flags

Runtime knobs with real defaults from the clap `Args` struct in `main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/mbsmf.yaml` | Configuration file path (read only for the OAuth2 knob above). |
| `-e, --log-level` | string | `logger.level`, else `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else is `info`). Without the flag, the config's `logger.level`, else `info`; `RUST_LOG` overrides both (#691). |
| `-l, --log-file` | path | unset | Accepted but currently **unused** — the parsed value is never referenced. |
| `-m, --no-color` | flag | off | Accepted but currently **unused** — the parsed value is never referenced. |
| `--sbi-addr` | string | `mbsmf.sbi.server[0].address`, else `127.0.0.1` (#1308) | SBI server bind address; beats the YAML (#1312). |
| `--sbi-advertise` | string | unset | The advertised SBI host (#1312); then `NEXTGCORE_SBI_ADVERTISE`, then `mbsmf.sbi.server[0].advertise`, then the bind address when it is not a wildcard. |
| `--sbi-port` | u16 | `7812` | SBI server port (docker deployments pass `7777`). |
| `--tls` | flag | off | Enable TLS on the SBI server. |
| `--tls-cert` | path | `/etc/nextgcore/tls/server.crt` (when `--tls`) | TLS certificate file. |
| `--tls-key` | path | `/etc/nextgcore/tls/server.key` (when `--tls`) | TLS private key file. |
| `--max-sessions` | usize | `256` | Maximum concurrent MBS sessions in the context pool. |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | NRF base URI for registration, heartbeat, and (when OAuth2 is on) JWKS/token issuance. |

## Behavior notes

- **Session admission is pool-capped, not quota-based.** `session_add` (`context.rs`) refuses new sessions once `--max-sessions` is reached; the `POST /mbs-sessions` handler then returns **400** with cause `CREATION_FAILED` (not 503). All session, subscription, and TMGI state is in-memory only — there is no state file, so everything is lost on restart.
- **NRF registration is best-effort.** At startup the MB-SMF `PUT`s an NF profile (`nfType: MB_SMF`, services `nmbsmf-mbssession` and `nmbsmf-tmgi`, `allowedNfTypes: AMF/SMF/NEF/SCP`, `heartBeatTimer: 10`) to `--nrf-uri`. A failure logs a warning and the daemon **operates without NRF** — no retry loop. On success a heartbeat worker runs every 5 seconds and PATCHes a real `/load` gauge: the active MBS-session count saturated at 100 (TS 29.510 §5.2.2.3.2 per code comment — "honest session-count proxy, no fabricated CPU numbers"). A heartbeat the NRF answers with 404 re-registers the profile (#434), and the NF deregisters from the NRF on shutdown (#235).
- **N4mb PFCP endpoints come from environment variables.** The persistent PFCP node targets `MB_UPF_ADDR` (default `127.0.0.7`) : `UPF_PFCP_PORT` (default `8805`), using `MBSMF_N4MB_ADDR` (default `127.0.0.1`) as the CP Node ID / F-SEID address. Requests are retransmitted on T1 expiry (3 s) up to N1 = 2 times (TS 29.244 §6.4 per code comments). The lower-layer SSM for multicast delivery is source = MB-UPF address, destination = a deterministic admin-scoped group `239.1.x.y` derived from the session id.
- **TMGI allocation** (`POST /nmbsmf-tmgi/v1/tmgi`) uses the serving PLMN from `MBSMF_PLMN_MCC`/`MBSMF_PLMN_MNC` (defaults `001`/`01`) and a fixed TTL of **3600 s** (`TMGI_DEFAULT_TTL_SECS`); expired entries are purged lazily on the next allocate/refresh. A session create that carries no TMGI gets the default TMGI `010203` in PLMN 001/01.
- **Debug routes are opt-in.** Setting `MBSMF_DEBUG_ROUTES` to any non-empty value exposes the non-spec `/mbs-sessions/{id}/activate` and `/mbs-sessions/{id}/members[/{supi}]` routes; off by default so the SBI surface is exactly the TS 29.532 resource set (per the code comment).
- **Other environment variables:** `NEXTGCORE_SBI_OAUTH2_REQUIRE` (overrides the YAML OAuth2 knob, see above), `RUST_LOG` (overrides `-e/--log-level`; the docker compose sets `RUST_LOG: info`), and `OTEL_EXPORTER_OTLP_ENDPOINT` (OpenTelemetry OTLP exporter, default `http://jaeger:4317`).
