# PCF Configuration

The PCF (Policy Control Function, `nextgcore-pcfd`) makes access-, session-, and application-level policy decisions for the 5G core, per TS 29.507, TS 29.512, TS 29.514 and TS 29.525 (as cited in the daemon's source comments). Its SBI router (`pcf_sbi_request_handler` in `src/bins/nextgcore-pcfd/src/app.rs`) serves four services: `Npcf_AMPolicyControl` (`/npcf-am-policy-control/v1/policies`), `Npcf_SMPolicyControl` (`/npcf-smpolicycontrol/v1/sm-policies`), `Npcf_PolicyAuthorization` (`/npcf-policyauthorization/v1/app-sessions`), and `Npcf_UEPolicyControl` (`/npcf-ue-policy-control/v1/policies`), plus a `N1MessageNotify` callback route (`/npcf-ue-policy-control/v1/notify/{polAssoId}/n1-message-notify`, TS 29.518 per code comments) on which the AMF returns the UE's MANAGE UE POLICY COMPLETE/REJECT. The binary itself is a thin wrapper: `main.rs` only calls `nextgcore_pcfd::run()`; all logic lives in the library crate (`lib.rs`/`app.rs`, Wave-6 lib-targetization).

Configuration is split between a YAML file (default path `/etc/nextgcore/pcf.yaml`, overridable with `-c/--config`), command-line flags, and an unusually large set of environment variables. The YAML file supplies the advertised SBI address/port, an optional FQDN, and the NRF URI; capacities and TLS-related flags are CLI-only; UE-policy delivery, URSP rules, UAV gating, the local PLMN, OAuth2 enforcement, and the OTLP endpoint are env-var driven.

> **Honesty note:** PCF behavior is validated by this project's own unit tests and matched-simulator Docker E2E runs, not by third-party conformance certification. Several pieces are explicitly bespoke or partial: the `urspRules` member the PCF reads from the UDR UePolicySet is a provisioning-side convention of this deployment, never a 3GPP wire field (documented as such in `ue_policy.rs`); the UAV flight-zone gate uses a hardcoded geofence (lat 37–38, lon −123…−122); the `intent_policy` module is Rel-20 research scaffolding not wired to any live handler; the `--tls*` flags do **not** enable TLS on the live HTTP/2 listener (see below); and `-k/--kill` and `-l/--log-file` are accepted but not functional (kill only logs and exits; no file logging is wired in `init_logging`).

## Example configuration

From `nextgcore/docker/rust/configs/5gc/pcf.yaml`:

```yaml
# PCF (Policy Control Function) Configuration
# Docker container configuration for 5G Core deployment

db_uri: mongodb://172.23.0.2/nextgcore

logger:
  file:
    path: /var/log/nextgcore/pcf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

pcf:
  sbi:
    server:
      - address: 172.23.0.13
        port: 7777
    client:
      nrf:
        - uri: http://172.23.0.10:7777
  metrics:
    server:
      - address: 172.23.0.13
        port: 9090
  # TLS configuration (G36: SBI TLS)
  # Enable: TLS_ENABLED=true SBI_SCHEME=https docker compose up -d
  tls:
    enabled: false
    cert: /etc/nextgcore/certs/pcf.crt
    key: /etc/nextgcore/certs/pcf.key
    ca: /etc/nextgcore/certs/ca.crt
    min_version: "1.2"
```

## YAML parameters

These are the fields actually deserialized by the daemon (`#[derive(Deserialize)]` structs `PcfYaml`/`PcfSection`/`SbiYaml`/`SbiServerYaml`/`SbiClientYaml`/`NrfClientYaml` in `src/bins/nextgcore-pcfd/src/app.rs`), plus one knob read via an untyped `serde_yaml` pass.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `pcf.sbi.server[].address` | string | absent → CLI `--sbi-addr` (`0.0.0.0`) | Overrides the SBI bind **and** advertised address so the NRF NFProfile carries a routable endpoint (not 0.0.0.0). Only the **first** list entry is read. |
| `pcf.sbi.server[].port` | u16 | absent → CLI `--sbi-port` (`7777`) | Overrides the SBI bind/advertised port. First entry only. |
| `pcf.sbi.server[].fqdn` | string | absent (no FQDN) | Optional advertised FQDN, emitted as `pcfFqdn` in TS 29.521 PcfBinding registrations towards the BSF (per code comment); never invented when absent — `pcfIpEndPoints` alone satisfies the spec NOTE. |
| `pcf.sbi.client.nrf[].uri` | string | absent → no NRF (unless CLI `--nrf-uri`) | NRF base URI seeded into the shared SBI context for NF registration, discovery, heartbeat, and (when OAuth2 is on) token/JWKS. Only the **first** list entry is used. |
| `<any-section>.sbi.oauth2.require` | bool | `false` | SBI OAuth2 enforcement (TS 33.501 §13.4.1, TS 29.510 §5.4.2 per code comments). Read by `oauth2_required()` via a raw `serde_yaml::Value` traversal that is root-key agnostic: `true` iff *any* top-level section sets `sbi.oauth2.require: true`. When on, incoming requests must carry an NRF-issued token with audience `PCF` (fails closed with 503 when no NRF URI is configured) and outbound SBI calls attach tokens. The env var `NEXTGCORE_SBI_OAUTH2_REQUIRE` takes precedence over the YAML in either direction. Note: no `pcf-oauth2.yaml` overlay ships in `docker/rust/configs/5gc/` — the env var is the practical switch. |

## Parsed-but-inert / decorative YAML fields

The daemon deserializes only the fields above; unknown YAML keys are silently ignored by serde. In the shipped example file:

- **`db_uri` is inert.** `nextgcore-pcfd` never calls `nextgcore_dbi_init` — its subscription/session-data lookups through `nextgcore-dbi` therefore error out at runtime and fall back to built-in defaults (see Behavior notes). The key exists for visual consistency with NFs that do open MongoDB.
- **`logger.file.path` and `logger.level` are inert.** The log level comes only from the CLI flag `-e/--log-level` (default `info`); `init_logging` builds an `env_logger` with `filter_level` and does not wire file output (the `-l/--log-file` flag is accepted but unused).
- **`global.max.ue` / `global.max.peer` are inert.** Context capacities come from the CLI flags `--max-ue` (1024) and `--max-sess` (4096).
- **`pcf.metrics.server[]` is inert.** The daemon starts no metrics HTTP server; its only telemetry export is OpenTelemetry OTLP via `OTEL_EXPORTER_OTLP_ENDPOINT`.
- **`pcf.tls.*` is inert.** No code reads this section. Even the CLI `--tls`/`--tls-cert`/`--tls-key` flags only flow into the legacy `SbiServerConfig` (`sbi_path.rs`), where they flip the *advertised* URI scheme to `https` in the legacy NF-instance builder; the live HTTP/2 listener is created from `NextgcoreSbiServerConfig::new(addr)` without any TLS wiring and serves cleartext h2c.

## Command-line flags

Runtime knobs with real defaults from the clap `Args` struct in `src/bins/nextgcore-pcfd/src/app.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/pcf.yaml` | Configuration file path. |
| `-l, --log-file` | path | unset | Log file path — parsed but currently **not used** by `init_logging` (no file logging). |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else falls back to `info`). |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Stub: logs "would send SIGTERM to running instance" and exits — does not actually signal anything. |
| `--sbi-addr` | string | `0.0.0.0` | SBI bind address; overridden by `pcf.sbi.server[0].address` when the YAML sets one. |
| `--sbi-port` | u16 | `7777` | SBI port; overridden by `pcf.sbi.server[0].port`. |
| `--tls` | flag | off | Sets the advertised scheme to `https` in the legacy NF-instance builder only; does **not** enable TLS on the live listener. |
| `--tls-cert` | path | unset | TLS certificate path (stored in the legacy config; not wired to the listener). |
| `--tls-key` | path | unset | TLS key path (same caveat). |
| `--nrf-uri` | string | unset | NRF URI. When set, the legacy SBI-open path stores it *after* the YAML seed, so it wins over `pcf.sbi.client.nrf[0].uri`; it also triggers an additional legacy NFProfile registration with its own instance ID. |
| `--max-ue` | usize | `1024` | Maximum UEs (sizes the context pool and the load-gauge denominator). |
| `--max-sess` | usize | `4096` | Maximum sessions. |

## Behavior notes

- **NRF registration and heartbeat**: at startup the PCF PUTs an NFProfile (`/nnrf-nfm/v1/nf-instances/{id}`) advertising `npcf-am-policy-control`, `npcf-smpolicycontrol` and `npcf-ue-policy-control` with `heartBeatTimer: 10` and `allowedNfTypes: [AMF, SMF, SCP]`, then spawns a heartbeat worker every 5 s that PATCHes a real `/load` gauge (TS 29.510 §5.2.2.3.2 per code comment): `load = (AM + SM policy associations) × 100 / (2 × max_ue)`, clamped 0–100. Registration failure is non-fatal — the PCF logs a warning and "will operate without NRF". The same NF instance ID doubles as `pcfId` in BSF PcfBinding registrations (TS 29.510 per comment).
- **Mandatory-IE rejection**: AM and UE policy create require `notificationUri`, `supi` and `suppFeat` (TS 29.507 §5.6.2.3 / TS 29.525 per comments); SM policy create requires `supi`, `pduSessionId`, `dnn`, `pduSessionType`, `notificationUri` and `sliceInfo.sst` (TS 29.512 §5.6.2.3). Anything missing → HTTP 400 with cause `MANDATORY_IE_MISSING`. `suppFeat` is negotiated (consumer ∩ producer): producer masks are `0x0` for AM/UE-policy/PolicyAuthorization and `0x3` for SM. Updates use the spec custom operations `POST …/policies/{id}/update` and `POST …/sm-policies/{id}/{update,delete}`; legacy `PATCH`/`DELETE` arms are kept for backward compatibility. Unmatched routes get 405.
- **Policy-data sources**: because the MongoDB layer is never initialized (see `db_uri` above), `nudr_handler` falls back to built-in defaults — AM UE-AMBR 1 Gbps up/down; SM 5QI 9, ARP 8, session AMBR 100/100 Mbps, no PCC rules. On the live SM path the PCF additionally does a bounded (3 s) NRF-discovered `nudr-dr` GET of SmPolicyData (TS 29.519 per comment) and maps only the `online`/`offline` charging flags into the decision; 404/unreachable falls back silently.
- **URSP delivery (UE policy)**: on UE-policy create the PCF builds a MANAGE UE POLICY COMMAND (TS 24.501 Annex D / TS 24.526 per comments) and delivers it via the AMF's N1N2MessageTransfer, subscribing for the uplink result *before* the transfer (TS 29.525 §4.2.2.2 order). Rules come from the UDR UePolicySet `urspRules` extension when provisioned, else a static catch-all default (`dnn: internet`, sst 1). The association stays `Pending` until a COMPLETE arrives; T3501 (default 30 s) retransmits exactly once, then marks the delivery `Failed` — fail-closed, never a fake `Delivered`.
- **UAV gating and BSF bindings**: an SM policy create whose DNN matches `PCF_UAV_DNN` (default `uav`) passes an altitude/flight-zone gate (Rel-18, TS 23.256 per comment) and is rejected with HTTP 403 `UAV_FLIGHT_NOT_AUTHORIZED` when out of policy. Each SM policy create/delete also best-effort registers/deregisters a PcfBinding at the BSF (TS 29.521 per comment) — a no-op when no BSF/NRF is reachable.
- **Environment variables** (all read directly by this binary):

  | Variable | Default | Effect |
  |---|---|---|
  | `NEXTGCORE_SBI_OAUTH2_REQUIRE` | unset (follow YAML) | `1/true/TRUE/yes` forces OAuth2 enforcement on; any other value forces it off. Checked **before** the YAML knob. |
  | `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OTLP endpoint for OpenTelemetry tracing. |
  | `PCF_LOCAL_PLMN` | `001-01` | Home PLMN as `MCC-MNC`; drives V-PCF vs H-PCF role detection per serving PLMN. |
  | `PCF_UE_POLICY_DELIVERY` | on | Kill-switch: `off/0/false/disabled/no` disables URSP N1N2 delivery (association-only, pre-Wave-6 behavior). |
  | `PCF_T3501_SECS` | `30` | T3501 duration in seconds; zero/invalid falls back to 30. |
  | `PCF_URSP_RULES` | unset | JSON array overriding the entire default URSP rule set; invalid/empty JSON falls back to the built-in catch-all with a warning. |
  | `PCF_UAV_DNN` | `uav` | Comma-separated DNN list treated as UAV sessions. |
  | `PCF_UAV_MAX_ALTITUDE` | `120` (meters) | UAV altitude ceiling. |
  | `PCF_UAV_POSITION` | `37.5,-122.5,min(max_alt,100)` | `lat,lon,alt` gated against the flight zone; the default is deliberately in-zone so the authorize path is exercised. |
