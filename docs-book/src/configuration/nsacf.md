# NSACF Configuration

The NSACF (Network Slice Admission Control Function, `nextgcore-nsacfd`) enforces per-slice admission quotas for UE registrations and PDU session establishment, per TS 23.502 §4.2.9 and TS 29.536 (as cited in the daemon's source comments). It serves the `Nnsacf_NSAC` (`/nnsacf-nsac/v1/slices/ues`, `/nnsacf-nsac/v1/slices/pdus`) and `Nnsacf_SliceEventExposure` APIs, plus Early Admission Control (EAC) notifications.

Configuration is split between a YAML file (default path `/etc/nextgcore/nsacf.yaml`, overridable with `-c/--config`) and command-line flags. The YAML file is the source for slice quotas, the NRF URI, and OAuth2 enforcement; most runtime knobs (bind address/port, TLS, thresholds) are CLI flags only.

> **Honesty note:** NSACF behavior is validated by this project's own unit and matched-simulator E2E tests (84/84 docker E2E as of 2026-07-02), not by third-party conformance certification. The vendored OpenAPI sets do not include `TS29536_Nnsacf_*.yaml`; field names mirror TS 29.536 terminology as documented in code comments.

## Example configuration

From `nextgcore/docker/rust/configs/5gc/nsacf.yaml`:

```yaml
# NSACF (Network Slice Admission Control Function) Configuration
logger:
  level: info

nsacf:
  sbi:
    server:
      - address: 172.23.0.34
        port: 7777
  nrf:
    uri: http://172.23.0.10:7777
  slice_quotas:
    - sst: 1
      max_ues: 1000
      max_pdu_sessions: 2000
    - sst: 2
      max_ues: 500
      max_pdu_sessions: 1000
    - sst: 3
      max_ues: 2000
      max_pdu_sessions: 4000
```

An OAuth2-enforcing variant (`nsacf-oauth2.yaml`, used via `docker-compose.oauth2.yml`) is identical except it adds:

```yaml
nsacf:
  sbi:
    oauth2:
      require: true
```

## YAML parameters

These are the fields actually deserialized by the daemon (`#[derive(Deserialize)]` structs `NsacfYaml`/`NsacfSection`/`SbiYaml`/`SbiOauth2Yaml`/`NrfYaml`/`SliceQuotaYaml` in `src/bins/nextgcore-nsacfd/src/main.rs`).

| Parameter | Type | Default | Description |
|---|---|---|---|
| `nsacf.nrf.uri` | string | falls back to CLI `--nrf-uri` (`http://127.0.0.1:7777`) | NRF base URI for NF registration, heartbeat, and (when OAuth2 is on) token issuance/JWKS. |
| `nsacf.sbi.oauth2.require` | bool | `false` | SBI OAuth2 bearer-token enforcement. When `true`, incoming requests must carry an NRF-issued token with audience `NSACF` (verified against the NRF JWKS, TS 33.501 §13.4.1 per code comment) and outbound SBI calls attach tokens. Default off so the dev/E2E path works without tokens. Overridden by CLI `--oauth2-require`. |
| `nsacf.slice_quotas` | list | *(none — see below)* | Local NSAC provisioning (TS 29.536 §6.1.3.4 per code comment). If omitted, the NSACF starts with an **empty quota table and rejects every admission request** with `SLICE_NOT_AVAILABLE`. |
| `nsacf.slice_quotas[].sst` | u8 | **required** | Slice/Service Type of the S-NSSAI. |
| `nsacf.slice_quotas[].sd` | string | absent (no SD) | Slice Differentiator as a 6-hex-digit string (TS 23.003 §28.4.2 form, e.g. `"000000"`). |
| `nsacf.slice_quotas[].max_ues` | u64 | uncapped (`u64::MAX`) | Maximum registered UEs for the slice. Absent means the UE count is **not subject to NSAC** (uncapped), not a zero quota. |
| `nsacf.slice_quotas[].max_pdu_sessions` | u64 | uncapped (`u64::MAX`) | Maximum PDU sessions for the slice. Same absent-means-uncapped semantic. |

### Parsed-but-inert / decorative YAML fields

The daemon deserializes only the fields above; unknown YAML keys are silently ignored by serde. In particular, in the shipped example files:

- **`logger.level` is inert.** The log level comes from the CLI flag `-e/--log-level` (default `info`) or `RUST_LOG`, not the YAML.
- **`nsacf.sbi.server[]` (address/port) is inert.** The SBI bind address and port come from the CLI flags `--sbi-addr`/`--sbi-port`; the YAML `server` list exists for visual consistency with other NF configs but is not read by `nextgcore-nsacfd`.

## Command-line flags

Runtime knobs with real defaults from the clap `Args` struct in `main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/nsacf.yaml` | Configuration file path. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`). |
| `-l, --log-file` | path | unset | Log file path. |
| `-m, --no-color` | flag | off | Disable color output. |
| `--sbi-addr` | string | `0.0.0.0` | SBI server bind address. |
| `--sbi-port` | u16 | `7813` | SBI server port (docker deployments pass `7777`). |
| `--tls` | flag | off | Enable TLS on the SBI server. |
| `--tls-cert` | path | `/etc/nextgcore/tls/server.crt` (when `--tls`) | TLS certificate file. |
| `--tls-key` | path | `/etc/nextgcore/tls/server.key` (when `--tls`) | TLS private key file. |
| `--max-quotas` | usize | `64` | Maximum number of slice quotas in the context pool. |
| `--nrf-uri` | string | `http://127.0.0.1:7777` | NRF URI fallback when `nsacf.nrf.uri` is absent. |
| `--state-file` | path | unset | File for persisting admission counters across restarts (loaded at startup, saved on graceful shutdown). |
| `--eac-threshold` | u8 | `80` | Early Admission Control activation threshold, percent of max UEs (TS 23.502 §4.2.9.5 per code comment). |
| `--oauth2-require` | bool | unset (follow config) | Dev override for `nsacf.sbi.oauth2.require`; wins over the config value in either direction. |

## Behavior notes

- **Admission result encoding** (TS 29.536 §6.1.3.2.3.1 per code comment): HTTP **204** = all requested S-NSSAIs admitted; **200** with `acuFailureList` keyed by SUPI = partial failure; **403** ProblemDetails = total failure. Failure reasons include `SLICE_NOT_FOUND`, `EXCEED_MAX_UE_NUM[_3GPP/_N3GPP]`, `EXCEED_MAX_PDU_NUM[_3GPP/_N3GPP]`.
- **Supported features**: the NSACF advertises `supportedFeatures: "0"` — no optional TS 29.536 §6.1.8 features; HNSAC/VHNSAC home/visited delegation is **not** supported.
- **Runtime reprovisioning**: quotas can also be updated at runtime via the spec custom operation `POST /nnsacf-nsac/v1/slices/local-configs/update`, and via a NextGCore admin-only extension at `/nnsacf-nsac/v1/slice-quotas` (explicitly *not* a TS 29.536 resource). The admin extension applies its own defaults when omitted: `maxUes` 10000, `maxPduSessions` 50000 — different from the YAML's uncapped semantic.
- **Per-access ceilings** (`maxUes3gpp`, `maxUesN3gpp`, `maxPdu3gpp`, `maxPduN3gpp`) are configurable only through `local-configs/update`, not through the YAML file.
