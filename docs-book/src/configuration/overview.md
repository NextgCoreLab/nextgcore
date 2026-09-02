# Configuration Overview

NextGCore network functions (NFs) are configured with per-NF YAML files, modelled on the Open5GS configuration layout. This page describes where the config files live, how they are loaded, and the parameters shared across NFs.

> **Honesty note.** Everything below is grounded in the current source tree. Configuration behaviour is exercised by unit tests and the project's own matched-simulator Docker E2E runs; it is **not** third-party certified. Any 6G/Rel-20 knobs are non-normative research prototypes.

## Where the config files live

| Location | Purpose |
|---|---|
| `configs/` (repo root) | Minimal sample; currently only `amf.yaml` (PLMN 999-70, TAC 1, SST 1) |
| `docker/rust/configs/5gc/` | The full working set used by the Docker E2E deployment: `amf.yaml`, `smf.yaml`, `upf.yaml`, `nrf.yaml`, `ausf.yaml`, `udm.yaml`, `udr.yaml`, `pcf.yaml`, `nssf.yaml`, `bsf.yaml`, `nsacf.yaml`, `nwdaf.yaml`, `lmf.yaml`, `ees.yaml`, `mbsmf.yaml`, `dccf.yaml`, `pin.yaml` plus `*-oauth2.yaml` variants (NRF/UDR/BSF/NSSF/NSACF) for OAuth2-enabled runs |
| `docker/rust/configs/` | `scp.yaml`, `sepp1.yaml`, `sepp2.yaml`; `epc/` holds the 4G/EPS set (`mme.yaml`, `hss.yaml`, `sgwc.yaml`, `sgwu.yaml`, `pcrf.yaml`) |
| `k8s/manifests/`, `deploy/helm/` | Kubernetes/Helm packaging of the same configs |

Each file has the same shape: optional `logger:` and `global:` sections, plus one NF-specific root section named after the NF (`amf:`, `smf:`, `upf:`, ...).

## How an NF loads its YAML

There are two cooperating layers.

**1. Per-NF binary (clap).** Each NF binary (e.g. `nextgcore-amfd`) parses CLI args and loads its YAML with `serde_yaml`. From `src/bins/nextgcore-amfd/src/lib.rs`:

- `-c / --config <path>` — config file, default `/etc/nextgcore/amf.yaml`
- `-l / --log_level <level>` — `trace|debug|info|warn|error`, default `info`
- `--ngap-addr` (AMF only) — NGAP bind address, default `0.0.0.0:38412`
- `--sctp-backend` (AMF only) — `userspace` (default, sctp-proto over UDP) or `kernel` (Linux kernel SCTP, needs the `kernel-sctp` build feature)

Loading is lenient: if the file is missing or fails to parse, the NF logs a warning and **continues with built-in defaults** rather than aborting.

**2. Shared app library (`src/libs/nextgcore-app/src/init.rs`, `config.rs`).** `nextgcore_app_initialize()` mirrors Open5GS's `ogs_app_initialize()`: it parses `-c` (config file), `-l` (log file), `-e` (log level), `-m` (domain mask), `-k` (config section id), then reads the YAML and parses the `db_uri`, `logger`, and `global` root sections. It also provides hot-reload plumbing (`ConfigWatcher` polls the file mtime every second and re-parses on change) and a snapshot/rollback `ConfigHistoryManager`.

## Common configuration blocks

### `logger`

```yaml
logger:
  file:
    path: /var/log/nextgcore/amf.log
  level: info
```

`RUST_LOG` takes precedence over the configured level where NFs use `nf_common_init()` (`env_logger::Env::default().default_filter_or(log_level)`); binaries that build the logger from `--log_level` use that flag directly.

### `global`

```yaml
global:
  max:
    ue: 1024      # code default: 1024 (MAX_NUM_OF_UE)
    peer: 64      # code default: 64 (MAX_NUM_OF_PEER)
```

Also accepted under `global`: `parameter` (NF-disable and network flags such as `no_ipv4`, `no_ipv6`, `prefer_ipv4`; setting both `no_ipv4` and `no_ipv6` fails validation), `sockopt` (`no_delay`, `linger`), and `pool` (packet-buffer pool sizes, e.g. `128: 65536` ... `big: 8`).

### NF section (`amf:`, `smf:`, `upf:`, ...)

Common sub-blocks seen in the Docker configs:

- `sbi.server` — list of `{address, port}` (port 7777 everywhere)
- `sbi.client.nrf` — list of `{uri}` pointing at the NRF
- `metrics.server` — Prometheus endpoint, port 9090 in all shipped configs
- `tls` — `enabled` (false by default), `cert`/`key`/`ca` paths, `min_version: "1.2"`; enabled at deploy time via `TLS_ENABLED=true SBI_SCHEME=https`
- Protocol servers per NF: AMF `ngap` (38412), SMF/UPF `pfcp` (8805), UPF `gtpu` (2152), SMF `gtpc`/`gtpu`
- SMF/UPF `session` subnets (`10.45.0.0/16` gw `10.45.0.1`, `2001:db8:cafe::/48`), SMF `dns` and `mtu: 1400`
- AMF-specific: `guami`, `tai`, `plmn_support` (PLMN 999/70 in samples), `security.integrity_order`/`ciphering_order` (NIA/NEA lists), `network_name`, `time.t3512` (540 s in the Docker config), and `nas.use_nextgcore_security` (default `false` — canary for the strict TS 24.501 §4.4 NAS-security path)

## Environment overrides

| Variable | Effect | Source |
|---|---|---|
| `RUST_LOG` | Overrides log level (via `nf_common_init`) | `init.rs` |
| `DB_URI` | Overrides the YAML `db_uri` (MongoDB) | `init.rs` stage 4 |
| `<NF>_SBI_ADDR` / `<NF>_SBI_PORT` | SBI bind address/port (e.g. `AMF_SBI_ADDR`, `UDM_SBI_PORT`); defaults `127.0.0.1:7777` | each NF `lib.rs` |
| `NRF_URI`, `PCF_URI`, `NSACF_URI` | Peer NF discovery URIs | NF binaries |
| `SMF_PFCP_ADDR/PORT`, `UPF_PFCP_ADDR/PORT` | PFCP endpoints | SMF/UPF |
| `AMF_NAS_SECURITY=nextgcore` | Forces the strict NAS-security path, overriding `nas.use_nextgcore_security` in YAML | amfd `lib.rs` |
| `NEXTGCORE_SBI_OAUTH2_REQUIRE` | Forces OAuth2 enforcement on the SBI server regardless of YAML | amfd `lib.rs` |
| `NEXTGCORE_SBI_PROFILE` | SBI security profile for amf/smf/ausf/udm. **Defaults to `production`** (mutually-authenticated TLS + a required OAuth2 access token). `dev`/`development`/`insecure`/`local`/`test` opt out to cleartext h2c; **any other value, including a typo, stays `production`** so a mistake cannot silently downgrade security | `nextgcore-sbi` `security.rs` |
| `NEXTGCORE_SBI_TLS_CERT` / `_KEY` / `_CA` | Override the production profile's certificate paths (defaults under `/etc/nextgcore/tls/`), so the certs can be mounted wherever the deployment puts them | `nextgcore-sbi` `security.rs` |
| `TLS_ENABLED`, `SBI_SCHEME` | Docker-compose knobs to enable SBI TLS | config comments |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector (default `http://jaeger:4317`; no-op if absent) | `init.rs` |

Precedence, where both exist: **environment variable > YAML > compiled-in default.**

### SBI security profile (issue #63)

`amf`, `smf`, `ausf` and `udm` resolve `NEXTGCORE_SBI_PROFILE` at startup. Under
`production` they serve SBI over mutually-authenticated TLS and require an OAuth2
access token whose audience is their own NF type, and they **refuse to start**
when the certificates named above are missing rather than falling back to
cleartext.

Every artefact this repo ships — `docker/rust/docker-compose.yml`,
`k8s/manifests/`, and the Helm chart via `global.sbiProfile` — sets the explicit
`dev` opt-out, because none of them mount SBI certificates. Local development and
the matched-simulator E2E are therefore unchanged.

**Known incomplete:** the profile configures the *inbound* listener. Those four
NFs still build their *outbound* peer clients as cleartext http with no client
certificate, so a call between two production-profile NFs fails at the TLS layer;
the production profile logs a warning saying so at startup. Until that lands, run
a uniformly dev-profile deployment or terminate TLS at a proxy.

## Common parameters and code defaults

| Parameter | Default (from code) | Where defined |
|---|---|---|
| Config file path | `/etc/nextgcore/<nf>.yaml` | clap `Args` in each NF |
| Log level | `info` | clap `Args` / `nf_common_init` |
| SBI bind | `127.0.0.1:7777` | env fallback in NF `run()` |
| `global.max.ue` | `1024` | `config.rs` `MAX_NUM_OF_UE` |
| `global.max.peer` | `64` | `config.rs` `MAX_NUM_OF_PEER` |
| Metrics port | `9090` (all shipped configs) | Docker YAMLs |
| NF-instance validity | `30` s (must be non-zero) | `NextgcoreLocalConf::prepare()` |
| Subscription validity | `86400` s | `NextgcoreLocalConf::prepare()` |
| Message wait duration | `10` s (derives SBI/PFCP/GTP retry timers) | `NextgcoreLocalConf::prepare()` |
| Handover wait | `300` ms | `NextgcoreLocalConf::prepare()` |
| `tls.enabled` | `false` | Docker YAMLs |
| `nas.use_nextgcore_security` (AMF) | `false` | amf.yaml / amfd |
| Max PLMNs / slices / sessions / bearers | 6 / 8 / 4 / 4 | `config.rs` constants |

## Dynamic reconfiguration

`nextgcore-app` includes a `ConfigReloadManager` that watches the config file and re-parses the `global` and NF-local sections on change, plus a versioned snapshot store with rollback and JSON export/import. These are library facilities (unit-tested); how much each NF wires them in varies — check the individual NF pages before relying on hot reload in a deployment.
