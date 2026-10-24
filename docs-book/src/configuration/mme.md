# MME Configuration

The MME (Mobility Management Entity, `nextgcore-mmed`) is the 4G/EPS control-plane anchor of the dual 5G+4G core. It serves S1-MME toward eNBs (S1AP encoded and decoded by `nextgcore-s1ap-gen`, the codec generated from the TS 36.413 ASN.1; the hand-written S1AP codec was removed, #514), NAS EMM/ESM toward UEs (TS 24.301), S11 GTPv2-C toward the SGW-C, S6a Diameter toward the HSS, and optionally N26 GTPv2-C toward an AMF for EPS↔5GS interworking. The crate also carries SGsAP message handling and the SBc-AP warning data structures and handlers; it has no SBc-AP transport (see [Not supported](#not-supported)).

Configuration comes from a YAML file (default `/etc/nextgcore/mme.yaml`, `-c/--config`), the freeDiameter `.conf` that file names, a few environment variables, and four CLI flags. A missing or malformed file, or one with no `mme:` section, logs a warning and leaves the built-in defaults in place (`src/bins/nextgcore-mmed/src/config.rs`).

> **Honesty note:** the nightly `Docker E2E (EPC)` job attaches a real LTE UE through nextgsim's eNB to this MME and pings through the default bearer with 0% loss (`docker/rust/epc-attach-check.sh`). Dedicated bearers, handover, idle mode/paging and IPv6 PDN are not asserted there. This is the project's own matched-simulator validation, not third-party certification.

## Example configuration

From `nextgcore/docker/rust/configs/epc/mme.yaml` (mounted by `docker-compose-epc.yml`, which runs the daemon as `-c /etc/nextgcore/mme.yaml` at `172.24.0.5` and publishes `36412/sctp` on `127.0.0.1`, or on `NEXTGCORE_RAN_PUBLISH_ADDR` for an external eNB; abridged, the shipped file also carries a commented-out `overload:` block):

```yaml
# NextGCore MME Configuration for Docker EPC Deployment
# Rust implementation

logger:
  file:
    path: /var/log/nextgcore/mme.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

mme:
  freeDiameter: /etc/freeDiameter/mme.conf
  s1ap:
    server:
      - address: 172.24.0.5
  gtpc:
    server:
      - address: 172.24.0.5
    client:
      sgwc:
        - address: 172.24.0.3
      smf:
        - address: 172.24.0.4
  metrics:
    server:
      - address: 172.24.0.5
        port: 9090
  gummei:
    - plmn_id:
        mcc: 999
        mnc: 70
      mme_gid: 2
      mme_code: 1
  tai:
    - plmn_id:
        mcc: 999
        mnc: 70
      tac: 1
  security:
    integrity_order: [EIA2, EIA1, EIA0]
    ciphering_order: [EEA0, EEA1, EEA2]
  network_name:
    full: NextGCore
    short: Next
  mme_name: nextgcore-mme0
```


## YAML parameters

All keys live under `mme:`. Every field is optional.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `freeDiameter` | path | none | freeDiameter `.conf` read for the S6a identity, realm, listen address and the HSS peer: `ConnectPeer = "<id>" { ConnectTo = "<addr>"; }` becomes the peer mmed dials (port `3868` when the file names none). Without a `ConnectPeer` with `ConnectTo`, no S6a peer is dialled and the warning says so. |
| `s1ap.server[].address` / `.port` | string / u16 | none / `36412` | S1-MME bind address. Only the first entry is bound; extra entries are named in a warning. |
| `gtpc.server[].address` / `.port` | string / u16 | none / `2123` | S11 GTP-C bind address. Only the first is bound. |
| `gtpc.client.sgwc[].address` / `.port` | string / u16 | none / `2123` | SGW-C S11 peer. The first is used for every session (TS 23.401 SGW selection by DNS is not implemented; a second entry is named in a warning). `gtpc.client.smf` is accepted and unused (the PGW-C is the SGW-C's peer, not the MME's). |
| `n26.server[].address` / `.port` | string / u16 | none / `2123` | N26 GTP-C bind address toward an AMF (#347). Read always, bound only when `MME_N26_INTERWORKING` is on. |
| `n26.client.amf[].address` / `.port` | string / u16 | none / `2123` | AMF N26 peer for Context Request / Forward Relocation. |
| `gummei[]` | list | empty | Served GUMMEIs: `plmn_id.{mcc,mnc}` (string or int), `mme_gid` (u16), `mme_code` (u8). With none configured every S1 Setup is answered with S1 Setup Failure (TS 36.413 §8.7.3.4). |
| `tai[]` | list | empty | Served TAIs: `plmn_id`, `tac` (u16). |
| `security.integrity_order` / `.ciphering_order` | list of strings | built-in order | `EIA0`–`EIA3` / `EEA0`–`EEA3`. A configured list replaces the built-in one. |
| `network_name.full` / `.short` | string | none | Network names sent to the UE. |
| `mme_name` | string | none | MME name. |
| `time.t3402.value` / `t3412.value` / `t3423.value` | u64 (s) | built-in | EMM timers signalled to the UE. |
| `overload.max_ue` | usize | `0` (off) | Above this many attached UEs the MME sends S1AP OVERLOAD START to every eNB, and OVERLOAD STOP when the count falls to 90% of it (TS 36.413 §8.7.6). |

Not read: `logger.*`, `global.max.*`, `mme.metrics.server`.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-mmed/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/mme.yaml` | Configuration file path. |
| `-l, --log-level` | string | `logger.level`, else `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else is `info`). Without the flag, the config's `logger.level`, else `info`; `RUST_LOG` overrides both (#691). |
| `--no-color` | flag | off | Disable colored output. |
| `-d, --daemon` | flag | off | Daemon mode. |

## Cargo feature: `kernel-sctp`

S1-MME runs **only** over native Linux kernel SCTP: mmed offers no userspace (sctp-proto) S1 backend. Built without `--features kernel-sctp` the daemon starts, binds nothing on 36412, and logs that S1-MME is absent, so no eNB can connect. The Docker builder (`docker/rust/Dockerfile.builder`) compiles mmed with the feature; it needs `libsctp` at build and run time and the host `sctp` kernel module.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `MME_N26_INTERWORKING` | off | `1`/`true` binds the N26 socket and enables EPS↔5GS interworking (idle-mode context transfer, connected-mode handover). Off: a standalone EPC, and a UE arriving from 5GS is handled as TS 24.301 requires of an MME with no N26. |
| `MME_N26_PEER_T3_SECS` | `3` | The AMF's GTPv2-C T3-RESPONSE (TS 29.274 §7.6), floored at 1 and capped at 60 (a larger value is logged and capped). With `MME_N26_PEER_N3` it sizes how long a sent N26 response is kept to answer the AMF's retransmission of the same request: (N3 + 1) x T3, 12 s by default. Set both to the AMF's values when they are longer than the defaults, or a late retransmitted Forward Relocation Request is processed a second time. |
| `MME_N26_PEER_N3` | `3` | The AMF's GTPv2-C N3-REQUESTS (TS 29.274 §7.6), capped at 10; see `MME_N26_PEER_T3_SECS`. |
| `MME_ECHO_INTERVAL_SECS` | `60` | GTPv2-C Echo (path management) interval; `0` disables it. |
| `MME_DIAMETER_TW_SECS` | `30` | S6a Device-Watchdog interval Tw (RFC 6733 §5.5, RFC 3539 §3.4.1), floored at 6. After Tw with nothing received a DWR is sent; with no answer within another Tw the connection is closed and redialled (Tc, doubling to at most 8 x Tc). A redialled connection carries traffic once three watchdogs are answered. hssd drops no idle connection; against an HSS that does (one built on `DiameterServer` drops after 3 x its Tc), keep Tw below that. An unparsable value is logged and 30 is used. |
| `MME_RESTART_COUNTER_FILE` | `/var/lib/nextgcore/mme-restart-counter` | Where the TS 23.007 restart counter is persisted; it is advanced on every start. |
| `MME_RESTART_COUNTER` | unset | Fixed restart counter (u8), overriding the persisted one. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OpenTelemetry OTLP exporter. |
| `MME_METRICS_ADDR` | unset | Full `ip:port` of the unauthenticated `/metrics` listener (handover failure counters). Wins over `NEXTGCORE_METRICS_BIND`. |
| `NEXTGCORE_METRICS_BIND` | `127.0.0.1` | Host of the `/metrics` listener on port 9090 when `MME_METRICS_ADDR` is unset (#837). `docker-compose-epc.yml` and the EKS EPC overlay set `0.0.0.0` inside the private network; no metrics port is published on the host. |

`RUST_LOG` overrides `-l/--log-level` when set (the `RUST_LOG: info` in `docker-compose-epc.yml` applies).

## Not supported

- **SBc-AP: no CBC interface (#1071).** mmed does not listen for, or connect to, a Cell Broadcast Centre. TS 29.168 SBc-AP runs over SCTP on port 29168 (PPID 24), and mmed has neither that transport nor an SBc-AP codec. As a result:
  - ETWS and CMAS warnings (TS 23.041) cannot be delivered. No Write-Replace Warning or Stop Warning arrives from a CBC, so no WRITE-REPLACE WARNING REQUEST or KILL REQUEST is sent to an eNB. The `sbc_handler` procedures exist, but nothing calls them in production.
  - An eNB's **PWS RESTART INDICATION** (TS 36.413 §8.12.3) is decoded and validated against the sender's own Global eNB ID. It is counted in `mme_s1ap_pws_restart_indications_total` and logged, but not propagated to a CBC. TS 23.007 §15A.1.2 has the CBC reload the restarted cells' warnings; mmed does not replay its own copy.
  - An eNB's **PWS FAILURE INDICATION** (TS 36.413 §8.12.4) is handled in the same way. It is decoded, validated against the sender, counted in `mme_s1ap_pws_failure_indications_total`, and its failed cells are logged. It is not propagated to a CBC.
  - Toward a CBC, mmed sends no SBc-AP PWS Restart Indication, PWS Failure Indication, Write-Replace Warning Indication or Stop Warning Indication.
