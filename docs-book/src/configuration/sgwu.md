# SGW-U Configuration

The SGW-U (Serving Gateway User Plane, `nextgcore-sgwud`) is the 4G/EPS user-plane NF in NextGCore's dual 5G+4G core. It owns a GTP-U UDP socket on port 2152 and forwards *G-PDU in → PDR match by TEID → FAR apply (FORW/BUFF/DROP) → G-PDU out* between S1-U (eNB) and S5-U (PGW-U). Its control plane is PFCP over Sxa toward the SGW-C on UDP 8805 (#59): inbound messages are decoded with the shared `nextgcore-pfcp` codec, Heartbeat runs in both directions with Recovery Time Stamp comparison, requests are retransmitted (T1/N1), and a failed SGW-C's sessions are removed. It has **no SBI/HTTP surface, no GTP-C and no Diameter interface**.

Configuration is a small YAML file (`-c/--config`, read by `src/bins/nextgcore-sgwud/src/config.rs`) plus environment variables. There is no clap parser: `-c/--config` and `-l/--log-level` (also `--config=`/`--log-level=`) are scanned from `argv`.

> **Honesty note:** the nightly `Docker E2E (EPC)` job waits for the SGW-C ↔ SGW-U Sxa association from both ends and pings through an attached LTE UE's default bearer, which crosses this SGW-U, with 0% loss. This is the project's own matched-simulator validation, not third-party certification.

## Example configuration

From `nextgcore/docker/rust/configs/epc/sgwu.yaml` (mounted read-only into the container by `docker-compose-epc.yml`):

```yaml
# NextGCore SGW-U Configuration for Docker EPC Deployment
# Rust implementation

logger:
  file:
    path: /var/log/nextgcore/sgwu.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

sgwu:
  pfcp:
    server:
      - address: 172.24.0.6
  gtpu:
    server:
      - address: 172.24.0.6
```

## YAML parameters

A missing or malformed file logs a warning and leaves the defaults.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `sgwu.pfcp.server[0].address` | IPv4 | none | PFCP Node ID when `PFCP_NODE_IP` is unset (then loopback). Not the bind address: that is `PFCP_BIND_ADDR`. |
| `sgwu.gtpu.server[0].address` | IPv4 | none | GTP-U address advertised in UP-allocated F-TEIDs when the socket is bound to a wildcard and `SGWU_GTPU_ADVERTISE` is unset. |
| `logger.level` | string | `info` | Log level when `-l/--log-level` is not given; `RUST_LOG` overrides both (#500). |

A non-IPv4 address is logged and ignored. Not read: `logger.file`, `global.max.*`.

## Command-line flags

| Flag | Default | Description |
|---|---|---|
| `-c, --config` | none | YAML file path (the Docker image passes `-c /etc/nextgcore/sgwu.yaml`). |
| `-l, --log-level` | from `logger.level`, else `info` | Log level. |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SGWU_GTPU_BIND` | `0.0.0.0:2152` | GTP-U bind address:port. |
| `SGWU_GTPU_ADVERTISE` | unset | IPv4 advertised in UP-allocated F-TEIDs; consulted only when the bound address is a wildcard. |
| `PFCP_BIND_ADDR` | `0.0.0.0:8805` | Sxa PFCP bind address:port. |
| `PFCP_NODE_IP` | `sgwu.pfcp.server[0].address`, then loopback | PFCP Node ID. |
| `SGWU_GTPU_ECHO_INTERVAL_SECS` | `60` | GTP-U Echo interval toward peers; `0` disables path probing. |
| `SGWU_GTPU_N3_REQUESTS` | `3` | Unanswered Echoes tolerated before the path is declared down. |
| `SGWU_MAX_BUFFERED_PACKETS` | `64` | Per-FAR buffer depth for BUFF. |
| `SGWU_QER_ENFORCEMENT` | off | `1`/`true`/`yes` enables QER gate/MBR enforcement (#60). Off by default because a mis-provisioned QER would drop traffic. |
| `SGWU_METRICS_PORT` | `9090` | Prometheus endpoint port. |
| `NEXTGCORE_METRICS_BIND` | `127.0.0.1` | Host the unauthenticated `/metrics` listener binds to (#837). The compose files and manifests set `0.0.0.0` inside the private container/pod network. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OTLP endpoint for OpenTelemetry traces; init is best-effort. |
| `RUST_LOG` | unset | Overrides the log level. |

## Behavior notes

- **GTP-U datagram handling** (`gtp_path.rs`): Echo Request is answered with an Echo Response carrying the mandatory Recovery IE with restart counter 0 (TS 29.281 §8.2 per code comment); a received Echo Response confirms the path (its Recovery value is ignored, per TS 29.281 §8.2); End Marker and G-PDU are dispatched through PDR/FAR lookup; undecodable packets and unknown message types are dropped with an error log.
- **Error Indication → ERIR**: an inbound Error Indication is mapped back to the FAR carrying that TEID and reported to the SGW-C via a PFCP Session Report Request (TS 29.244 §5.10 per code comment). If no FAR matches, it is logged and swallowed.
- **Session admission**: the pool is hard-coded to 1024 sessions (`sgwu_context_init(1024)`); when full, `sess_add` logs `Maximum number of sessions [1024] reached` and the establishment fails. Per-FAR buffering (BUFF action) holds at most `SGWU_MAX_BUFFERED_PACKETS` packets (default 64), flushed when forwarding resumes (TS 29.244 §5.3.1 per code comment).
- **F-TEID CH allocation can fail silently in the shipped deployment**: when a Create PDR carries the CH (CHOOSE) flag (TS 29.244 §8.2.3 per code comment), the UP allocates a TEID and must advertise its own GTP-U address; with no address configured it returns PFCP cause `NO_RESOURCES_AVAILABLE`. With the default wildcard bind the address comes from `SGWU_GTPU_ADVERTISE`, then `sgwu.gtpu.server[0].address` (the shipped compose relies on the YAML's `172.24.0.6`).
- **PFCP association/heartbeat FSM** (`pfcp_sm.rs`, `timer.rs`): `will_associate` retries association every 3 s and moves to `Associated` on an Association Setup Request/Response; both timers have `max_count = 0`, meaning **unlimited retries**. On entry to `Associated` the node sends a Heartbeat Request and answers incoming ones; the no-heartbeat timer is 10 s. A restoration path exists (`pfcp_restoration`, `sess_remove_all_for_pfcp_node`, and Create-PDR restoration-indication TEID reuse).
- **Usage reporting (URR)** (#215 / #267 / #427, TS 29.244 §5.2.2.1 / §7.5.2.4). The SGW-U models Create / Update / Remove URR on Session Establishment and Session Modification, stores each rule with its Measurement Method, Reporting Triggers, Volume Threshold, Volume Quota, Time Threshold and Measurement Period, links it to the PDRs that name it, and populates `PfcpSess.urr_ids`. `apply_far` counts bytes and packets against every URR the matched PDR names; crossing a requested trigger produces a Usage Report with a **monotonic UR-SEQN** (§8.2.60), carried as IE 80 in a Session Report Request with the USAR report-type bit set. Time triggers are driven from a clock (#427). Session deletion emits one final report per URR as IE 79 in the Session Deletion Response, tagged TEBUR. A threshold is checked **only when its Reporting Triggers bit is set** — §8.2.41 makes that IE the CP function's request, so a provisioned threshold with a clear trigger bit stays silent. A duration-only (`DURAT`) URR accumulates no volume, and a report that measured nothing omits the Volume Measurement IE rather than sending an all-zero one.
  - **QER-dropped, FAR-dropped and buffer-full traffic is NOT counted.** §5.2.2.1 measures the network resources the UP function *uses*, and a packet it discarded consumed none. Counting it would over-bill a subscriber for traffic the network refused to carry; under-counting a dropped packet costs the operator nothing it was entitled to. Traffic **accepted** into a BUFF FAR's buffer is counted, once, at buffering time — not again on flush. A packet the buffer **rejects** because it is already at capacity is not counted (#267: it was, so a downlink burst past capacity over-billed its whole tail). A buffered packet is still billed on the paths where it is provably never delivered — session teardown discards the queue, a failed flush logs and continues, and an SGW-C switching the FAR to DROP discards it — so the claim is "accepted", not "delivered".
  - **Volume Threshold is per measurement period; Volume Quota is cumulative for the session** (#267). Counters are cumulative with a reported-so-far watermark, so a report carries its period's delta while the total survives for the quota check. Resetting the counters on each report — as #215 did — made a quota **unreachable** whenever a threshold also fired.
  - **Timestamps are NTP-epoch** (RFC 5905, per §8.2.34-§8.2.37), not UNIX. #215 wrote UNIX seconds, so every Start/End/First/Last Packet time was ~70 years low.
  - **VOLQU is octet 6 bit 1** of the Usage Report Trigger. #215 put it on octet 5 bit 7, which is DROTH, so a quota-exhaustion report claimed a dropped-downlink-traffic threshold instead.
  - **A report carries every satisfied trigger**, not just the first: the IE is a bitmask, and reporting one while resetting the period consumed the others' conditions silently.
  - **Query URR and the QAURR flag** are answered with immediate Usage Reports (#427).
- **GTP-U path failure** detected by unanswered Echoes is reported to the SGW-C in a PFCP Node Report (#217).
- **No state files** are read or written; all session/PDR/FAR/QER/BAR/URR state is in-memory and lost on restart. For URRs that means unreported volume does not survive a restart.
