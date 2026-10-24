# SGW-C Configuration

The SGW-C (Serving Gateway Control plane, `nextgcore-sgwcd`) is the 4G/EPC control-plane half of the Serving Gateway. It terminates three interfaces, each on a real socket: **S11** (GTPv2-C from the MME, UDP 2123), **S5/S8-C** (GTPv2-C toward the PGW-C, #52) and **Sxa** (PFCP toward the SGW-U, #387). S11 responses are gated on the Sxa results (#54), and the attach's Create Session Request is relayed to the PGW over S5/S8 with a PAA (#491). It also handles Modify Bearer, Delete Session, Release Access Bearers, indirect data-forwarding tunnels, Downlink Data Notification and the bearer Commands.

Configuration is split three ways: a YAML file (default `/etc/nextgcore/sgwc.yaml`, `-c/--config`) that supplies the Sxa addresses and the advertised control-plane address, CLI flags (log level), and `SGWC_*` environment variables for the S11 bind, the PGW peer, the S5-C and GTP-U advertised addresses and the restart counter.

> **Honesty note:** the nightly `Docker E2E (EPC)` job waits for the Sxa association from both ends and then attaches a real LTE UE whose default bearer crosses this SGW-C's sessions with a 0%-loss ping. This is the project's own matched-simulator validation, not third-party certification.

## Example configuration

From `nextgcore/docker/rust/configs/epc/sgwc.yaml` (mounted read-only to `/etc/nextgcore/sgwc.yaml` by `docker-compose-epc.yml`):

```yaml
# NextGCore SGW-C Configuration for Docker EPC Deployment
# Rust implementation

logger:
  file:
    path: /var/log/nextgcore/sgwc.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

sgwc:
  gtpc:
    server:
      - address: 172.24.0.3
  pfcp:
    server:
      - address: 172.24.0.3
    client:
      sgwu:
        - address: 172.24.0.6
```

## YAML parameters

Parsed by `src/bins/nextgcore-sgwcd/src/config.rs`. Every field is optional; a missing or malformed file logs a warning and changes nothing.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `sgwc.pfcp.server[0].address` | string | none | Address this SGW-C presents on Sxa: its PFCP Node ID when `SGWC_PFCP_NODE_IP` is unset (#387). Loopback is the last resort, with a warning. |
| `sgwc.pfcp.client.sgwu[0].address` / `.port` | string / u16 | `127.0.0.1` / `8805` | The SGW-U this SGW-C associates with and provisions over Sxa. `SGWC_SGWU_ADDR` overrides it. |
| `sgwc.gtpc.server[0].address` | string | none | Advertised S11/S5-C control-plane address when the S11 socket is bound to a wildcard (the default) and `SGWC_S11_ADVERTISE` is unset (#482). It is **not** used as the GTP-U address; set `SGWC_GTPU_ADVERTISE` to the SGW-U's address. |

Not read: `logger.*` (use `-l/--log-level`) and `global.max.*`.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-sgwcd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | string | `/etc/nextgcore/sgwc.yaml` | Configuration file path. |
| `-l, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); unrecognized values fall back to `info`. |
| `--no-color` | flag | off | Parsed but never read — currently has no effect. |
| `-d, --daemon` | flag | off | Parsed but never read — currently has no effect. |

## Behavior notes

- **Sxa association** (TS 29.244 §6.2.6, #1001):
  - The SGW-C sets up the association with its SGW-U at startup.
  - While there is no association, it retries the Association Setup every 10 s (T1 3 s,
    N1 2 per attempt). This covers an SGW-U that comes up later, and one that refuses the
    first Setup because its allowlist has not yet resolved the SGW-C's address.
  - Once associated, it sends the SGW-U a Heartbeat Request every 10 s.
  - No Heartbeat Response after T1 x (N1 + 1) is a PFCP path failure. The association and
    its sessions are kept, and heartbeating continues. Setting the association up again over
    a path that only blinked would make a conformant SGW-U drop every session (TS 29.244
    §6.2.6.2.2).
  - A newer Recovery Time Stamp means the SGW-U restarted. The stamp is carried in its
    Heartbeat Response and in its own Heartbeat Request. It is normalised to NTP seconds
    (#995), so a pre-#995 SGW-U's Unix seconds do not read as a restart, and an older stamp
    from a reordered message is ignored. After a restart:
    - the association is set up again;
    - every established PFCP session is established again with the same CP F-SEID, F-TEIDs,
      PDRs and FARs. The SGW-C allocates them all, so the MME and the PGW keep their
      endpoints.
  - While there is no association, the SGW-C sends no PFCP session message (TS 29.244 §6.2.6.1).
    A Create Session Request is refused with No resources available before it is relayed to
    the PGW. Other S11 requests that need a PFCP session message are answered with a failure.
- **Environment variables** (read in `gtp_path.rs` / `pfcp_path.rs` / `main.rs`):

  | Variable | Default | Effect |
  |---|---|---|
  | `SGWC_S11_BIND` | `0.0.0.0:2123` | S11 GTPv2-C UDP bind `address:port`. |
  | `SGWC_S11_ADVERTISE` | unset | Advertised control-plane IPv4; consulted only when the bound address is a wildcard. Falls back to `sgwc.gtpc.server[0].address`. |
  | `SGWC_GTPU_ADVERTISE` | unset (falls back to the bound or `SGWC_S11_ADVERTISE` address, not the YAML one) | SGW-U user-plane IPv4 placed in S1-U/S5-U F-TEIDs. The EPC compose sets it to the SGW-U (`172.24.0.6`). |
  | `SGWC_PGW_S5C` | unset | PGW-C S5/S8 peer (`ip` or `ip:port`, port `2123` by default). **Unset means the SGW-C refuses an S11 Create Session Request** rather than answering it from local state. The EPC compose sets `172.24.0.4`. |
  | `SGWC_S5C_ADVERTISE` | the S11 address | Dedicated S5-C address, if different from S11. |
  | `SGWC_PFCP_BIND_ADDR` | `0.0.0.0:8805` | Sxa PFCP bind `address:port`. |
  | `SGWC_PFCP_NODE_IP` | `sgwc.pfcp.server[0].address`, then `127.0.0.1` | PFCP Node ID (IPv4). |
  | `SGWC_SGWU_ADDR` | `sgwc.pfcp.client.sgwu`, then `127.0.0.1:8805` | SGW-U override (`ip` or `ip:port`). |
  | `SGWC_ECHO_INTERVAL_SECS` | `60` | GTPv2-C Echo interval; `0` disables probing. |
  | `SGWC_RESTART_COUNTER_FILE` | `/var/lib/nextgcore/sgwc-restart-counter` | Persisted TS 23.007 §18 restart counter, advanced on every start. |
  | `SGWC_RESTART_COUNTER` | unset | Test override of the restart counter (u8). |
  | `SGWC_RESTART_DELETE_CONTEXTS` | off | `1`/`true`/`yes` deletes contexts when a peer's restart is detected. Off by default because a misfiring heuristic would drop live sessions (#53). |
  | `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OTLP endpoint for OpenTelemetry traces. |

- **No advertised GTP-U address means total session rejection.** If the S11 socket is bound to a wildcard and neither `SGWC_S11_ADVERTISE` nor `SGWC_GTPU_ADVERTISE` is set, every Create Session Request is rejected with `NO_RESOURCES_AVAILABLE`.
- **Rejection semantics on S11** (per TS 29.274 tables cited in `s11_parse.rs` comments): a missing mandatory IE triggers a response with cause `MANDATORY_IE_MISSING` plus the offending IE type; an unknown header TEID gets `CONTEXT_NOT_FOUND`; Bearer Resource, Modify Bearer and Delete Bearer Commands are relayed to the PGW over S5/S8 (#606).
- **GTPv2-C reliability defaults** come from `Gtp2XactConfig::default()` in `libs/nextgcore-gtp/src/v2/xact.rs`: T3-RESPONSE 3 s, N3-REQUESTS 3, responses cached for 12 s so retransmitted requests are answered identically without creating duplicate sessions. N3 exhaustion marks the peer path `Failed` (TS 29.274 §7.6 per code comment); a changed peer Recovery counter logs a stale-contexts warning and resets the path to `Idle` (TS 23.007 §18 per code comment).
- **No NRF, no session store.** As an EPC NF the SGW-C has no SBI server and performs no NRF registration or heartbeat; UE/session/bearer/tunnel state is in-memory and lost on restart. Only the restart counter is persisted (`SGWC_RESTART_COUNTER_FILE`).
- **`RUST_LOG` overrides `-l/--log-level`** when set, as in every NF.
