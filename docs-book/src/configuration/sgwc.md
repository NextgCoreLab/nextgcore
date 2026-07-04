# SGW-C Configuration

The SGW-C (Serving Gateway Control plane, `nextgcore-sgwcd`) is the 4G/EPC control-plane half of the Serving Gateway, ported from `src/sgwc/` of the C reference. Per the daemon's module docs it terminates three interfaces: **S11** (GTPv2-C from the MME), **S5-C** (GTPv2-C toward the PGW), and **Sxa** (PFCP toward the SGW-U). In the current code only S11 is a live network endpoint: `gtp_path.rs` owns a real UDP socket (well-known GTPv2-C port 2123, TS 29.274 §4.2 per code comment) with a receive/dispatch loop, Echo Request/Response with Recovery, restart-counter staleness detection (TS 23.007 §18 per code comment), and a full T3/N3 retransmission transaction layer. It dispatches Create Session, Modify Bearer, Delete Session, Release Access Bearers, Create/Delete Indirect Data Forwarding Tunnel, Bearer Resource Command, Downlink Data Notification Ack/Failure, and Create/Update/Delete Bearer Responses (message builders and strict parsers cite TS 29.274 §7.2.x tables in `s11_build.rs`/`s11_parse.rs`). The Sxa PFCP path (`pfcp_path.rs`) and S5-C forwarding are handler-level stubs — see the behavior notes.

Configuration is split three ways, unusually for this project: a YAML file path (default `/etc/nextgcore/sgwc.yaml`, overridable with `-c/--config`) that the daemon accepts **but never parses**, a small set of CLI flags (log level), and environment variables (`SGWC_*`), which carry all of the real network configuration — bind address, advertised control-plane and user-plane addresses, and the restart counter.

> **Honesty note:** SGW-C behavior is validated by this project's own unit tests and in-process loopback-socket tests (the S11 procedures in `gtp_path.rs` are exercised over real UDP sockets), plus the matched-simulator Docker EPC deployment — not by third-party conformance certification. Two of the three advertised interfaces are not wired to the network: `pfcp_open()` binds no socket and `send_pfcp_message()` only logs, so Sxa provisioning toward the SGW-U never leaves the process, and S5-C forwarding toward a live PGW peer "is not wired yet" (comment in `gtp_path.rs`). The Create Session Response is therefore sent synchronously, before any user-plane confirmation — a code comment notes this send moves to the Sxa response handler once an asynchronous PFCP transport lands.

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

**None.** Unlike most NextGCore NFs, `nextgcore-sgwcd` defines no `#[derive(Deserialize)]` config structs anywhere in its crate (no `serde`/`serde_yaml` usage at all), and it never opens the config file: `SgwcApp::init` receives the path as `_config_path` and ignores it (`src/bins/nextgcore-sgwcd/src/main.rs`). The only use of `-c/--config` is a startup log line (`Configuration: <path>`). A code comment in `init()` states "In a real implementation, these values would come from config".

### Parsed-but-inert / decorative YAML fields

Because nothing is deserialized, **every field in the shipped example YAML is decorative**:

- **`logger.file.path` and `logger.level` are inert.** The log level comes solely from the CLI flag `-l/--log-level` (default `info`); there is no file logging.
- **`global.max.ue` / `global.max.peer` are inert.** The in-code pool caps are a hardcoded `ctx.init(1024, 4096, 16384, 32768)` (max UE/session/bearer/tunnel) — and even that call is dead: it is gated behind an `Arc::try_unwrap` on a freshly cloned shared context, which can never succeed, so the caps stay `0`. The context guards check `max_* > 0`, so `0` means **unlimited**, not zero capacity.
- **`sgwc.gtpc.server[].address` is inert.** The S11 bind address comes from the `SGWC_S11_BIND` environment variable (default `0.0.0.0:2123`).
- **`sgwc.pfcp.server[].address` and `sgwc.pfcp.client.sgwu[].address` are inert.** The PFCP path is a stub that binds no socket and dials no SGW-U peer.
- **freeDiameter config is not consumed.** The SGW-C has no Diameter role and no Diameter code; `docker/rust/configs/epc/freeDiameter/` ships only `hss.conf`, `mme.conf`, and `pcrf.conf`, and the compose file mounts that directory into the MME/HSS/PCRF containers, not the SGW-C.

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-sgwcd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | string | `/etc/nextgcore/sgwc.yaml` | Configuration file path. Logged at startup, never parsed (see above). |
| `-l, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); unrecognized values fall back to `info`. |
| `--no-color` | flag | off | Parsed but never read — currently has no effect. |
| `-d, --daemon` | flag | off | Parsed but never read — currently has no effect. |

## Behavior notes

- **Environment variables are the real config surface** (all read in `gtp_path.rs` / `main.rs`; env value wins over the built-in default, and there is no YAML or CLI equivalent for any of them):

  | Variable | Default | Effect |
  |---|---|---|
  | `SGWC_S11_BIND` | `0.0.0.0:2123` | S11 GTPv2-C UDP bind `address:port`. |
  | `SGWC_RESTART_COUNTER` | `1` | Local restart counter advertised in Recovery IEs (u8; unparseable values fall back to `1`). |
  | `SGWC_S11_ADVERTISE` | unset | Advertised control-plane IPv4; consulted only when the bound address is a wildcard. |
  | `SGWC_GTPU_ADVERTISE` | unset (falls back to the advertised S11 address) | SGW-U user-plane IPv4 placed in S1-U F-TEIDs. |
  | `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OTLP endpoint for OpenTelemetry traces. |

- **No advertised GTP-U address means total session rejection.** If the S11 socket is bound to a wildcard and neither `SGWC_S11_ADVERTISE` nor `SGWC_GTPU_ADVERTISE` is set, the context has no GTP-U address and every Create Session Request is rejected with `NO_RESOURCES_AVAILABLE`. The shipped `docker-compose-epc.yml` sets no `SGWC_*` variables, so this caveat applies to that deployment as-is.
- **Rejection semantics on S11** (per TS 29.274 tables cited in `s11_parse.rs` comments): a missing mandatory IE triggers a response with cause `MANDATORY_IE_MISSING` plus the offending IE type; an unknown header TEID gets `CONTEXT_NOT_FOUND`; a Bearer Resource Command is answered with a Bearer Resource Failure Indication carrying `SERVICE_NOT_SUPPORTED` because S5-C forwarding is not wired (TS 29.274 §7.2.6 per code comment).
- **GTPv2-C reliability defaults** come from `Gtp2XactConfig::default()` in `libs/nextgcore-gtp/src/v2/xact.rs`: T3-RESPONSE 3 s, N3-REQUESTS 3, responses cached for 12 s so retransmitted requests are answered identically without creating duplicate sessions. N3 exhaustion marks the peer path `Failed` (TS 29.274 §7.6 per code comment); a changed peer Recovery counter logs a stale-contexts warning and resets the path to `Idle` (TS 23.007 §18 per code comment).
- **No NRF, no state files.** As an EPC NF the SGW-C has no SBI server and performs no NRF registration or heartbeat; all UE/session/bearer/tunnel state is in-memory (`OnceLock<Arc<SgwcContext>>`) and lost on restart.
- **`RUST_LOG` is ignored.** Logging is initialized via `env_logger::Builder::new().filter_level(...)` without env parsing, so the `RUST_LOG=info` set by the Docker compose files has no effect on this daemon; use `-l/--log-level`. Internal timer defaults (PFCP association retry 3 s, PFCP no-heartbeat 10 s in `timer.rs`, polled every 100 ms) are effectively dormant while the Sxa path is stubbed.
