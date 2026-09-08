# SGW-U Configuration

The SGW-U (Serving Gateway User Plane, `nextgcore-sgwud`) is the 4G/EPS user-plane NF in NextGCore's dual 5G+4G core. It owns a real GTP-U UDP socket on port 2152 (TS 29.281, as cited in the daemon source) and implements the forwarding path *G-PDU in → PDR match by TEID → FAR apply (FORW/BUFF/DROP) → G-PDU out* between the S1-U (eNB) and S5-U (PGW) interfaces (`src/bins/nextgcore-sgwud/src/gtp_path.rs`, `main.rs` comments). Its control plane is PFCP over the Sxa reference point toward the SGW-C — session establishment/modification/deletion/report handling in `sxa_handler.rs`, response building in `sxa_build.rs`, and an association/heartbeat state machine in `pfcp_sm.rs` (TS 29.244 and TS 23.214 per code comments). It has **no SBI/HTTP surface, no GTP-C, and no Diameter interface**.

Unlike most NextGCore NFs, this daemon has **no YAML config loading and no CLI parser at all**: `main.rs` defines no clap `Args` struct and no `#[derive(Deserialize)]` config structs, and never opens a config file. The only configuration surface is **environment variables** (`SGWU_GTPU_BIND`, `SGWU_GTPU_ADVERTISE`, `OTEL_EXPORTER_OTLP_ENDPOINT`, plus `RUST_LOG` via `env_logger::init()`). The Docker deployment still mounts a YAML file and passes `-c /etc/nextgcore/sgwu.yaml` on the command line (`Dockerfile.nf` `CMD` / `docker-compose-epc.yml` `command:`), but the binary never reads `argv`, so both the flag and the file are ignored.

> **Honesty note:** SGW-U behavior is validated by this project's own in-crate unit tests only — not by third-party conformance certification, and (per the project directive) not against Open5GS as an oracle, although the modules are documented as ports of a C reference (`Port of src/sgwu/*.c` per module comments). Two gaps are worth knowing: `pfcp_path::pfcp_open()` is a stub that logs but binds no PFCP socket (UDP 8805 appears only in comments), and `main()` initializes the subsystems, dispatches the entry event, and then immediately runs the shutdown sequence — the long-running poll loop is described only in a `// Note:` comment. The GTP-U server, PFCP FSM, and Sxa handlers are real and unit-tested, but the wired-together daemon lifecycle is not exercised end-to-end; the project's 84/84 Docker E2E result covers the 5GC (UPF) data path, not this EPC NF.

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

**None.** The binary contains no `#[derive(Deserialize)]` configuration structs and never opens the YAML file — there is no `-c/--config` handling in `src/bins/nextgcore-sgwud/src/main.rs` (its `Cargo.toml` does not even depend on serde or clap). Every key in the shipped example file is therefore decorative; see below.

### Parsed-but-inert / decorative YAML fields

The **entire shipped `sgwu.yaml` is inert** for this daemon:

- **`logger.file.path` and `logger.level` are inert.** Logging is `env_logger` configured by `RUST_LOG` (the compose file sets `RUST_LOG: info`); nothing writes to `/var/log/nextgcore/sgwu.log`.
- **`global.max.ue: 1024` is inert but coincidental.** The session pool really is 1024, but it is hard-coded as `context::sgwu_context_init(1024)` in `main.rs`, not read from YAML.
- **`global.max.peer: 64` is inert.** No peer-pool sizing exists in this binary.
- **`sgwu.pfcp.server[].address` is inert.** `pfcp_open()` binds nothing; the address is never read.
- **`sgwu.gtpu.server[].address` is inert.** The GTP-U bind comes from `SGWU_GTPU_BIND` (default `0.0.0.0:2152`), not from YAML. The `172.24.0.6` value merely mirrors the container's compose-assigned IP.
- **freeDiameter configs are not consumed.** `docker/rust/configs/epc/freeDiameter/` serves the Diameter NFs (MME/HSS/PCRF); `nextgcore-sgwud` has no Diameter code and never reads those files.

## Command-line flags

**None.** There is no clap parser; `main()` never inspects `std::env::args`. The Docker image entrypoint appends `-c /etc/nextgcore/sgwu.yaml` (`Dockerfile.nf` default `CMD`, overridden with the same shape in `docker-compose-epc.yml`), which the process accepts and silently ignores.

## Environment variables

The actual configuration surface (all read in `main.rs` and `gtp_path.rs`):

| Variable | Default | Description |
|---|---|---|
| `SGWU_GTPU_BIND` | `0.0.0.0:2152` | GTP-U bind address:port (`DEFAULT_GTPU_BIND`, TS 29.281 §4.4.2.3 per code comment). |
| `SGWU_GTPU_ADVERTISE` | unset | IPv4 address advertised in UP-allocated F-TEIDs. Consulted **only** when the bound address is wildcard/non-IPv4; a concrete bound IPv4 always wins. Unparseable values are silently discarded (advertise address becomes `None`). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://jaeger:4317` | OTLP endpoint for OpenTelemetry traces (service name `nextgcore-sgwud` from `CARGO_PKG_NAME`); init is best-effort (`.ok()`), failures are non-fatal. |
| `RUST_LOG` | `env_logger` default (`error`) | Log filter; the EPC compose sets `info`. |

## Behavior notes

- **GTP-U datagram handling** (`gtp_path.rs`): Echo Request is answered with an Echo Response carrying the mandatory Recovery IE with restart counter 0 (TS 29.281 §8.2 per code comment); received Echo Response recovery values are ignored; End Marker and G-PDU are dispatched through PDR/FAR lookup; undecodable packets and unknown message types are dropped with an error log.
- **Error Indication → ERIR**: an inbound Error Indication is mapped back to the FAR carrying that TEID and reported to the SGW-C via a PFCP Session Report Request (TS 29.244 §5.10 per code comment). If no FAR matches, it is logged and swallowed.
- **Session admission**: the pool is hard-coded to 1024 sessions (`sgwu_context_init(1024)`); when full, `sess_add` logs `Maximum number of sessions [1024] reached` and the establishment fails. Per-FAR buffering (BUFF action) holds at most `MAX_BUFFERED_PACKETS = 64` packets, flushed when forwarding resumes (TS 29.244 §5.3.1 per code comment).
- **F-TEID CH allocation can fail silently in the shipped deployment**: when a Create PDR carries the CH (CHOOSE) flag (TS 29.244 §8.2.3 per code comment), the UP allocates a TEID and must advertise its own GTP-U address; with no address configured it returns PFCP cause `NO_RESOURCES_AVAILABLE`. Because the default bind is wildcard `0.0.0.0:2152` and `docker-compose-epc.yml` sets neither `SGWU_GTPU_BIND` nor `SGWU_GTPU_ADVERTISE`, the advertised address resolves to `None` — set `SGWU_GTPU_ADVERTISE` (or bind a concrete IPv4) for CH allocation to work.
- **PFCP association/heartbeat FSM** (`pfcp_sm.rs`, `timer.rs`): `will_associate` retries association every 3 s and moves to `Associated` on an Association Setup Request/Response; both timers have `max_count = 0`, meaning **unlimited retries**. On entry to `Associated` the node sends a Heartbeat Request and answers incoming ones; the no-heartbeat timer is 10 s. A restoration path exists (`pfcp_restoration`, `sess_remove_all_for_pfcp_node`, and Create-PDR restoration-indication TEID reuse).
- **Usage reporting (URR)** (#215 / #267, TS 29.244 §5.2.2.1 / §7.5.2.4). **Read the two ceilings first: URR provisioning cannot arrive from an SGW-C, and no Usage Report can leave.** There is no PFCP IE decoder in sgwud at all — `pfcp_path::handle_pfcp_recv` reads only the message-type octet and still carries the comment "In actual implementation: 1. Parse PFCP message", and `SessionEstablishmentRequest` is constructed in production exactly once, as `::default()`. So the URR handlers below are driven only in-process, and the egress side is a logging placeholder (see #217). #215's spec declared the egress ceiling and this page asserted the opposite about ingress; #267 corrected that. What follows describes the *modelling and encoding*, which are real and tested, not a live interface. The SGW-U models Create / Update / Remove URR on Session Establishment and Session Modification, stores each rule with its Measurement Method, Reporting Triggers, Volume Threshold, Volume Quota, Time Threshold and Measurement Period, links it to the PDRs that name it, and populates `PfcpSess.urr_ids`. `apply_far` counts bytes and packets against every URR the matched PDR names; crossing a requested trigger produces a Usage Report with a **monotonic UR-SEQN** (§8.2.60), carried as IE 80 in a Session Report Request with the USAR report-type bit set. Session deletion emits one final report per URR as IE 79 in the Session Deletion Response, tagged TEBUR. A threshold is checked **only when its Reporting Triggers bit is set** — §8.2.41 makes that IE the CP function's request, so a provisioned threshold with a clear trigger bit stays silent. A duration-only (`DURAT`) URR accumulates no volume, and a report that measured nothing omits the Volume Measurement IE rather than sending an all-zero one.
  - **QER-dropped, FAR-dropped and buffer-full traffic is NOT counted.** §5.2.2.1 measures the network resources the UP function *uses*, and a packet it discarded consumed none. Counting it would over-bill a subscriber for traffic the network refused to carry; under-counting a dropped packet costs the operator nothing it was entitled to. Traffic **accepted** into a BUFF FAR's buffer is counted, once, at buffering time — not again on flush. A packet the buffer **rejects** because it is already at capacity is not counted (#267: it was, so a downlink burst past capacity over-billed its whole tail). A buffered packet is still billed on the paths where it is provably never delivered — session teardown discards the queue, a failed flush logs and continues, and an SGW-C switching the FAR to DROP discards it — so the claim is "accepted", not "delivered".
  - **Nothing is sent over the wire yet, and nothing can arrive.** `pfcp_path::send_pfcp_request` is a logging placeholder (see below), so a Usage Report is built correctly and then goes nowhere; and with no IE decoder, a Create URR from an SGW-C cannot reach the handler that would store it. Issue #217 covers both directions.
  - **Volume Threshold is per measurement period; Volume Quota is cumulative for the session** (#267). Counters are cumulative with a reported-so-far watermark, so a report carries its period's delta while the total survives for the quota check. Resetting the counters on each report — as #215 did — made a quota **unreachable** whenever a threshold also fired.
  - **Timestamps are NTP-epoch** (RFC 5905, per §8.2.34-§8.2.37), not UNIX. #215 wrote UNIX seconds, so every Start/End/First/Last Packet time was ~70 years low.
  - **VOLQU is octet 6 bit 1** of the Usage Report Trigger. #215 put it on octet 5 bit 7, which is DROTH, so a quota-exhaustion report claimed a dropped-downlink-traffic threshold instead.
  - **A report carries every satisfied trigger**, not just the first: the IE is a bitmask, and reporting one while resetting the period consumed the others' conditions silently.
  - **No Query URR / Query All URRs**, so a Remove URR discards its residual volume rather than reporting it. The amount is logged at `warn` so it is visible rather than silently lost.
- **PFCP requests from the SGW-U are not actually transmitted**: `pfcp_path::send_pfcp_request` formats a debug line and returns, with a comment describing what a real implementation would do. So Session Report Requests — Downlink Data Reports, Error Indication Reports and Usage Reports alike — are built and dropped. Tracked as issue #217.
- **No state files** are read or written; all session/PDR/FAR/QER/BAR/URR state is in-memory and lost on restart. For URRs that means unreported volume does not survive a restart.
