# PCRF Configuration

The PCRF (Policy and Charging Rules Function, `nextgcore-pcrfd`) is the 4G/EPC policy node in NextGCore's dual 5G+4G core. It is a pure Diameter server (RFC 6733 responder, per the `fd_path.rs` module comment): PCEFs (P-GW) connect on **Gx** (TS 29.212 §5.6 messages / §5.3 AVPs, as cited in the daemon source) and AFs (P-CSCF) connect on **Rx** (TS 29.214 §4.4.1 AAR, §4.4.4 STR, §4.4.6 ASR, per code comments). Both applications share one Diameter listener; incoming requests are dispatched by Application-Id (`dispatch_request` in `fd_path.rs`). The PCRF answers Gx CCR with CCA and Rx AAR/STR with AAA/STA, and originates Gx RAR (Charging-Rule-Install/Remove) and Rx ASR over the peer connections the remote nodes established. There is no SBI/HTTP surface and no NRF interaction — this NF is Diameter-only.

Configuration is almost entirely command-line flags. The daemon accepts a YAML file path (default `/etc/nextgcore/pcrf.yaml`, overridable with `-c/--config`), but the parser behind it — `pcrf_context_parse_config` in `src/bins/nextgcore-pcrfd/src/context.rs` — is a stub that returns `Ok(())` without reading the file. `main.rs` only checks that the file exists and logs a message. Every operative knob (Diameter identity/realm, listen address, session limit, log level) is a clap flag on the `Args` struct in `src/bins/nextgcore-pcrfd/src/main.rs`.

> **Honesty note:** PCRF behavior is validated by this project's own unit tests and matched-simulator Docker E2E deployments, not by third-party conformance certification. Three things an operator should know up front: (1) **the YAML config file is not parsed at all** — it is decorative (see below); (2) the freeDiameter-style config shipped in `docker/rust/configs/epc/freeDiameter/pcrf.conf` is **never read** by this Rust binary (the `--diameter-config` flag is accepted but unused; identity/realm/address come from other flags); (3) although a subscriber-policy DB lookup exists in the code (`lookup_subscriber_policy` via `nextgcore-dbi`), this binary never initializes the MongoDB connection, so **every session gets the built-in default policy profile** (QCI 9, APN-AMBR 100 Mbps DL / 50 Mbps UL).

## Example configuration

From `nextgcore/docker/rust/configs/epc/pcrf.yaml` (mounted read-only at `/etc/nextgcore/pcrf.yaml` by `docker-compose-epc.yml`, which starts the daemon with `-c /etc/nextgcore/pcrf.yaml` and no other flags):

```yaml
# NextGCore PCRF Configuration for Docker EPC Deployment
# Rust implementation

db_uri: mongodb://mongodb:27017/nextgcore

logger:
  file:
    path: /var/log/nextgcore/pcrf.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

pcrf:
  freeDiameter: /etc/freeDiameter/pcrf.conf
  metrics:
    server:
      - address: 172.24.0.9
        port: 9090
```

## YAML parameters

**None.** The daemon deserializes zero fields from the YAML file. There is no `#[derive(Deserialize)]` config struct anywhere in `src/bins/nextgcore-pcrfd/`; the config entry point `pcrf_context_parse_config(_config_path)` in `src/bins/nextgcore-pcrfd/src/context.rs` is a stub that immediately returns `Ok(())` (its own comment reads "Note: Implement YAML configuration parsing"). `main.rs` logs `Loading configuration from <path>` when the file exists, which can mislead — nothing is loaded. All runtime behavior is driven by the CLI flags below and two environment variables (see Behavior notes).

### Parsed-but-inert / decorative YAML fields

Because parsing is a stub, **every** field in the shipped example file is inert:

- **`db_uri` is inert.** The binary has a `--db-uri` flag too, but neither is ever passed to `nextgcore_dbi_init`/`nextgcore_mongoc_init` — no MongoDB connection is made by this daemon.
- **`logger.file.path` and `logger.level` are inert.** Logging goes to stderr via `env_logger`; the level comes from `-e/--log-level` (default `info`). The `-l/--log-file` flag is also accepted but never used by `init_logging` in `main.rs`.
- **`global.max.ue` / `global.max.peer` are inert.** The only session limit is the `--max-sess` flag (and even that is stored, not enforced — see Behavior notes).
- **`pcrf.freeDiameter` is inert.** Neither the YAML pointer (`/etc/freeDiameter/pcrf.conf`) nor the CLI default (`--diameter-config /etc/nextgcore/freeDiameter/pcrf.conf`) is ever opened. The shipped `docker/rust/configs/epc/freeDiameter/pcrf.conf` (Identity `pcrf.localdomain`, Realm `localdomain`, `ListenOn 172.24.0.9`, `ConnectPeer smf.localdomain`) is mounted into the container but ignored; the daemon's actual identity/realm/listen address come from `--diameter-id`/`--diameter-realm`/`--diameter-addr`, whose defaults happen to match the conf's Identity/Realm. The PCRF never dials out to peers (`ConnectPeer` has no equivalent): it only accepts inbound connections.
- **`pcrf.metrics.server[]` (address/port) is inert.** No Prometheus/metrics HTTP server is started by this binary; the only telemetry is the optional OTLP trace exporter (env var, see below).

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-pcrfd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/pcrf.yaml` | Configuration file path. Only its existence is checked; contents are ignored (stub parser). |
| `-l, --log-file` | path | unset | Accepted but **never used** — logs always go to stderr. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); unrecognized values fall back to `info`. |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Stub: logs "would send SIGTERM to running instance" and exits; does not actually signal anything. |
| `--diameter-config` | path | `/etc/nextgcore/freeDiameter/pcrf.conf` | FreeDiameter configuration file — accepted but **never read**. |
| `--diameter-id` | string | `pcrf.localdomain` | Diameter Origin-Host identity of this PCRF. |
| `--diameter-realm` | string | `localdomain` | Diameter Origin-Realm. |
| `--diameter-addr` | socket addr | `0.0.0.0:3868` | Diameter listen address; Gx and Rx share this one listener. Must parse as `host:port` or startup fails with "Invalid --diameter-addr". |
| `--max-sess` | usize | `1024` | Maximum number of sessions. Stored in the context and logged at startup, but **no code path enforces it** — `gx_session_add` never checks it. |
| `--db-uri` | string | unset | MongoDB URI — parsed but never wired to the DB layer. |
| `--db-name` | string | `nextgcore` | Database name — parsed but never used. |
| `--state-file` | path | unset | JSON snapshot file for the Gx/Rx session tables (#57). Falls back to `NEXTGCORE_PCRF_STATE_FILE`; an empty value is treated as unset. With neither set the PCRF is memory-only. |

## Behavior notes

- **Peer handling (RFC 6733, per code comments):** CER/CEA (responder role), DWR/DWA and DPR/DPA are handled by the shared `nextgcore_diameter::peer::DiameterPeer`. The PCRF sends a device watchdog every 30 s (`timer_tc` default in `DiameterConfig`) and closes the connection after 3 consecutive missed watchdogs (`MAX_MISSED_WATCHDOGS` in `fd_path.rs`). Peers are registered by Origin-Host once the CER/CEA exchange completes.
- **Gx CCR semantics (TS 29.212 §5.6 per code comments):** `INITIAL_REQUEST` creates the Gx session and indexes it by Session-Id and by Framed-IP-Address / Framed-IPv6-Prefix; `UPDATE_REQUEST` and `TERMINATION_REQUEST` for an unknown Session-Id are answered with Result-Code 5002 `DIAMETER_UNKNOWN_SESSION_ID`. An **initial** provisioning CCA carries Default-EPS-Bearer-QoS, QoS-Information (APN-AMBR), Event-Triggers (QoS/RAT change, UE IP allocate/release) and a Charging-Rule-Install. Termination clears the IP bindings and fires Rx ASRs toward any bound AF sessions. An *incoming* Gx RAR is rejected with 3001 `DIAMETER_COMMAND_UNSUPPORTED` (the PCRF only originates RAR); unknown applications get 3007 `DIAMETER_APPLICATION_UNSUPPORTED`.
- **What an UPDATE answer carries is now a function of what the PCEF reported (#57).** Before #57 every CCR-U got the same static payload the initial request got, regardless of the request — TS 29.212 §4.5.1 makes the PCRF's decision a function of the reported Event-Trigger and its related data, so unconditional replay meant a consumer could not tell "policy changed" from "nothing happened".
  - `RAT_CHANGE` re-authorizes: the CCA restates Default-EPS-Bearer-QoS and QoS-Information for the new access.
  - `QOS_CHANGE` re-authorizes **only if** the QoS-Information the PCEF reports diverges from what was authorized. On agreement the CCA carries no QoS at all. On divergence it carries the **authorized** values, correcting the PCEF — never an echo of what was reported.
  - `UE_IP_ADDRESS_ALLOCATE` / `UE_IP_ADDRESS_RELEASE` install and clear the IP→session mapping. The release takes the address from the *session*, not from the CCR, because a release report need not echo the address it releases.
  - A CCR-U reporting **no** recognized trigger provisions nothing. Rules are never re-installed on an update; the PCEF holds them from the initial provisioning.
  - `RAT-Type` is recorded on the session whenever reported. It was previously hardcoded to `0` and never populated.
- **PCC rule failure reports are acted on (TS 29.212 §4.5.12, #57).** A `Charging-Rule-Report` with `PCC-Rule-Status = INACTIVE` withdraws the named rule from the PCRF's installed set and from every bound Rx session. If that leaves an Rx session with **no** installed rule, the AF is aborted with an ASR — the state where "the AF believes an unenforced service is active" is the harm §4.5.12 exists to prevent. Three deliberate limits: `TEMPORARILY INACTIVE` withdraws nothing (§5.3.19 says the rule is expected back, so aborting would tear down an AF session that is about to work); no `Charging-Rule-Remove` is sent back, per §4.5.12's own NOTE that the PCRF *"does not need request the PCEF to remove the inactive PCC rule"*; and `Charging-Rule-Base-Name` is logged but not resolved, because this PCRF provisions no base names and so has no membership list to expand one against. `PCRF_ASR_ON_RULE_FAILURE=0` keeps the bookkeeping update and suppresses the ASR; it defaults **on**, because off reproduces the defect.

## Durable state (#57)

Off by default. With `--state-file` (or `NEXTGCORE_PCRF_STATE_FILE`) the PCRF
snapshots the Gx and Rx session tables on every mutation and reloads them at boot,
so a restart no longer answers `DIAMETER_UNKNOWN_SESSION_ID` (5002) for every live
PDN connection's CCR-U and CCR-T indefinitely. Uses the shared
`nextgcore-core::state_store::StateStore` (atomic + fsynced + `0600` writes; a
snapshot that cannot be read is never overwritten). An unreadable snapshot, or one
from a newer build, **fails startup**.

Two details specific to pcrfd:

- **The index hashes ARE persisted**, unlike the other NFs in this tree.
  `gx_session_remove` and `rx_session_remove` drop only the hash entry and leave a
  **tombstone** in the vector, because a Gx session's `rx_sessions` and an Rx
  session's `gx_session_idx` are positional indexes that compacting would
  re-point. So the hash — not the vector — records which sessions are live, and it
  is not derivable. Rebuilding it from every vector entry would resurrect every
  session ever terminated. Only the live sid *set* is stored; the indexes
  themselves are re-derived from position, so a persisted index cannot disagree
  with the list it points into.
- **The IP maps are derived on restore** from the session table under the same
  `has_ipv4`/`has_ipv6` conditions the live path uses, and only for live sessions,
  so a tombstone's old address does not come back resolving to a session that no
  longer answers.

Not enabled in the shipped Docker EPC compose, so the default E2E path is unchanged.

**The restart-signalling alternative was not taken.** #57 offered either
persistence or clean restart signalling via a fixed-at-start `Origin-State-Id`.
`nextgcore-diameter`'s `origin_state_id()` returns `SystemTime::now()` seconds on
every call, so it is not a stable per-instance restart indicator (RFC 6733 §8.16)
and the signalling option has no working foundation today. That is filed as its own
diameter-layer issue; persistence needs nothing from it.
- **Policy is always the default profile in practice:** `build_subscriber_session_data` (`gx_path.rs`) tries `nextgcore_dbi_subscription_data`, but since this binary never initializes the Mongo client, the lookup always fails and it falls back to the built-in `default_profile` — QCI 9, ARP derived from the QCI table, APN-AMBR 100,000,000 bps down / 50,000,000 bps up, and one catch-all non-GBR PCC rule named `pcrf-<apn>-default` (precedence 100, bidirectional `permit ... ip from any to assigned` IPFilterRules).
- **Rx session binding (TS 29.214 per code comments):** an AAR is bound to the Gx (IP-CAN) session via the UE IP address; if no Gx session matches, the AAA carries Experimental-Result 5065 `IP_CAN_SESSION_NOT_AVAILABLE` (vendor 10415). If pushing the derived PCC rules to the PCEF via Gx RAR fails, the AAA carries 5063 `REQUESTED_SERVICE_NOT_AUTHORIZED`. An STR triggers a Gx RAR with Charging-Rule-Remove and unbinds the Rx session.
- **PCRF-initiated requests:** RAR/ASR are sent over the connection the target peer established (looked up by Origin-Host); the answer wait is capped at 5 s (`ANSWER_TIMEOUT` in `fd_path.rs`) with no application-level retransmission. If the peer is not connected the send fails immediately.
- **Environment variables:** `OTEL_EXPORTER_OTLP_ENDPOINT` sets the OpenTelemetry OTLP trace endpoint (default `http://jaeger:4317`; export failure is silently ignored). Note that `RUST_LOG` is **not** read — `init_logging` builds `env_logger` without consulting the environment, so the `RUST_LOG: info` set in `docker-compose-epc.yml` has no effect on this daemon; only `-e/--log-level` does. `NEXTGCORE_PCRF_STATE_FILE` supplies the durable-state path when `--state-file` is absent (the flag wins), and `PCRF_ASR_ON_RULE_FAILURE` (`0`/`false`/`no`/`off`) suppresses the §4.5.12 ASR. Gx/Rx message counters are held in memory and logged as a summary line at shutdown.
