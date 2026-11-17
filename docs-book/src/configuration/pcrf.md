# PCRF Configuration

The PCRF (Policy and Charging Rules Function, `nextgcore-pcrfd`) is the 4G/EPC policy node in NextGCore's dual 5G+4G core. It is a pure Diameter server (RFC 6733 responder, per the `fd_path.rs` module comment): PCEFs (P-GW) connect on **Gx** (TS 29.212 §5.6 messages / §5.3 AVPs, as cited in the daemon source) and AFs (P-CSCF) connect on **Rx** (TS 29.214 §4.4.1 AAR, §4.4.4 STR, §4.4.6 ASR, per code comments). Both applications share one Diameter listener; incoming requests are dispatched by Application-Id (`dispatch_request` in `fd_path.rs`). The PCRF answers Gx CCR with CCA and Rx AAR/STR with AAA/STA, and originates Gx RAR (Charging-Rule-Install/Remove) and Rx ASR over the peer connections the remote nodes established. There is no SBI/HTTP surface and no NRF interaction — this NF is Diameter-only.

Configuration comes from a YAML file (default `/etc/nextgcore/pcrf.yaml`, `-c/--config`) and from the clap flags of the `Args` struct in `src/bins/nextgcore-pcrfd/src/main.rs`. The file's `pcrf:` section is parsed by `pcrf_context_parse_config` in `src/bins/nextgcore-pcrfd/src/context.rs`. It supplies the Diameter identity, realm and listen address, directly (`pcrf.diameter`) or through the freeDiameter file named by `pcrf.freeDiameter`. A flag passed on the command line beats both (see "Diameter identity precedence" below). The top-level `db_uri` and `logger.level` are read too. The session limit and the state file are flags only.

> **Honesty note:** PCRF behavior is validated by this project's own unit tests and matched-simulator Docker E2E deployments, not by third-party conformance certification. Three things an operator should know up front: (1) **part of the YAML config file is inert** (`logger.file.path`, `global.max.*`; see below), and unknown keys anywhere in it are ignored without a warning, so a misspelt `pcrf.diameter` key silently keeps the lower-precedence value; (2) the freeDiameter file is read **only** through the YAML's `pcrf.freeDiameter` key, and only for its Identity, Realm, first ListenOn and Port. The `--diameter-config` flag is accepted but never read; (3) the subscriber store named by the top-level `db_uri` (or `--db-uri`) is opened at startup (#1459) and each Gx session's QCI, ARP and APN-AMBR come from the subscriber's provisioned session for the APN; a configured store that cannot be reached **fails startup**.

## Example configuration

From `nextgcore/docker/rust/configs/epc/pcrf.yaml`. `docker-compose-epc.yml` mounts it read-only at `/etc/nextgcore/pcrf.yaml`, mounts `configs/epc/freeDiameter/` at `/etc/freeDiameter`, and starts the daemon with `-c /etc/nextgcore/pcrf.yaml --diameter-addr 0.0.0.0:3868`:

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
  # Diameter identity for this node. Commented out so this file keeps the
  # built-in defaults; uncomment and set your PLMN to advertise a real
  # Origin-Host/Origin-Realm. RFC 6733 6.1 routes and authorizes on
  # Destination-Realm, so a wrong realm breaks interop with real peers.
  # TS 23.003 19.2 formats the EPC realm as epc.mncNNN.mccMMM.3gppnetwork.org.
  # An explicit --diameter-id/--diameter-realm flag overrides these.
  # diameter:
  #   identity: pcrf.epc.mnc001.mcc001.3gppnetwork.org
  #   realm: epc.mnc001.mcc001.3gppnetwork.org
  #   addr: 172.24.0.9
  #   port: 3868
```

## YAML parameters

`main.rs` checks whether the `-c` file exists. A **missing** file is not an error: the daemon starts on the flags and built-in defaults (logged at debug). A file that **exists** is parsed by `pcrf_context_parse_config`. If it cannot be read or is not valid YAML, **startup fails** ("Failed to parse config ..."). A file with no `pcrf:` section is valid and keeps the defaults. So is a `pcrf:` section with neither a `diameter` block nor a `freeDiameter` key; with only `freeDiameter`, that file supplies what it states. The top-level `db_uri` is read separately by `resolve_db_uri` in `main.rs` (#1459), and `logger.level` by the shared `nf_log_level`.

### `pcrf.diameter`

| Key | Sets | Notes |
|---|---|---|
| `identity` | Origin-Host (RFC 6733 §6.3) | Beaten by `--diameter-id`. |
| `realm` | Origin-Realm (RFC 6733 §6.4) | Beaten by `--diameter-realm`. |
| `addr` | Host of the shared Gx + Rx listener | Beaten by `--diameter-addr`. Without it the host is `127.0.0.1` (#1308). |
| `port` | Port of that listener | Beaten by `--diameter-addr`. Without it the port is `3868`. |
| `port_tls` | Stored | **Inert**: pcrfd opens no TLS listener. |

Each key is optional, and an absent key leaves the lower-precedence value in place. `addr` and `port` fall back independently, so setting only one of them keeps the default for the other. Any other key under `pcrf.diameter` is ignored.

### `pcrf.freeDiameter`

A path to a freeDiameter-style `.conf`. It is loaded with `nextgcore_diameter::fd_conf::FreeDiameterConf::load` **before** `pcrf.diameter` is applied, so it is the lower-precedence source:
- `Identity`, `Realm`, the **first** `ListenOn` and `Port` set the identity, realm, listen host and listen port. `SecPort` is stored like `port_tls` and is just as inert.
- `ConnectPeer` is parsed and dropped, because the PCRF never dials out: it only accepts inbound connections. The flags (`No_IPv6`, `No_TCP`, `NoRelay`, ...) are also parsed and not applied.
- Any other directive is logged at info as "directives not interpreted".
- A directive from the list above whose value does not parse (`Port = "abc"`, `Port = 70000`, `ListenOn = ""`) sets nothing. Each one is logged at WARN as `'<Directive> = <value>' does not parse`, and the next source applies: the YAML, a flag, or the default. An earlier valid occurrence of the same directive stands.
- A file that cannot be read is a **warning**, not a startup failure, and the daemon continues without it.

The path is recorded in the context for diagnosis. The `--diameter-config` flag does not feed this loader and is never read.

In the shipped Docker EPC deployment this file is `docker/rust/configs/epc/freeDiameter/pcrf.conf`, which sets Identity `pcrf.localdomain`, Realm `localdomain` and `ListenOn 172.24.0.9`. Identity and realm match the built-in defaults. Its listen host is overridden by the compose file's `--diameter-addr 0.0.0.0:3868`.

### Diameter identity precedence

`resolve_diameter_identity` in `main.rs` resolves each value as **CLI flag > `pcrf.diameter` > `pcrf.freeDiameter` file > built-in default**. The built-in defaults are `pcrf.localdomain` / `localdomain` / `127.0.0.1:3868`. The flags have no clap default, so only an explicitly passed flag outranks the file. `--diameter-addr` takes a whole `host:port` and so replaces both halves. The resolved identity, realm and listen address are logged at startup ("PCRF Diameter identity: ...").

### Other keys

- **`db_uri` opens the subscriber store (#1459).** The top-level `db_uri` (or `--db-uri`, which wins) names the MongoDB that each CCR's policy is read from. It is opened before the Diameter listener; an unreachable server is retried 5 times, 2 s apart, and then **fails startup**, as does a malformed URI. A SIGTERM during that wait exits cleanly. Each attempt waits one server selection, which nextgcore-dbi bounds unless the URI sets `serverSelectionTimeoutMS` itself. Store reads run with `block_in_place`, so a slow read does not hold a Diameter runtime worker. With no `db_uri` configured the PCRF still starts, logs a warning, and answers the built-in default (see Behavior notes). Before #1459 the key was never read.
- **`logger.level` is read; `logger.file.path` is inert.** Logging goes to stderr via `env_logger`. The log level is `-e/--log-level` when given, else this file's `logger.level`, else `info`; `RUST_LOG`, when set, overrides all three (#691). The `-l/--log-file` flag is also accepted but never used.
- **`global.max.ue` / `global.max.peer` are inert.** The only session limit is the `--max-sess` flag (and even that is stored, not enforced — see Behavior notes).
- **No `pcrf.metrics.server[]`** (removed from the shipped config, #1312): no Prometheus/metrics HTTP server is started by this binary; the only telemetry is the optional OTLP trace exporter (env var, see below).

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-pcrfd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | path | `/etc/nextgcore/pcrf.yaml` | Configuration file path. A missing file is skipped; a present one that cannot be read or parsed fails startup (see YAML parameters). |
| `-l, --log-file` | path | unset | Accepted but **never used** — logs always go to stderr. |
| `-e, --log-level` | string | `logger.level`, else `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else is `info`). Without the flag, the config's `logger.level`, else `info`; `RUST_LOG` overrides both (#691). |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Not supported: logs an error and exits non-zero without signalling anything; stop the NF through its supervisor. |
| `--diameter-config` | path | `/etc/nextgcore/freeDiameter/pcrf.conf` | Accepted but **never read**. The freeDiameter file that is read is the one the YAML's `pcrf.freeDiameter` names. |
| `--diameter-id` | string | `pcrf.diameter.identity`, else the freeDiameter Identity, else `pcrf.localdomain` | Diameter Origin-Host identity of this PCRF. Beats the config file. |
| `--diameter-realm` | string | `pcrf.diameter.realm`, else the freeDiameter Realm, else `localdomain` | Diameter Origin-Realm. Beats the config file. |
| `--diameter-addr` | socket addr | from `pcrf.diameter.addr`/`port`, else the freeDiameter ListenOn/Port, else `127.0.0.1:3868` (loopback, #1308) | Diameter listen address; Gx and Rx share this one listener. Beats the config file. The resolved address must parse as `host:port`, or startup fails with "Invalid Diameter listen address". |
| `--max-sess` | usize | `1024` | Maximum number of sessions. Stored in the context and logged at startup, but **no code path enforces it** — `gx_session_add` never checks it. |
| `--db-uri` | string | the YAML `db_uri`, else unset | Subscriber store (MongoDB) URI; beats the YAML (#1459). A configured store that cannot be reached fails startup. |
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
- **Policy source:** `build_subscriber_session_data` (`gx_path.rs`) reads `nextgcore_dbi_subscription_data` for the CCR's IMSI and takes the QCI, ARP and APN-AMBR of the provisioned session whose name is the Called-Station-Id (APN), else the UE-level AMBR. When the store is reachable but holds nothing for the subscriber or APN, or no store is configured, it falls back to the built-in `default_profile` (below). When the store **cannot be read** at runtime (an outage; each read gives up after one server selection, 1 s by default, #1462), the PCRF does not invent a policy (#1539 review): a CCR-I is answered with Experimental-Result `DIAMETER_ERROR_INITIAL_PARAMETERS` (5140, vendor 10415), so the PCEF rejects the IP-CAN session establishment (TS 29.212 §4.5.1); a CCR-U is answered 2001 with no QoS or trigger provisioning, so the session keeps the policy the PCEF already enforces; a CCR-T does not read the store. The outage is logged at WARN, at most once per 10 s with a count. The default profile is QCI 9, ARP derived from the QCI table, APN-AMBR 100,000,000 bps down / 50,000,000 bps up, and one catch-all non-GBR PCC rule named `pcrf-<apn>-default` (precedence 100, bidirectional `permit ... ip from any to assigned` IPFilterRules).
- **Rx session binding (TS 29.214 per code comments):** an AAR is bound to the Gx (IP-CAN) session via the UE IP address; if no Gx session matches, the AAA carries Experimental-Result 5065 `IP_CAN_SESSION_NOT_AVAILABLE` (vendor 10415). If pushing the derived PCC rules to the PCEF via Gx RAR fails, the AAA carries 5063 `REQUESTED_SERVICE_NOT_AUTHORIZED`. An STR triggers a Gx RAR with Charging-Rule-Remove and unbinds the Rx session.
- **PCRF-initiated requests:** RAR/ASR are sent over the connection the target peer established (looked up by Origin-Host); the answer wait is capped at 5 s (`ANSWER_TIMEOUT` in `fd_path.rs`) with no application-level retransmission. If the peer is not connected the send fails immediately.
- **Environment variables:** `PCRF_RELEASE_RESTARTED_PCEF_SESSIONS` (`1`/`true`/`yes`/`on`; off by default) releases the Gx sessions of a PCEF whose restart was detected from Origin-State-Id (#365); off by default because it drops traffic, while the detection itself is always on. `OTEL_EXPORTER_OTLP_ENDPOINT` sets the OpenTelemetry OTLP trace endpoint (default `http://jaeger:4317`; export failure is silently ignored). `RUST_LOG` overrides `-e/--log-level` when set. `NEXTGCORE_PCRF_STATE_FILE` supplies the durable-state path when `--state-file` is absent (the flag wins), and `PCRF_ASR_ON_RULE_FAILURE` (`0`/`false`/`no`/`off`) suppresses the §4.5.12 ASR. Gx/Rx message counters are held in memory and logged as a summary line at shutdown.
