# HSS Configuration

The HSS (Home Subscriber Server, `nextgcore-hssd`) is the central subscriber database of the 4G/EPS side of the dual 5G+4G core. Its one real wire interface is **S6a**: a Diameter server (application ID 16777251) that accepts MME connections and answers AIR (Authentication-Information), ULR (Update-Location) and PUR (Purge-UE) requests, and carries HSS-initiated CLR (Cancel-Location) and IDR (Insert-Subscriber-Data) on the same connections — per TS 29.272 and RFC 6733 as cited throughout `src/bins/nextgcore-hssd/src/s6a_path.rs`. Authentication vectors are generated with Milenage, including real AUTS re-synchronisation (TS 33.102 §6.3.5 per code comments) and per-vector random RAND (TS 33.401 per code comment). **Cx** (IMS, application ID 16777216) and **SWx** (non-3GPP AAA, TS 29.273 per the `swx_path.rs` header) exist as handler libraries (`handle_uar`/`handle_mar`/`handle_sar`/`handle_lir` in `cx_path.rs`, `handle_mar`/`handle_sar` in `swx_path.rs`), and both applications are advertised in the S6a server's capabilities exchange, but no request dispatch reaches those handlers: only S6a requests are answered. The HSS speaks no SBI, S1AP or GTP.

Configuration comes from a YAML file (default `/etc/nextgcore/hss.yaml`, `-c/--config`), CLI flags and a few environment variables. Unlike the 5GC NFs, an **unreadable or invalid YAML file stops startup** (`hss_context_parse_config` in `context.rs`): a silently ignored file would revert the node's Diameter identity to a different PLMN. A file with no `hss.diameter` block (the shipped one) is fine and keeps the defaults. The subscriber store (MongoDB, via `nextgcore-dbi`) is opened at startup and is mandatory (#478): with no `--db-uri` and no `db_uri` in the file the daemon exits.

> **Honesty note:** HSS behavior is validated by this project's own unit tests (including TS 33.102 §6.3.5 AUTS resync cases per code comments) and by the nightly `Docker E2E (EPC)` job, where a real LTE attach through nextgsim's eNB is authenticated from this HSS (AIR answered from the subscriber store, #484) — not by third-party conformance certification. The daemon does not link or embed freeDiameter; the Diameter stack is the project's own `nextgcore-diameter` library.

## Example configuration

From `nextgcore/docker/rust/configs/epc/hss.yaml` (mounted by `docker-compose-epc.yml`, which starts the container with `-c /etc/nextgcore/hss.yaml`):

```yaml
# NextGCore HSS Configuration for Docker EPC Deployment
# Rust implementation

db_uri: mongodb://mongodb:27017/nextgcore

logger:
  file:
    path: /var/log/nextgcore/hss.log
  level: info

global:
  max:
    ue: 1024
    peer: 64

hss:
  freeDiameter: /etc/freeDiameter/hss.conf
  metrics:
    server:
      - address: 172.24.0.8
        port: 9090
```

## YAML parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `db_uri` (top level) | string | none | MongoDB URI of the subscriber store, used when `--db-uri` is not given. Connection is retried 5 times, 2 s apart, then startup fails. |
| `hss.diameter.identity` | string | `hss.epc.mnc001.mcc001.3gppnetwork.org` | Origin-Host. |
| `hss.diameter.realm` | string | `epc.mnc001.mcc001.3gppnetwork.org` | Origin-Realm (TS 23.003 §19.2 format). |
| `hss.diameter.addr` / `.port` | string / u16 | `0.0.0.0` / `3868` | S6a listen address and port. |
| `hss.diameter.port_tls`, `.no_fwd` | u16, bool | none | Parsed into the Diameter config. |
| `hss.diameter.timer_tc` | i32 (s) | `1` (applied as `.max(1)`) | Tc timer (RFC 6733 §12). |
| `hss.diameter.connections[]` | list | empty | Peers: `identity`, `addr`, `port`, `timer_tc`. |
| `hss.freeDiameter` | path | none | Recorded for diagnosis only; this daemon does not parse freeDiameter `.conf` files. |

The `--diameter-id`/`--diameter-realm`/`--diameter-addr`/`--diameter-port` flags override the YAML values.

### Parsed-but-inert / decorative YAML fields

- **`logger.level` is read; `logger.file.path` is inert.** The log level is `-e/--log-level` when given, else this file's `logger.level`, else `info`; `RUST_LOG`, when set, overrides all three (#691). `-l/--log-file` is accepted by clap but never used, so logs always go to stderr.
- **`global.max.ue` and `global.max.peer` are inert.** The identity-pool size comes from the CLI flag `--max-ue` (default `1024`); there is no peer cap in the code.
- **`hss.freeDiameter` and the `--diameter-config` flag** point at `docker/rust/configs/epc/freeDiameter/hss.conf`, which no code reads.
- **`hss.metrics.server` is inert.** The daemon starts no metrics HTTP server; its only telemetry export is OpenTelemetry OTLP tracing (`nextgcore_metrics::otel::init_otel` in `main.rs`).

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-hssd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | string | `/etc/nextgcore/hss.yaml` | Configuration file path. Unreadable or invalid YAML stops startup. |
| `-l, --log-file` | string | unset | **Accepted but unused** — `init_logging()` never opens it; logging always goes to stderr. |
| `-e, --log-level` | string | `logger.level`, else `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`; anything else is `info`). Without the flag, the config's `logger.level`, else `info`; `RUST_LOG` overrides both (#691). |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Not supported: logs an error and exits non-zero without signalling anything; stop the NF through its supervisor. |
| `--diameter-config` | string | `/etc/nextgcore/freeDiameter/hss.conf` | **Accepted but unused** — no code reads freeDiameter config files. |
| `--diameter-id` | string | YAML, then `hss.epc.mnc001.mcc001.3gppnetwork.org` | Origin-Host override. |
| `--diameter-realm` | string | YAML, then `epc.mnc001.mcc001.3gppnetwork.org` | Origin-Realm override. |
| `--diameter-addr` | string | YAML, then `0.0.0.0` | S6a listen address override. |
| `--diameter-port` | u16 | YAML, then `3868` | S6a listen port override. |
| `--max-ue` | usize | `1024` | The only fully wired tuning flag: sizes the identity pools as `max_impi = max_ue`, `max_impu = max_ue * 4` (ratio hard-coded in `main.rs`). |
| `--db-uri` | string | unset | Subscriber-store MongoDB URI; wins over the YAML `db_uri`. One of the two is required. |
| `--db-name` | string | `nextgcore` | Parsed but not passed anywhere; the database comes from the URI. |

## Behavior notes

- **S6a failure model** (TS 29.272 §7.4 + RFC 6733 §7.1 per code comments, `S6aFailure` in `s6a_path.rs`): missing mandatory AVPs → Result-Code 5005 (`DIAMETER_MISSING_AVP`); unknown command → 3001 with the E-bit set (protocol error, RFC 6733 §7.2 per code comment); unknown subscriber → Experimental-Result 5001 (`ERROR_USER_UNKNOWN`, vendor 10415); failed AUTS resync → Experimental 4181 (`AUTHENTICATION_DATA_UNAVAILABLE`); subscriber without any APN configuration → Experimental 5420 (`ERROR_UNKNOWN_EPS_SUBSCRIPTION`, TS 29.272 §5.2.1.1.3 per code comment) unless the ULR sets Skip-Subscriber-Data; any other internal error → 5012 (`DIAMETER_UNABLE_TO_COMPLY`). User-Name (IMSI) is enforced on every request; AIR additionally requires Visited-PLMN-Id and Requested-EUTRAN-Authentication-Info; ULR requires Visited-PLMN-Id, RAT-Type and ULR-Flags (TS 29.272 Tables 7.2.5/1, 7.2.3/1 per code comments).
- **Vector generation**: AIR yields 1–4 E-UTRAN vectors (`MAX_VECTORS_PER_AIR = 4`, request clamped), each with a fresh cryptographically random RAND, a strictly increasing 48-bit SQN (`SQN_STEP = 32`, masked per TS 33.102 per code comment), Milenage f1/f2345, and KASME derivation; the advanced SQN is persisted back to the subscriber record.
- **HSS-initiated CLR/IDR/DSR/RSR** (TS 29.272 Tables 7.2.7/1, 7.2.9/1, §7.2.11, §7.2.15) are sent over an MME peer connection tracked in an in-process peer registry. IDR applies a subdata mask (MSISDN/ARD/barring/AMBR/RAU-TAU/APN-config) before encoding Subscription-Data. PUA-Flags freeze the M-TMSI/P-TMSI depending on PUR-Flags (TS 29.272 §5.2.1.3.3 per code comment).
- **HSS-initiated requests are tracked, retransmitted and requeued (#56, RFC 6733 §5.5.4).** Each is recorded by Session-Id when sent; its answer clears it. An unanswered request is retransmitted every 30 s (`HSS_INITIATED_RETRANSMIT_SECS`, Tc scale) up to 3 transmissions (`HSS_INITIATED_MAX_ATTEMPTS`), then abandoned with an error log naming the divergence. A request for a **disconnected** peer is **queued**, not dropped, and delivered when that peer registers — it neither retransmits nor spends its retry budget while it waits. Before #56 these were fire-and-forget: a momentary link loss silently discarded the procedure, and nothing could tell an answered request from a lost one.
- **Inter-MME Cancel Location on ULR (#56, TS 29.272 §5.2.1.1.3).** `handle_ulr` now **reads** the stored MME identity before overwriting it, and sends a Cancel Location with Cancellation-Type `MME_UPDATE_PROCEDURE` to the previous MME when it differs. The read has to happen first: `nextgcore_dbi_update_mme` is a blind `$set`, so once it runs the previous identity is unrecoverable and the Cancel Location can never be sent — which is how stale UE contexts accumulated on previous MMEs after an inter-MME TAU. Comparison is ASCII-case-insensitive (a Diameter identity is a FQDN, RFC 6733 §4.3.1), because treating a case difference as a different node would send a spurious Cancel Location that detaches a UE mid-attach. The Cancel Location is **non-fatal**: the new MME's location update has already succeeded, and failing it because the *old* MME is unreachable would deny service to a UE that attached correctly.
- **Notify (NOR/NOA) is served (#56, TS 29.272 §5.2.5.1.1, §7.2.17).** A dynamically allocated PDN-GW identity in `MIP6-Agent-Info` is persisted against its APN (`pgw_id`), preferring the FQDN in `MIP-Home-Agent-Host` over the address in `MIP-Home-Agent-Address` as §7.3.45 requires. An identity with **no** `Service-Selection` and no `Context-Identifier` is refused: nothing names the APN it belongs to. A NOR carrying only IEs this HSS does not model (terminal information, UE SRVCC capability, monitoring-event status, homogeneous IMS voice support) is answered **NOA 2001**, not 3001 — before #56 it fell to the dispatch catch-all and got 3001 with the E-bit, which tells a conformant MME the whole Notify command is unsupported so it stops using the procedure, including the PDN-GW notification that *is* handled.
- **Restart restoration (#56, TS 29.272 §5.2.3, TS 23.007).** A running-marker file (`$HSS_RUNTIME_DIR/hssd-running`, default `/var/run/nextgcore/`) is written at startup and removed on a clean shutdown; finding one at startup means the previous run died. That **arms** restart restoration for 300 s (`RESTART_RESET_WINDOW_SECS`) rather than sending immediately — the HSS is the S6a *responder*, so at startup no MME is connected and an immediate send would reliably reach nobody. Every MME registering inside the window is sent a Reset-Request with no `User-Id` prefixes (all subscribers) and no `User-Name` (§7.2.15's format has none: Reset applies to a *set*). A marker that cannot be written disables crash detection for that run and says so, because declaring every start unclean would make every MME re-run Update Location for its whole subscriber base.
- **3GPP-Charging-Characteristics (#56).** Encoded as the TS 29.061 §16.4.7.2 **4-character hexadecimal UTF8String**, not the raw 2-octet OctetString this tree used to emit — two octets round-trip against themselves and against nothing else. Both encodings are **accepted** on parse, so a peer still sending the legacy form keeps working. The value is now sourced from the subscriber record (per-APN `charging_characteristics` first, then subscriber-level) instead of the hardcoded `None` it used to be; a provisioned value that is not 4 hex characters is **omitted with a warning** naming the subscriber, because a wrong charging class is a billing error. *Verification limit: TS 29.061 is not vendored in this tree, so the 4-hex-char form rests on TS 29.272 Table 7.3.1/2's deferral to it plus issue #56's citation, not on a quotable local source — which is why the parser accepts both.*
- **Subscriber-change watching is OFF by default (#56).** `HSS_SUBSCRIBER_WATCH=1` enables a 5 s poll of the subscriber collection that drives IDR on a changed subscription and CLR (`SUBSCRIPTION_WITHDRAWAL`) on a deleted one (TS 29.272 §5.2.2.1.1, §5.2.1.2.1). Issue #56's suggested approach was to wire this into "the existing DB change-poll loop"; **there was no such loop** — the event loop was a 100 ms `sleep` with comments describing what a full implementation would do — so it was built. Off by default because it is the one part whose MongoDB read no test in this tree can verify, and a misfiring watcher does not merely fail to notify: it sends unsolicited Cancel Locations that **detach live UEs**. Deliberate design points: an inter-MME move sends nothing (that Cancel Location is `handle_ulr`'s, and acting here too would cancel the same UE twice); a newly attached subscriber sends nothing (its data came in the ULA); the fingerprint covers only the fields that reach Subscription-Data, so an SQN increment — which happens on *every* authentication — does not fire an IDR; and a failed read keeps the previous view rather than reading as "every subscriber was deleted".
- **Process model**: the main thread runs a 100 ms polling loop that watches the shutdown flag and state-machine health, sweeps the outstanding HSS-initiated request table every 5 s, and (when enabled) polls for subscriber changes every 5 s; the S6a server runs on its own single-threaded tokio runtime in a dedicated `hss-s6a-diameter` thread, with MongoDB-touching dispatch pushed to the blocking pool. MongoDB change-stream integration in `sm.rs` is placeholder-level ("Note: Call …" comments); #56's watcher polls instead. There are no state files, but there is a running marker (see restart restoration above).
- **Environment variables**: `HSS_SUBSCRIBER_WATCH` (`1`/`true`/`yes`/`on` enables subscriber-change watching, #56) and `HSS_RUNTIME_DIR` (directory for the running marker, default `/var/run/nextgcore`, #56). `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://jaeger:4317`) — it targets the OTLP trace exporter. `RUST_LOG` overrides `-e/--log-level` when set.
