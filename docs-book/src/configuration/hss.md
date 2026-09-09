# HSS Configuration

The HSS (Home Subscriber Server, `nextgcore-hssd`) is the central subscriber database of the 4G/EPS side of the dual 5G+4G core. Its one real wire interface is **S6a**: a Diameter server (application ID 16777251) that accepts MME connections and answers AIR (Authentication-Information), ULR (Update-Location) and PUR (Purge-UE) requests, and carries HSS-initiated CLR (Cancel-Location) and IDR (Insert-Subscriber-Data) on the same connections — per TS 29.272 and RFC 6733 as cited throughout `src/bins/nextgcore-hssd/src/s6a_path.rs`. Authentication vectors are generated with Milenage, including real AUTS re-synchronisation (TS 33.102 §6.3.5 per code comments) and per-vector random RAND (TS 33.401 per code comment). **Cx** (IMS, application ID 16777216) and **SWx** (non-3GPP AAA, TS 29.273 per the `swx_path.rs` header) exist as handler libraries (`handle_uar`/`handle_mar`/`handle_sar`/`handle_lir` in `cx_path.rs`, `handle_mar`/`handle_sar` in `swx_path.rs`), but `main.rs` starts **no Diameter listener for them** — their `init` functions only log; only the S6a server is spawned. The HSS speaks no SBI, S1AP or GTP.

Configuration is nominally split between a YAML file (default path `/etc/nextgcore/hss.yaml`, overridable with `-c/--config`) and command-line flags — but in this daemon the split is lopsided: the YAML file is **checked for existence and then ignored** (see below), so every effective runtime knob is either a CLI flag or a hard-coded default. The only environment variable the binary reads is `OTEL_EXPORTER_OTLP_ENDPOINT`.

> **Honesty note:** HSS behavior is validated by this project's own unit tests (27 tests in `s6a_path.rs` alone, including TS 33.102 §6.3.5 AUTS resync cases per code comments) and by this project's matched-simulator Docker deployments — not by third-party conformance certification. Two things deserve extra candor. First, `hss_context_parse_config()` in `context.rs` is a stub that returns `Ok(())` without reading the file, so the entire shipped YAML is decorative. Second, the binary **never initializes its MongoDB connection** (`nextgcore_dbi_init`/`nextgcore_mongoc_init` is called nowhere in this crate — in the whole workspace only `nextgcore-udrd` calls it), so at runtime every DB-backed lookup returns `DbiError::NotInitialized`; this crate's unit tests exercise the DB-dependent paths only as failure cases — the `*_without_db_fails` tests in `s6a_path.rs` assert that AIR/ULR/PUR handling and IDR sending error out with no DB (surfacing as 5012/5001 failure answers at the dispatch layer), and the end-to-end test explicitly runs with "no DB: well-formed failure, never silence". An in-memory test store does exist in `nextgcore-dbi` (`test-helpers` feature, `libs/nextgcore-dbi/src/test_store.rs`), but it is enabled only by `nextgcore-udrd`'s dev-dependencies — not by `nextgcore-hssd` — and it is not compiled into the release binary. The daemon does not link or embed freeDiameter; the Diameter stack is the project's own `nextgcore-diameter` library.

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

**None.** This binary defines no `#[derive(Deserialize)]` configuration structs. `main.rs` checks whether the `--config` path exists and calls `hss_context_parse_config(&args.config)` (`src/bins/nextgcore-hssd/src/context.rs`), which is a documented stub — it returns `Ok(())` without opening the file. No YAML field can change the daemon's behavior.

The values the daemon actually runs with come from hard-coded defaults in `HssContext::new()` (`context.rs`) combined with `unwrap_or_else` fallbacks in `main.rs` when the S6a server is spawned:

| Effective setting | Value | Source |
|---|---|---|
| Diameter Origin-Host | `hss.epc.mnc001.mcc001.3gppnetwork.org` | `main.rs` `unwrap_or_else` on `diam_config.cnf_diamid` (always `None`) |
| Diameter Origin-Realm | `epc.mnc001.mcc001.3gppnetwork.org` | `main.rs` `unwrap_or_else` on `cnf_diamrlm` |
| S6a listen address | `0.0.0.0` | `main.rs` `unwrap_or_else` on `cnf_addr` |
| S6a listen port | `3868` | `HssContext::new()` sets `cnf_port: 3868`; `main.rs` also maps `0` → `3868` |
| Diameter Tc timer | `1` | `cnf_timer_tc` defaults to `0`; `main.rs` applies `.max(1)` (library default would be 30) |

Because the config parser is a stub, there is currently no supported way to change the Diameter identity, realm, bind address or port of this daemon — not via YAML, and no CLI flag exists for them either.

### Parsed-but-inert / decorative YAML fields

Since nothing in the file is read, **every** field in the shipped example is decorative:

- **`db_uri` is inert.** The daemon never connects to MongoDB at all — neither this key nor the `--db-uri`/`--db-name` CLI flags are ever dereferenced (see Behavior notes).
- **`logger.file.path` and `logger.level` are inert.** Log level comes only from the CLI flag `-e/--log-level` (default `info`); `-l/--log-file` is accepted by clap but `init_logging()` never uses it, so logs always go to stderr.
- **`global.max.ue` and `global.max.peer` are inert.** The identity-pool size comes from the CLI flag `--max-ue` (default `1024`); there is no peer cap in the code.
- **`hss.freeDiameter` is inert.** No code reads freeDiameter-style `.conf` files; the shipped `docker/rust/configs/epc/freeDiameter/hss.conf` (Identity/Realm/ListenOn/NoRelay, mounted read-only into the container) is never opened by the Rust daemon, and the `--diameter-config` flag that points at it is likewise never used after parsing.
- **`hss.metrics.server` is inert.** The daemon starts no metrics HTTP server; its only telemetry export is OpenTelemetry OTLP tracing (`nextgcore_metrics::otel::init_otel` in `main.rs`).

## Command-line flags

From the clap `Args` struct in `src/bins/nextgcore-hssd/src/main.rs`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `-c, --config` | string | `/etc/nextgcore/hss.yaml` | Configuration file path. Existence is checked and logged, then the file is ignored (stub parser). |
| `-l, --log-file` | string | unset | **Accepted but unused** — `init_logging()` never opens it; logging always goes to stderr. |
| `-e, --log-level` | string | `info` | Log level (`trace`/`debug`/`info`/`warn`/`error`); any other value silently falls back to `info`. |
| `-m, --no-color` | flag | off | Disable color output. |
| `-k, --kill` | flag | off | Logs "would send SIGTERM to running instance" and exits — it does **not** actually signal anything. |
| `--diameter-config` | string | `/etc/nextgcore/freeDiameter/hss.conf` | **Accepted but unused** — no code reads freeDiameter config files. |
| `--max-ue` | usize | `1024` | The only fully wired tuning flag: sizes the identity pools as `max_impi = max_ue`, `max_impu = max_ue * 4` (ratio hard-coded in `main.rs`). |
| `--db-uri` | string | unset | **Accepted but unused** — never passed to `nextgcore-dbi`. |
| `--db-name` | string | `nextgcore` | **Accepted but unused.** |

## Behavior notes

- **S6a failure model** (TS 29.272 §7.4 + RFC 6733 §7.1 per code comments, `S6aFailure` in `s6a_path.rs`): missing mandatory AVPs → Result-Code 5005 (`DIAMETER_MISSING_AVP`); unknown command → 3001 with the E-bit set (protocol error, RFC 6733 §7.2 per code comment); unknown subscriber → Experimental-Result 5001 (`ERROR_USER_UNKNOWN`, vendor 10415); failed AUTS resync → Experimental 4181 (`AUTHENTICATION_DATA_UNAVAILABLE`); subscriber without any APN configuration → Experimental 5420 (`ERROR_UNKNOWN_EPS_SUBSCRIPTION`, TS 29.272 §5.2.1.1.3 per code comment) unless the ULR sets Skip-Subscriber-Data; any other internal error → 5012 (`DIAMETER_UNABLE_TO_COMPLY`). User-Name (IMSI) is enforced on every request; AIR additionally requires Visited-PLMN-Id and Requested-EUTRAN-Authentication-Info; ULR requires Visited-PLMN-Id, RAT-Type and ULR-Flags (TS 29.272 Tables 7.2.5/1, 7.2.3/1 per code comments).
- **Vector generation**: AIR yields 1–4 E-UTRAN vectors (`MAX_VECTORS_PER_AIR = 4`, request clamped), each with a fresh cryptographically random RAND, a strictly increasing 48-bit SQN (`SQN_STEP = 32`, masked per TS 33.102 per code comment), Milenage f1/f2345, and KASME derivation; the advanced SQN is persisted back to the subscriber record.
- **MongoDB is never connected**: because no code path calls `nextgcore_dbi_init`, in the released binary every AIR/ULR/PUR that reaches the database answers 5012 `UNABLE_TO_COMPLY` (via `map_dbi_error`, which reserves 5001 for `SubscriberNotFound`). The `db_uri` YAML key and `--db-uri` flag exist but change nothing. Treat the S6a data path as unit-test/matched-sim validated logic, not a deployable subscriber database yet.
- **HSS-initiated CLR/IDR/DSR/RSR** (TS 29.272 Tables 7.2.7/1, 7.2.9/1, §7.2.11, §7.2.15) are sent over an MME peer connection tracked in an in-process peer registry. IDR applies a subdata mask (MSISDN/ARD/barring/AMBR/RAU-TAU/APN-config) before encoding Subscription-Data. PUA-Flags freeze the M-TMSI/P-TMSI depending on PUR-Flags (TS 29.272 §5.2.1.3.3 per code comment).
- **HSS-initiated requests are tracked, retransmitted and requeued (#56, RFC 6733 §5.5.4).** Each is recorded by Session-Id when sent; its answer clears it. An unanswered request is retransmitted every 30 s (`HSS_INITIATED_RETRANSMIT_SECS`, Tc scale) up to 3 transmissions (`HSS_INITIATED_MAX_ATTEMPTS`), then abandoned with an error log naming the divergence. A request for a **disconnected** peer is **queued**, not dropped, and delivered when that peer registers — it neither retransmits nor spends its retry budget while it waits. Before #56 these were fire-and-forget: a momentary link loss silently discarded the procedure, and nothing could tell an answered request from a lost one.
- **Inter-MME Cancel Location on ULR (#56, TS 29.272 §5.2.1.1.3).** `handle_ulr` now **reads** the stored MME identity before overwriting it, and sends a Cancel Location with Cancellation-Type `MME_UPDATE_PROCEDURE` to the previous MME when it differs. The read has to happen first: `nextgcore_dbi_update_mme` is a blind `$set`, so once it runs the previous identity is unrecoverable and the Cancel Location can never be sent — which is how stale UE contexts accumulated on previous MMEs after an inter-MME TAU. Comparison is ASCII-case-insensitive (a Diameter identity is a FQDN, RFC 6733 §4.3.1), because treating a case difference as a different node would send a spurious Cancel Location that detaches a UE mid-attach. The Cancel Location is **non-fatal**: the new MME's location update has already succeeded, and failing it because the *old* MME is unreachable would deny service to a UE that attached correctly.
- **Notify (NOR/NOA) is served (#56, TS 29.272 §5.2.5.1.1, §7.2.17).** A dynamically allocated PDN-GW identity in `MIP6-Agent-Info` is persisted against its APN (`pgw_id`), preferring the FQDN in `MIP-Home-Agent-Host` over the address in `MIP-Home-Agent-Address` as §7.3.45 requires. An identity with **no** `Service-Selection` and no `Context-Identifier` is refused: nothing names the APN it belongs to. A NOR carrying only IEs this HSS does not model (terminal information, UE SRVCC capability, monitoring-event status, homogeneous IMS voice support) is answered **NOA 2001**, not 3001 — before #56 it fell to the dispatch catch-all and got 3001 with the E-bit, which tells a conformant MME the whole Notify command is unsupported so it stops using the procedure, including the PDN-GW notification that *is* handled.
- **Restart restoration (#56, TS 29.272 §5.2.3, TS 23.007).** A running-marker file (`$HSS_RUNTIME_DIR/hssd-running`, default `/var/run/nextgcore/`) is written at startup and removed on a clean shutdown; finding one at startup means the previous run died. That **arms** restart restoration for 300 s (`RESTART_RESET_WINDOW_SECS`) rather than sending immediately — the HSS is the S6a *responder*, so at startup no MME is connected and an immediate send would reliably reach nobody. Every MME registering inside the window is sent a Reset-Request with no `User-Id` prefixes (all subscribers) and no `User-Name` (§7.2.15's format has none: Reset applies to a *set*). A marker that cannot be written disables crash detection for that run and says so, because declaring every start unclean would make every MME re-run Update Location for its whole subscriber base.
- **3GPP-Charging-Characteristics (#56).** Encoded as the TS 29.061 §16.4.7.2 **4-character hexadecimal UTF8String**, not the raw 2-octet OctetString this tree used to emit — two octets round-trip against themselves and against nothing else. Both encodings are **accepted** on parse, so a peer still sending the legacy form keeps working. The value is now sourced from the subscriber record (per-APN `charging_characteristics` first, then subscriber-level) instead of the hardcoded `None` it used to be; a provisioned value that is not 4 hex characters is **omitted with a warning** naming the subscriber, because a wrong charging class is a billing error. *Verification limit: TS 29.061 is not vendored in this tree, so the 4-hex-char form rests on TS 29.272 Table 7.3.1/2's deferral to it plus issue #56's citation, not on a quotable local source — which is why the parser accepts both.*
- **Subscriber-change watching is OFF by default (#56).** `HSS_SUBSCRIBER_WATCH=1` enables a 5 s poll of the subscriber collection that drives IDR on a changed subscription and CLR (`SUBSCRIPTION_WITHDRAWAL`) on a deleted one (TS 29.272 §5.2.2.1.1, §5.2.1.2.1). Issue #56's suggested approach was to wire this into "the existing DB change-poll loop"; **there was no such loop** — the event loop was a 100 ms `sleep` with comments describing what a full implementation would do — so it was built. Off by default because it is the one part whose MongoDB read no test in this tree can verify, and a misfiring watcher does not merely fail to notify: it sends unsolicited Cancel Locations that **detach live UEs**. Deliberate design points: an inter-MME move sends nothing (that Cancel Location is `handle_ulr`'s, and acting here too would cancel the same UE twice); a newly attached subscriber sends nothing (its data came in the ULA); the fingerprint covers only the fields that reach Subscription-Data, so an SQN increment — which happens on *every* authentication — does not fire an IDR; and a failed read keeps the previous view rather than reading as "every subscriber was deleted".
- **Process model**: the main thread runs a 100 ms polling loop that watches the shutdown flag and state-machine health, sweeps the outstanding HSS-initiated request table every 5 s, and (when enabled) polls for subscriber changes every 5 s; the S6a server runs on its own single-threaded tokio runtime in a dedicated `hss-s6a-diameter` thread, with MongoDB-touching dispatch pushed to the blocking pool. MongoDB change-stream integration in `sm.rs` is placeholder-level ("Note: Call …" comments); #56's watcher polls instead. There are no state files, but there is a running marker (see restart restoration above).
- **Environment variables**: `HSS_SUBSCRIBER_WATCH` (`1`/`true`/`yes`/`on` enables subscriber-change watching, #56) and `HSS_RUNTIME_DIR` (directory for the running marker, default `/var/run/nextgcore`, #56). `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://jaeger:4317`) — it targets the OTLP trace exporter. Notably, `RUST_LOG` is **not** consulted: `init_logging()` builds `env_logger` with an explicit `filter_level` from `-e/--log-level` and never calls the env-parsing constructors, so the `RUST_LOG: info` set by `docker-compose-epc.yml` has no effect on this daemon.
