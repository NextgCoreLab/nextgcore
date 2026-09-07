# nextgcore #61: user-plane path and PFCP peer failure detection

Verified against `main` @ `d120b2d`. All of the issue's cites re-verified and all still held.

`Refs #61`, **not Closes**. Ships gaps 1, 3 and 4 — sgwud GTP-U Echo probing and path-failure
detection, upfd PFCP heartbeat outstanding-tracking and peer-down, and removal of the dead
`peer_nodes` sweep. **Gap 2 (Node Report Request) is split to #217**, because it is blocked on
infrastructure that does not exist.

## Why gap 2 could not ship: sgwud has no PFCP transport

The issue frames gap 2 as "the codec exists; only the sender is missing". The sender is missing
because there is nothing to send *through*:

* `pfcp_path::pfcp_open()` opens **no socket** — its body is a comment reading *"In actual
  implementation: Create UDP sockets for PFCP (port 8805)"*;
* `send_pfcp_request()` and `send_pfcp_response()` log a line and `return Ok(())`;
* `main.rs` runs **no PFCP receive loop**.

Adding a Node Report caller would have added one more caller to a stub returning a fabricated `Ok` —
code that reads as working and sends nothing. That is worse than the gap, and it is a defect class
this repo already has a recorded learning about.

The finding is broader than Node Report and is written into #217: the same facade means sgwud never
sends Session Establishment/Modification/Deletion Responses either, so it cannot function as a PFCP
peer at all. Whether sgwud is intended as a scaffold is a decision for the maintainer, which is why
#217 carries the `architecture` label.

Detection still landed here, so #217 has a clean hook: `failed_gtpu_paths()` and the failed
transition inside `note_echo_unanswered`.

## Gap 1 — sgwud GTP-U path management

sgwud answered inbound Echo Requests and never probed anyone; the Echo **Response** arm discarded the
message, so nothing could resolve a probe even if one had been sent.

* A per-peer path table with an unanswered counter and a failed flag.
* Probe targets come from the installed FARs' Outer Header Creation — the peers we are actually "in
  contact with" (§20.3.1) — **deduplicated**, so a busy eNB with many bearers is probed once rather
  than per bearer.
* Driven from the receive loop, whose 100 ms read timeout supplies the cadence without a second
  thread needing its own shutdown story. The previous round's probe is counted as missed *before* the
  next is sent; a response arriving in between has already cleared it.
* **The path fails when the counter EXCEEDS N3-REQUESTS, not when it reaches it.** §20.3.1 says
  "down if the counter exceeds N3-REQUESTS"; failing at N3 would declare a path down one probe early.
  This has its own test and its own revert check.
* An Echo Response clears the counter and the failure, so a recovered path recovers.
* `SGWU_GTPU_ECHO_INTERVAL_SECS` (0 disables) and `SGWU_GTPU_N3_REQUESTS` are configurable — §20.3.1
  mandates the detection, not the cadence.

## Gaps 3 and 4 — upfd PFCP heartbeat

The heartbeat was fire-and-forget: `send_heartbeat_request` recorded nothing, the response arm
cleared nothing, and `declare_peer_failure` was reachable only from a Recovery-Time-Stamp change or an
explicit Association Release. A silently dead SMF/SGW-C kept its association and every session
indefinitely.

* `HeartbeatState` tracks outstanding sequence numbers and **consecutive unanswered rounds**.
* `close_heartbeat_round()` counts a miss only when something sent went unanswered, and declares the
  peer down at `HEARTBEAT_MAX_MISSES` (3 rounds ≈ 30 s at the 10 s cadence). The heartbeat loop closes
  the previous round before sending the next.
* **Any response resets the counter**, not only the matching one: a response proves liveness whichever
  round it answers, so an out-of-order or duplicated response must not leave a peer marked missing.
  An unknown sequence number is harmless.
* Each closed round drops its stale sequence numbers, so the outstanding set cannot grow unbounded.

**The dead sweep was deleted, not repaired.** It iterated `pfcp_ctx.peer_nodes`, a map nothing in the
crate ever inserted into, and guarded on `last_heartbeat_check.elapsed() > heartbeat_timeout` —
elapsed time, not missed responses — so even with the map populated it would have declared failure
against a healthy peer. Both defects are why it is gone: the state it needed already exists on the
server, next to the socket that sends and receives the heartbeats. Its now-unused locals went with it.

## Verification

Ten new tests. Workspace **5775 passed / 0 failed** (was 5765), `cargo test --workspace` exit 0,
checked for `^error`. fmt clean; `cargo clippy --workspace` (the CI gate) exit 0 with zero warnings.

Revert-verified, each failing its named test: failing the path at N3 rather than above it; discarding
the Echo Response; a heartbeat round never counting a miss; a response not resetting the counter; and
probe targets not deduplicated.

**One revert initially passed and was fixed:** the dedup revert targeted `far_ohc_peers` while
`gtpu_peer_addresses` deduplicated too, so the test stayed green. Re-run against *both* layers it
fails, which is the honest check — the redundancy is deliberate (a public accessor whose contract says
"every distinct peer") but only one layer is load-bearing for the test.

**Not verified:** no real eNB, PGW-U, SMF or SGW-C was involved. Probe *firing* is not covered by a
test — only the counter transitions and the target selection are; driving it would need a 60 s wait or
an injectable clock. The peer-down path is asserted on the miss counter, not by observing an
association actually torn down after real silence. Docker E2E is skipped by CI. GitNexus impact
analysis, which CLAUDE.md mandates, was not run (no MCP server connected); caller analysis was
grep-based.
