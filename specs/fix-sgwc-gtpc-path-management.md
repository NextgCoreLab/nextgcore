# nextgcore #53 (SGW-C GTP-C): path management and restart restoration

Verified against `main` @ `abe1cc3`. All of the issue's cites re-verified and all still held.

`Closes #53`. Ships all five gaps.

## Gap 3 — the restart comparison (the actively harmful one)

`note_peer_recovery` used `previous != restart_counter`, so a counter moving **backwards** was
treated as a restart. TS 23.007 §18 says the opposite: a stored value larger than the received one
"indicates a possible race condition" and the message "shall be discarded". Acting on it tears down
live contexts on a reordered datagram — the failure is worse than the gap it was meant to cover.

Replaced with `restart_counter_order` returning `Restarted` / `Unchanged` / `Stale`. The stored
counter is now only overwritten when the value is genuinely ahead, so a racing datagram cannot
rewrite it backwards and make the *next* legitimate message look like a restart.

**A deliberate reading, documented on the function:** a true modulo-256 wrap (255 → 0) is reported
`Stale`, not `Restarted`. §18 is written as a plain magnitude comparison and #53's acceptance
criteria require a rolled-over value to be discarded. The cost is that a peer's 256th restart is not
detected from its counter alone — it is still caught by N3 exhaustion. Chosen because the alternative
(treating any backwards jump as a restart) deletes live sessions on every reordered message.

## Gap 2 — restart-triggered deletion, gated off

`delete_contexts_for_peer` tears down each of the peer's sessions on SGW-U via PFCP **before**
`ue_remove` drops the local records — once the UE is gone there is nothing left to build a Session
Deletion Request from. A failed SGW-U is logged and does not block dropping local state, or the
contexts leak exactly as they did before.

Off by default behind `SGWC_RESTART_DELETE_CONTEXTS`, as the issue requires: the path can drop live
sessions if the restart heuristic misfires.

## Gap 1 — Echo path management

Driven from the existing rtx thread (a separate timer task would need its own shutdown story).
Interval from `SGWC_ECHO_INTERVAL_SECS`, default 60, `0` disables — §20.3.1 says an entity *may*
probe. N3 exhaustion now runs the same cleanup as a restart instead of only recording `Failed`.

**A regression this caused, and the fix.** The first version probed a peer immediately on first
sight, which broke two existing tests asserting no further traffic. The tests were right: a peer
enters `peer_state` *because* we just heard from it, so probing it at once wastes a round trip and
injects unsolicited traffic into an exchange in flight. The first sighting now starts the interval.
The production code was wrong, not the tests.

## Gap 4 — persistent local restart counter

`advance_persistent_restart_counter` reads, increments and rewrites a file (temp + rename, so a
crash mid-write cannot leave a truncated value). Absent file → 1. Malformed → log loudly and restart
at 1: refusing to boot would take an EPC control plane down over a scratch file, while continuing
silently would hide the restart from every peer. 255 wraps to 1, keeping 0 free as "never
persisted". `SGWC_RESTART_COUNTER` is now a test-only override and says so at startup.

## Gap 5 — Version Not Supported Indication

`handle_datagram` distinguishes `GtpError::InvalidVersion(v)`. For `v > 2` it replies with the
8-octet type-3 message, echoing the offending sequence number so the peer can correlate. A **lower**
version (GTPv1) is still dropped: §7.7.2 covers versions higher than GTPv2 only, and a test asserts
that, so the fix cannot drift into "reply to anything we cannot parse".

## Verification

Nine new tests. Workspace **5752 passed / 0 failed** (was 5743), `cargo test --workspace` exit 0,
checked for `^error`. fmt clean; `cargo clippy --workspace` (the CI gate) exit 0.

Revert-verified: restoring the `!=` comparison fails `restart_counter_order_discards_a_backwards_jump`;
dropping the version reply fails `unsupported_gtp_version_gets_a_version_not_supported_reply`;
pinning the counter to 1 fails `persistent_restart_counter_advances_across_starts`.

Deletion scoping is asserted **positively** — a second UE on a different MME must survive
`delete_contexts_for_peer`, so code that deleted everything would fail.

**Not verified:** no real MME, SGW-U or restart was exercised; PFCP teardown is asserted by local
state removal, not by observing an SGW-U receive it. Docker E2E is skipped by CI. The 60s Echo
interval means the scheduler's *firing* is not covered by a test — only its configuration and the
first-sighting rule are; driving it would need a 60s sleep or an injectable clock. GitNexus impact
analysis, which CLAUDE.md mandates, was not run (no MCP server connected); caller analysis was
grep-based.
