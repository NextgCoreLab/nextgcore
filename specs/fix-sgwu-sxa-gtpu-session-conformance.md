# nextgcore #60 (SGW-U): Sxa/GTP-U session-level conformance

Verified against `main` @ `e930d65`. All of the issue's cites re-verified and all still held.

`Closes #60`. Ships gaps 2, 3, 4 and 5 — Error Indication peer matching, BAR/DDN buffering control,
End Marker, and QER enforcement. **Gap 1 (URR usage reporting) is split to #215.**

## Scope: URR split to #215, on the issue's own authority

The issue states it: *"URR usage reporting alone is a sizable feature and may be split into its own
issue if it cannot land atomically."* CONVENTIONS' separable-part rule applies — when the issue text
authorises a split, file that part and close the parent once the rest is done, naming the split in
the PR so the close is auditable.

URR is a whole subsystem: measurement methods, reporting triggers, thresholds and quotas,
byte/packet counting in the data path, Usage Report IEs on both the Session Report Request and the
Session Deletion Response, and a monotonic UR-SEQN, mirroring upfd's `DataPlaneUrr`. The other four
gaps are independent of it and three are outright conformance bugs that ship safely today, so
holding them behind a charging subsystem would be the wrong trade.

Note the count arithmetic honestly: closing #60 while filing #215 leaves the open count unchanged.

#215 also carries a decision the URR implementer must make deliberately: `apply_far` now has QER
enforcement ahead of the forwarding decision, so whether gate/MBR-dropped traffic counts toward
usage is a live question — counting it would over-bill.

## Gap 4 — End Marker (the smallest and most valuable)

TS 29.281 §7.3.2.1: an End Marker for an unknown TEID "shall" be ignored. It answered with an Error
Indication instead. This is not merely non-conformant: End Markers arrive **during a handover path
switch**, so the race it hits is the normal case, and the peer may read the indication as loss of
bearer context.

A companion test asserts a **G-PDU** for an unknown TEID *still* draws an Error Indication (§7.3.1),
so the fix cannot drift into "never send an Error Indication".

## Gap 2 — Error Indication peer matching

TS 29.281 §7.3.1: "The TEID and GTP-U peer Address together uniquely identify the related ... EPS
bearer." `far_find_by_ohc_teid` matched the TEID alone and returned the first hit, so a collision
named the wrong session — and the resulting ERIR can tear down an unrelated bearer.

New `far_find_by_ohc_teid_peer` matches both, and both address families independently, so a v4
indication cannot match a FAR holding only a v6 peer. A TEID match with a peer mismatch returns
`None` and is logged-and-dropped: dropping is the safe direction, since a genuinely lost bearer will
be re-reported.

The test installs **two sessions holding the same outbound TEID toward different peers** — the exact
collision — and asserts each peer resolves to its own session, plus that a third peer matches
nothing.

## Gap 3 — BAR / DDN buffering

`downlink_data_notification_delay` was stored and never read; Update BAR in a Session Report Response
was parsed as a bare cause and discarded; the buffer cap was a hardcoded 64.

* `SgwuBar` gained DL Buffering Duration and Suggested Packet Count, and `ddn_delay()` converts the
  **50 ms units** of §8.2.28 (a unit slip here is a 20× timing error, so it has its own test).
* `handle_session_report_response` applies an Update BAR. It is a **partial** update per
  Table 7.5.9.2-1: members the CP function omitted survive, which the test pins.
* `buffer_capacity` honours the suggested packet count, falling back to a
  `SGWU_MAX_BUFFERED_PACKETS`-overridable default. `far_buffer_packet` now takes the capacity rather
  than reading a constant.
* The first Downlink Data Report is delayed by the BAR's DDN delay **on a detached thread** — the
  receive loop must not stall, or every packet behind it waits too. If the thread cannot be spawned
  the report is sent undelayed rather than dropped.

## Gap 5 — QER enforcement, gated off

`apply_far` never consulted the QER, so a CLOSED gate still forwarded and MBR was never policed.

Now it enforces both, **behind `SGWU_QER_ENFORCEMENT` (default off)** as the issue requires:
enforcement changes forwarding, and a mis-provisioned QER would black-hole traffic that flows today.
A test asserts the off case still forwards, so the default is proven inert rather than assumed.

* Gate status per §8.2.7: bits 1-2 UL, bits 3-4 DL. **An absent Gate Status IE reads as OPEN** —
  §8.2.7 makes closed something the CP must ask for, so defaulting closed would black-hole every
  session whose QER omits it.
* MBR is a token bucket refilled at the MBR and **capped at one second's worth**; without that cap an
  idle bearer accumulates unlimited credit and then bursts far above its MBR. `mbr_bps() == 0` means
  not-provisioned, i.e. unlimited, not a zero-rate cap. A poisoned bucket lock forwards rather than
  dropping — a lock must not become a traffic black hole.
* Direction comes from the PDI source interface (ACCESS ⇒ uplink).

## Verification

Thirteen new tests. Workspace **5765 passed / 0 failed** (was 5752), `cargo test --workspace` exit 0,
checked for `^error`. fmt clean; `cargo clippy --workspace` (the CI gate) exit 0.

Revert-verified individually, all seven failing their named test: End Marker error-indicating again;
TEID-only FAR matching; QER gate never consulted; gate bits read from the wrong direction; DDN delay
as milliseconds rather than 50 ms units; Update BAR overwriting unsupplied members; buffer cap
ignoring the suggested count.

**Not verified:** no real MME, eNB or SGW-C was involved. The DDN *delay timing* is not covered by a
test — only the unit conversion is; asserting the delay would need a real sleep or an injectable
clock. MBR policing is asserted on the bucket arithmetic, not on sustained traffic. Docker E2E is
skipped by CI. GitNexus impact analysis, which CLAUDE.md mandates, was not run (no MCP server
connected); caller analysis was grep-based.
