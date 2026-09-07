# nextgcore #81 (UPF): QER RQI/PPI reach the downlink header; the vestigial peer registry goes

Verified against `main` @ `3d17f28`. The issue's cites are from `76ea248`, and **its second gap has since
been fixed** — see "Already done".

`Closes #81`.

## Already done on main (re-verified, not re-implemented)

Gap 2 (no missed-heartbeat failure declaration) landed in #218 during the #61 work, after this issue was
written:

* `PfcpServer` tracks `outstanding: HashSet<u32>` and `consecutive_misses` (`pfcp_path.rs`), inserted on
  heartbeat send and cleared on any Heartbeat Response.
* `close_heartbeat_round` counts consecutive **unanswered rounds** and calls `declare_peer_failure` at
  `HEARTBEAT_MAX_MISSES` (3), releasing the association and its sessions — criterion 4.
* The dead `n4_no_heartbeat` sweep over `peer_nodes` was removed, and its guard (elapsed wall-clock
  rather than missed responses) with it.

So criterion 5's "**or its replacement per-peer registry**" is satisfied by state that lives next to the
socket that sends and receives the heartbeats, rather than by a separate map. What was left of the old
design is dealt with below.

## Gap: RQI and PPI were parsed nowhere and could never reach the wire (criteria 1-3)

`parse_create_qer` stopped at the QFI. `ParsedCreateQer` and `DataPlaneQer` had no fields to hold the
markings. And every downlink G-PDU went out through `PduSessionContainer::dl`, which hardcodes
`rqi = false` and `ppi = None`. So reflective QoS (TS 23.501 §5.7.5) and paging-policy differentiation
were **silently inert no matter what the SMF provisioned** — an interop surprise rather than a visible
failure, because the packets still flowed and the QFI was still correct.

The GTP-U codec already supported both fields, so no wire-format work was needed. What was added:

* **`pfcp_ie::RQI = 123`** and **`PAGING_POLICY_INDICATOR = 158`**, taken from the TS 29.244 IE-type
  table, with the bit layouts from §8.2.88 (octet 5 bit 1, rest spare) and §8.2.116 (octet 5 bits 1-3,
  value 0-7). Only bit 1 of the RQI IE is read — a test pins that `0xFE` in the spare bits does **not**
  set the flag, because reading the whole octet would turn every spare bit into a reflective-QoS trigger.
* **A PPI wider than 3 bits is masked, not dropped**, at both the parse and the encode step, so a
  mis-provisioned QER still yields a well-formed header rather than an omitted field.
* **`PduSessionContainer::dl_with_marking`** alongside the existing `dl`. Kept separate rather than
  adding parameters to `dl`: the great majority of downlink packets carry neither marking and should not
  pay for an options struct, and a caller with markings to set is making a deliberate choice.
  `build_gtpu_header_with_qfi` and `encapsulate_dl_gpdu` now delegate to the marked variants with both
  off, so there is exactly one place that lays out the header.
* **`DataPlaneQer`'s `Clone` copies the markings.** Its `Clone` is hand-written and copies field by
  field, so a new field is silently dropped by default — and the data plane clones QERs, which would
  have disabled reflective QoS wherever a copy was taken while the original still looked correct. A test
  asserts the round trip *through* a clone.
* **The buffered-DL flush path is marked too.** That path forwards against the *session's* QFI rather
  than a per-packet PDR/QER match (pre-existing behaviour), so the markings are taken from the QER that
  owns that same QFI — same flow, same treatment. Without this, the packets that woke the UE would be
  the only ones stripped, which is precisely when a paging policy matters.

## Gap residue: `peer_nodes` deleted (criterion 5)

#218 removed the sweep but left the map: declared, default-initialised, cleared in one place, never
inserted into, and read only by two tests asserting it was empty. That is exactly the shape this repo has
twice recorded as a hazard — an unpopulated per-peer registry reads as a peer table the UPF maintains,
and the next person adding heartbeat state would reasonably put it there, back into a map with no
readers. `PfcpNode` is retained: it is still the type used for association bookkeeping.

## Verification

**6 new tests** (1 in `n4_build`, 5 in `data_plane`). upfd 285 → 290 passed. Workspace
`cargo test --workspace` green; `cargo clippy --workspace` (the CI gate) clean, zero warnings;
`cargo fmt --all --check` clean.

**Revert-verified: 10 reverts, 10 bit.** Including the two halves of the forwarding wiring separately
(the encapsulator call *and* reading the QER's fields), and an inverted case — making the *unmarked*
path set RQI — so the regression guard is shown to be load-bearing rather than trivially true.

**The wiring test earned its keep, and it is worth recording why.** An earlier patch script asserted on
four anchors and the fourth did not match, so it raised before writing — silently dropping the
forwarding-path edit while the helper edits from a previous script had already landed. Every helper-level
assertion passed. `dl_forwarding_applies_the_qer_markings_to_the_sent_gpdu` — which drives a real packet
through `handle_downlink_packet` and reads the markings off the G-PDU the gNB socket receives — failed
with `left: 0, right: 64`, which is what sent me back to look. This is the recorded lesson that
extracting logic into a tested helper leaves the *wiring* untested, encountered live rather than in
principle.

**Not verified:** no gNB. The cross-repo note on the issue still holds — this is coupled to
NextgCoreLab/nextgsim#44, and marking without enforcement is inert: the gNB extracts QFI/RQI from the
container but runs no SDAP entity, so nothing acts on the bit yet. What is established here is that the
bit and the PPI reach the wire in the TS 38.415 §5.5.2 field positions, asserted at the byte level
against a header parsed out of a really-sent G-PDU. The heartbeat criteria (4, 5) were re-verified by
reading `close_heartbeat_round` and by the existing suite staying green; no new test was written for
behaviour #218 already covers. Docker E2E is skipped by CI. GitNexus impact analysis, which CLAUDE.md
mandates, was **not run** — no MCP server connected; eleventh consecutive PR to record it.
