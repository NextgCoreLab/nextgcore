# nextgcore #306 (upfd): a Session Modification's rule operations reach the rule store

Verified against `main` @ `4f3af48`. TS 29.244 Table 7.5.4.1-1, §7.5.5, §8.2.36, §8.2.37, §8.2.50.

#306 is accurate. Every claim in it still holds, and verifying it turned up one adjacent
gap of the same kind that criterion 1 cannot honestly be met without.

## Verified against current main

| claim in the issue | site on `4f3af48` | still true? |
|---|---|---|
| the modification handler parses only Update FAR, Update QER, Create/Update BAR, SMReq-Flags | `pfcp_path.rs:1345-1508` | yes |
| Create/Update/Remove URR, Remove QER, and every PDR/FAR operation are unparsed | grep: no reader for any | yes |
| `UPDATE_URR` / `REMOVE_URR` / `REMOVE_QER` constants exist with no reader | `n4_build.rs:100-105` | yes |
| the establishment path *does* parse Create PDR/FAR/QER/URR | `pfcp_path.rs:1115-1254` | yes |
| the response is `RequestAccepted` regardless | it answers on the session lookup alone | yes |
| the library models all of these after #304 | `message.rs:703-726` | yes |
| upfd's session model differs from sgwud's (`AtomicU64` behind an `Arc`) | `data_plane.rs:1123` | yes |
| **not in the issue:** the Measurement Period IE is parsed nowhere | `ParsedCreateUrr` has no such field | **new** |
| **not in the issue:** QAURR is a constant with no reader | `pfcpsmreq_flags::QAURR` | **new** |

The two new rows are the same defect as the issue's subject, and the first one makes criterion 1
("Create URR provisions measurement") unmeetable as stated: `parse_create_urr` reads the PERIO
reporting-trigger **flag** and never the period behind it, so `DataPlaneUrr::measurement_period_secs`
— whose one reader is the data plane's periodic sweep — could never be anything but `None`. A URR
"provisioned with measurement" that can never report periodically is the same half-truth one layer
down, so it is fixed here rather than filed.

## Decision 1: option 2 — extend upfd's own walk — and the drift risk is guarded, not accepted

Criterion 6 asks for the choice and the reason.

**Option 2.** The Update X IEs carry the same IE set as their Create X counterparts (Table 7.5.4.2-1
against 7.5.2.2-1 and siblings), so `parse_create_pdr` / `_far` / `_qer` / `_urr` — already exercised
by the establishment path on every session — are reused verbatim, and the four Remove IEs are one
rule-id sub-IE each. Option 1 does not just swap a decoder: `PfcpSessionEvent::SessionModified` and
`SessionEstablished` carry upfd's `ParsedCreate*` types, so moving to the library's would rewrite the
event enum, both handlers and the data-plane consumer in `main.rs`. #304 sized that as needing its
own revert pass and #306 repeats the sizing; that is still the right sizing.

The argument for option 1 is drift — two decoders for one message. Rather than accept it, this PR
**pins them together**: `the_library_decoder_and_upfds_walk_agree_on_one_modification` builds a
Session Modification with the LIBRARY encoder, decodes it with both, and asserts the rule ids and
thresholds match. Reverting upfd's Measurement Period lookup makes that test fail, so it is a real
guard. If the library's wire format moves and upfd's walk does not follow, it fails here.

## Decision 2: what an unapplicable rule operation is answered with

Criterion 5. Four cases, three answers, and the split is the load-bearing part:

- **A malformed rule body** (a Create URR with no URR ID) → cause 69 `MandatoryIeIncorrect` plus
  §7.5.5's Offending IE naming the IE type. Skipping it silently is this issue's defect one level
  down.
- **An UPDATE naming a rule the session does not hold** → cause 73 `RuleCreationModificationFailure`
  plus the Offending IE. The new threshold, gate or forwarding action has nowhere to land, so the CP
  function's intent is not satisfied, and ignoring it is exactly "accepted a modification it did not
  apply".
- **A REMOVE naming a rule the session does not hold** → `RequestAccepted`, deliberately. The rule is
  gone, which is what was asked. Answering 73 would fail a modification that achieved its intent.
  Logged at debug, and guarded by its own test so the asymmetry with the update case is visible as a
  decision rather than an oversight.
- **An IE type upfd does not model at all** → ignored, because TS 29.244 §6.2 requires unknown IEs to
  be ignored for forward compatibility. Not a change; stated so the boundary of the above is clear.

§7.5.5 gives ONE Cause and ONE Offending IE per message, so with several failures the FIRST is
reported — the earliest is the one whose rejection explains the rest. And a rejected modification
emits **no** apply event: sending it anyway would leave the data plane holding rules the response
just refused, which is the same divergence in the other direction.

## Decision 3: the PFCP layer tracks rule IDs, because the response must be built before the apply

To refuse an Update for an absent rule, the handler has to know which rules the session holds — and
it cannot ask the data plane, because the response is built and sent **before** the data plane has
consumed the event. Validating against the data-plane store would reject a rule created by a
modification one round earlier that the consumer has not applied yet.

So `PfcpSessionInfo` gains a `SessionRuleIds` set per kind, written synchronously inside the same
critical section that updates the session, in §7.5.4's order — remove, then create, then update. That
makes it the only race-free answer to "does this rule exist" at response-building time. It is a split
of concerns, not duplication: the PFCP layer owns the ids (its contract with the CP function), the
data plane owns the rules' behaviour.

## Decision 4: a removed URR reports its residual volume in the Modification Response

The issue's scope note says a removed URR whose counters keep running is "a leak as well as a wrong
bill". Both halves are closed, and the volume is not discarded:

- The residual is reported in the **response**, in IE 78 (`USAGE_REPORT_SMR`) with the TERMR trigger
  — §8.2.36 defines TERMR as covering "removal of the URR" as well as session termination.
- This was cheap because the pieces were already here with no caller: the `USAGE_REPORT_SMR` constant,
  `add_usage_report`'s carrier parameter, and `PfcpServer`'s data-plane handle (added for the deletion
  path's final reports). `collect_final_usage_reports` is generalised to `collect_usage_reports(seid,
  only, reason)` and the deletion path now calls through it.
- #215 had to settle for warn-and-drop on the SGW-U side because that daemon had no way to reach the
  counters. upfd does, so it should not inherit the compromise.
- The counters stop because dropping the `Arc` from `session.urrs` is the only route the data path has
  to them, asserted with `Arc::strong_count`.

QAURR (§8.2.50) is honoured on the same machinery: every URR reports immediately with IMMER, minus any
URR this same message removed, which has already reported with TERMR — reporting both would
double-count it.

## Decision 5: Update URR re-thresholds in place, so the measured volume survives

Criterion 2, and the reason `DataPlaneUrr`'s thresholds changed shape. They were plain `Option<u64>`
behind the `Arc` the data plane holds, so the only way to change one was to rebuild the rule — which
zeroes the `AtomicU64` counters. That is a wrong bill, not a lost setting.

They are now atomics with documented sentinels (`u64::MAX` for volume, `0` for seconds) read through
accessors. Atomics rather than a lock because `record` runs per packet; `u64::MAX` rather than `0` for
volume because a zero-byte threshold is a threshold already met, and confusing the two would turn
"measure without a threshold" into "report on the first packet".

A threshold the update **omits** is withdrawn rather than silently retained — `set_reporting` writes
all five slots — and that is asserted, because the opposite reading is equally defensible and a reader
should not have to guess which was chosen.

## Decision 6: one PDR builder, not two

The modification path needed to install PDRs, which the establishment path already did inline. Rather
than write a second builder, the establishment path's is extracted to
`data_plane_pdr_from_parsed`. Two builders for one rule is how the SDF-filter compilation, or the
QFI, or the precedence sort ends up present on one path and absent on the other — the drift argument
of Decision 1, applied one layer in.

Create FAR and Update FAR (likewise QER) install identical shapes, so they run through one loop
rather than two.

## Verification

Every test drives a real datagram into the bound socket and then runs the emitted event through
`crate::handle_pfcp_session_event` — the production apply path, not a copy. Asserting the parsed
event alone would pass in exactly the broken state this issue describes, because the parse was the
missing half and the apply did not exist.

| claim | how it was made to fail | result |
|---|---|---|
| Create URR on a modification provisions measurement | disable the `created_urrs` apply | **fails** |
| …including the Measurement Period | point the `MEASUREMENT_PERIOD` lookup at an unsent IE type | **fails** |
| Update URR does not reset the measured volume | `reset_counters()` after `set_reporting`, as a rebuild would | **fails** |
| a removed URR reports its residual volume | invert the `removed_urr_ids.is_empty()` guard | **fails** |
| a removed URR stops measuring | drop the `dp_urrs.remove(id)` loop | **fails** |
| Remove QER detaches the policing | drop the `dp_qers.remove(id)` loop | **fails** |
| Remove PDR detaches the detection rule | make the `retain` predicate always true | **fails** |
| Remove FAR detaches the forwarding rule | drop the `dp_fars.remove(id)` loop | **fails** |
| an Update for an absent rule is refused with an Offending IE | short-circuit the `contains` check | **fails** |
| QAURR is honoured | force `query_all_urrs` false | **fails** |
| removals apply before creates | move the removal after the create | **fails** |
| a malformed rule body is reported | drop the `note_first_failure` call | **fails** |
| the two decoders agree | the Measurement Period revert above | **fails** |

Thirteen reverts, thirteen bites. Two earlier attempts did **not** compile and the harness reported
`DID-NOT-COMPILE` rather than a pass — the failure mode this repo has recorded as indistinguishable
from a decorative test. A third revert reported `PASSED` because the patch did not actually invert the
apply order (it moved the removal to the top of the create block, which is still remove-then-create);
rewritten to move it *after* the inserts, it bites. That one is worth recording: a revert that reads
like an inversion and is not is a false negative, and reading only the verdict would have called the
ordering claim unverified.

Workspace: 300 upfd tests (was 290), `cargo clippy --workspace` 0, `cargo fmt --check` clean.

## Ceilings

- **The establishment handler keeps its inline shape.** It parses the same IEs correctly and no
  criterion asks about it, but its rule installation is still written inside a `match` arm in
  `main.rs`, so only the modification path's application is reachable from a test today. The PDR
  builder extraction is the one piece of it this PR shares.
- **`updated_pdrs` / `created_pdrs` are applied but not asserted over the wire beyond the removal
  case.** The PDR store is a precedence-sorted `Vec`, and the replace-then-sort behaviour on an Update
  PDR has no test of its own; the criteria named Remove PDR, which is guarded.
- **The Update QER path still rebuilds the QER from scratch** (`DataPlaneQer::new` then set fields),
  so an Update QER omitting a member resets it and any token-bucket state is lost. That is
  pre-existing, adjacent to Decision 5's reasoning, and NOT changed here: no criterion asks, and the
  right answer depends on whether a QER's token bucket is state the CP function expects to survive a
  re-authorisation — which is a decision, not a fix.
- **No timer.** A Measurement Period is now provisioned and stored, and the data plane's existing
  30-second sweep is what reads it; whether that sweep fires at the *provisioned* cadence rather than
  its own is not tested here and is the same shape as the open sgwud lazy-reporting task.
- **`Arc::strong_count` is the counters-stopped assertion**, which proves the data path can no longer
  reach the URR rather than proving no packet is counted. A packet already inside `record` when the
  removal lands is counted into a rule nobody will read — accepted, and it is what the pre-removal
  report exists to bound.
- **No E2E.** Loopback datagrams in one process; the Docker jobs are `workflow_dispatch`-only.
