# nextgcore #193: tell the consumer when a resource cannot be served

Verified against `main` @ `62ddaaa`.

#193's symptom is real: an NF that cannot honour a resource says nothing, and the
consumer finds out as an unexplained 404 or never. Its **detection** claims are
stale in both directions, and its criterion 2 is already met.

## Verified against current main

| claim in the issue | site on `62ddaaa` | still true? |
|---|---|---|
| upfd tracks the peer Recovery Time Stamp and detects CP restart | `upfd/pfcp_path.rs:881` `check_peer_recovery` | yes |
| Gap 2: "Detection is not wired to cleanup **or** notification" | **cleanup is wired on both sides.** `upfd/pfcp_path.rs:719` `declare_peer_failure` drops the association, clears the session map, logs both counts at warn, and raises `PfcpSessionEvent::PeerFailure`, which `upfd/main.rs:1148` turns into a data-plane flush. smfd's `teardown_association` does the same locally | **false for cleanup**, true for notification |
| criterion 2: "on detecting a peer restart, sessions affected are cleared locally and the outcome is logged in terms an operator can act on" | as above, with four existing tests (`pfcp_path.rs:3106/3149/3178/3198`) covering the ownership guard as well | **already met before this PR** |
| Gap 3: "**After #191 lands**, an SMF may restore PFCP sessions the UPF has already discarded" | #191 **has** landed, and shipped the interlock: the snapshot carries each UPF's Recovery Time Stamp, seeded back at boot, so a restart *is* detected and the restored sessions flushed | **partly stale** — the restart case is closed; the same-stamp per-session case is not |
| #191, #192 described as pending | both **CLOSED**; #190's shared `StateStore` is in `nextgcore-core` | stale |
| Gap 1: "No outbound signal on unrecoverable state" | nothing notified anyone, anywhere | **yes — this is the whole issue** |

So the work is not "wire detection to cleanup". It is the *signal*, plus the one
reconciliation case the Recovery Time Stamp cannot see.

## Decision 1: notify where the evidence is, which subsumes eager-vs-lazy

#193's pre-check demands a choice between notifying **at boot** for everything
that failed to restore and notifying **lazily** on first touch, applied
uniformly. Applied literally, either choice is wrong for an SMF:

- **Eager** would have to guess. At boot the SMF has a restored session map and a
  set of stamps. Whether the UPF still holds those sessions is not knowable until
  the first Association Setup answers with *its* stamp. "Assume everything
  survived" is today's silence; "assume nothing did" releases sessions that are
  perfectly alive, which is worse than the defect.
- **Lazy** would leave a real gap. A session whose `PolicyBinding` record did not
  survive the restore is unusable *immediately* — no PCF association, no
  authorized QoS, no FSM state — and waiting for a request to arrive means the
  consumer keeps believing in it for as long as it stays quiet.

The rule adopted is one step behind the dichotomy and covers both: **notify at
the point where the NF has evidence that a resource cannot be served.** Three
such points exist, and the eager/lazy split falls out of where the evidence comes
from rather than being imposed:

| # | Trigger | Evidence | Timing | Scope |
|---|---|---|---|---|
| 1 | a restored session's policy binding did not deserialise | local, at restore | **boot** | one session |
| 2 | the UPF's Recovery Time Stamp changed, or the association was released | the peer's own stamp | first association | every session on that UPF |
| 3 | the UPF answered a request with cause 65, *Session context not found* | the peer's own cause code | on that request | that one session |
| 4 | a PCF `sessions` record did not deserialise | local, at restore | **boot** | one SM policy association |

Every notification this PR sends is backed by something the NF actually knows.
TS 29.500 §6.5 permits either reading; this one has that property, and the module
doc states it so a later NF adopting the pattern applies the same rule.

## Decision 2: the callback is salvaged from the RAW record

This is what makes (1) and (4) possible at all, and it is the finding of the
issue.

Both smfd and pcfd read their record lists **per record**, so one entry whose
schema moved does not discard the snapshot (`context.rs`'s `filter_map` and
`records()`). What that leaves behind is asymmetric and was invisible: in smfd the
*session* under the same key restores independently, so the SMF ends up holding a
PDU session with no binding; in pcfd the association simply vanishes while the SMF
keeps its URI. Either way the consumer still believes in the resource, and the
obvious reading is that there is nobody to notify — the record that carried the
callback is precisely the one that could not be read.

But it failed **typed deserialisation**, not JSON parsing: `StateStore` already
validated the file as JSON before any of this runs. So `smContextStatusUri` /
`notification_uri` are still readable from the raw `serde_json::Value`, and both
NFs now salvage them. That turns "nothing can be done" into a conformant
notification.

Where the salvage fails, the count says so and the log is an `error` naming the
reference, rather than a success count that quietly includes it.

## Decision 3: persistence is not the gate, and criterion 4 is honoured where it applies

Criterion 4 asks that an NF with no durable store "behaves as today" and that this
issue "must not make the memory-only path chattier". Two readings, and they differ:

- Triggers (1) and (4) are **boot-only and store-only**: with no state file
  nothing is restored, so nothing is emitted. `nothing_restored_means_nothing_emitted`
  asserts it. Criterion 4 is met exactly.
- Trigger (2) is deliberately **not** gated. A memory-only SMF with 200 live
  sessions strands 200 AMF contexts just as thoroughly when the UPF restarts —
  the AMF's stale view does not depend on whether the SMF wrote a file. Gating the
  signal on a persistence setting would leave the shipped default carrying the
  exact defect this issue exists to remove, and the traffic in question is one
  POST per session that was previously discarded in silence. That is required
  signalling, not chatter.

Stated rather than buried, because it is the one place this PR does not do what a
criterion literally says.

## Decision 4: only cause 65, and every reference claiming that SEID

`cause_means_session_gone` returns true for **65 only**. The other rejection
causes (mandatory IE missing, rule creation failed, no established association)
are about the *request*; dropping a session on those would destroy a live one over
a malformed message. Pinned by a test that walks the neighbouring causes.

The reverse lookup from SEID to `sm_context_ref` returns **all** matches, not the
first. A UPF allocates one F-SEID per session, so in a healthy deployment there is
at most one — but if two references claim the same SEID the SMF cannot tell them
apart and the UPF has just said that SEID has no context, so both are wrong.
Taking the first made the result depend on `HashMap` iteration order, and **that
is not hypothetical: it made this PR's own N4-level test fail 1 run in 5** against
a stand-in UPF that hands out a constant SEID. Found by running the crate suite
six times rather than once, and fixed in the production function rather than only
in the test.

## Decision 5: the stand-in UPF gained a cause knob

`stand_in::StandInUpf::answer_sessions_with(cause)` makes the stand-in answer
Session Modification and Deletion with an arbitrary cause. Scoped to the
session-level messages: a stand-in that refused the association handshake could
not first establish the session the reconciliation is about. Without it the four
N4 call sites could only be verified by calling the reconciler directly, which is
the same "the wiring is untested" defect one layer up.

## Verification

Every behavioural claim was made to fail before being written down.

| claim | how it was made to fail | result |
|---|---|---|
| teardown notifies the AMF, not just the log | replace the `notify_sessions_unrecoverable` call in `teardown_association` with `0` | **fails** `a_peer_restart_notifies_the_amf_before_flushing_the_session_map` |
| reconciliation drops the session, not only notifies | keep the session in the map | **fails** 3 tests incl. the N4-level one |
| only cause 65 drops a session | make every non-accepted cause qualify | **fails** `only_cause_65_means_the_session_is_gone` |
| an unchanged stamp notifies nobody | make `check_peer_restart` treat any stored stamp as a restart | **fails** `an_unchanged_stamp_notifies_nobody` **and** #191's own `an_unchanged_recovery_time_stamp_leaves_restored_sessions_alone` |
| smfd salvages the callback from the raw record | return `None` instead of reading `smContextStatusUri` | **fails** `an_unreadable_binding_yields_its_session_and_a_salvaged_callback` |
| boot drops the unusable session as well as notifying | notify but keep it | **fails** 2 boot tests |
| the SEID lookup is total | take the first match | **fails** `two_references_on_one_seid_are_both_reconciled` |
| pcfd salvages the SMF callback | return `None` for `notification_uri` | **fails** `an_unrestorable_association_yields_a_salvaged_callback_and_resource_id` |
| pcfd actually sends the terminate | count it and send nothing | **fails** `boot_terminates_an_unrestorable_association_toward_the_smf` |

Every consumer-facing assertion is on the **wire** — a stub AMF/SMF counting
POSTs and recording bodies — not on a log line, which criterion 1 asks for
explicitly. All are positive assertions on `statusInfo.resourceStatus == "RELEASED"`
or `resourceUri`, values reachable only from inside the path under test.

Gates: workspace **6378 passed / 0 failed** (was 6373 at branch point, 6352 two
issues ago); `cargo clippy --workspace` and `--all-targets` 0 errors;
`cargo fmt --all --check` clean; `cargo test -p nextgcore-smfd` 6 consecutive
clean runs after the flake above was fixed.

## Ceilings

- **Only two NFs, and only two resource kinds.** Gap 1's prose also names
  *subscriptions*: nefd, nwdafd and pcfd's event subscriptions all use the same
  per-record skip and would all benefit. They are not done here, and the reason is
  not effort: **TS 29.522 defines no termination notification for a monitoring
  subscription at all**, so an NEF that lost one has no conformant way to say so —
  the choice is between inventing a message and staying quiet, and inventing is
  worse. TS 29.520 has an analytics-subscription *termination request* (consumer →
  NWDAF) which is the opposite direction. Closing that half needs a spec decision
  per API, not a repeat of this pattern, and is worth its own issue.
- **Only the SMF→AMF and PCF→SMF directions.** When the SMF releases sessions on
  a UPF restart it does **not** delete the corresponding PCF SM policy
  associations, so the PCF is left holding them — the mirror image of the defect
  being fixed, one hop further out. `Npcf_SMPolicyControl_Delete` exists on the
  normal release path and is not driven from here.
- **No throttling.** One POST per session, sequentially, on the association
  teardown path. A UPF restart with a large session count produces a proportional
  burst at the AMF exactly when it may itself be recovering. The issue's pre-check
  raises this; bounding it needs a policy (rate, batching, or the TS 29.500
  retry-after loop) that no criterion specifies.
- **Best-effort delivery.** A transport failure is logged and the next consumer is
  still tried; there is no retry and no persistence of undelivered
  notifications, so an AMF that is down during the burst never learns. That
  matches every other notification path in this tree and is not better for being
  consistent.
- **The UPF has nothing to send.** Criterion 2's "or notification" half has no
  implementable target: TS 29.244 gives the UP function no "I lost your sessions"
  message. The CP learns of a UP restart from the Recovery Time Stamp in the next
  Heartbeat or Association Setup Response, which upfd already reports correctly.
  Stated rather than left looking unfinished.
- **A poisoned snapshot notifies nobody.** When the whole file is unreadable the
  store poisons and startup fails, which is #190's deliberate behaviour — there is
  no state, so there is no list of consumers to tell. The salvage only helps when
  individual records fail.
- **pcfd's terminate cause is `UNSPECIFIED`.** No enumerated TS 29.512 cause
  describes "the producer lost its own record". Picking a closer-sounding one
  would misreport what happened.
- **No E2E.** Every wire assertion is a loopback POST inside one process. The
  Docker jobs remain `workflow_dispatch`-only and untouched, and nothing in this
  tree restarts a UPF or corrupts a snapshot in a container.
- **pcfd's boot notification is fire-and-forget through `spawn_notification`**, so
  a failure after the spawn is invisible to the count it returns. The count means
  "handed to the runtime", which the doc says.
