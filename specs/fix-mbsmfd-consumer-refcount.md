# nextgcore #295 (mbsmfd): count the consumers on a shared MBS transport

Verified against `main` @ `23148ce`.

#295 is the other half of #76's gap 7. The SSM half ("SSM sessions are unmanageable") landed there;
this is the consumer-counting half, left out because it needed a decision #76 did not settle.
TS 23.247 §7.2.1.3 / §7.2.1.4.

## Verified against current main

| claim in the issue | site on `23148ce` | still true? |
|---|---|---|
| `ContextUpdateReqData.nfcInstanceId` is parsed and never tracked | `types.rs:374` (required, no default) | yes |
| the terminate leg releases the transport unconditionally | `main.rs:1196-1223` | yes |
| #76 made START idempotent (the establish side of the shared model) | `session_context_start` → `session_activate_n4mb` | yes |
| `MbsSession.group_members` tracks UE SUPIs, not consumer NFs | `context.rs:163` | yes |
| nothing on the ContextUpdate path touches `group_members` | grep: only `member_join`/`member_leave` | yes |
| `session_context_terminate` marks ReleasePending; `release_n4mb_transport` clears | `context.rs:892`, `main.rs:1072` | yes |
| the AMF N2 leg **also** releases the transport | `main.rs:1563` (`MbsDisRelReq`) | yes — **not stated in the issue**, see Ceilings |

## Decision 1: a ContextUpdate START registers `nfcInstanceId`; TERMINATE deregisters; release on empty

This is the decision #295 asks for, and it takes the issue's first option.

Nothing in the tree registers a consumer, so the count has to start somewhere. TS 23.247 §7.2.1.3
models the START as the establish side of a *shared* distribution session, which makes the START the
honest place: the count becomes derivable from traffic the MB-SMF already sees, rather than from a
member the schema does not have. The alternative — counting only an explicit `leaveInd` join/leave —
would leave the shared-transport hazard on exactly the `leaveInd == false` path, which is the one
most traffic takes.

The risks the issue names are handled by **keying the set on `nfcInstanceId` rather than counting**:

- a consumer that restarts and re-STARTs is the same entry, so it cannot inflate the count
  (`a_repeated_start_from_one_consumer_does_not_double_count`);
- a repeated TERMINATE removes an id that is no longer there, so it cannot release a transport another
  consumer still holds. Reverting the set to counter semantics — remove *something* rather than the
  named consumer — fails a named test.

A session with **no** registered consumers yields "release", deliberately: sessions created before any
START, and every existing single-consumer flow, keep releasing on the first TERMINATE. That is what
makes criterion 6 hold without a special case.

## Decision 2: the never-departing consumer is logged, not timed out

#295 offers a TTL on the consumer entry, NRF liveness, or nothing-but-a-log.

**Logged.** A TTL would have the MB-SMF tear down a transport that is still carrying data because a
consumer was quiet — the failure it would introduce is worse than the one it fixes, and it is the same
failure this issue exists to prevent (remaining consumers whose sessions look fine and stop
receiving). NRF liveness is the principled answer and needs an NF-status subscription this daemon does
not have; adding one is its own issue.

So the pin is accepted and made visible: the terminate leg logs at `warn` with the remaining consumer
ids, because nothing else in the system can name who is holding a transport open. Criterion 5 accepts
either an implementation or an explicit log; this is the log, with the reasoning recorded rather than
left as a shrug.

## Decision 3: only the SMF leg registers, and the AMF N2 release stays unconditional

The AMF leg's `nfcInstanceId` is the **AMF's**, and an AMF relaying N2 for shared delivery is not what
pins the MB-UPF session. Counting it would let an AMF's silence hold a transport open, and — worse —
deregistering it would find it absent from a set the SMF STARTs populate, so a legitimate N2-driven
release would stop releasing anything. That would break `test_router_context_update_amf_release_golden_204`
for a reason unrelated to what this issue is about.

`session_context_terminate` therefore keeps its unconditional form for that leg, and
`session_context_terminate_for` is the ref-counted one the SMF leg uses. The consequence is a real gap
in a different dimension, filed separately — see Ceilings.

## Acceptance criteria

- [x] Two consumers START the same TMGI; the first to TERMINATE gets `204` and the transport stays up.
      A test asserts `n4mb_session` is still present and no Session Deletion was sent.
- [x] The second TERMINATE releases it; the test asserts the deletion is sent and the context is
      cleared afterwards.
- [x] A repeated TERMINATE from the same `nfcInstanceId` does not double-decrement.
- [x] A START from an `nfcInstanceId` already in the set does not double-count.
- [x] The never-departing-consumer decision is implemented or logged, and stated either way —
      Decision 2.
- [x] The existing release tests still pass: a session with exactly one consumer behaves as it does
      today (95 → 97 tests, none changed).

### How "no Session Deletion was sent" is asserted

`release_n4mb_transport` is the only path that sends one, and it clears `n4mb_session` whether or not
the MB-UPF answered — which is how the existing AMF-release test observes a release. So a context that
is still present is a release that did not happen. Stated in the test rather than left as an
inference, because it is the one assertion here that is indirect.

## Verification

Workspace **6285 passed / 0 failed** over three consecutive runs (baseline 6283 on `23148ce`; +2 —
mbsmfd 95 → 97). `cargo clippy -p nextgcore-mbsmfd --all-targets` zero warnings; `cargo fmt --all --
--check` clean.

| revert | expected to break | result |
|---|---|---|
| the terminate ignores the consumer set (the #295 defect restored) | `two_consumers_share_a_transport_and_only_the_last_terminate_releases_it` | **1 failed** |
| START does not register a consumer | both new tests | **2 failed** |
| the set behaves as a counter (remove *something*, not the named id) | the two-consumer test | **1 failed** |
| an empty `nfcInstanceId` is stored as a consumer | `a_repeated_start_from_one_consumer_does_not_double_count` | **1 failed** |

## Ceilings

- **The RAN-node dimension has the same first-writer-wins shape and is NOT fixed here.** The AMF leg
  releases the shared transport on an `MbsDisRelReq` N2 container (`main.rs:1563`), which is one RAN
  node's release of shared delivery — so it tears the MB-UPF session down for every other RAN node
  still receiving. That needs a per-`ranNodeId` set, which nothing in the tree tracks, and it is a
  different set from the `nfcInstanceId` one #295 scopes. Filed as its own issue.
- **Nothing unpins a transport whose consumer never terminates** (Decision 2). The log names who holds
  it; no timer or liveness check exists.
- **The consumer set is memory-only**, like the rest of mbsmfd (`MbsSession` derives no serde and this
  daemon has no `StateStore`). An MB-SMF restart loses the counts, so the first TERMINATE after a
  restart releases a transport other consumers may still be using. Consistent with the whole daemon's
  posture rather than a new gap, and worth naming because the recovery is worse than the steady state.
- **A consumer sending an empty `nfcInstanceId`** cannot be tracked and keeps the pre-#295 behaviour.
  The schema makes the member required, so this is a non-conformant peer; it is logged and accepted
  rather than rejected, because rejecting it would be a new 400 for traffic that works today.
