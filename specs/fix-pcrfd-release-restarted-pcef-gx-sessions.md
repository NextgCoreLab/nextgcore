# fix(pcrfd): release the Gx sessions of a restarted PCEF

Closes NextgCoreLab/nextgcore#365. Completes the reaction half of #287's detection.

## Criterion 1 was already met — the new index turned out to be unnecessary

#365's headline premise is that `PcrfGxSession` "does not record the peer host at all"
and that the work therefore needs a `peer_host` field added. **Tabled against `main`
first, per the recorded rule that these criteria drift: the field already exists**
(`context.rs:73`) and is already written on the CCR-I that creates the session
(`gx_path.rs:1102`, `session.set_peer_host(&info.origin_host)` on the
`INITIAL_REQUEST` branch).

So criterion 1 needed no code. What the issue got exactly right is the *design* call it
made about the index, and that is what was implemented:

> Deriving it on demand by walking `gx_sessions` avoids [index divergence] entirely and
> is O(n) on a path that runs once per peer restart — which is the right trade here.

`PcrfContext::gx_sessions_for_peer` derives the set. No second map, so nothing can
disagree with the session list and resolve to the wrong record — the hazard the AMF work
(#341, #363) keeps rediscovering.

### The derived lookup walks the INDEX, not the session vector

This is the non-obvious part. `gx_session_remove` deliberately removes only the
`gx_sid_hash` entry and the IP maps, leaving the positional `gx_sessions` element in
place, because `PcrfGxSession::rx_sessions` holds *indexes* into that vector and
compacting it would repoint every binding.

A released session therefore still **exists** in the vector. A lookup that iterated it
would hand back sessions released long ago, and the release path would then "release"
them again on every subsequent restart. `gx_sid_hash` is the set of sessions that are
actually reachable, which is the set the question is about.

The result is also **sorted by Session-Id**, because `gx_sid_hash` is a `HashMap` and its
iteration order is not stable — leaving it unsorted would make release order, and any
test asserting on it, a coin flip.

## The seam: an observer hook in the shared library

#287's detection lives in `nextgcore_diameter`'s peer state machine — deliberately, so
every NF gets it for free. That left no way for one NF to react. The seam is now explicit:

- `restart::PeerRestartObserver` — a plain `fn` pointer. Not a boxed closure: the reaction
  is a property of the *binary*, decided once at startup, and an `fn` keeps this module
  free of allocation and `Send`/`Sync` reasoning on a path that runs inside CER handling.
- `restart::set_peer_restart_observer` — `OnceLock`, so a binary cannot end up with two
  reactions racing to tear the same state down. A second install is **reported** and
  ignored, rather than silently deciding which one wins.
- Invoked from `peer.rs`'s CER/CEA path beside `log_peer_restart_outcome`, **not** from
  inside `observe_peer_restart`, so recording a value stays side-effect free and the
  library's own unit tests of the comparison cannot trip a reaction.

The observer receives **every** outcome, not only `Restarted`. The branch belongs to the
NF: handing it only restarts would hide `Regressed` — the one outcome meaning the signal
itself cannot be trusted — from the code best placed to log it against its own state.

## Only `Restarted`, and the test that proves the other four do nothing

`PeerRestartOutcome` has five variants and exactly one licenses a teardown. The others
are not near-misses:

| variant | why it must not release |
|---|---|
| `NotAdvertised` | the peer does not implement §8.16; nothing is known either way |
| `FirstSighting` | a baseline — acting here releases on every peer's first connect, i.e. every session at startup |
| `Unchanged` | it demonstrably has not restarted |
| `Regressed` | §8.16 requires the value to **increase**, so a decrease is evidence the signal cannot be trusted |
| `Restarted` | the value increased — this is the case |

`no_other_outcome_releases_anything` loops over all four rejected variants rather than
testing one, because the mistake being guarded is a branch written `!= Unchanged` — and
that passes a test which only checks `Unchanged`.

## Default OFF, and why that differs from its neighbour

`PCRF_RELEASE_RESTARTED_PCEF_SESSIONS`, a runtime switch rather than a cargo feature so
CI compiles and exercises both states.

It defaults **OFF** while `PCRF_ASR_ON_RULE_FAILURE` one function away defaults **ON**,
and the reason is specific: this **drops traffic on a false positive**. The trigger is a
single peer-supplied integer comparison, and if it fires wrongly the PCRF tears down the
policy state of live sessions and aborts their AF sessions. The recorded house rule is
explicit — a runtime switch defaulting ON *except where the behaviour drops traffic* —
and #56 defaulted its subscriber-change watcher off for the same hazard class.

#287's detection is always on because it destroys nothing. This is the opposite.

**Fails closed on anything unrecognised.** `the_switch_accepts_the_conventional_spellings`
pins `1/true/yes/on` as enabling and `0/false/no/off/""/maybe` as not. The default is
asserted with the variable **absent**, not set to `"0"` — those are different states, and
only absent is what a deployment that never heard of this switch actually has.

**When off, the log names the sessions it would have released.** A signal nobody reads is
worse than none, and an operator deciding whether to enable this needs to see what it
would have done — not a line saying a release was skipped.

## Criterion 5: the Rx side

An Rx session bound to a released Gx session is released with it, and its AF is told with
an **ASR carrying Abort-Cause `BEARER_RELEASED`** — the same answer, through the same
`pcrf_rx_send_asr_for_target` helper, that a CCR-T already produces for the same reason.
Sending nothing would leave the AF believing an unenforceable service is live, which is
#57's own argument for the rule-report ASR next door.

Two details:

- **The `peer_host` asymmetry #365 flags is real and is honoured.**
  `PcrfRxSession::peer_host` is the **P-CSCF's** host — the ASR's destination — and is
  emphatically not the key this release is keyed on. That is `PcrfGxSession::peer_host`.
- **`peer_realm` is passed as `None`, deliberately.** `PcrfRxSession` stores no AF realm.
  The CCR-driven abort paths fill it from the CCR's `Origin-Realm`, which they legitimately
  can because the triggering request came from the peer being reported on. There is no such
  request here, and the realm that *is* to hand is the restarted **PCEF's** — which would
  be actively wrong, since the ASR is addressed to the AF.
  `pcrf_rx_send_asr_for_target` already falls back to our own realm, which is at least
  true of the sender.

The ASRs are **spawned**: the observer runs on the peer's own task, so the synchronous
part is one index walk plus the local removals, and anything crossing the network is
handed off. When no runtime is available the Rx sessions are still released locally and
the log says the AFs were **not** told, rather than implying they were.

## Criterion 4: #57's spec now distinguishes the two restarts

`specs/fix-pcrfd-gx-dynamic-policy.md` gains a table and the argument that they are
complements, not alternatives: persistence survives **our** restart, this cleans up after
**theirs**. The point worth writing down is that they interact — a Gx session reloaded
from #57's snapshot is exactly the record that should be released when its PCEF reconnects
with a higher `Origin-State-Id`, so *without* this release, #57's durability makes the
staleness longer-lived rather than shorter.

## The two-PCEF test, and its revert round

`a_restart_releases_only_the_restarted_peers_sessions` seeds **two** Gx sessions for one
PCEF and one for another. The two-peer shape is the point: a single-peer test passes
identically against a release that ignores `Origin-Host` and drops every Gx session in the
context, which is the worst available bug here.

**Revert round** — dropping the `Origin-Host` predicate from the derived lookup:

```
test peer_restart::tests::a_restart_releases_only_the_restarted_peers_sessions ... FAILED
  another PCEF's session must SURVIVE: this is what a single-peer test cannot
  distinguish from releasing everything
test peer_restart::tests::the_lookup_walks_the_index_not_the_session_vector ... FAILED
test gx_path::tests::ue_ip_address_release_clears_the_mapping ... FAILED
test result: FAILED. 78 passed; 3 failed
```

The third failure is the instructive one: an unscoped release reached a **sibling
module's** session in the process-global context. That is the blast radius the test doc
claims, demonstrated rather than asserted.

## Ceilings

- **No E2E.** The shipped Docker EPC compose does not enable this switch, so the E2E path
  is unchanged and does not exercise it — the same ceiling #57 recorded for durable state.
- **No corroboration beyond the CER.** One CER/CEA is treated as sufficient evidence,
  which is #287's recorded answer to its own question 4 and is not revisited here. It is
  also why the switch defaults off: the whole reaction rests on that single observation.
- **The release is local plus an ASR.** No RAR, and no attempt to tell the restarted PCEF
  anything — it has forgotten the sessions, so there is nothing to tell it.
- **`install()` is called from `main` after Gx and Rx are up**, because the reaction
  touches both. A binary that never calls it keeps #287's purely diagnostic behaviour.
- **GitNexus impact analysis unrunnable**: the MCP server is not connected this session,
  so `CLAUDE.md`'s `gitnexus_impact` mandate could not be satisfied. Blast radius was
  established by grep instead — the only pre-existing function whose behaviour is touched
  is `observe_capabilities_exchange`, which gains one call.

## Verification

- `cargo test -p nextgcore-pcrfd`: 81 passed (was 76; +5).
- `cargo test --workspace --no-fail-fast`: **6616 passed, 0 failed**.
- `cargo fmt --all -- --check` clean; `cargo clippy -p nextgcore-pcrfd -p nextgcore-diameter
  --all-targets` reports **zero** warnings; `cargo clippy --workspace` no errors.
- Revert round run and restored, as above.
