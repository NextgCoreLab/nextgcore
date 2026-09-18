# fix(test): three tests that only flake under a full parallel workspace run

Closes NextgCoreLab/nextgcore#368.

#368 banked evidence rather than a diagnosis: 1 failure in 8 `cargo test --workspace
--no-fail-fast` runs at `main` @ `4bee94e`, 0 failures in 10 runs of the two crates in
isolation, and **all three failing in the same run** — `pcfd`'s
`boot_counts_an_association_with_no_callback_as_unreachable` and
`boot_terminates_an_unrestorable_association_toward_the_smf`, plus `sgwcd`'s
`s11_build::tests::test_create_session_response_round_trip`.

The issue's own cheapest hypothesis — that the `pcfd` pair rests on `free_port`, which
#367 showed is *free* rather than *unbindable* — is **wrong**, and the issue asked for
exactly this to be checked before anything else. Neither `pcfd` test binds a port it
needs to be unreachable: the wire test serves a stub SMF on one and counts arrivals,
and the sibling sends nothing at all. `free_port` is not involved in either.

Both defects are the same class as #367's (shared process-global state), in two
different shapes, and the "three failing together" signature turns out to be two
causes, not one — the `pcfd` pair genuinely fails as a pair, and `sgwcd` is
independent.

## The `pcfd` pair: one queue, two tests, drained with `mem::take`

`PcfContext::unrestorable_associations` is a `RwLock<Vec<_>>` on the process-global
`pcf_self()`, and `take_unrestorable_associations` drains it **entirely**:

```rust
pub fn take_unrestorable_associations(&self) -> Vec<UnrestorableAssociation> {
    std::mem::take(&mut *write_through_poison(&self.unrestorable_associations))
}
```

Both tests queued one entry into that shared `Vec` and then called
`pcf_notify_unrestorable_associations()`, which drains it. Interleaved, whichever
drained first got **both** entries and the other drained nothing:

| interleaving | wire test expects `(1, 0)` | mute test expects `(0, 1)` |
|---|---|---|
| serial | `(1, 0)` ✓ | `(0, 1)` ✓ |
| mute queues between wire's queue and wire's drain | `(1, 1)` ✗ | `(0, 0)` ✗ |

That table is why they fail in the *same* run rather than in different ones, and the
window is why isolation never showed it: the wire test's own queue→drain gap is a few
instructions, and only a loaded runner reliably lands a sibling inside it.

### Fix: remove the shared mutation, not lock around it

`notify_unrestorable_associations(pending: Vec<UnrestorableAssociation>)` now carries
the decision, and `pcf_notify_unrestorable_associations()` is the thin wrapper that
drains the global into it. The two behavioural tests pass their own batch, so they are
deterministic and order-independent, and the global is untouched by either.

This is the shape the issue asked for ("remove the shared mutation rather than lock
around it") and it needs no lock, because after the change exactly **one** test touches
that queue.

No lock was added deliberately. A lock with a single taker reads load-bearing and is
not — the same reason #359's redundant re-insert was deleted rather than shipped.

### What keeps the wiring covered

Extracting a pure function is the setup for the recorded trap where *the helper is
tested and the wiring is not*. Two tests guard against it:

- `the_boot_notifier_drains_the_process_global_queue_once` drives the **wrapper**, so
  the drain cannot be removed with every other test still green. Its doc says it must
  stay the only toucher of that queue, and why.
- `a_mixed_batch_is_counted_per_entry` asserts `(1, 1)` for a two-entry batch — which
  is *literally the value the racing pair used to observe*, so the mechanism is
  demonstrated deterministically rather than revert-verified. A revert of a
  probabilistic failure proves nothing (#367).

## `sgwcd`: a "pure" codec round trip that reads a process-global at build time

`test_create_session_response_round_trip` looks pure — `provision`, build, encode,
decode, assert. It is not. `build_create_session_response` re-reads the ambient address
slot **at build time**, after `provision` has returned:

```
s11_build.rs:183   let s11_addr = ctx.s11_address();
```

and three test families write that single process-global slot with three different
values:

| writer | slot | value |
|---|---|---|
| `s11_build::tests::provision` | `s11_addr` | `10.11.0.5` |
| `gtp_path::tests::test_server` | `s11_addr` | `10.99.0.2` |
| `gtp_path::tests::test_server` | `gtpu_addr` | `10.99.0.1` |
| `s11_handler::tests` (CIDFT) | `gtpu_addr` | `10.11.0.7` |

So a `test_server` landing between `provision`'s write and the builder's read puts
`10.99.0.2` in the Sender F-TEID, and the assertion on `10.11.0.5` fails. A codec test
that is not deterministic is not pinning the codec — which is what #368 said was worth
knowing regardless of the flake, and it was right.

Unlike the maps beside them (which tests keep apart with unique IMSIs), these slots hold
exactly one value for the whole process, so whoever wrote one last owns every sibling's
answer.

### Fix: widen the existing lock's remit, do not add a second

`sgwcd` already had one ambient test lock, `pfcp_path::SXA_TEST_LOCK`, covering
`SXA_NODE`/`OUTBOUND`, the S11 server global and the stand-in SGW-U's environment. The
scalar address slots were simply outside its remit.

They are now inside it, and the lock is renamed `context::PROCESS_STATE_TEST_LOCK` and
declared beside the largest global it guards — matching `smfd`'s #308 precedent, whose
doc records why: four locks over one ambient state were four disjoint agreements, and
#276 showed a **second** lock over shared state *hangs* the suite rather than merely
flaking it. One agreement means there is no lock order to get wrong.

Guarding the writers alone would have been no protection at all (the recorded #308
finding), so the readers are covered too: every test that reaches
`build_create_session_response`, `build_create_indirect_data_forwarding_tunnel_response`,
`build_s5c_create_session_request`, `handle_create_indirect_data_forwarding_tunnel_request`,
`dispatch_create_session_request` or `dispatch_bearer_resource_command` now holds it.
Enumerated mechanically rather than by hand: 20 `test_server` call sites, 12
`stand_in_sgwu` call sites, 8 `provision` call sites, 1 `s11_handler` test, 2 direct
`pfcp_path` callers.

### The deadlock this design had to avoid

The obvious implementation — have each helper take the lock itself — **self-deadlocks**,
and would have replaced a 1-in-8 flake with a hang. Twelve `gtp_path` tests call
`stand_in_sgwu` *and* `test_server` in the same test, so a helper-side acquisition would
take the same non-reentrant mutex twice.

So there is exactly **one acquisition point per test**, and it is enforced by the
compiler rather than by convention: `test_server`, `stand_in_sgwu` and `provision`
require a `&ProcessStateGuard` they cannot manufacture. A test that forgets the guard
does not compile.

`ProcessStateGuard` keeps the `Drop` cleanup the old `SxaTestGuard` had. Because the
guard is now bound at the top of the test, it drops *last* — after any `StandInSgwu` —
so cleanup still runs at the very end.

Sync `#[test]`s take it via `process_state_test_guard_blocking()`, which uses
`blocking_lock()`. That is sound precisely because a sync test has no runtime to block,
which is the same justification `smfd` records.

### The deterministic demonstration

`the_sender_fteid_address_is_read_from_the_global_at_build_time` performs the sibling's
write *inline* — `provision`, then `set_s11_address(10.99.0.2)`, then build — and
asserts the message carries `10.99.0.2`. It pins the impurity itself, so it fails the
moment the builder stops re-reading the slot, and it needs no luck to reproduce.

## Verification

- `cargo test -p nextgcore-pcfd`: 207 passed (was 205; +2).
- `cargo test -p nextgcore-sgwcd`: 88 passed (was 87; +1). No hang, which is the
  specific risk the one-acquisition-per-test design exists to avoid.
- `cargo test --workspace --no-fail-fast` looped 12 times: see the PR body for the
  counts. A single green run says nothing about a 1-in-8, per the recorded deflake rule.
- Every new test name was grepped out of the run output rather than inferred from a
  summary line: a filter can match the wrong tests and still read green, and
  `cargo test -p nextgcore-pcfd --bin nextgcore-pcfd` reported `running 0 tests` during
  this work — the bin target holds none of them.

## Ceilings

- The `sgwcd` guard is enforced for the three helpers that write ambient state. A future
  test that writes `s11_addr`/`gtpu_addr`/`s5c_addr`/`pgw_s5c_peer` *without* going
  through one of them is still on its own; the lock's doc names the slots so that is a
  documented obligation rather than a discovered one.
- `free_port` is untouched. #367's `refused_port` migration was checked against these
  three tests as the issue asked, and none of them is a `free_port` caller — so there
  was nothing to migrate, and the remaining `free_port` callers are still the ones that
  want a port with nothing listening.
