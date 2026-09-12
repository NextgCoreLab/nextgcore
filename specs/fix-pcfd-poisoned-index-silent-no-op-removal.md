# fix(pcfd): a poisoned index turned every removal into a silent no-op

Closes #338.

#338 filed a once-seen, never-reproduced failure of `each_uav_guard_refuses_on_its_own` and
asked, in its last criterion, whether the leak was **real** or a test race — "worth deciding
which before fixing".

**It is real.** There is a production leak, it is deterministically reproducible, and the same
mechanism explains why the flake appeared only in the run #338 describes and never again. The
test was *also* fragile, for the reason #338 suspected, and that is fixed too — but it is the
second finding, not the first.

## Criterion 1 — the enumeration

Every pcfd test that mutates the process-global PCF context or a `PCF_*` env var, and whether it
takes `CONTEXT_GUARD` (57 tests; mechanically enumerated, not eyeballed):

| | tests | takes `CONTEXT_GUARD` |
|---|---|---|
| touch the global PCF context | 49 | 20 |
| **touch the global PCF context WITHOUT the guard** | **29** | — |
| mutate a `PCF_*` env var | 15 | 7 |
| mutate a `PCF_UAV_*` env var | 3 | **3 (all)** |

So #338's hypothesis 1 is confirmed and hypothesis 2 is not:

- **29 unguarded context mutators**, including session-creating ones — `sm_policy_lifecycle_over_real_http`, `sm_policy_create_negotiates_supp_feat_not_echo`, `app_session_create_*`, `ue_policy_create_get_update_delete_lifecycle`, `create_binds_by_ipv6_address_within_the_session_prefix`, … A `sess_count()` delta read across an `await` is therefore falsifiable by any of them. `CONTEXT_GUARD` "only helps against tests that also take it", exactly as #338 says.
- **The `PCF_UAV_*` env vars are not the exposure.** All three tests that set them take the guard, and no unguarded test sets any of them. The 8 unguarded env mutators touch `PCF_UE_POLICY_DELIVERY`, `PCF_URSP_RULES`, `PCF_T3501_SECS`, `PCF_LOCAL_PLMN` — none of which `is_uav_dnn()` reads.

## Criterion 4 — decided first, because it changes what the fix is

`sess_count()` is `self.sess_list.read().map(|l| l.len()).unwrap_or(0)`. It reports **0 on a
poisoned lock**. And `sess_remove` acquired five locks as `self.x.write().ok()?`, which returns
`None` — silently — if any is poisoned.

Two of those five, `ipv4addr_hash` and `ipv6prefix_hash`, **are not touched by `sess_add`**. That
asymmetry is the whole defect:

1. a create takes the `sess_add` path and **succeeds**;
2. the UAV guard refuses, and the compensating `sess_remove` hits the poisoned index and returns
   `None` **before reaching `sess_list.remove(&id)`** — having removed nothing;
3. the caller cannot tell that from "was not there", because both are `None`;
4. the session is leaked, and **a poisoned lock stays poisoned for the life of the process**, so
   every later removal leaks too — ordinary SM-policy deletes included — until
   `max_num_of_sess` refuses all creates.

That is the unbounded growth #90 fixed, reachable again by another route. Reproduced
deterministically in `a_poisoned_index_does_not_turn_a_removal_into_a_silent_no_op`: with
`ipv6prefix_hash` poisoned, `sess_add` returns a session, `sess_remove` returns `None`, and
`sess_count()` stays 1.

### Why this explains the observation and the non-reproduction

#338 records that the failure happened in a run where **four other tests were also failing**, and
that it never recurred across 8 green suite runs and 5 runs of the test alone. A panicking test
poisons any lock it held, permanently, for every test that follows it in that binary. So:

- **panicking siblings → poisoned index → the refusal genuinely leaks → the assertion fails.**
- **green suite → no panic → no poison → nothing to see**, at any load.

The "conditions" section of #338 is therefore the strongest single piece of evidence for this
mechanism, and it is why a load loop was never going to reproduce it (see criterion 3).

### The fix

`write_through_poison(&lock)` — `lock.write().unwrap_or_else(|e| e.into_inner())` — applied to
the **removal family**, where a silent give-up is a leak rather than a "not found":
`sess_remove`, `ue_sm_remove`, `ue_am_remove`, `app_remove`, `event_sub_remove`. After the change
the only `None` these can return is the genuine "the record was not there".

Using the data through the poison is the right trade: the alternative is a permanent, unbounded
leak, and the worst case is a **stale index entry**, whose lookups resolve to an id no longer in
the primary list and answer `None` — which is what a caller of a removed record should get.

Lock **order and atomicity are unchanged**: the same locks are taken, in the same order, in the
same single scope. Only the poison arm differs. That matters because six documented AB-BA
inversion fixes in this file (#66/#192) depend on the order, and the `drop(..)`-before-`persist`
discipline depends on the scoping.

## Criterion 2 — the test is de-fragilised too

The `sess_count()` delta is replaced, in both UAV refusal tests, by a **per-`(SUPI, PSI)`**
assertion, which no sibling's session can move:

```rust
let ue_sm = ctx.read().expect("ctx").ue_sm_find_by_supi(&supi)
    .expect("the refused create must still have resolved a UE-SM");
assert!(ctx.read().expect("ctx").sess_find_by_psi(ue_sm.id, 9).is_none(), ...);
```

The UE-SM lookup is `expect`, not `if let Some(..)` as one of them had. The session assertion is
**negative**, and a negative assertion is satisfied by every path that never arrived — including
a create rejected before it resolved a UE-SM at all. Requiring the UE-SM first is the positive
half that proves the path did run. It holds by construction: the refusal removes the session, not
the UE, and the create resolves the UE-SM find-then-add (`app.rs:1960`), so a retry reuses it
rather than orphaning one.

## Revert-verify

- **The production fix.** Restoring `self.ipv6prefix_hash.write().ok()?` on that one line —
  a *behavioural* revert, not a deletion, so it cannot fail as a compile error — makes
  `a_poisoned_index_does_not_turn_a_removal_into_a_silent_no_op` fail on its named assertion,
  *"a poisoned INDEX must not make the removal report 'was not there'"*.
- **The de-fragilised assertions are stronger, not weaker.** Short-circuiting the compensating
  removal (`if false && context.sess_remove(..)`) makes **both** UAV tests fail on their own
  named assertions — `"authorization withheld: the refusal must leave no session for this (SUPI,
  PSI)"` and the `uav_session_is_refused_*` equivalent — while the
  `uav_session_is_allowed_once_*` control still passes. So the per-SUPI form still catches the
  #90 defect the count delta was there to catch.
- Each injection and restoration was confirmed by grep count before and after the run.

## Criterion 3 — the loop, and what it can and cannot show

25 consecutive runs of the pcfd unit-test binary with **3 concurrent load generators** (the smfd,
amfd and upfd unit-test binaries on repeat, competing for cores):

**25 pass, 0 fail.**

Stated plainly: this is a **non-regression measurement, not a reproduction**. The original
failure needed a *panicking* sibling to poison a lock, which a green load loop by construction
never produces — so this loop could not have failed either before or after the fix. The thing
that pins the defect is the deterministic poisoning test, not the loop. Recording the loop
because #338 asked for it, and recording its ceiling because a 25/25 here would otherwise read
as "the flake is gone" when what closed it is the mechanism above.

## Ceilings, stated rather than implied

- **20 of the 24 poison-fragile functions are untouched.** `.write().ok()?` / `.read().ok()?`
  appears at **50 sites in 24 functions**. Only the 5 removal functions are changed, because
  there a silent give-up leaks. The `*_find_*` family answering `None` on poison is wrong but
  bounded (it reads as "not found"), and the `*_add` family returning `None` is fail-loud. Both
  deserve the same treatment and neither is this issue; filed as a follow-up rather than swept
  in, because "use the data through the poison" is a different judgement call on a read path
  than on a removal.
- **`sess_count()` still answers `unwrap_or(0)` on poison**, i.e. it under-reports rather than
  failing. It feeds `get_load()`, so a poisoned `sess_list` makes the PCF advertise load 0 — the
  same shape as #325's UPF defect. Not fixed here: it needs a decision about whether a load
  gauge should be able to report "unknown", which is #325's question over again.
- **The refusal leaves a `PcfUeSm` behind** with no sessions. Bounded — one per SUPI, reused by
  the find-then-add on retry — so it is not the unbounded leak, and #90 deliberately removed only
  the session. Recorded because the new assertion now depends on that UE-SM being there.
- The enumeration is of `#[test]`/`#[tokio::test]` functions in `bins/nextgcore-pcfd/src`;
  peer-crate strict-peer tests that call `test_support::init_context()` from *other* crates are
  not counted, and they are a further population of unguarded global mutators.

## Verification

- Workspace **6538 tests, 0 failures** (6537 + the new poisoning guard). `cargo clippy
  --workspace` 0 errors. `cargo fmt --all -- --check` clean.
- `nextgcore-pcfd --lib`: 200 passed, 1 ignored.

## Files

- `src/bins/nextgcore-pcfd/src/context.rs` — `write_through_poison` and the five removal paths;
  the deterministic poisoning guard.
- `src/bins/nextgcore-pcfd/src/app.rs` — both UAV refusal tests re-scoped from a `sess_count()`
  delta to a per-`(SUPI, PSI)` lookup.
