# fix(pcfd): one poison semantics for the whole context — lookups, adds, the load gauge, and the snapshot

Closes #344.

#344 asked for a **decision** before a sweep: on a poisoned lock, should the lookup family
(a) use the data through the poison, (b) propagate a distinguishable error so a caller can 503,
or (c) abort the process. And, separately, whether a load gauge may report "unknown".

## Criterion 1 — the decision

**Option 1: one semantics for the whole file. Read and write THROUGH the poison.**

- A poisoned lock means a thread unwound while holding it. Every write scope in this file is a
  short straight line of `insert`/`remove` calls on `HashMap`s under *separate* locks, so the
  realistic torn state is **one index updated and its sibling not** — exactly the state
  `write_through_poison` already accepts on the removal paths (#338), and a state whose stale index
  entry resolves to an id that is not in the primary list and therefore answers `None` anyway.
- **A false "not found" is not the safer answer.** Poison is permanent, so from the first panic
  every lookup 404s a live session for the life of the process: the SMF is told its association
  does not exist, it deletes nothing, and the record leaks. That is the #338 defect reached from
  the read side, not a milder cousin of it.
- **Option 2 rejected**: it changes 14 signatures and every caller, and a PCF that 503s every
  request forever has the availability outcome of aborting without the clarity of a crash.
- **Option 3 rejected** for the reason #338 already chose to keep serving: a localized bug should
  not take the NF down.

## Criterion 2 — the enumeration, corrected

#344 says "45 sites in 19 functions". The **19 functions is right; the 45 sites is not, and the
population was the wrong one.** Counting `.read()/.write().ok()?` and excluding comment lines
(the issue's count appears to include the comment on `sess_remove` that quotes the old pattern):

| population | sites |
|---|---|
| `.ok()?` — the family #344 enumerated | **35** in 19 functions |
| `if let Ok(..) = ..write()` — silently skips the whole mutation | 8 |
| `match ..write() { .., Err(_) => false }` — silently failed update | 6 |
| `if let (Ok(a), Ok(b), ..) = (..)` tuple acquisitions | 14 |
| `.read().map(len).unwrap_or(0)` — under-reporting counts | 7 |
| `let Ok(x) = ..read() else { return empty }` | 1 |
| the global context's own outer lock | 3 |

So the same defect had **six more syntaxes**, and three of them are worse than the lookup case
#344 asked about:

1. **`*_remove_all` / `*_remove_all_for_*` are removals that still silently no-op.** #338 fixed
   five removal functions; `ue_am_remove_all`, `ue_sm_remove_all`, `sess_remove_all_for_ue` and
   `app_remove_all_for_sess` are removals too and were missed because they use
   `if let Ok(..)` rather than `.ok()?`. Two of them are the *cascades* that the
   already-poison-tolerant `ue_sm_remove` and `sess_remove` rely on, so a poisoned lock made a
   UE removal succeed while stranding every session under it. `fini` calls two of them, so a
   poisoned index also let the previous run's associations survive a re-init.
2. **`snapshot()` serialised a poisoned list as `[]`, and `persist` wrote that over a good
   snapshot.** This is the worst consequence in the file: permanent, silent data loss on **disk**.
   #66 established "never overwrite what you could not read" for an unreadable *file*; nothing
   guarded an unreadable *list*. The revert-verify output shows what shipped:
   `"ueSms":[{... "sess_ids":[1]}], "sessions":[]` — a snapshot that lost the session *and*
   contradicts itself.
3. **`sessions_number_by_snssai_and_dnn` returned 0**, which reads as "this UE has no session on
   this DNN" — the answer that lets a duplicate through.

All 78 acquisitions in the file now go through `write_through_poison` / the new
`read_through_poison`. No per-site exceptions were needed: there is no site in this file where
answering from the data is worse than answering with a lie.

## Criterion 3 — the load gauge

**#344's premise is wrong on the site and right on the defect.** It says `sess_count()` feeds
`get_load()`. It does not — `get_load` reads `ue_am_list` and `ue_sm_list` directly. But the defect
it describes was real at *those* two lines: `unwrap_or(0)` on a poisoned list made a PCF serving
live associations advertise `load: 0` to the NRF, permanently, and an SMF doing load-aware
selection would then pick it every time. Same shape as the UPF's `load: 0` (#325).

The "may a load gauge report unknown?" question **does not arise** once the counts read through
the poison: the length is knowable, so there is nothing to report as unknown and no `Option` to
plumb through the NRF profile builder. `pcf_instance_get_load()`'s own outer lock is fixed too —
honest inner counts are no use if the wrapper still answers 0.

## Criterion 4 — the tests

Four, each on a **local `PcfContext`** (never `pcf_self()`: poison is permanent and would break
every sibling test in the binary — which is how #338 surfaced), sharing one `poison()` helper that
asserts the lock really is poisoned before the test proceeds. Each was revert-verified against its
own named assertion:

| test | revert | fails with |
|---|---|---|
| `a_poisoned_lock_does_not_turn_a_lookup_into_a_false_404` | lookups back to `.ok()?` | "a poisoned list must not answer 'not found' for a live session" |
| `a_poisoned_index_does_not_fail_an_add` | `sess_add` back to `.ok()?` | "a poisoned index must not fail the create" |
| `a_poisoned_list_does_not_make_the_load_gauge_report_zero` | counts back to `unwrap_or(0)` | "the count must come through the poison, not answer 0" |
| `a_poisoned_list_is_not_persisted_as_an_empty_snapshot` | `snapshot` back to `unwrap_or_default()` | "a poisoned list must not be written out as empty" + the losing snapshot |

The add test poisons `sm_policy_id_hash` specifically, because `sess_add` takes it while the
preceding `ue_sm_add` does not — so the create is the first operation to meet the poison, mirroring
the index choice in #338's removal test. The persistence test poisons `sess_list` and then performs
an **unrelated** `ue_am_add`, so the session is collateral damage of a write that never touched it.

## Criterion 5

Workspace **6559 passed, 0 failed** (main: 6558 after #346). `cargo clippy --workspace` 0 errors,
`cargo fmt --all --check` clean.
