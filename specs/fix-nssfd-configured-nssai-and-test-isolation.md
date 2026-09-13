# fix(nssfd): configuredNssai was decided by whichever AMF had reported availability

Closes #346.

#346 filed a single CI failure of `test_nsselection_ue_cu_no_requested_nssai_no_allowed_list`
on an unrelated PR (#345, which touches `nas`/`amfd`/`smfd`/`docs`), and asked in its last
criterion whether the missing `configuredNssai` was a **test** defect or a **conformance** one:
"decide which before fixing".

**It is both, and the conformance half is the one that would have shipped.** The response member
was filtered by the union of the NSSAI-availability documents AMFs had registered. On CI that
union came from a sibling test; in a deployment it comes from any AMF that registers a partial
picture. The test isolation was independently broken, in the way #346 suspected and one further
way it did not name.

## Criterion 1 — does `NssfContext::init` reset or latch?

**It latches, and it clears nothing even on the first call.** `context.rs:570-577` is

```rust
pub fn init(&mut self, max_nf: usize) {
    if self.initialized.load(Ordering::SeqCst) { return; }
    self.max_num_of_nf = max_nf;
    self.initialized.store(true, Ordering::SeqCst);
}
```

so the per-test `nssf_context_init(512)` recorded a pool size on the first call in the process and
was a no-op afterwards. It never touched `nssai_availability`, `subscriptions`, `target_amf_set`,
`plmn_supported_snssai_restriction`, the NSI table or the home table. #346's hypothesis — "if
`init` is once-only/latching then whichever test ran first decides the global's contents" — is
confirmed structurally, no measurement needed.

The latch is **correct for production** and is now documented as such rather than fixed: `main`
calls `nssf_context_init_with_state` first, which may restore a snapshot from disk, and only then
`nssf_context_init(args.max_nf)`. An `init` that cleared would delete the restored state.

## Criterion 3 — where `configuredNssai` comes from, and which global state decides it

```
configuredNssai                      main.rs:1094
  <- sel.configured                  nnssf_handler.rs (registration selection)
  <- filtered by `plmn_supported`    the UNION of snapshot.per_nf_support
  <- context.per_nf_supported_snssais()
  <- the process-global `nssai_availability` map
```

The filter read: `plmn_supported.is_empty() || plmn_supported.contains(s)`. So

- **no** availability registered anywhere -> no filtering -> the full subscription (this is why
  the test passed locally, and why it passed for months);
- **any** availability registered -> a subscribed S-NSSAI absent from every registered document is
  dropped from the Configured NSSAI.

The failing assertion was therefore never about the UE-CU rule it is named for. It is
`handle_ns_selection_ue_cu` -> `handle_ns_selection_registration` -> this filter, and the
registration algorithm produced no `configuredNssai` for a subscription that plainly had one.

### The conformance call

`per_nf_support` is the wrong source. Each availability document is **one AMF's slice picture** —
the tree says so itself where it authorizes writes to the resource ("the resource is one AMF's
slice picture, so the only consumer entitled to write it is that AMF", `context.rs`). Registering
availability is per-AMF and optional, so a slice absent from every registered document has not
been shown unsupported by the PLMN, only unreported. Reading absence as "not supported in the
serving PLMN" is what let a partial picture truncate the Configured NSSAI.

The authoritative source is the **configured** PLMN S-NSSAI set, which this crate already models
and documents as exactly that (`plmn_supported_snssai_restriction`, "the set of S-NSSAIs supported
in this PLMN (TS 29.531 §6.2.3.2.3.1)"). So `configuredNssai` is now the subscription restricted
by that set when one is configured, and the whole subscription when none is — the same default-allow
stance the availability-write path already takes. `per_nf_support` keeps its one correct use, the
AMF re-selection immediately below the filter, where "which AMF can serve this" is the actual
question.

Why this matters past the flake: the UE stores the Configured NSSAI in non-volatile memory
(TS 24.501 Annex C.1, TS 23.501 §5.15.4.1), so a truncated one outlives the availability report
that caused it. Note the new snapshot field is `Option<Vec<SNssai>>` and is `Some` only when
`has_plmn_snssai_restriction()` is true: `plmn_supported_snssais()` returns an empty vector for
both "no restriction" and "restricted to {}", and those are opposite answers.

## Criterion 2 — a context each test fully owns

#346 counted 23 tests taking `NSSF_TEST_LOCK` and 1 not. The enumeration was of the wrong
population: there were **three** guards over this one global, and the count only covered the first.

| guard | where | tests |
|---|---|---|
| `NSSF_TEST_LOCK` (`std::sync::Mutex`) | `main.rs` test module | 23 |
| `availability_state_guard` (`tokio::sync::Mutex`) | `main.rs`, 40 lines below it | 11, of which **2 take only this one** |
| — none at all — | `nnssf_handler.rs` `setup_context()` | **7**, all of them mutating the global |

Guards that do not order against each other serialise nothing. The two tests holding only
`availability_state_guard` — `test_http_nsselection_registration_scenario` and
`test_http_availability_lifecycle_with_notifications` — are availability **writers**, and the
failing test holds only `NSSF_TEST_LOCK` and is an availability **reader** through
`per_nf_supported_snssais()`. That is the window, and it is exactly as wide as CI's scheduling.
`nnssf_handler`'s `setup_context()` was worse than unguarded: it called `init(100)` on the global
and one of its tests leaves an NSI in the global NSI table, which every later snapshot reads back
as `nsiInformationList`.

The fix is the shape #308 established for this repo and #338 used for its guard test: **one lock,
declared beside the global it guards** (`context.rs`, not a `mod tests`, so every module takes the
same one), and the acquisition hands back a context that has been **replaced**, not cleared field
by field:

```rust
pub(crate) fn nssf_test_guard(max_nf: usize) -> std::sync::MutexGuard<'static, ()> {
    let guard = NSSF_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    *context = NssfContext::new();
    context.init(max_nf);
    guard
}
```

Replacing outright rather than calling `fini()` is deliberate: `fini` clears only the NSI and home
tables and leaves availability, subscriptions, the target AMF set and the PLMN restriction behind —
the four that actually leaked. Replacing also means a field added later cannot be forgotten here.
All 32 acquisition sites now go through it, including the 6 tests that previously took no guard
while driving handlers that read the global (the "covering readers as well as writers" half of
#308).

The old comment above `NSSF_TEST_LOCK` asserted that "`nssf_context_init` WIPES that context". It
does not, and the belief that it did is why a lock was added without a reset. Corrected in place.

## Criterion 4 — measurement

- `cargo test -p nextgcore-nssfd --bins`, 15 iterations x `--test-threads` in {1,2,4,8,16}:
  **0 failures in 75 runs**. Thread count varied because #346 correctly notes a green loop proves
  little if the trigger is ordering rather than concurrency.
- Whole workspace: **6558 passed, 0 failed** (main was 6555; +3 tests). `cargo clippy --workspace`
  0 errors, `cargo fmt --all --check` clean.

## Criterion 5 — the tests, revert-verified

Three new tests, each made to fail on its own named assertion before being kept:

1. `a_foreign_amf_availability_report_does_not_erase_configured_nssai` — installs one AMF's
   document covering a slice the UE is not subscribed to, then asserts the state that would have
   caused the failure (availability data exists; no document covers sst 1; no PLMN restriction is
   configured) *before* asserting the response. This is the CI failure made deterministic.
   **Revert:** restore the `per_nf_support` filter -> fails with the CI message verbatim,
   "configuredNssai must survive a foreign AMF's availability document".
2. `a_configured_plmn_restriction_still_filters_configured_nssai` — proves the fix changed the
   filter's *source* and did not delete the filter. **Revert:** same -> fails.
3. `the_test_guard_resets_every_field_a_sibling_could_leave_behind` — dirties all five leakable
   fields, asserts the dirt is really installed (or the reset assertions would pass on an
   already-clean context and prove nothing), then takes a fresh guard and proves each is clean and
   that `max_num_of_nf` was applied rather than left at 0. **Revert:** drop the
   `*context = NssfContext::new()` line -> **five** tests fail, including
   `test_nsselection_ue_cu_no_requested_nssai_no_allowed_list` itself, which is the CI failure
   reproduced deterministically from the isolation side as well.

Assertions are positive throughout (a named S-NSSAI is present at a known index), not "the bad
thing is absent" — an absence assertion is satisfied by every path that never arrives.
