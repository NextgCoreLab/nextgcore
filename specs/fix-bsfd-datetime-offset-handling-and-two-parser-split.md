# RFC 3339 migration 5 of 5: apply the offset, and fix the fail-open expiry it was causing in `bsfd` and `nsacfd`

Verified against `main` @ `4ec257a`. Last of the five per-daemon migrations, and the only one that is a
**defect fix** rather than a consolidation. Follow-up to PR #239 (#94).

## The task's premise was wrong, and that is the whole change

The task says:

> the shared module is the only one that REJECTS a non-UTC offset instead of reading it as UTC — a copy
> that does not reject shifts a deadline by hours

That conflates two different things. `bsfd`'s copy does **not** read a non-UTC offset as UTC; it **applies**
it. So the premise "the copies are the lax ones" is inverted here: `bsfd`'s parser was the *correct* one and
the shared module was the strict-and-wrong one.

The strictness was not merely pedantic. **Every consumer of the shared parser treats `None` as "no
deadline"**, so refusing a conformant offset did not shift a deadline — it *deleted* one:

| daemon | site | what a `+02:00` expiry did before this change |
|---|---|---|
| `bsfd` | `context.rs` `BsfSubscription::wants` (#98) | parser returned `None` → deadline check skipped → **a lapsed subscription kept matching**, so notifications went on being delivered to an expired subscriber |
| `nsacfd` | `context.rs:425` `report_decision` (#96) | same shape → never `Exhausted` → **kept reporting past its own expiry** |
| `nssfd` | `main.rs:2390` | `unwrap_or(nssf_deadline)` → a conformant consumer's requested expiry silently replaced by the NSSF default |

Both `bsfd` (`lib.rs:1147`) and `nsacfd` (`main.rs:1571`) store a consumer's `expiry` **verbatim with no
validation**, so the bad input is reachable from the wire in both. A refused deadline is strictly worse than
a shifted one, which is what makes this a fix.

And TS 29.571's `DateTime` is RFC 3339, which permits any offset — so honouring it is what the spec says
anyway.

## `bsfd` was using both parsers, on two resources, in one daemon

The sharpest evidence that this needed settling rather than mechanically migrating:

* the **binding**'s `expiry` (`BsfSess::set_expiry`, and the ingress validation in `lib.rs:720`) went
  through `bsfd`'s own offset-applying parser;
* the **subscription**'s `expiry` (`BsfSubscription::wants`, added by #98) went through the shared
  offset-rejecting one.

Same field name, same wire type, two resources, two answers. Migrating `bsfd` down to the shared parser
would have made the binding side start rejecting timestamps it accepts today — a regression at a wire field,
introduced by the consolidation meant to prevent exactly that.

## What changed

**`nextgcore_sbi::datetime`:**

* `split_zone` — a new helper that peels a trailing `Z`/`z` or numeric `±HH:MM` / `±HHMM` and returns the
  offset in seconds. **No zone at all is still refused**, because a naive local time names no instant and
  guessing UTC for it is the hazard the old strictness was actually worried about. A malformed zone
  (`+2:00`, `+xx:00`, `+25:00`, `+02:60`) is refused rather than read as UTC.
* `rfc3339_to_epoch_signed(&str) -> Option<i64>` — the full parse, applying the offset. Signed because a
  positive-offset instant just after the epoch resolves to *before* it, which `u64` cannot hold; `bsfd`'s
  call sites are `i64` anyway.
* `rfc3339_to_epoch(&str) -> Option<u64>` — now a narrowing of the signed one via `u64::try_from`, so a
  pre-epoch result is `None`. That is the same answer the pre-migration implementation gave through its
  `days < 0` guard, so `nssfd`/`nsacfd` see no change other than offsets now working.

Accepting the no-colon `±HHMM` spelling is a deliberate uniformity call: the shared parser already accepted
`+0000`, and `eesd`'s parser accepts `±HHMM` generally, so accepting both spellings is easier to explain
than accepting `+0000` while refusing `+0200`. It is not strictly RFC 3339 (`time-numoffset` requires the
colon) and that is stated at the site.

**`bsfd`:** its parser is deleted and re-exported from the shared module under the same name, so all call
sites read unchanged. The `wants()` matcher now uses that one parser, and its unparseable branch **fails
closed** — an expiry we cannot read must not be treated as permission to keep notifying, which is the same
fail-open this change is about.

**`nsacfd`:** no code change. The shared parser fix is what repairs it; a regression test pins that.

## Three pinned-behaviour tests inverted, each with the flip recorded

The project's signal that behaviour widened deliberately:

1. `datetime.rs`'s `rejects_a_non_utc_offset_rather_than_reading_it_as_utc` → `applies_a_non_utc_offset_rather_than_refusing_it`. It pinned the defect, not the guard.
2. `bsfd`'s `rfc3339_to_epoch("2026-06-12 00:00:00Z") == None` → now `Some(...)`. RFC 3339 §5.6 permits the space separator and the shared parser always accepted it; `bsfd`'s copy did not.
3. `bsfd`'s `rfc3339_to_epoch("2026-06-12T00:00:00+0200") == None` → now `Some(...)`, per the uniformity call above.

Each inversion is commented at the site with why, rather than the old assertion being deleted.

## Verification

Workspace: **5941 passed / 0 failed** across three consecutive runs (baseline 5938; two tests added, one
`bsfd` regression and the shared parser's split into three tests where there were two). `cargo clippy
--workspace` and `cargo fmt --all -- --check` clean. Three runs because the change touches a shared library
every NF links.

**Nine claims revert-verified:**

| # | claim | test that bit |
|---|---|---|
| 1 | the offset is applied, not ignored | `applies_a_non_utc_offset_rather_than_refusing_it` |
| 2 | the offset's sign is honoured | same |
| 3 | a zoneless time is still refused | `refuses_input_with_no_defined_instant` |
| 4 | out-of-range zone fields are refused, not read as UTC | same |
| 5 | the `u64` entry point still rejects a pre-epoch instant | `pre_epoch_instants_are_none_for_u64_and_kept_when_signed` |
| 6 | `bsfd`'s subscription matcher honours an offset expiry | `an_expired_subscription_does_not_match_whatever_zone_its_expiry_uses` |
| 7 | an unreadable `bsfd` expiry fails **closed** | same |
| 8 | `nsacfd`'s report decision honours an offset expiry | `report_triggers_gate_emission` |
| 9 | `bsfd`'s own parse test reaches the shared parser | `test_rfc3339_to_epoch` |

### The harness lied twice, and both are the recorded failure modes

Worth writing down because they are exactly the two the project's revert lesson warns are indistinguishable
from a decorative test:

* **Claim 6 first came back GREEN because the revert was a SEMANTIC NO-OP.** The revert pointed `bsfd`'s
  matcher back at `nextgcore_sbi::datetime::rfc3339_to_epoch` — but that function *also* applies offsets
  now, so both sides of the substitution behaved identically. Reading the substitution for equivalence, as
  the lesson says to, is what caught it. The real revert restores the *old strictness inside `split_zone`*,
  and then claim 6 bites — and so do 8 and 9, which is the stronger result: one revert of the shared parser
  fails tests in three different crates.
* **Claim 8 first came back NOT-RUN** because the test name was wrong (`report_decision_honours_every_trigger`
  does not exist; the real one is `report_triggers_gate_emission`). Treated as inconclusive rather than as a
  pass, per the same lesson.

## Merge-order dependency, and it is not optional

**Corrected after checking rather than assuming.** An earlier draft of this section predicted a *textual*
conflict with migration 4. There is none: `git merge-tree` reports every pair of the five branches merging
clean, because migration 4 adds to `datetime.rs`'s formatter half while this rewrites its parser half. Every
other pair among the eleven open branches is clean too.

**The dependency is semantic, and git cannot see it.** Migration 1 makes `nrfd` a *consumer* of the shared
parser; this change makes that parser apply an offset instead of refusing it. Neither branch alone is wrong,
they merge clean, and **the combined state fails** `nrfd`'s
`rfc3339_rejects_non_utc_and_malformed_input` — verified by building `main` + migration 1 + this branch and
running `cargo test -p nextgcore-nrfd`, which panics at `main.rs:5800` with `offset`. No CI run could have
seen it, because no branch contained both.

Resolved here rather than left for whoever merges second: **migration 1 is merged into this branch**, so this
branch's CI validates the combined state, and `nrfd`'s assertion is inverted with the flip recorded at the
site — the fourth inversion this change makes, and the one that only exists in the combination.

That still leaves an ORDER requirement, just not a conflict one: this must merge **after** migration 1,
because it contains migration 1's content and the inverted assertion only makes sense once `nrfd` uses the
shared parser. Recommended order: **1, 2, 3 → 4 → 5 (this one)**.

## Ceilings

* **A garbage `expiry` is still unvalidated at ingress** in both `bsfd` (subscriptions; the binding side
  *is* validated) and `nsacfd`. This change makes `bsfd`'s matcher fail closed on one, but `nsacfd`'s
  `report_decision` still skips the check for an unparseable expiry, i.e. it stays fail-open for genuine
  garbage. Validating at creation is the real fix and belongs with #96, not in a datetime migration —
  flagged rather than silently half-done.
* **`nssfd`'s improvement is untested here.** A conformant consumer's `+02:00` requested expiry is now
  honoured instead of being replaced by the NSSF default, but no test covers that path; `nssfd` normalises
  what it stores, so the change is only observable at the create boundary.
* **`eesd`'s `parse_rfc3339_to_epoch` is still a seventh parser.** It honours offsets like the new shared
  one, so it is no longer *divergent*, but it is still a copy — along with the `civil_from_days` /
  `days_from_civil` pair that serves it. Now that the shared parser has the same semantics, deleting it is
  finally a mechanical change; it was not before, which is why migration 4 deferred it.
