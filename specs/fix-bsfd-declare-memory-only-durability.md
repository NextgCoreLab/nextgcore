# bsfd durability: decide memory-only, say so, and guard the statement

Verified against `main` @ `4ec257a`. No issue number — this is the decision the #98 spec deferred and
TASKS.md carried: *"Either make bindings durable first and subscriptions with them, or state explicitly that
bsfd is a memory-only NF and that consumers must re-subscribe after a restart."*

**The decision is memory-only.** Recorded below with the reasoning, so it is a posture rather than a gap.

## The premises, re-verified

Both hold exactly as the task states:

* `grep -rn 'nextgcore_mongoc_init\|nextgcore_dbi_init' src/bins/nextgcore-bsfd/` returns **nothing**. The
  daemon never initialises the shared DBI layer.
* The `bsf_bindings` helpers exist (`context.rs`: `bsf_db_upsert_binding`, `bsf_db_delete_binding`,
  `bsf_db_load_all_bindings`, each with exactly one caller) and every call is best-effort — failures logged at
  debug — so in the standalone binary bindings live in memory only.

And the follow-on: `lib.rs` stores a subscription verbatim in memory, so subscriptions were never durable
either.

## Why memory-only, rather than "durable, later"

The task frames this as a choice between two honest options. It is more than that: **restoring bindings would
be worse than losing them**, which turns the choice into a decision with a reason.

A TS 29.521 binding is a **live** association between a UE's PDU session and the PCF *currently* serving it.
While the BSF is down that association can change — the session can be released, or another PCF can take it
over. A restored binding therefore asserts a fact that may no longer hold, and a consumer reading it is told
**the wrong PCF**. That is worse than being told nothing: "nothing" (a `204` from
`GET /pcfBindings?ipv4Addr=…`) makes the consumer re-discover, whereas a wrong answer makes it send policy
traffic to a PCF that does not serve the session.

Restoring **subscriptions alone** — the thing the task explicitly forbids — would be worse still, and now
there is a sharper way to say why: a subscriber that survived a restart while its bindings did not would
either be notified about nothing at all, or, if the expiry/removal sweep read absent bindings as removed, be
told bindings *"deregistered"* that were simply never restored. That is a **fabricated event**, which this
project treats as the most serious class of defect — the same reason a stub returning `Ok` is treated as a
lie rather than a placeholder.

So durability here is not a missing feature to be added when convenient. It requires a *recovery-time answer*
first, which is a protocol addition rather than a storage change.

## What was written

1. **A first-class `## Durability: bsfd is a memory-only NF` section** in
   `docs-book/src/configuration/bsf.md`, placed after the behaviour notes. It states what is lost, what a
   consumer must do (re-register bindings, re-subscribe), why restoring bindings would be worse, and — so the
   option stays costed rather than rediscovered — the four things that would have to change to make it
   durable: bindings first and subscriptions with them; a URI source plus an init call and a decision about
   an unreachable database at boot; a recovery-time answer for the staleness above; and the durable-snapshot
   hazards this project has already paid for (restore before the listener accepts, persist removals, never
   resurrect a deleted record).
   The pre-existing "Honesty note" bullet that half-said this now points at the section instead of restating
   it, so there is one statement rather than two that can drift.
2. **The same statement in the code**, as a module doc comment on `context.rs`. A claim that lives only in a
   book is easy to contradict from the source; a reader of `bsf_db_upsert_binding` now finds the posture
   where the dormant helper is.
3. **A source guard that keeps it true** — `tests::bsfd_is_declared_memory_only`. It reads bsfd's own
   sources and fails if any of them calls `nextgcore_mongoc_init` or `nextgcore_dbi_init`, naming the doc
   page and the module comment in the failure message. Modelled on `nextgcore_core::signal`'s `--kill` guard,
   including its self-check: it asserts the persistence helpers are still **present**, so it cannot pass by
   having nothing left to look at.

The Mongo helpers are deliberately **kept**. Deleting them would remove the option and lose the schema work
in `sess_to_doc`; documenting them as the dormant half of a stated posture is what the task asked for.

## Verification

Workspace: **5939 passed / 0 failed** over two consecutive runs (baseline 5938; the added test is the guard).
`cargo clippy --workspace` and `cargo fmt --all -- --check` clean.

**The guard was revert-verified**, which for a guard is the only thing that distinguishes it from decoration.
Injecting `nextgcore_dbi::mongoc::nextgcore_dbi_init("mongodb://localhost/nextgcore")` into `bsfd/src/lib.rs`
makes it **FAIL**, with the offending line quoted in the message.

### The guard's first version had a false negative, and the revert is what exposed it

Worth recording because it is the failure mode a passing test hides. The first version skipped any line
containing a `"` character, in order not to match the guard's own string literals — which would have
**silently skipped a real `nextgcore_dbi_init("mongodb://…")` call**, i.e. the most likely form of the exact
thing being guarded against. A guard that cannot see the realistic case is worse than no guard, because it
reports safety.

Fixed by building both markers with `concat!("nextgcore_", "dbi_init")` so this file never contains either as
a contiguous string, which removes the need for the heuristic entirely. The revert above uses the
string-argument form deliberately, so it proves the fix and not just the guard.

The first revert attempt also failed for a *harness* reason and was treated as inconclusive rather than as a
pass: the injection was prepended to `lib.rs`, which does not compile because inner (`//!`) doc comments must
be the first thing in a file. Appending it compiled, and then it bit.

## Ceilings

* **No test proves a restart loses state**, because nothing in this repo drives a bsfd process through a
  restart. The claim rests on there being no persistence call path at all, which the guard checks
  structurally — a stronger check than a test that restarted a process and observed an empty store, since
  that would pass on a database that merely happened to be unreachable.
* **The docs-book statement is prose**, and prose can still drift from behaviour in ways a grep cannot see —
  for example if a future in-process embedder initialises the DBI layer from *outside* bsfd, which the guard
  cannot detect because it only reads bsfd's sources. That path is named in the existing env-vars bullet and
  is unchanged by this decision.
* **The "Honesty note" also mentions `bsf_sbi_send_request` / `bsf_sbi_discover_and_send`**, which the #234
  change deletes. That sentence is still accurate on this branch; whichever change lands second should drop
  that clause. Flagged rather than fixed here, because editing it on this branch would conflict with nothing
  and mislead a reviewer comparing against `main`.
