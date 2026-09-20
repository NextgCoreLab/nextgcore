# Cross-repo E2E criteria: split the per-PR gate from the interop run

**Issue:** nextgcore #349 (blocks #75; same shape blocks #303 / #328)
**Verified against:** nextgcore `main` @ `0d1c349`

## The problem

An acceptance criterion that asks for a cross-repo end-to-end test cannot be
satisfied by any gate CI runs on a pull request.

Verified state of the harness:

- The only jobs that check out nextgsim are **Docker Build**
  (`.github/workflows/ci.yml:109`), **Docker E2E** (`:175`) and
  **Docker E2E (EPC)** (`:239`).
- `docker-build` carries `if: ${{ github.event_name == 'workflow_dispatch' }}`
  at `:111`, and both E2E jobs declare `needs: docker-build`, so all three are
  reachable only from a manual dispatch.
- No in-tree Rust test references nextgsim: `rg -l nextgsim tests/` is empty.

So a test written to satisfy such a criterion lives in a stage that never runs
on a PR and is not run by whoever merges it. That is worse than an unmet
criterion, because it **reads as covered**. This is the #308 failure mode: a
signal nobody reads gates nothing.

## Decision

**Options 3 + 4 from the issue, together.** Two gates with different jobs, and
criteria must say which half they mean.

1. **Per-PR gate: an in-process test against a strict fake peer, in this repo.**
   Uses the established pattern — a real socket/`SbiServer` peer inside a
   `#[tokio::test]`, as `smfd`'s UDM tests and `pcfd`'s peer tests already do.
   It proves this NF emits and parses conformant APER and completes the
   procedure. It does **not** prove interoperability with the real nextgsim
   peer, and must not be described as if it does.

2. **Scheduled interop run: the real cross-repo E2E, nightly.** Adds a
   `schedule:` trigger so Docker Build and both E2E jobs run without a human
   remembering to dispatch them. Keeps `workflow_dispatch` for on-demand runs.

Rejected, with reasons:

- **Option 1 alone** (add the stage, accept it is manual) — leaves the
  criterion met only in the letter. A regression lands silently and surfaces
  whenever someone next dispatches. Without a convention for *when* it is
  dispatched, it rots.
- **Option 2 alone** (promote Docker E2E to run on every PR) — the strongest
  signal, but it containerises and recompiles two workspaces per PR. The
  workflow comment at `ci.yml:7-11` records that this was measured and
  rejected; re-litigating it is out of scope for a decision about how to word
  criteria, and the nightly run buys most of the signal at a fraction of the
  cost.

## Why a nightly needs an owner, and what stands in for one

The issue names the real risk: a nightly red is indistinguishable from a
nightly nobody read. That is the same failure mode as the retry that hid a 20%
flake for months (#308).

Mitigation that does not depend on anyone volunteering to watch:
`schedule:`-triggered failures appear on the repository's default-branch commit
status and in the Actions tab's failure list, and the run is named
`Docker E2E` — so the next PR author sees a red default branch. That is weaker
than a page and is stated as weaker. It is not claimed to be sufficient
supervision; it is claimed to be strictly better than dispatch-only, which
produces no signal at all unless someone acts first.

## How criteria must be worded from now on

A cross-repo E2E criterion must name which gate it belongs to. Instead of:

> Integration test: an end-to-end X drives the nextgsim peer and asserts Y.

write two:

> - Per-PR: an in-process test against a strict fake peer asserts X completes
>   and round-trips APER.
> - Scheduled: the nightly cross-repo E2E drives the real nextgsim peer and
>   asserts Y.

This is a **rewording, not a relaxation**: both halves must exist. What changes
is that the honest split is visible in the criterion rather than discovered by
whoever tries to close it.

Per the project's existing rule that a gap belongs in the code and not only in
a PR body, the per-PR test's module docs must state what it does not prove and
name the scheduled job that does.

## Consequences

- #75's criterion 6 becomes two criteria and is satisfiable; #75 is unblocked
  and its `needs-human` label can come off.
- #303 / #328 are the same shape and are unblocked by the same decision.
- Docker Build and both E2E jobs run nightly. The `workflow_dispatch` path is
  unchanged, so on-demand runs still work.
- A nightly failure is visible but unowned. Named as a residual risk rather
  than solved.
- The convention that says to hand back an umbrella whose harness is
  dispatch-gated (CONVENTIONS.md) is superseded for the cross-repo E2E case
  specifically: the answer is now the two-gate split, not a decision issue.

## Follow-up found by the first dispatched run (2026-09-20)

Dispatching the workflow after this landed exposed that the cross-repo checkout
was **already broken, and had been for some time**: all three
`actions/checkout` steps pinned `ref: first_implementation`, and nextgsim has
since renamed its default branch, so `git ls-remote --heads` shows only `main`.
Every heavy job failed at checkout with `The process '/usr/bin/git' failed with
exit code 1`.

This is the failure mode the decision above was written to prevent, arriving
one layer deeper than expected: the job was not merely unrun, it was
**unrunnable**, and dispatch-only gating is exactly why nobody noticed. The last
successful heavy run was 2026-07-05.

Fixed by tracking `main` rather than re-pinning: a pinned ref is the thing that
rotted, and a cross-repo E2E is only meaningful against current nextgsim. With
the nightly schedule now in place, a future rename surfaces within a day instead
of whenever someone next presses the button.

## Verification

- `.github/workflows/ci.yml` parses and the three heavy jobs carry a condition
  admitting both `schedule` and `workflow_dispatch`.
- A dispatch run still triggers them (the condition is a disjunction, not a
  replacement).
- The fast gate (check / test / clippy / fmt) is untouched and still runs on
  every push and PR.
