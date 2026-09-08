# RFC 3339 migration 3 of 5: `pcfd` onto `nextgcore_sbi::datetime`

Verified against `main` @ `4ec257a`. Third of the five per-daemon migrations; follow-up to PR #239 (#94).

## What was removed

Two functions from `bins/nextgcore-pcfd/src/npcf_eventexposure.rs`:

| copy | verdict |
|---|---|
| `:34` `pub fn epoch_to_rfc3339(secs: u64) -> String` | byte-identical to the shared one |
| `:59` `fn now_secs() -> u64` | the shared `now_epoch_secs` under a different name |

`epoch_to_rfc3339` is the youngest of the six copies and the most avoidable: **#90 added it the day before
the shared module existed**, and both it and the shared version descend from `udmd`'s, so the three were
identical from the moment the second was written. Nothing about the emitted timestamp changes.

`now_secs` is not in the task's inventory of six but belongs to the same duplication — same body, same
`unwrap_or(0)` for a pre-epoch clock, same purpose. It is imported as
`use nextgcore_sbi::datetime::now_epoch_secs as now_secs;` so the call site at `:388` reads unchanged; the
alias keeps the diff to the definition rather than spreading a rename through the file.

## Why this matters rather than being tidiness

The timestamp is the `timeStamp` of an `Npcf_EventExposure` notification (`:388`) — a wire field a consumer
compares against its own clock. Same argument as the other four: a leap-year or offset fix applied to one
copy leaves the rest wrong.

## Verification

Workspace: **5938 passed / 0 failed** over two consecutive runs, unchanged from the `main` baseline. No test
added or removed; `pcfd`'s existing `epoch_to_rfc3339_matches_known_instants` now exercises the shared
implementation and still passes. `cargo clippy --workspace` and `cargo fmt --all -- --check` clean.

**Revert-verified.** Reverting the shared formatter to `days = secs / 86_400 + 1` made
`npcf_eventexposure::tests::epoch_to_rfc3339_matches_known_instants` **FAIL** — proving `pcfd`'s tests now
reach the shared code rather than a leftover private copy, which is the failure mode a green suite would
otherwise hide. Anchor confirmed unique, revert confirmed to compile, named test confirmed to have run.

## Ceiling

Nothing new is tested — a pure redirect. `now_secs` has no test either before or after, which is
unremarkable for a wall-clock reader but worth stating: the claim about it is "same body, same name in the
shared module", established by reading, not by a test.
