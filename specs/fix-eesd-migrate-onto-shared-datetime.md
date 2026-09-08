# RFC 3339 migration 4 of 5: `eesd`, and the signed entry point the shared module was missing

Verified against `main` @ `4ec257a`. Fourth of the five per-daemon migrations; follow-up to PR #239 (#94).

This is the one the task called out as the migration's real work: *"eesd's takes `i64`, the others `u64` —
that signature split is the migration's real work"*.

## Why `eesd`'s copy was not interchangeable

`bins/nextgcore-eesd/src/types.rs:500`, `pub fn epoch_to_rfc3339(epoch: i64) -> String`, split the epoch with
`div_euclid` / `rem_euclid` rather than `/` and `%`. That is not a stylistic difference:

| epoch | `div_euclid`/`rem_euclid` (eesd) | `as u64` then `/`,`%` (the shared `u64` path) |
|---|---|---|
| `-1` | `1969-12-31T23:59:59Z` | a year around 584 billion (`-1 as u64` is 18446744073709551615) |
| `-86401` | `1969-12-30T23:59:59Z` | likewise nonsense |

So narrowing `eesd` to the `u64` entry point would have been a **silent behaviour regression at a wire
field** — precisely the class of defect that having six copies is supposed to stop, introduced by the
consolidation meant to prevent it.

## The resolution: widen the shared module, do not narrow the caller

`nextgcore_sbi::datetime` gains `epoch_to_rfc3339_signed(i64)`, which **is** `eesd`'s implementation
promoted. `epoch_to_rfc3339(u64)` stays as the common case, so none of the other four daemons' call sites
change. Both now share one extracted `civil_from_days(days: i64)` helper; they differ only in how they split
an epoch into days and seconds-of-day, which is exactly where the signedness matters.

`eesd` re-exports the shared signed function under the old name
(`pub use ...::epoch_to_rfc3339_signed as epoch_to_rfc3339;`) so every call site in `main.rs` reads
unchanged.

Deliberately **not** done: making `epoch_to_rfc3339(u64)` a wrapper that casts to `i64`. For `secs`
above `i64::MAX` the cast wraps negative, which would change the `u64` function's output for inputs it
currently handles (absurdly, but differently). Sharing the calendar conversion and not the split keeps both
entry points bit-for-bit as they were.

## Out of scope, and why it is worth naming

`eesd` also has `parse_rfc3339_to_epoch` (`types.rs:449`), which **honours** a numeric `±HH:MM` / `±HHMM`
offset. The shared `rfc3339_to_epoch` currently **rejects** any non-UTC offset. That disagreement is not
`eesd`'s problem to fix here — it is the subject of migration 5 (`bsfd`), whose copy has the same
offset-honouring behaviour and whose two parsers currently disagree with each other inside one daemon. It is
flagged here so the omission is visible: this PR migrates the inventory item (`epoch_to_rfc3339`) and leaves
`eesd`'s parser for that change.

## Verification

Workspace: **5939 passed / 0 failed** over two consecutive runs, against the `main` baseline of 5938 — the
one added test is the signed entry point's. `cargo clippy --workspace` and `cargo fmt --all -- --check`
clean.

**Three claims revert-verified:**

| claim | revert | result |
|---|---|---|
| `eesd` formats via the shared signed entry point | `div_euclid(86_400) + 1` | `types::tests::test_epoch_to_rfc3339_roundtrip` FAILED |
| the Euclidean split is load-bearing for pre-epoch instants | replace with truncating `/` and `%` | `signed_epochs_agree_with_unsigned_and_handle_pre_epoch_instants` FAILED |
| the `u64` path still goes through the shared calendar conversion | `days + 719_469` in `civil_from_days` | `known_instants_round_trip` FAILED |

**The harness caught its own bug on the first attempt**, which is worth recording because it is the exact
failure mode the project's revert lesson names: claim 1 first came back `NOT_RUN`, not `GREEN`. The cause was
a **wrong target flag** — `eesd` is `[[bin]]`-only with no `[lib]`, so `cargo test --lib` matched nothing and
the run reported zero tests. Treating that as inconclusive rather than as "the test is decorative" is what
stopped a pointless rewrite of a test that was fine; re-run with `--bin nextgcore-eesd`, it bit.

## Ceiling

`eesd`'s `parse_rfc3339_to_epoch`, `days_from_civil` and `civil_from_days` remain in `types.rs`: the parser
is out of scope (above) and the two calendar helpers still serve it. So `eesd` still holds a second
`civil_from_days`, identical to the one now in the shared module. Migration 5 is the right place to remove
it, once the parser question is settled — deleting it now would leave the parser calling into the shared
module for one half of its arithmetic and its own code for the other.
