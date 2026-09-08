# RFC 3339 migration 2 of 5: `udmd` onto `nextgcore_sbi::datetime`

Verified against `main` @ `4ec257a`. Second of the five per-daemon migrations; follow-up to PR #239 (#94),
which created `libs/nextgcore-sbi/src/datetime.rs` and deliberately left the six pre-existing copies alone.

## The copy removed

`bins/nextgcore-udmd/src/notify.rs:133`, `pub fn epoch_to_rfc3339(secs: u64) -> String`.

**Byte-identical** to the shared module's function — the shared module was derived from this one, down to
the `Howard Hinnant's civil_from_days` comment and the multi-line `format!`. So there is no behavioural
question and no signature question. `notify.rs` now carries
`pub use nextgcore_sbi::datetime::epoch_to_rfc3339;` in its place, which keeps `udmd`'s public surface
unchanged (the function was `pub` and is re-exported through `lib.rs`'s `pub mod notify`) while making the
shared module the single implementation.

## Why this matters rather than being tidiness

The timestamp goes on the wire: it is the `timeStamp` of a `#83` Nudm_SDM Data Change Notification /
Nudm_EE Event Occurrence report (`notify.rs:204`). A subscriber compares it against its own clock, so a
leap-year error here is an interop defect — and fixing it in one of six copies would leave the other five
wrong.

## Verification

Workspace: **5938 passed / 0 failed** over two consecutive runs, unchanged from the `main` baseline. No test
added or removed; `udmd`'s existing golden literals (`epoch_to_rfc3339(0)`, `1_000_000_000`, and the
`2024-02-29` leap day at `notify.rs:404`) now exercise the shared implementation and still pass.
`cargo clippy --workspace` and `cargo fmt --all -- --check` clean.

**Revert-verified.** As in migration 1, the claim under test is not the arithmetic (`datetime.rs` has its
own golden instants) but that `udmd`'s call sites and tests now *reach* the shared code — the failure mode of
a botched migration being a leftover private copy that every test silently passes over. Reverting the shared
formatter to `days = secs / 86_400 + 1` made `notify::tests::epoch_to_rfc3339_formats_utc` **FAIL**; the
revert was confirmed to have a unique anchor, to compile, and to have actually run that named test.

## Ceiling

Nothing new is tested — this is a pure redirect, and a new test would only restate what the revert proves.
`udmd`'s leap-day literal is the strongest existing assertion and it is now anchored to the shared code.
