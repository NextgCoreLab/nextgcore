# RFC 3339 migration 1 of 5: `nrfd` onto `nextgcore_sbi::datetime`

Verified against `main` @ `4ec257a`. First of the five per-daemon migrations the shared-module task
enumerates. `nrfd` is taken first because it held **both** functions and because the shared module was
derived from its copies, so this is the one migration with no behavioural question at all.

No issue number: this is the tracked follow-up from PR #239 (#94), which created
`libs/nextgcore-sbi/src/datetime.rs` as the canonical home and deliberately left the six pre-existing
copies in place.

## The two copies removed

| copy | signature | verdict |
|---|---|---|
| `main.rs:2001` `epoch_to_rfc3339` | `fn(u64) -> String` | semantically identical to the shared one |
| `main.rs:2070` `rfc3339_to_epoch` | `fn(&str) -> Option<u64>` | **character-for-character** the shared one's algorithm |

`rfc3339_to_epoch` needs no argument: the shared module's body is this function, moved. The doc comment in
`datetime.rs` even says so ("the same reasoning nrfd's copy records").

`epoch_to_rfc3339` differs in exactly one way, and it is not a behavioural one: `nrfd` typed the
civil-days intermediates (`doe`, `yoe`, `doy`, `mp`, `d`) as `i64` where the shared module casts to `u64`.
Since the input is `u64`, `days = secs / 86400 >= 0`, so `z = days + 719468 > 0`, `era >= 0` and
`doe ∈ [0, 146096]` — every intermediate is non-negative and the two typings compute the same values. The
migration is therefore behaviour-preserving, and that is asserted rather than assumed: `nrfd`'s existing
golden-literal tests (`epoch_to_rfc3339(0) == "1970-01-01T00:00:00Z"`,
`epoch_to_rfc3339(1_700_000_000) == "2023-11-14T22:13:20Z"`) pass unchanged against the shared
implementation.

## Why this matters rather than being tidiness

These are **wire** timestamps: `validityTime` on an `Nnrf_NFManagement` subscription (`main.rs:1936`,
`:1897`, `:2120`). A leap-year or offset bug fixed in one copy stays broken in the other five. `nrfd` was
also the only daemon holding *both* directions, so it was the only place where a format/parse asymmetry
could be introduced and still round-trip locally.

## Verification

Workspace: **5938 passed / 0 failed** over two consecutive runs — unchanged from the `main` baseline, which
is the point: no test was added or removed and none changed behaviour. `cargo clippy --workspace` and
`cargo fmt --all -- --check` clean.

**Revert-verification for a migration is a different question**, and the task flags exactly why: "a
timestamp change cannot be caught by a round-trip test that formats and parses with the same code". A
round-trip through both shared functions would pass even if both were wrong in mirrored ways. So the claim
tested here is not "the arithmetic is right" (`datetime.rs`'s own golden-instant tests cover that) but
**"nrfd's call sites now reach the shared code"** — because the failure mode of a botched migration is a
leftover private copy still being used, which every test would pass over silently.

Both directions were reverted **inside the shared module** and `nrfd`'s tests were confirmed to bite:

| claim | revert applied to `datetime.rs` | result |
|---|---|---|
| `nrfd`'s formatting comes from the shared module | `days = secs / 86_400 + 1` (off by one day) | `test_nrfd_08_epoch_to_rfc3339` **FAILED** |
| `nrfd`'s parsing comes from the shared module | make the zone-strip always fail | `nrfd`'s parse tests **FAILED** |

Each revert was checked for a unique anchor, for compiling, and for the named test actually running before
its result was trusted.

## Note for the migration that follows

`nrfd`'s tests at `main.rs:5801` and `:5805` assert that `rfc3339_to_epoch` **rejects** `+02:00` and
`-05:00`. That matches the shared module's current, deliberately strict behaviour. The **`bsfd` migration
(5 of 5) changes it**: `bsfd`'s copy does not merely fail to reject a non-UTC offset, it correctly
*applies* it — so the shared module gains offset handling and these two assertions will need inverting,
with a comment recording the flip. Flagged here so the change is not a surprise when it lands, and so
nobody "fixes" those assertions in isolation.

## Ceiling

Nothing new is tested. The claim is "behaviour is unchanged and the shared code is now the one that runs",
and both halves are established by existing golden-literal tests plus the two reverts above — not by a new
test, which for a pure redirect would only restate what the reverts already prove.
