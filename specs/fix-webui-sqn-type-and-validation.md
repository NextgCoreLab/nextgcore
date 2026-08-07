# Fix: WebUI writes SQN as a BSON String, breaking post-AKA maintenance

Resolves nextgcore #119.

## Problem

All cites verified against merged `main` (`36f0247`).

### 1. SQN type mismatch (the core bug)

`SecurityContext.sqn` is typed `String` (`bins/nextgcore-webui/src/main.rs:81`)
and serialised verbatim into BSON via `bson::to_document` (`main.rs:298`
create, `main.rs:310` update). The rest of the stack treats that field as a
64-bit integer:

- read: `security.get_i64(NEXTGCORE_SQN_STRING)`
  (`libs/nextgcore-dbi/src/subscription.rs:87`) — a String yields `Err`, so
  `auth_info.sqn` silently stays `0`;
- maintenance: `$inc: 32` then `$bit … "and": NEXTGCORE_MAX_SQN`
  (`subscription.rs:147-162`) — both are numeric-only Mongo operators and
  error against a String field.

The Node model gets it right (`webui/server/models/subscriber.js:26`,
`Schema.Types.Long`), so the two shipped UIs disagree on the same field.

TS 33.102 §6.3 makes SQN a 48-bit counter the home network advances per
successful authentication; TS 29.505 carries it as a `SequenceNumber` subject
to arithmetic maintenance. A String is not a counter.

**Impact:** a subscriber provisioned through the Rust WebUI cannot have its
SQN advanced. After the first authentication SQN_HE cannot move, which
de-synchronises AKA, causes repeated AUTS re-sync failures, and can block
attach. This is the replay protection of 5G-AKA.

### 2. Standalone WebUI defaults to the wrong database

`--db-name` defaults to `open5gs` (`main.rs:41`), while the dbi connection
falls back to `nextgcore` (`mongoc.rs:104-107`) and the seed script writes
`nextgcore` (`docs/assets/webui/mongo-init.js:5`). An operator running the
standalone UI without `--db-name` provisions into a database the UDR never
reads — presenting as "subscriber not found" after an apparently successful
create.

### 3. No server-side validation, and silent key corruption

`create_subscriber` only checks that `imsi` and `security.k` are non-empty
(`main.rs:216-218`). Worse, `nextgcore_ascii_to_hex` (`types.rs:434-447`)
`filter_map`s over 2-char windows, **silently dropping** any pair that is not
valid hex, then truncates to the buffer length. A malformed K is persisted
wrong with no diagnostic, and authentication then fails for no visible reason.

## Fix

1. **`sqn` becomes `i64`.** Serialises to BSON Int64, matching `get_i64` and
   the `$inc`/`$bit` maintenance path. A custom `Deserialize` accepts Int64,
   Int32, **and** String, so legacy documents carrying a String `sqn` still
   load rather than failing the whole read — the compat path is required, not
   optional, because the on-disk schema is already populated in existing
   deployments.
2. **Default `--db-name` to `nextgcore`**, agreeing with the dbi fallback and
   the seed. Asserted by a test against the dbi constant so the two cannot
   drift again.
3. **Validate on create and update**, returning HTTP 400 rather than writing:
   IMSI 5–15 digits, K and OPc/OP 32 hex chars, AMF 4 hex, SD 6 hex.
4. **`nextgcore_ascii_to_hex` gains a checked sibling.** A new
   `nextgcore_ascii_to_hex_checked` returns `Result` and rejects odd-length or
   non-hex input; the lenient function keeps its signature and delegates, so
   the 6 existing call sites are unchanged. Chosen over changing the existing
   signature because those call sites read already-persisted data where a hard
   error would turn a corrupt record into a failed read; validation belongs at
   the ingress, which is what (3) adds.

## Non-goals

- Migrating stored String `sqn` values. The compat deserialiser makes them
  readable; a coercion migration is a separate, gated operation and the issue
  explicitly says to split it.
- UI consolidation and wiring a UI into `docker-compose.yml` with auth/TLS
  (issue #118 territory, and port 3000 is already Grafana). Tracked separately.

## Verification

Tests in `bins/nextgcore-webui/src/main.rs` (the crate currently has none) and
`libs/nextgcore-dbi/src/types.rs`:

1. `sqn` serialises to `Bson::Int64` — asserts the stored BSON type, which is
   the actual defect.
2. A legacy document with `"sqn": "42"` (String) deserialises to `42i64`.
3. Int64 and absent-field cases both deserialise.
4. The WebUI's default db name equals the dbi fallback constant.
5. Validation rejects: short IMSI, non-digit IMSI, 31-char K, non-hex K,
   3-char AMF — and accepts a known-good subscriber.
6. `nextgcore_ascii_to_hex_checked` errors on odd-length and on non-hex input,
   and agrees with the lenient function on valid input.

Each new test must be verified to FAIL when its fix is reverted. Full
workspace `cargo test`, `cargo fmt --check` and CI-equivalent
`cargo clippy --workspace` must be clean.

### Revert-check results

Reverting each fix in isolation, so one change at a time is under test:

| Reverted | Tests that failed |
|---|---|
| `--db-name` back to `open5gs` | `default_db_name_matches_dbi_fallback` (1) |
| validation back to the non-empty check | `validation_rejects_malformed_{imsi,key,amf…,slice_sd}`, `validation_bounds_sqn_to_48_bits` (5) |
| compat deserialiser removed (field stays `i64`) | `legacy_string_sqn_deserialises`, `empty_string_sqn_is_zero` (2) |
| `nextgcore_ascii_to_hex_checked` delegating to the lenient fn | `test_ascii_to_hex_checked_rejects_malformed_input` (1) |

`validation_accepts_a_good_subscriber` correctly keeps passing under the
validation revert — it asserts the positive case.

**The `sqn: String` → `i64` change itself cannot be revert-tested
mechanically:** restoring the `String` type fails compilation in 9 places, so
there is no build in which the old behaviour and the new tests coexist. The
`i64`-dependent assertions (`sqn_serialises_as_bson_int64`,
`stored_sqn_is_readable_via_get_i64`) are therefore *type-enforced* rather than
revert-proven. That is weaker evidence and is stated rather than glossed: they
still pin the exact property `$inc`/`$bit` require, which is what the defect
was.

Not covered: a live create → `increment_sqn` → read round-trip needs a real
mongod, and this crate has no such harness. The BSON-type assertion is the
proxy — it pins the exact property `$inc` requires. Stated plainly rather than
claimed as integration coverage.
