# nextgcore #192 (PCF): policy associations and app sessions survive a restart

Verified against `main` @ `59fb9e3`.

The **last member of #192**. NEF landed in #197, NWDAF in #198, and BSF was removed from the
issue's scope after turning out to have a MongoDB-backed store already (#196). This closes
the issue.

## The defect

`pcfd` holds every consumer-facing policy association in memory only, so #192's wording
applies directly: *"a restarted PCF cannot answer updates or deletes for live
associations."* An AMF holding an AM policy association URI, or an SMF holding an
`sm-policies/{smPolicyId}` URI, gets a 404 on its next update — and the SMF cannot even
tear the session's policy down cleanly.

## The hazard count is higher than #192's note assumed

The task note said "8+ maps, four secondary indexes, and a u64 ID allocator". Verified
against the code, it is **11 maps, seven secondary indexes, and four allocators**:

| | field | derivable from |
|---|---|---|
| primary | `ue_am_list: HashMap<u64, PcfUeAm>` | — |
| primary | `ue_sm_list: HashMap<u64, PcfUeSm>` | — |
| primary | `sess_list: HashMap<u64, PcfSess>` | — |
| primary | `app_list: HashMap<u64, PcfApp>` | — |
| index | `supi_am_hash` | `ue_am_list` (`supi` → id) |
| index | `association_id_hash` | `ue_am_list` (`association_id` → id) |
| index | `supi_sm_hash` | `ue_sm_list` (`supi` → id) |
| index | `sm_policy_id_hash` | `sess_list` (`sm_policy_id` → id) |
| index | `ipv4addr_hash` | `sess_list` (`ipv4addr` ≠ 0 → id) |
| index | `ipv6prefix_hash` | `sess_list` (`ipv6prefix_string` → id) |
| index | `app_session_id_hash` | `app_list` (`app_session_id` → id) |

Allocators: `next_ue_am_id`, `next_ue_sm_id`, `next_sess_id`, `next_app_id` — all
`AtomicUsize::new(1)`.

## Decision 1: indexes are REBUILT, never persisted

Only the four primary lists go in the snapshot. All seven indexes are derived on restore.

This is not just a size saving. A persisted index can **disagree** with its primary list —
after a schema change, or a snapshot written while a mutation was in flight — and a
disagreeing index is worse than a missing one: `sess_find_by_sm_policy_id` would return a
stale id that resolves to a *different* session, or to nothing while the session is right
there. Deriving makes disagreement impossible by construction, which is the same
one-source-of-truth argument that made the NWDAF token codec delegate rather than duplicate.

This is also exactly what #192's BSF criterion demands and generalises: *"a restored binding
is discoverable by the same query that found it before the restart — restoring the map is
not enough if the lookup index is rebuilt separately."* Here **all six lookup paths** are
asserted post-restore, not just the primary-key one.

## Decision 2: all four allocators are lifted above the restored maximum

This is the #191-class hazard the task flagged, ×4. `next_ue_am_id` restarts at 1, so the
first new AM association after a restart is allocated id 1 — which a restored record already
occupies. `ue_am_list.insert(1, ..)` then **silently replaces the restored association**,
and `supi_am_hash`/`association_id_hash` are left pointing at a record for a different
subscriber. That is not data loss; it is data *substitution*, and nothing logs it.

The counters are persisted **and** recomputed: on restore each becomes
`max(persisted_counter, max_restored_id + 1)`. Persisting alone trusts a value that could
predate the records; recomputing alone would reuse the ids of deleted records. Taking the
maximum of both is correct under either failure and costs nothing. Reusing a deleted
record's id would in fact be harmless — these are internal pool handles and the wire uses
the UUID fields (`association_id`, `sm_policy_id`, `app_session_id`) — but "harmless as far
as I can see" is not the standard for an allocator.

## Decision 3: `snapshot` takes one lock at a time

`context.rs` already carries **six documented AB-BA lock-inversion fixes**, each a comment
explaining which pair deadlocked and why the canonical order is primary-list-first. Adding a
function that holds four write-adjacent read guards at once would be reckless in that file.

So `snapshot` acquires each primary list **individually**, clones out, and drops the guard
before taking the next. It therefore holds at most one lock at any instant and **cannot
participate in any deadlock cycle**, whatever the mutators do. The cost is that the snapshot
is not a single atomic instant across all four lists — acceptable, because every mutation
persists immediately afterwards, so the next write reconciles any skew, and the alternative
risks wedging the NF.

The guard-drop rule from #197/#198 applies with more force here: mutators hold up to **five**
write guards, and `persist` → `snapshot` takes read locks on the same maps. `std::sync::RwLock`
is not reentrant, so every mutation scopes its guards and persists after they drop.

## Decision 4: enum representation, split by whether a codec already exists

Same rule as #198, applied to a tree where both cases occur:

* `AccessType`, `RatType`, `PduSessionType` have **no existing wire codec anywhere in
  pcfd** (grep for `"3GPP_ACCESS"`, `"IPV4V6"`, `"EUTRA"` finds nothing). The snapshot is
  their first serialised surface, so `#[serde(rename)]` with the TS 29.571 tokens creates
  the *only* table — no duplication is possible.
* `FlowStatus` **does** have one (`from_wire`/`as_wide` per TS 29.514/29.512), so it gets a
  hand-written `Serialize`/`Deserialize` that **delegates**, exactly as `AnalyticsId` does in
  nwdafd. Adding renames beside an existing table is how the two drift.

Struct field names use derive defaults. Unlike variant names, these are the identifiers the
code already reads and writes; `AfPccRule::to_json` remains responsible for the TS 29.512
*wire* shape, and the two surfaces are deliberately separate.

## Not persisted

* **`AnalyticsState` / `AnalyticsPolicyEngine`** — live in `intent_loop.rs`, not in
  `PcfContext`, and are recomputed from NWDAF queries.
* **`UavPolicyAuthorization`** — built per request in `app.rs` from config.
* **`EnergyAwarePolicy`, `UrspSubscriptionData`** — no users outside `context.rs` at all;
  dead, filed rather than deleted (same call as nwdafd's `DataSource`).
* `max_num_of_ue`, `max_num_of_sess`, `initialized` — configuration, not state.

## Why there is no deferred flush here (unlike #198)

NWDAF needed one because its dispatcher rewrote the store per subscription per tick. PCF has
**no periodic sweep**: every mutation is a consumer request (create/update/delete an
association, session or app session), so one persist per request is O(1) per request, not
O(N) per tick. All twelve mutators persist synchronously, which is also what the answered
201/204 requires.

## Verification plan

* `associations_survive_a_restart` — all four lists round-trip, with the nested trees
  asserted (`ursp_rules`, `af_pcc_rules`, `subscribed_default_qos`, `binding`).
* `every_lookup_index_is_rebuilt_after_a_restart` — the #192 BSF criterion generalised: all
  six lookups (`by_supi` ×2, `by_association_id`, `by_sm_policy_id`, `by_ipv4addr`,
  `by_ipv6addr`, `by_app_session_id`) find the restored record.
* `id_allocators_do_not_collide_with_restored_records` — the substitution bug: allocate
  after a restore and assert nothing restored was replaced. One case per allocator.
* `the_on_disk_enum_representation_is_the_ts_29571_token`.
* `a_committed_fixture_snapshot_still_loads`.
* `a_deleted_association_is_not_resurrected_by_a_restart`.
* `a_corrupt_snapshot_fails_startup_and_survives`.
* `without_a_state_file_nothing_is_persisted`.
* `fini_cannot_overwrite_a_good_snapshot_with_an_empty_one`.

## Verification (actual)

Ten new tests. Workspace **5706 passed / 0 failed**, `cargo test --workspace` exit 0, no
compile errors (checked for `^error`, not only for a `test result:` line). `cargo fmt --all
--check` clean; `cargo clippy --workspace --all-targets` exit 0 with no warning in pcfd.

**Revert-verified (four claims, each by making the change and watching the named test fail):**

| revert | test that fails |
|---|---|
| drop the allocator lift from `restore_from` | `id_allocators_do_not_collide_with_restored_records` — *"UE AM id collided with a restored one"* |
| drop one index rebuild (`sm_policy_id_hash`) | `every_lookup_index_is_rebuilt_after_a_restart` — *"the SMF's resource URI resolves through this"* |
| remove `StateStore::disabled()` from `fini` | `fini_cannot_overwrite_a_good_snapshot_with_an_empty_one` |
| drop `persist()` from `sess_remove` | `a_deleted_association_is_not_resurrected_by_a_restart` — *"the session removal must reach disk by itself"* |

The removal test checks each removal **on disk immediately**, not only after the restart —
the lesson from #198, where two removals in one test covered for each other because a
full-store persist rewrites what the other deleted.

**A fixture bug caught by the tests.** The committed fixture's `ipv4addr` was
`170995719`, which is `10.49.48.7`, not the `10.45.0.7` its sibling `ipv4addr_string` said
(the correct u32 is `170721287`). The index was therefore rebuilt under one key while the
lookup parsed another, and `every_lookup_index_is_rebuilt_after_a_restart` caught it. Worth
noting because it is the exact failure mode the *code* is designed to prevent — a
denormalised pair disagreeing — reproduced by hand in a test fixture.

**Not verified:** no `pcfd` process was restarted; the tests exercise `PcfContext` across a
real file, not the binary across a real restart, and CI skips the Docker E2E. The
one-lock-at-a-time claim for `snapshot` is a structural argument from reading, not a
concurrency test — pcfd has no deadlock test harness, and the existing AB-BA fixes in this
file are likewise comment-documented rather than test-pinned.

## Definition of done

- [x] `--state-file` + `NEXTGCORE_PCF_STATE_FILE`, flag wins, empty treated as unset
- [x] All four primary lists reload at boot; all seven indexes rebuilt
- [x] Every lookup path finds a restored record
- [x] No allocator can collide with a restored id
- [x] Deleted associations are not resurrected
- [x] Memory-only default byte-identical when no state file is configured
- [x] Unreadable snapshot fails startup and is not overwritten
- [x] Documented in `docs-book/src/configuration/pcf.md` and `overview.md`
- [x] **#192 closes**

## Follow-ups

* `EnergyAwarePolicy` and `UrspSubscriptionData` in `context.rs` have no users outside that
  file — dead, like nwdafd's `DataSource`. Filed rather than deleted, since removing public
  API is a separate change from adding persistence.
* The state file is not wired into `docker/rust/docker-compose.yml`, matching nefd and
  nwdafd; only udrd is on by default there (#194). #192's criteria ask for the flag and the
  docs, not the default.
