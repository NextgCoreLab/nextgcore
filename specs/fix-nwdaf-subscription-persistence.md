# nextgcore #192 (NWDAF): analytics and ML-provision subscriptions survive a restart

Verified against `main` @ `bd90166` (post-#197).

Ships `Refs #192` — the NWDAF member. PCF is the last one left; NEF landed in #197 and
BSF was removed from the issue's scope after turning out to already have a
MongoDB-backed store (see the #192 comment and #196).

## The defect

`nwdafd` holds every consumer-facing subscription in memory only:

| map | TS 29.520 resource | lost on restart |
|---|---|---|
| `analytics_subscriptions` | `NnwdafEventsSubscription` (`eventSubscriptions[]`) | the whole subscription |
| `ml_prov_subscriptions` | `NwdafMLModelProvSubsc` | the whole subscription |
| `event_levels` | THRESHOLD edge state (nwafd-07) | the "previously observed level" |

The consumer-visible consequence is #192's own wording: *notifications simply stop
with no termination signal*. A consumer that subscribed successfully holds a resource
URI which now 404s, and because the NWDAF drives closed-loop automation the silence
is indistinguishable from "nothing to report".

`event_levels` is the subtler one. `threshold_crossed(prev=None, ..)` fires whenever
the current level is already past the threshold
(`notification_dispatcher.rs:threshold_crossed`), so losing the edge state means a
restart **re-fires every THRESHOLD subscription whose measured instance is already
above its threshold** — a duplicate alarm that reads as a real new crossing.

## The on-disk representation is the actual decision

Persisting NEF was mechanical because its persisted fields were opaque `String`s.
NWDAF's tree contains domain enums, so `derive(Serialize)` *chooses a compatibility
surface*: the snapshot format is read back by a later build, and `StateStore` refuses
to overwrite a snapshot it cannot parse (#190), so a representation that changes
between builds does not reset quietly — **the NF fails startup after an upgrade.**

### What is actually in the derive chain

Smaller than #192's own note assumed. `EventSubscription.matching_dir` is
`Option<String>`, not `MatchingDirection`, so the matching-direction enum is **not**
reachable from the persisted tree and needs no codec. Six types, two of them enums:

| type | codec |
|---|---|
| `AnalyticsId` (25 variants) | **manual**, delegates to `as_str`/`from_str` |
| `NotificationMethod` (2 variants) | **manual**, delegates to `as_str`/`from_wire` |
| `SNssai` | derive (`sst`, `sd` — field names already the TS 29.571 spelling) |
| `EventSubscription` | derive |
| `AnalyticsSubscription` | derive |
| `MlProvSubscription` | derive |

### Decision: spec tokens, emitted by the existing wire codec

The two enums serialise as their **TS 29.520 tokens** (`NF_LOAD`, not `NfLoad`;
`PERIODIC`, not `Periodic`), because the spec text is the stable contract and the
Rust identifiers are ours to rename.

They get a **hand-written `Serialize`/`Deserialize` that calls `as_str` / `from_str`**
rather than 25 `#[serde(rename = "…")]` attributes. Attributes would create a second,
independent copy of the token table, and nothing would catch it drifting from
`as_str` — `test_analytics_id_token_round_trip` only exercises `as_str`/`from_str`.
Delegating makes the on-disk token *definitionally* the wire token: one table, and
the existing yaml-pinned test guards it. (This is the repo's own
count-the-implementations lesson applied before the duplication exists rather than
after.)

`AnalyticsId` serialises via `as_str` (`NwdafEvent`), **not** `as_event_id`
(`EventId`). Two reasons: `as_event_id` is partial — `PFD_DETERMINATION` has no
`EventId` spelling, so it could not be encoded at all — and both persisted sites
(`eventSubscriptions[].event`, `mLEventSubscs[].mLEvent`) are typed `NwdafEvent`
upstream anyway.

### The document is versioned and a newer one is refused

`{"version": 1, …}`. An unknown (newer) version **fails startup** instead of
restoring what it recognises, because restoring partially and then persisting would
rewrite a newer-format file in the older format — the same destroy-the-evidence shape
#190 exists to prevent, arrived at by downgrade rather than corruption.

### Absent members default; identity members do not

The realistic future break is not a renamed token but an *added field*: an old
snapshot read by a new binary fails `missing field` per record, and `restore_from`
skips records individually, so every subscription would be dropped with only a
`warn` per record. Optional/derived/counter fields therefore carry
`#[serde(default)]`; identity and semantic fields (`subscription_id`,
`notification_uri`, `event`, `active`, `expiry`, `notification_correlation_id`) stay
required, because a record missing one of those is not recoverable data. A comment on
each struct states the rule for whoever adds the next field.

## Write amplification: the dispatcher does not persist per subscription

Nine mutation points, split by whether the caller has already promised the consumer
something:

**Synchronous persist** (consumer-visible resource lifecycle — the 201/204 has been
answered, so it must be durable before the response): `add_subscription`,
`update_subscription`, `remove_subscription`, `add_ml_prov_subscription`,
`update_ml_prov_subscription`, `remove_ml_prov_subscription`.

**Mark dirty, flushed once per dispatcher tick**: `update_subscription_last_notification`,
`mark_subscription_terminated`, `mark_ml_prov_notified`, `set_event_level`.

The reason is arithmetic. Those four are called *per subscription per tick* from
`dispatch_notifications`, and `StateStore::persist` rewrites the whole store with two
`fsync`s. At the shipped `--max-subscriptions 1024` a synchronous persist per call
rewrites a ~500 KB store up to 1024 times per 30 s tick — half a gigabyte of writes
and ~2000 `fsync`s to record counter bumps. `dispatch_notifications` therefore calls
`flush_state_if_dirty()` once at the end of the tick.

The durability window this opens is bounded by one tick (30 s default) and so is its
worst case: a crash inside the window can repeat one notification or let one
subscription exceed `maxReportNbr` by the reports in that tick. It cannot resurrect a
deleted subscription, which is the failure that must not happen — that path persists
synchronously. Because the dispatcher ticks unconditionally, a future call site that
forgets to flush is still covered by the next tick.

`set_event_level` has a second reason to be deferred: it is called from
`build_event_notifications` while the engine mutex is held, and `persist` → `snapshot`
takes read locks on both subscription maps. Persisting there would introduce an
engine-mutex-then-map ordering against the documented context-read-then-engine order.

## Deliberately not persisted

* **`nrf_status_subscription`** — the NWDAF's *own* NFStatusSubscribe subscription at
  the NRF. Restoring it is actively harmful: `maybe_renew_nrf_subscription` treats
  `validity_unix: None` as "nothing to renew", so a restored record would make the
  NWDAF believe it has a live collector channel it does not have, and NF_LOAD data
  collection — the only live analytics path in this build — would silently never
  re-establish. Re-subscribing at boot instead leaks at most one NRF-side
  subscription, bounded by its own `validityTime`. This answers #192's "re-validate a
  restored subscription at boot?" question for the *outbound* direction; inbound
  consumer subscriptions are restored optimistically, matching NEF, since TS 23.527
  defines no re-validation handshake and a consumer's resource URI must keep working.
* **`data_sources`** — `add_data_source` has no non-test caller anywhere in the
  binary, so the map is always empty at runtime. Persisting it would snapshot
  nothing. Filed separately rather than deleted here.
* **`engine` samples** — a bounded rolling sample window, rebuilt from NRF
  notifications within a tick or two.
* **`sensing_results`** (`--features sensing`) — an explicitly bounded, lossy 6G
  telemetry ring.

## Two traps carried over from #197, both real here

**The write guard must drop before persisting.** `persist` → `snapshot` takes a read
lock on the same maps and `std::sync::RwLock` is not reentrant, so holding the write
guard across the call deadlocks. Every mutation scopes its guard and persists after.

**Removals are persisted.** Otherwise a deleted subscription is resurrected at the
next boot and the NWDAF resumes POSTing analytics to a consumer that explicitly
unsubscribed.

**And one that is new here:** `fini()` clears every map, and the dispatcher is a
detached task that can tick during shutdown. `fini()` therefore
`StateStore::disabled()`s the store *before* clearing, so an emptied context can
never be written over a good snapshot.

## Verification

* `subscriptions_survive_a_restart` — both maps plus `event_levels` round-trip
  through a real file into a fresh context; asserts the nested tree specifically
  (`events[].event`, `notification_method`, `snssais`, `target_snssai`,
  `reports_sent`).
* `a_deleted_subscription_is_not_resurrected_by_a_restart` — the removal half, for
  both subscription kinds.
* `the_on_disk_enum_representation_is_the_ts_29520_token` — reads the persisted JSON
  and asserts the literal tokens `"NF_LOAD"` / `"PERIODIC"`, so a switch to Rust
  variant names fails here rather than at a customer's upgrade.
* `a_committed_fixture_snapshot_still_loads` — a snapshot literal committed *in the
  test source* restores fully. This is the only test that catches a representation
  change, because every other test writes and reads with the same build.
* `an_older_snapshot_missing_optional_members_still_loads` — the added-field case.
* `a_newer_snapshot_version_is_refused` — downgrade fails startup, file intact.
* `a_corrupt_snapshot_fails_startup_and_survives`.
* `without_a_state_file_nothing_is_persisted` — the shipped memory-only default.
* `a_threshold_does_not_refire_after_a_restart` — the `event_levels` half, asserted
  through `threshold_crossed` rather than through storage.
* `deferred_bookkeeping_is_written_by_the_tick_flush` — both halves: before the flush
  the file still holds the old counter (so the deferral is real, not accidental), and
  after it the counter survives a restart.
* `fini_cannot_overwrite_a_good_snapshot_with_an_empty_one`.
* `state_file_precedence_is_flag_then_env_and_empty_means_unset` — the precedence the
  docs claim. `resolve_state_file` was split out of `main` to make it testable without
  a process environment.

**Revert-verified (four claims, each checked by making the change and watching the named
test fail):** dropping `persist` from `remove_subscription`, or from
`remove_ml_prov_subscription`, fails `a_deleted_subscription_is_not_resurrected_by_a_restart`;
removing the `StateStore::disabled()` from `fini` fails
`fini_cannot_overwrite_a_good_snapshot_with_an_empty_one`; putting
`#[derive(Serialize, Deserialize)]` on `AnalyticsId` in place of the hand-written codec
fails `the_on_disk_enum_representation_is_the_ts_29520_token`.

**A green test that proved nothing, caught by that pass.** The removal test first passed
with the analytics `persist` deleted: the ML removal's `persist` rewrites the *whole*
store, which by then no longer held the deleted analytics subscription either, so one
removal covered for the other. Both are now asserted on disk immediately after each
removal. The same shape was latent in `subscriptions_survive_a_restart` — the
end-of-scope flush would have covered for both create paths — so that test now pins the
creates before the flush runs.

Workspace **5687 passed / 0 failed**, `cargo test --workspace` exit 0, no compile errors
(checked for `^error`, not only for a `test result:` line — a crate that fails to compile
emits no result line at all). `cargo fmt --all --check` clean; `cargo clippy --workspace
--all-targets` exit 0 with no warning in any file touched.

**Not verified:** no `nwdafd` process was restarted — the tests exercise `NwdafContext`
across a real file, not the binary across a real restart, and CI skips the Docker E2E
that could do the latter. The startup wiring in `main.rs` is covered by reading, not by
execution. The write-amplification figures are arithmetic from `write_atomic`'s
implementation, not measured.

## Definition of done

- [x] `--state-file` + `NEXTGCORE_NWDAF_STATE_FILE`, flag wins, empty treated as unset.
- [x] Analytics and ML-provision subscriptions reload at boot.
- [x] Deleted subscriptions are not resurrected.
- [x] On-disk enum representation is the TS 29.520 token, pinned by a fixture.
- [x] Memory-only default byte-identical when no state file is configured.
- [x] Unreadable snapshot fails startup and is not overwritten.
- [x] Documented in `docs-book/src/configuration/nwdaf.md` and `overview.md`.
- [ ] PCF — still open on #192.

## Follow-ups this turned up

* `DataSource` / `data_sources` in `context.rs` is dead: `add_data_source` has no
  non-test caller, so `get_data_sources` and `data_source_count` can only ever report
  an empty map. Not deleted here — removing public API is a separate change from adding
  persistence.
* The state file is not wired into `docker/rust/docker-compose.yml`, matching nefd
  (#197); only udrd is switched on by default there (#194). #192's criteria ask for the
  flag and the docs, not the default.
