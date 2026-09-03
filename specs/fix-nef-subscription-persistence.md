# nextgcore #192 (NEF): monitoring subscriptions and triggering transactions survive a restart

Verified against `main` @ (post-#196).

Ships `Refs #192` — the NEF member. PCF and NWDAF remain; BSF was removed from that
issue's scope after it turned out to already have a MongoDB-backed store (see the
#192 comment and #196).

## The defect

`nefd`'s two northbound maps — TS 29.122 §5.3 Monitoring Event subscriptions and
§5.10 Device Triggering transactions — were in-memory only. The module doc said so
plainly: *"All state is in-memory (`RwLock<HashMap<..>>`); persistence is out of
scope."*

The consequence is more visible than for most NFs: **NEF consumers are external
AFs**. After a restart an AF's subscription resource 404s and its notifications
simply stop, with no termination signal it could act on, so the dangling state sits
outside the operator's network.

## The change

Adopts `nextgcore-core`'s `StateStore` (added in #190) — the `StateStore` type
rather than the `read_snapshot`/`write_snapshot` free functions, exactly as #192's
own guidance says: `StateStore` enforces "never overwrite a snapshot you could not
read" internally, and a new adopter has no reason to take that obligation on by
hand. The free functions exist only because the four pre-existing NFs each had their
own `state_path` field with 17–18 references.

* The four persisted types gained `Serialize`/`Deserialize`. All fields were already
  plain (`String`, `Option<SouthboundRef>`), so no manual codec was needed.
* `snapshot` / `restore_from` / `persist` on `NefContext`, with `persist` called from
  the three mutation points: `subscription_insert`, `subscription_remove`,
  `transaction_insert`.
* `--state-file` plus `NEXTGCORE_NEF_STATE_FILE`, matching the precedence the other
  NFs use: the flag wins, and an empty value is treated as unset rather than as a
  path.
* Restored **before** the SBI server can accept a subscription, so a restored record
  is never shadowed by a fresh one.

### Two details that would have been bugs

**The write guard must drop before persisting.** `persist` → `snapshot` takes a
*read* lock on the same map, and `std::sync::RwLock` is not reentrant — holding the
write guard across the call deadlocks. Each mutation therefore scopes its guard and
persists after. This is the rule udrd's store header already documents ("every
accessor copies data out and drops the guard before any other lock").

**Removals are persisted too.** Persisting inserts but not removals is the subtler
half: the resource would be **resurrected** at the next boot and the NEF would resume
forwarding notifications for a subscription the AF had explicitly deleted. bsfd had
exactly this shape on its DB-delete path (#196), which is what prompted checking for
it here.

## Verification

* `subscriptions_and_transactions_survive_a_restart` — round-trips both maps through
  a real file across a fresh context, and specifically asserts the `southbound`
  reference survives. That field is the one that matters most: without it the NEF
  cannot tear down the producer-side subscription when the AF deletes its own.
* `a_deleted_subscription_is_not_resurrected_by_a_restart` — the removal half.
  **Revert-verified:** dropping the `persist()` from `subscription_remove` fails
  exactly this test.
* `a_corrupt_snapshot_fails_startup_and_survives` — an unreadable snapshot is an
  error at startup, not a silent empty boot, and the file is left intact.
* `without_a_state_file_nothing_is_persisted` — the shipped memory-only default is
  unchanged.

Workspace **5674 passed / 0 failed**, `cargo test` exit 0. fmt clean; `cargo clippy
--workspace --all-targets` 0 errors.

**Not verified:** no `nefd` process was restarted — the tests exercise `NefContext`
across a real file, not the binary across a real restart, and CI skips the Docker
E2E that could do the latter. The startup wiring in `main.rs` is covered by reading,
not by execution.

## Definition of done

- [x] Subscriptions and transactions reload at boot from the configured snapshot.
- [x] A deleted subscription is not resurrected.
- [x] Memory-only default byte-identical when no state file is configured.
- [x] An unreadable snapshot fails startup and is not overwritten.
- [ ] PCF and NWDAF — still open on #192.
