# nextgcore #66 (part 1): one NF state store, and a corrupt snapshot that destroyed itself

Verified against `main` @ `e78e0c1`.

Ships `Refs #66` — criteria **1, 6, 7** plus a data-loss defect the issue does not
mention. **#66 stays OPEN**; the per-NF persistence members are named below and
should be filed separately, which the issue's own suggested approach invites
("Land per-NF persistence independently (each NF is separately shippable)").

## What the issue got wrong, and what that revealed

#66 says UDR is "the one NF with a durable store". Against current `main` that is
false: **four** NFs already have one —

| NF | file | shape |
|---|---|---|
| nrfd | `nnrf_handler.rs` | `snapshot` / `persist` / `load` / `write_atomic` |
| nssfd | `context.rs` | identical |
| udrd | `data_store.rs` | identical |
| nsacfd | `context.rs` | `save_state` / `load_state`, offloaded via `spawn_blocking` |

`write_atomic` was **byte-for-byte identical in three files**. So were `persist`
and `load`, bar the NF name in the log line. That is the same shape as the `--kill`
flag duplicated across twelve daemons, and it had the same consequence: one defect,
present in all four copies.

## The defect

**A corrupt snapshot was treated as "no state".**

```rust
let doc = match serde_json::from_str(&content) {
    Ok(v) => v,
    Err(e) => {
        log::warn!("UDR state file {} is not valid JSON: {e}", path.display());
        return;                     // <- store stays EMPTY, boot continues
    }
};
```

Boot then proceeds with an empty store, and the very next mutation calls
`persist()` — which rewrites the file from that empty snapshot. `udrd` has five
such call sites (`data_store.rs:346–387`); any one of them makes the loss
permanent.

So a truncated write, a container killed mid-rename, or a half-mounted volume
means:

* the UDR comes up with **zero** subscriber registrations — every
  `amf-3gpp-access` and `smf-registration` gone;
* the NRF comes up with an **empty NF registry**;
* and the first write destroys the operator's only recoverable copy.

The process that failed to read the file deletes the evidence that it failed.

This is the same class as the load-or-create defect fixed in #184 (a malformed
signing key must not be silently regenerated) — and worse, because here the
overwrite is what destroys the data.

## The fix

`nextgcore-core`'s new `state_store` module is the single implementation, and it
distinguishes three cases rather than two:

| file | meaning | behaviour |
|---|---|---|
| absent | first boot / disabled | empty, persisting enabled |
| present, valid | normal restart | restored, persisting enabled |
| present, **invalid** | a human must look | empty, **persisting REFUSED** |

Each of the four NFs gained a `state_unreadable` flag set when its load fails;
while set, `persist` logs an error naming the consequence and writes nothing, so
the unreadable file survives. `AtomicBool` because `persist` takes `&self` (these
stores live behind `OnceLock`/`RwLock`).

Three incidental fixes came with consolidating:

* **fsync.** The old writer did `write` + `rename` with no flush, so "atomic" meant
  well-ordered, not durable — a crash after the rename could leave the new name
  pointing at unflushed content, i.e. exactly the corruption above. Now the temp
  file is flushed and fsynced, and the parent directory is synced so the rename
  itself survives.
* **`0600`.** These snapshots were world-readable. The UDR's is keyed by IMSI.
* **Temp-file collision.** `Path::with_extension("tmp")` *replaces* the extension,
  so `udr.state` and `udr.json` in one directory both wrote `udr.tmp`. The shared
  writer derives `.<full-file-name>.tmp` instead.

nsacfd keeps its `spawn_blocking` offload — that is a deliberate choice to avoid
stalling a tokio worker on disk I/O, and forcing it onto the synchronous helper
would have regressed it. Only the inner write was swapped.

## Why free functions rather than making every NF own a `StateStore`

Each NF's context has 17–18 references to its `state_path` field, so replacing the
field wholesale was a wide, risky refactor across four files. `read_snapshot` /
`write_snapshot` let each NF keep its existing shape and gain the fix in a handful
of lines. `StateStore` remains the richer entry point, with the poison guard
enforced internally, for NFs that adopt persistence next.

The trade-off is explicit in the docs: `write_snapshot` cannot enforce the poison
guard (it holds no state), so its contract says the caller must not call it after a
failed read — and each of the four callers now honours that with its own flag.

## Verification

Five tests in `state_store` cover the mechanism: disabled store is inert; absent →
round trip, with `0600` asserted; **a corrupt snapshot is never overwritten**; a
directory-where-a-file-is-expected poisons rather than looking absent; sibling
state files do not collide on temp names.

One test at the UDR level (`a_corrupt_state_file_is_not_destroyed_by_the_next_write`)
proves the *wiring*, not just the mechanism — that this store really routes
through the guard. The shared test would pass even if udrd had not been migrated.

**Revert-verified twice:** removing the poison check from `StateStore::persist`
fails the shared test; removing udrd's `state_unreadable` guard fails the UDR-level
one.

## Deliberately NOT here — the rest of #66

This delivers the shared abstraction (criterion 1), the flag-gated memory-only
default (criterion 6) and documentation (criterion 7). Outstanding:

* **Criterion 2 — SMF.** PFCP sessions, policy bindings and the IPv4 pool are
  memory-only with no store at all. The largest single piece, and the one the issue
  ranks second.
* **Criterion 3 — UDR persistence on by default** in the shipped Docker/E2E config.
  Cheap, and the issue calls UDR "the most severe member". Deliberately not bundled:
  turning it on means choosing a writable snapshot path in the container and the
  k8s/Helm manifests, which is a deployment decision rather than a code one.
* **Criterion 4 — PCF/BSF bindings and NWDAF/NEF subscriptions** reload at boot.
  Four NFs, none of which has a store today; `state_store` is now the pattern to
  adopt.
* **Criterion 5 — restoration signalling** (TS 23.527, TS 29.244 §5.22): emit
  status/termination notifications for resources that cannot be recovered. This is
  protocol work, not persistence work, and is the least related to this change.

## Definition of done (this PR)

- [x] One shared durable-snapshot implementation; three byte-identical copies and
      one variant removed.
- [x] A corrupt or unreadable snapshot is never overwritten; the file survives.
- [x] Writes are fsynced, `0600`, and cannot collide on temp names.
- [x] Memory-only default preserved exactly when no state file is configured.
- [x] Documented, with the three-case table.
- [ ] Per-NF persistence for SMF / PCF / BSF / NWDAF / NEF, UDR default-on, and
      restoration signalling — filed separately.
