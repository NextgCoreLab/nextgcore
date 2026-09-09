# nextgcore #191: smfd PFCP sessions, policy bindings and the IPv4 pool get a durable store

Verified against `main` @ `f019c75`.

Closes #191. Split out of #66 (criterion 2), which is already closed; the sibling
per-NF persistence issues are #192 (done) and #193 (restoration signalling, open).

## The defect

`smfd` held every resource whose lifetime spans a PDU session in in-memory
context maps with no durable store and no reload at boot:

* `pfcp_sessions: RwLock<HashMap<String, u64>>` (`context.rs`) — `sm_context_ref`
  → UPF SEID. Lost on restart, so the UPF holds N4 sessions the SMF can no longer
  modify or delete.
* `policy_bindings: RwLock<HashMap<String, PolicyBinding>>` — the PCF SM policy
  association, authorized QoS, the GSM FSM state and the EASDF DNS context id.
  Lost on restart, so a restarted SMF cannot terminate or update policy for a
  live session.
* `ipv4_pool: Ipv4Pool` — a 65536-bit bitmap plus a count. **This is the one with
  a correctness consequence beyond "state is gone".** Rebuilt empty, the very
  next `allocate()` returns `10.45.0.2` — an address a live UE still holds. That
  is address *substitution*, and nothing logs it.

Premise re-verified before starting: `grep -rn 'state_file\|StateStore\|state_store'
src/bins/nextgcore-smfd/src/` returned nothing. The issue's "four NFs already use
it" has drifted to seven (nrfd, nssfd, nsacfd, udrd, nwdafd, pcfd, nefd); the
prior art it names is still correct.

## The pre-check the issue demanded, and its answer

> *"Confirm what the SMF actually keys sessions by, and whether a restored PFCP
> session is usable without renegotiating with the UPF — a snapshot that restores
> SMF-side bookkeeping the UPF has already discarded is worse than not restoring
> it."*

Keyed by `sm_context_ref` (the session index rendered as a decimal string), which
is also the key `policy_bindings` uses, so one key spans both maps.

The second half is the real question, and the answer is **no, not on its own** —
so restoring the map alone would have shipped the harm the pre-check names. But
the fix is small and already half-built in this tree, rather than being #193's
restoration signalling:

`pfcp_path.rs` already detects a UPF restart by comparing the peer's Recovery
Time Stamp against a stored one (`check_peer_restart` → `teardown_association` →
`clear_pfcp_sessions`, TS 29.244 §5.22 / TS 23.527 §4.2). It cannot fire across
an *SMF* restart because a fresh process holds `None` and has nothing to compare
against. So the snapshot carries `upfRecoveryTimeStamps` alongside the session
map, and `main` seeds each `PfcpClient` with its peer's stored stamp **before the
association loop is spawned**. The first Association Setup after a reload then
either:

* reports a **different** stamp — the UPF restarted while the SMF was down, the
  association is torn down and exactly these restored sessions are flushed; or
* reports the **same** stamp — the UPF did not restart, so the restored SEIDs are
  genuinely valid.

This is the minimum interlock that makes criterion 2 honest rather than harmful.
It is deliberately **not** TS 23.527 restoration: it does not reconcile *which*
sessions survived, and it signals no peer about the ones that did not. That
remains #193.

## The change

### `session_extensions.rs` — the pool's snapshot surface

* `Ipv4Pool::allocated_addrs()` — every set bit as an `Ipv4Addr`, ascending so
  the same pool state serialises identically each write (a set-ordered result
  would rewrite the whole file for no change).
* `Ipv4Pool::reserve(addr)` — mark one address allocated, returning whether *this
  call* marked it. That distinction is what stops the reserved `.0.0`/`.0.1`
  (which `new()` marks without counting, and `allocated_addrs` reports) from
  inflating `active_count` on restore.

### `gsm_sm.rs` / `context.rs` — serialisable bindings

`GsmState`, `gsm_sm::SmData`, `GsmFsm` and `PolicyBinding` gain serde derives.
`GsmState` serialises **by variant name**, not discriminant, so inserting a state
mid-enum cannot silently reinterpret an existing snapshot — a binding restored
into `Initial` when it was `Operational` would re-run establishment for a live
session. `serde(default)` throughout so a snapshot predating a member still loads.

### `context.rs` — the store

Mirrors pcfd's adoption (`SNAPSHOT_VERSION`, `set_state_file`, `snapshot`,
`restore_from`, `persist`, poison-on-failed-load, disable-before-`fini`), using
`StateStore` rather than the free functions so the never-overwrite-what-you-cannot-read
guard is enforced rather than owned by the caller.

Two properties worth naming:

* **`snapshot` holds at most one lock at any instant.** It clones each map out and
  drops the guard before taking the next. This file carries several documented
  lock-ordering rules (`sess_remove`, `sess_update`, `sess_find_by_ipv4`); a
  function holding three guards at once would be a new inversion waiting to
  happen. The cost — the document is not one atomic instant — is paid back by
  every mutation persisting immediately after its guards drop.
* **`BTreeMap`, not `HashMap`, in the document.** A `HashMap` iterates differently
  per process, so the file would churn wholesale on every write and a diff would
  never show which record actually changed.

`fini` disables the store **before** clearing anything: `ue_remove_all` empties
every list and releases every address, and smfd has background tasks (the PFCP
listener, the association loop, the timer loop) that can still reach a mutation
during shutdown, so a persist reached afterwards would write an empty snapshot
over a good one.

### Persist call sites

Every production mutation of the three concerns, each **after** its write guard
closes (`persist` → `snapshot` re-reads the same locks and `RwLock`/`Mutex` are
not reentrant):

| Site | Mutation |
|---|---|
| `main.rs` create (`ipv4_pool.allocate`) | allocation |
| `main.rs` create (`pfcp_sessions.insert`) | session |
| `main.rs` create (`policy_bindings.insert`) | binding |
| `main.rs` modify ×2 (`ambr`/`five_qi`) | binding |
| `main.rs` EASDF report (`easdf_reported_eas`) | binding |
| `main.rs` release (`pfcp_sessions.remove`, `ipv4_pool.release`) | session, allocation |
| `context.rs` `sess_remove` (`ipv4_pool.release`) | allocation |
| `pfcp_path.rs` `clear_pfcp_sessions` | session (the restart flush) |
| `pfcp_path.rs` `associate` / `check_peer_restart` | peer stamp |

The allocation is persisted **at allocate time**, before the session or binding
exists, because the failure directions are not symmetric: a snapshot holding an
address whose session never completed leaks one address, while a snapshot missing
an address a UE is using hands that address to a second UE.

The peer stamp persists **only on change** — the association loop re-reports the
same stamp every heartbeat, and rewriting the snapshot every 10s per peer for an
unchanged value is pure write amplification.

`session_extensions.rs`'s `DualStackAllocator` owns a second `Ipv4Pool` and is
**not** persisted: it is constructed only in its own unit tests
(`grep DualStackAllocator` finds no production caller), so persisting it would be
snapshotting a pool nothing allocates from.

### Deviation from the issue's stated approach

> *"`smfd` gains a `--state-file` flag plus `NEXTGCORE_SMF_STATE_FILE`, matching
> the precedence the other four NFs use"*

The precedence is matched exactly (flag wins over env var; empty value treated as
unset), but the flag is parsed by the same hand-rolled `argv` scan smfd already
uses for `-c`/`--config` rather than by clap. **smfd has no clap `Args` struct** —
`main.rs` says so explicitly at the `SMF_EASDF` switch — and introducing one
would turn every argument the daemon currently ignores into a hard startup error.
Same substance, no new failure mode for existing deployments.

## Verification

Every guard below was revert-verified: the fix was broken, the **named** test was
watched to fail, and the file was restored (checked by `md5sum -c` against a
pre-revert baseline).

| Guard | Revert applied | Result |
|---|---|---|
| `snapshot_restores_sessions_bindings_and_ip_allocations` | `restore_from` counts allocations without `reserve`-ing them | FAILED ✓ |
| `a_restored_allocation_is_not_reissued` | same | FAILED ✓ |
| `a_released_allocation_is_not_restored` | `sess_remove` does not `persist` | FAILED ✓ |
| `a_newer_snapshot_is_refused_and_not_overwritten` | version comparison short-circuited to `false` | FAILED ✓ |
| `without_a_state_file_nothing_is_persisted` | a state file armed in the watched directory | FAILED ✓ |
| `a_seeded_recovery_time_stamp_makes_a_peer_restart_detectable` | `seed_peer_recovery_time_stamp` stores `None` | FAILED ✓ |
| `an_unchanged_recovery_time_stamp_leaves_restored_sessions_alone` | same | **still passed** — see below |

Two of these are worth stating plainly rather than filing under "green".

**The negative control does not prove the seed works, by construction.** With no
stamp stored, `matches!(None, Some(stored) if stored != rts)` is `false`, so "an
unchanged stamp must not tear down" is satisfied by a build that stores no stamp
at all. Its job is the *other* mutant — a version that flushes unconditionally,
which would make the whole snapshot pointless — and it does catch that. The
positive test is what pins the seed. Both are stated so a later reader does not
mistake the pair for two independent proofs.

**`without_a_state_file_nothing_is_persisted` carries a positive control**, added
after noticing the absence assertion ("no files in this directory") would also
pass if the scan were looking in the wrong place. An armed context now writes
into the same directory first and the test asserts the file appears, before the
memory-only context is checked to add nothing.

### A race found in my own tests

The two `pfcp_path` tests failed on the second run, not the first:
`clear_pfcp_sessions` empties the **process-global** map, so the positive test's
teardown was flushing the negative test's key mid-assertion. Fixed by purity where
possible and one lock where not — `SESSION_MAP_LOCK`, taken by *every* test in the
module that can reach a teardown (`test_heartbeat_detects_peer_restart`,
`test_inbound_association_release`, `test_teardown_clears_load_state`, and the two
new ones), so there is one agreement about that variable rather than two disjoint
ones. Three consecutive full-crate runs green afterwards.

## Ceilings

* **No wire interop.** Everything is verified in-process against this tree's own
  PFCP client and a fake UPF socket. The Docker E2E jobs are the only place a real
  restart-with-UPF would be exercised, and durable state is deliberately **not**
  enabled in the shipped compose file, so that path is unchanged and untested here.
* **The restart flush is process-wide, not per-peer.** With several UPFs
  configured, one peer's restart discards the session bookkeeping for all of them.
  The map has no peer column, so fixing it means changing what `pfcp_sessions`
  stores — no issue asks for that, and it is pre-existing behaviour.
* **A restored session is bookkeeping, not a working session.** The interlock
  proves the UPF did not restart; it does not prove any individual session
  survived on it. That is #193.
* **The `SmfSess` list itself is not persisted.** #191 names three concerns and
  the session list is not one of them; `sess_add_by_psi`/`sess_add_by_apn` are
  still only reached from tests on the SBI path, which is #78's defect, not this
  one. Persisting a list nothing populates would be snapshot theatre.
* **GitNexus impact analysis unrunnable** (52nd consecutive PR): the MCP server is
  not connected in this session, so `nextgcore/CLAUDE.md`'s mandate to run
  `gitnexus_impact` before editing could not be satisfied. Blast radius was
  established by grep and is enumerated in the persist-call-sites table above.
