# nextgcore #235: deregister from the NRF on shutdown, and stop selecting a discovery-cache entry forever

Verified against `main` @ `4ec257a`. Both gaps were still present exactly as described. Three details in
the issue's inventory turned out to be understated — see "What the issue understated".

`Closes #235`.

## Gap 1: nothing deregistered, and the one client that existed had no caller

`udmd` owned the workspace's only `NFDeregister` client (`udm_nrf_deregister`, `sbi_path.rs:321`) and
**never called it** — `grep` for it returned the definition and the `lib.rs:71` re-export, nothing else.
Sixteen other registering NFs had no client at all. So every NF left its profile behind on exit and the
NRF handed it to consumers until the supervision timer expired.

### The design point: the ID is recorded by the library, not passed at 17 call sites

Every NF that registers an `NFProfile` also spawns the shared heartbeat worker. That is not an
approximation — it is an exact coincidence, and it is what makes the fix small:

| | registers `nnrf-nfm` | spawns heartbeat worker |
|---|---|---|
| amfd, ausfd, bsfd, dccfd, easdfd, lmfd, mbsmfd, nefd, nsacfd, nssfd, nwdafd, pcfd, smfd, tsctsf, udmd, udrd, upfd | yes (17) | yes (17) |
| pind | no — `PIND-01` removed its registration deliberately | no |
| scpd, seppd | no — `nnrf-disc` consumers only | no |
| nrfd | n/a (it *is* the NRF; own housekeeping) | no |
| eesd, hssd, mmed, pcrfd, sgwcd, sgwud, webui | no | no |

So `spawn_heartbeat_worker_with_load` records the instance ID into a library-owned slot, and
`deregister_self()` takes **no argument**. That matters more than it looks: an ID threaded by hand through
17 shutdown sites is exactly where a copy-paste error lives, and a `DELETE
/nnrf-nfm/v1/nf-instances/{someone-else's-id}` is a worse bug than no deregistration at all.

### Ordering, and what is deliberately swallowed

* **Deregister BEFORE stopping the listener.** The reverse order opens the bad window — not serving, but
  still advertised. This order opens the harmless one: briefly serving while no longer advertised.
* **Pause the heartbeat before the DELETE.** A tick landing after the DELETE would `PATCH` a profile that
  no longer exists, which reads to an operator as the NRF losing registrations rather than as an ordering
  bug here. The issue #22 NES deregister action already established this ordering; this reuses it.
* **404 is success.** A profile the NRF does not hold is the state we wanted. An NF shutting down after
  its supervision timer already expired should not log a warning that invites investigation.
* **A failure is logged, never returned.** `deregister_self` returns `bool` (was a DELETE issued at all),
  not `Result`. Refusing to exit because the NRF is unreachable would be worse than the stale profile this
  is pre-empting, and the supervision timer is still the backstop.

`amfd` is the one NF where the insertion point needed a decision: it has both `shutdown()` and
`shutdown_async()`, and only the async one can await. It is also the only one with a caller
(`lib.rs:954`) — the sync twin is dead — so the deregistration goes in `shutdown_async`.

Two hand-rolled DELETEs were migrated onto the one client: `udmd`'s uncalled `udm_nrf_deregister` (deleted,
with a comment at the site recording why) and the inline DELETE in `udmd`'s NES sleep path
(`nes_driver.rs:136`), which additionally gains the 404-is-success handling it lacked.

## Gap 2: a cached NF profile was selectable for the whole process lifetime

`SbiContext::nf_instances` was a bare `HashMap<String, NfInstance>` with no expiry, no eviction and no
re-discovery. The compound failure the issue names is the real one: the stale entry is never dropped
**and** a peer that registers later is never learned, so a rolling restart can leave a consumer
permanently pointed at a dead endpoint while the NRF is entirely correct.

### TTL from `validityPeriod`, plus evict-on-transport-failure

Taken over the fuller `Nnrf_NFManagement` status-notify subscription, as the issue recommends: it removes
the permanent-staleness case without adding a subscription lifecycle to every consumer. The map now holds
a `CachedNfInstance { instance, expires_at: Option<Instant> }`.

Design decisions worth review:

* **Expired entries read as ABSENT rather than being flagged.** `get_nf_instance`,
  `find_nf_instances_by_type`, `find_nf_instances_by_service` and `nf_instance_count` all skip them. This
  is what makes re-discovery free: every consumer already has a "not in cache -> discover" branch (e.g.
  `amfd`'s `resolve_service_endpoint`, which re-discovers on a miss precisely because a late-registering
  NSACF was invisible), and an expired entry now takes it.
* **`Instant`, not wall-clock.** A clock step must not make a live entry look expired or a dead one live.
* **`add_nf_instance` still means "never expires", and that is deliberate.** The strict-peer harnesses seed
  the registry by hand to stand in for an NRF; giving them a TTL would make them flake on timing. The
  doc-comment says loudly that it opts out and points at the with-validity variant, and there is a test
  pinning the difference so a later reader does not "tidy" the two into consistency.
* **A missing `validityPeriod` falls back to 3600s, not to forever.** 3600 matches `nrfd`'s own
  `NRF_DISC_VALIDITY_PERIOD` default. The point of a fallback is that a *foreign* NRF omitting the member
  must not mean "cache this peer for the process lifetime"; an hour is a bound, not a guess at intent.
* **An explicit `validityPeriod: 0` is honoured as zero.** An NRF saying "do not cache this" is an
  instruction. Coercing it to the default would be the lower-configuration-layer-can-never-win mistake.
* **Eviction fires on a TRANSPORT failure only, never on an error status.** A 4xx/5xx means the peer
  answered: the endpoint is live and its profile is fine. Evicting on a 500 would drop a healthy peer
  because it was briefly unhappy.
* **`evict_nf_instance_on_failure` is separate from `remove_nf_instance` and returns whether it removed
  anything.** The name carries the reason at the call site, and the return lets a caller log the difference
  between "we dropped the stale peer" and "someone else already had" instead of claiming an eviction it did
  not perform.

Wired at all four production discovery writers (`amfd/sbi_path.rs`, `ausfd/app.rs`, `udmd/sbi_path.rs`,
`nssfd/main.rs`) — each reads the `validityPeriod` once for the whole `SearchResult`, which is where
TS 29.510 puts it: it is a property of the answer, not of an individual profile. Eviction is wired at
`udmd`'s two send paths, which are the two shapes: resolve-by-ID (`udm_sbi_send_request`) and
select-by-type-then-send (`udm_sbi_discover_and_send_nudr_dr`, which now remembers *which* profile it
selected so it can evict that one).

## What the issue understated

1. **Four production cache writers, not two.** The issue cites `amfd/sbi_path.rs:505` and
   `udmd/sbi_path.rs:305` as examples; the full set is those plus `ausfd/app.rs:1960` and
   `nssfd/main.rs:3008`. All four are wired.
2. **`udmd` had TWO hand-rolled DELETEs, not one.** Besides the uncalled `udm_nrf_deregister`, the NES
   sleep path (`nes_driver.rs:136`, feature-gated) had its own inline copy. Adding a third per-NF copy was
   the thing most worth avoiding here.
3. **The set of registering NFs is exactly the set that spawns the heartbeat worker.** The issue lists NFs
   with no deregistration client, which is accurate, but does not note this coincidence — and it is the
   whole reason the fix needed no per-NF ID plumbing.

## Verification

Workspace: **5949 passed / 0 failed** across three consecutive full runs (baseline on `main` for this
branch: 5938 / 0 — the difference is the eleven tests added here). `cargo clippy --workspace` and
`cargo fmt --all -- --check` clean. Three consecutive
runs rather than two because this change adds port-binding tests and touches process-global state, which
is the bar this project settled on for exactly that case.

**Fifteen behavioural claims individually revert-verified** — each reverted in isolation, with the named
test confirmed to have actually RUN and then FAILED, and the tree restored afterwards:

| # | claim | test that bit |
|---|---|---|
| 1 | `find_nf_instances_by_type` skips expired | `expired_instance_reads_as_a_cache_miss_on_every_path` |
| 2 | `get_nf_instance` skips expired | same |
| 3 | `find_nf_instances_by_service` skips expired | same |
| 4 | `nf_instance_count` skips expired | same |
| 5 | `purge_expired_nf_instances` drops expired | `purge_expired_drops_only_the_expired` |
| 6 | `add_nf_instance` never expires | `add_without_validity_never_expires` |
| 7 | eviction actually removes | `eviction_on_failure_removes_the_entry_and_reports_whether_it_did` |
| 8 | `validityPeriod` drives the TTL and `0` is honoured | `search_result_validity_reads_the_member_and_honours_zero` |
| 9 | spawning the heartbeat worker records the ID | `test_registered_nf_instance_id_plumbing` |
| 10 | `deregister_self` issues the DELETE | `test_shared_deregister_self_removes_the_profile_from_the_real_nrf` |
| 11 | the heartbeat is paused before the DELETE | same |
| 12 | a 404 from the NRF is success | same |
| 13 | `udmd` by-ID send evicts on transport failure | `transport_failure_evicts_the_cached_instance_by_id` |
| 14 | `udmd` by-type send evicts the profile it selected | `transport_failure_evicts_the_selected_udr` |
| 15 | `udmd` discovery passes the validity into the cache | `discovery_honours_the_search_result_validity_period` |

The revert harness checked itself against the four ways a revert lies: the anchor was asserted **unique**
in its file, a compile failure was treated as inconclusive rather than as a bite, the named test had to be
seen to run (a zero-tests-ran summary is inconclusive), and each substitution was read for semantic
equivalence before being trusted.

Claim 10 is the one that matters most and is proved against the **real NRF handler**, not a mock:
`nrfd`'s own test module starts a real `SbiServer` on `nrf_sbi_request_handler`, registers a profile over
HTTP, then calls `deregister_self()` and asserts the profile is gone from `nf_manager()` — `nrfd`'s actual
registry — and that a subsequent GET is 404. The existing
`test_http_lifecycle_register_discover_patch_deregister` already proved `nrfd`'s DELETE handler, but it
drives the DELETE by hand; what was unproven, and is now proved, is that the shared client added to 17
shutdown paths reaches it.

### Two authoring traps hit and fixed in-session, both worth recording

**The SBI profile defaults to Production, so a test that dials loopback gets a TLS error, not a refused
connection.** The first version of the two eviction tests passed — but at the wrong layer: `get_client`
built a TLS client and failed on a missing `/etc/nextgcore/tls/client.crt` rather than being refused by the
closed port the test comment described. A TLS setup error *is* a transport failure, so the eviction
assertion held and the test looked fine; the mechanism it documented was simply not the mechanism it
exercised, and which one it got depended on whether a sibling test had already forced Dev. All three new
`udmd` tests now set `set_sbi_profile_override(SbiProfile::Dev)` explicitly, matching the eleven existing
sites that do.

**A `.first()` over the process-global cache picked a sibling test's profile.** The by-type eviction test
intermittently evicted the by-ID test's UDR instead of its own, because `find_nf_instances_by_type`
returns a `HashMap`-ordered view of a process-global map. Distinct IDs did not help — distinctness was
never the problem, the shared view was. Fixed by taking `udmd`'s existing process-wide
`test_support::CONTEXT_GUARD` (poison-tolerant, so one failing test does not turn its siblings into
misleading second failures) in all three tests, then confirming 6 consecutive clean runs of
`cargo test -p nextgcore-udmd --lib`. The test's doc comment now records that it *did* race, so nobody
removes the guard on the grounds that the IDs are distinct.

## Ceilings

Stated rather than papered over:

* **No test drives any NF's `main()` shutdown**, so the seventeen one-line insertions are compile-checked
  and reviewed but not observed firing. There is no shutdown harness for any NF in this repo to hang such a
  test off. What *is* observed is the function they all call, end-to-end against the real NRF. The
  distinguishing risk is therefore "one NF's line is in an unreachable branch", which review covers and a
  test would not, since a test would have to call the same function.
* **Only `udmd`'s discovery writer has a validity test.** `amfd`, `ausfd` and `nssfd` carry the same three
  lines and are type-checked, but no test observes their cached entries expiring. This is the recorded
  "the helper is tested and the wiring is not" pattern, reduced from four instances to three rather than
  eliminated; each would need its own stub-NRF harness.
* **Eviction is wired in `udmd` only.** `amfd`'s `resolve_service_endpoint` returns `(host, port)` and
  discards the instance ID, so evicting there means threading the ID out to every send site — a bigger
  refactor than this issue asks for. `amfd` still benefits from the TTL half: an expired entry takes its
  existing re-discovery branch.
* **`purge_expired_nf_instances` has no production caller.** The reads already ignore expired entries, so
  it is bookkeeping (stopping a long-lived consumer accumulating dead profiles), not correctness. It is
  tested, and deliberately not wired to a timer here: adding a background task to every NF is a separate
  decision from bounding the reads.
