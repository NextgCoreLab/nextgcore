# fix(upfd): delete the dead session model, and repair the load gauge it was feeding

Closes #325.

## Criterion 1 — what `rule_match`'s callers do with `None` today

#325 asks this first because it decides whether the issue is a latent cleanup or a live
packet-path defect. The answer is **neither of the two the issue anticipated**, and finding
that out changes which option is correct.

`rule_match.rs`'s four `sess_find_by_ipv4/6` call sites live inside exactly two functions:

| function | site | its own callers |
|---|---|---|
| `upf_sess_find_by_ue_ip_address` | `rule_match.rs:192,223` | `rule_match.rs:560,563,566,570` — **all inside `#[cfg(test)] mod tests`** |
| `upf_sess_find_by_ue_ip_address_src` | `rule_match.rs:290,304` | **none, anywhere** |

`rg upf_sess_find_by_ue_ip_address bins/ libs/` outside `rule_match.rs` returns nothing. So the
`None` never reaches production code: the chain is dead at both ends, not just at the write
end. Nor is the rest of the module load-bearing — `get_ip_version`, `get_ipv4_dst_addr`,
`get_ipv6_dst_addr` and `IPV4_MIN_HEADER_LEN` have no callers outside it either, and
`arp_nd.rs` declares its **own** `Ipv6Header` rather than using this one.

**No traffic is affected, because the live data path never asks these functions anything.**
It has its own UE-IP index: `DataPlaneSessionManager::ue_ip_map`
(`data_plane.rs:1466`), written by `add_session_from_pfcp` on the N4 establishment path
(`main.rs:767`) and read by `find_by_ue_ip` for downlink (`data_plane.rs:2474`) and for the
uplink source-spoofing check (`data_plane.rs:2267`). That index works.

### But the dead store IS reachable, through a path #325 does not mention

`sess_count()` reads `sess_list` (`context.rs:1745`) — and `sess_count` has a **production
caller**: `get_load()` (`context.rs:1759`), which feeds three live sites.

| consumer | site | what it advertises |
|---|---|---|
| NRF heartbeat `NFProfile.load` PATCH | `main.rs:173` | TS 29.510 §5.2.2.3.2 load percentage |
| NRF registration `NFProfile.load` | `main.rs:529` | same, at registration |
| PFCP Heartbeat **Load Control Information** | `pfcp_path.rs:1062` | TS 29.244 §5.19.1 metric (behind `compute-aware-upf`) |

So the UPF reports **load = 0 to the NRF and to the SMF no matter how many sessions it is
serving**, and `get_load`'s own doc comment asserts the opposite: *"an honest occupancy metric
derived from real session state — the UPF never fabricates a CPU-based load figure"*. It does
not fabricate a CPU figure; it reports a constant. An SMF doing load-aware UPF selection sees
every UPF at 0 and cannot balance; a saturated UPF keeps attracting sessions.

**A second, independent defect on the same line.** `max_num_of_sess` is the denominator, and
it is **always 0**: `UpfContext::init` needs `&mut self`, `upf_self()` hands out
`&'static UpfContext`, and `upf_context_init` therefore *discards* its argument behind a
comment saying so (`context.rs:1813-1817`) — while `main.rs:149` dutifully passes
`--max-sessions` (default 1024). With a zero denominator `get_load` takes its
`checked_div` → `None` branch and reports the **raw session count** saturated at 100. So even
with a working count, a UPF at 100 of 1024 sessions would report `load: 100` — fully loaded at
under 10% occupancy.

Both halves have to be fixed together, because repointing the count is what makes the
denominator bug observable.

## Criterion 2 — the decision, and why

**Option 1: delete the store.** #325's three options differ in blast radius, and criterion 1's
answer settles it: option 2 (re-point `rule_match` at `PfcpSessionInfo`) would build a second
UE-IP index to serve **a caller that does not exist**, and would have to reinvent the
`ipv4_framed_routes`/`ipv6_framed_routes`/`RouteTrie` support on a type that lacks it — all
for a lookup no packet ever reaches. Option 3 is worse for the reason #325 gives.

Deleting is also the only option that satisfies criterion 3 as written, since options 2 and 3
both keep a `UpfSess` alive.

What goes:

- `UpfSess` and its `impl`/`Default` — including `tsn_bridge` (criterion 4) and the
  `check_framed_routes`/`urr_acc_*` methods that only it had.
- `UpfContext::sess_list` and all thirteen `sess_*` methods, plus `get_all_sessions`.
- The five lookup indices that existed only to resolve into `sess_list`:
  `upf_n4_seid_hash`, `smf_n4_seid_hash`, `smf_n4_f_seid_hash`, `ipv4_hash`, `ipv6_hash`.
- `RouteTrie` and the two `ipv4_framed_routes`/`ipv6_framed_routes` tries (criterion 4), whose
  only feeder was the callerless `sess_add_framed_route`.
- `IpSubnet` and both `NEXTGCORE_MAX_NUM_OF_*` constants, reachable only from the above.
  `UeIp` is **kept**: it turned out to be a field of `Pdr` (`context.rs:525`), part of a
  second, unreferenced *rule* model in the same file. That model is a different and milder
  defect — nothing reads it, so unlike the session store it never reached the wire — and
  removing it needs a call on the workspace-wide `dead_code = "allow"` that hides it. Filed
  as **#335** rather than folded in here.
- `rule_match::upf_sess_find_by_ue_ip_address` and `_src`, and the four assertions that were
  their only callers.
- `n4_handler::Pdr::ipv4_framed_routes` / `ipv6_framed_routes` — declared, never assigned,
  never read. They looked like the surviving half of a framed-route feature whose only sink
  was `sess_add_framed_route`; leaving them behind would misrepresent the wire decode as
  present. Removing them is the No-Broken-Windows half of criterion 4.

What stays, and why it is not the same defect: `PfcpSessionInfo` (written by the N4 handlers,
read by the report and modification paths) and `DataPlaneSession` (written by
`add_session_from_pfcp`, read by the forwarding path) are both production-written **and**
production-read.

## What replaces the count

`sess_count()` keeps its name and its callers and changes its source: it now reads a **gauge
handed to it by the one authoritative N4 store**, `PfcpServer::sessions`.

```rust
// UpfContext
session_gauge: RwLock<Option<Arc<AtomicUsize>>>,
max_num_of_sess: AtomicUsize,
```

`PfcpServer` owns the `Arc<AtomicUsize>` and `store`s `sessions.len()` inside **every** write
scope that changes the map's size — establishment insert, deletion remove, and the
peer-failure clear — and `main.rs` hands the handle to `UpfContext` right after the server is
constructed.

**Why a gauge and not "populate the second store" (option 3).** The distinction matters
because a mirrored `usize` sounds like the thing #325 warns against. It is not the same
failure mode:

- Option 3's failure is a **session** present in one store and absent from the other, so the
  UE-IP lookup returns a session with no PDRs — #325's words, "actively worse than `None`".
- This gauge is written **from `sessions.len()`**, never incremented, and always inside the
  same critical section as the mutation. It cannot hold a value the map never had. A future
  mutation site that forgot it would leave the gauge *stale until the next write*, which is a
  wrong number, not a wrong forwarding decision.

`max_num_of_sess` becomes an `AtomicUsize` so `upf_context_init` can actually record
`--max-sessions`, which turns `get_load`'s percentage branch on. `init` and `fini` take
`&self` for the same reason — `&mut self` is what made them uncallable from `upf_self()`.

`init` now stores the ceiling **unconditionally** and uses the `initialized` flag only to
latch liveness. Gating the store on the flag would mean a context something had already
marked live could never record a ceiling: harmless in production, where `upf_context_init`
is called exactly once from `main`, but in a test binary the process-global is shared and
whichever test got there first would decide the ceiling for every other.

Tests that touch the global serialise on `UPF_GLOBAL_TEST_LOCK`, declared beside
`UPF_CONTEXT` rather than inside a `mod tests` — a lock declared inside one module's test
block is unreachable from a sibling module's, so the next test that needs one declares a
second, and two locks are two disjoint agreements about one variable (#308). The async test
holds the `std::sync::Mutex` guard across awaits with `#[allow(clippy::await_holding_lock)]`
and a stated reason: the awaits are exactly the window a sibling could interleave in, and a
second `tokio` lock for the async half would recreate the split the lock prevents.

## Criterion 3 — the test that pins it

`the_load_gauge_follows_the_live_n4_session_store` (in `pfcp_path`, where the N4 path can
actually be driven) runs Association Setup, Session Establishment and Session Deletion over
a socket through the real handlers, and asserts `upf_self().sess_count()` after each step.
**Nothing in it touches a session store directly**, which is what makes it an assertion
about wiring rather than about arithmetic: it fails if the gauge stays 0, and it fails if
the gauge is fed by anything other than the store the N4 path writes.

That is the honest reading of "a test pins this". A test cannot assert the *absence* of some
future parallel store, but it can assert that the store the production reader reads is the
store the production writer writes — and the violation of exactly that was the bug. The
deletion assertion is not redundant with the establishment one: a gauge that only ever
counted up would pass the first and still be wrong.

The old `test_get_load_gauge` is the counter-example that motivates the split. It drove the
count with `ctx.sess_add(...)` — a writer that exists only in tests — so it proved 20% for
2-of-10 and **passed**, while the shipped binary reported 0 for every deployment. It
survives, rewritten, as a test of the **arithmetic only** (now also pinning that a
percentage cannot exceed 100), with the wiring assertion moved to where the wiring is.

`the_session_ceiling_reaches_the_global_context` covers the denominator half through the
process-global, because that is the trip the ceiling did not survive.

## Revert-verify

Both new properties were made to fail before being trusted, and each revert was confirmed
applied by grep before the test was run:

- Removing `publish_session_count` from the establishment path:
  `the_load_gauge_follows_the_live_n4_session_store` fails on the named assertion, *"an
  established N4 session must be visible to the load gauge; 0 here is the shipped defect, a
  UPF advertising load 0 while serving a session"*.
- Removing the ceiling `store` from `UpfContext::init`:
  `the_session_ceiling_reaches_the_global_context` fails with `left: 50, right: 25` —
  reproducing the shipped behaviour exactly, a raw count where a percentage belongs.

The second revert was **narrowed** on purpose. Reverting `upf_context_init` to its old
discard-the-argument body also stopped `initialized` being set, so the test failed on its
liveness assertion instead of its ceiling assertion — a signal that could not distinguish
"init never ran" from "the ceiling was dropped". Reverting only the `store` isolates the
property under test.

## Ceilings, stated rather than implied

- **`add_session_from_pfcp` is gated on `ue_ipv4.is_some()`** (`main.rs:755`), so an
  IPv6-only session never enters the data plane's `seid_map`. That is why the load gauge is
  taken from `PfcpServer::sessions` (which every established session enters) and not from
  `DataPlaneSessionManager::session_count()`. The IPv6-only gap in the data-plane store is a
  separate defect and is not touched here.
- **`#321`'s note in `specs/fix-pfcp-tsc-container-codec.md` is updated** (criterion 4): its
  "`UpfSess` also has a `tsn_bridge` field, and it is UNREACHABLE" reasoning described a type
  that no longer exists, so the note now records that the duplication was resolved by deleting
  the dead half — which is the outcome that note was waiting for.
- **`#223` is the same defect class in `smfd`** and is deliberately not touched: it is
  `decision`-labelled and its `SmfSess` has far more production readers than `UpfSess` had.
- **`dead_code = "allow"` is the ambient condition that let this rot** (`Cargo.toml:210`,
  commented "Future-use code for Rel-17/18/20 features"). It is why a store with production
  readers and test-only writers raised nothing for as long as it did. Narrowing it is a
  workspace-wide change with its own blast radius and belongs to #335.

## Verification

- Workspace **6520 → 6513** tests, 0 failures: 9 tests removed with the types they
  exercised, 2 added. `cargo clippy --workspace` 0 errors, and `nextgcore-upfd` is at **0
  warnings** — the pre-existing `unused import: Bytes` in `pfcp_path`'s tests went with it,
  a one-line broken window in a file this change already touches. `cargo fmt` clean.
- **8 consecutive `nextgcore-upfd` runs**, 297 passed each. Required rather than optional:
  the two new tests share a process-global, and one green run of a test that serialises on a
  lock proves nothing about the lock.

## Files

- `src/bins/nextgcore-upfd/src/context.rs` — dead model removed; `sess_count` repointed;
  `max_num_of_sess` made settable.
- `src/bins/nextgcore-upfd/src/rule_match.rs` — the two UE-IP lookups and their tests removed.
- `src/bins/nextgcore-upfd/src/pfcp_path.rs` — session gauge maintained beside `sessions`.
- `src/bins/nextgcore-upfd/src/n4_handler.rs` — dead `Pdr` framed-route fields removed.
- `src/bins/nextgcore-upfd/src/main.rs` — gauge handed to `UpfContext`.
- `specs/fix-pfcp-tsc-container-codec.md` — #321's note updated.
