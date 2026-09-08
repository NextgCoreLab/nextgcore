# nextgcore #242 (udmd): delete the unreachable state-machine SBI half and `nudr_handler.rs`

Verified against `main` @ `c296445` (after #205). Every cite in the issue still holds, with one
correction.

## Verified against current main

| claim in the issue | check on `c296445` | still true? |
|---|---|---|
| nothing constructs `UdmEvent::sbi_server` / `::sbi_client` | `grep -rn 'UdmEvent::sbi_server\|UdmEvent::sbi_client' --include='*.rs' src/` | **almost** — see correction |
| the only event the daemon dispatches is `UdmEvent::sbi_timer` | `app.rs:3504` inside `run_event_loop_async`, the sole `dispatch` caller | yes |
| all five `nudr_handler` public functions have zero external callers | grepped each name excluding its own file → 5 × nothing | yes |
| `nudr_handler.rs` is the only consumer of `nudm_handler`'s `HandlerResult` / `http_status` | after deleting it, both compile out with no other break | yes |
| `send_method_not_allowed_response` (+ `send_bad_request_response`, `send_forbidden_response`) have no caller | yes, and #242 makes the whole module callerless | yes |
| `udrd`'s and `pcfd`'s own `nudr_handler` are live — this is udmd-only | `udr_sm.rs:247/251/267/288` still call theirs | yes |

**Correction.** The issue says the two constructors have "no production caller, **no test caller**".
There were two test callers, `event.rs:396` and `:408`, in `event.rs`'s own unit tests. That does not
change the finding — a constructor whose only callers are the tests of the module that defines it is
still unreachable from the daemon — but it is why the removal took two `event.rs` tests with it, and
it is worth stating rather than leaving a reader to wonder why the grep in the issue and the grep
here disagree.

## Decision: delete, not wire

The issue frames this as a maintainer call and lays out both branches. Delete, on this evidence:

1. **The live daemon is not event-driven at all.** `app.rs::udm_sbi_route` is an async HTTP
   dispatcher that parses its own requests and owns its own responses. Wiring the FSM would mean
   choosing which of two request paths is authoritative and porting one onto the other — the
   issue's own step 3 says as much and asks for it to be its own feature issue.
2. **The unreachable path was already hollow.** #236 / udmd-04 had reduced every child-FSM handler
   (`handle_nudm_ueau_request`, `handle_nudm_uecm_request`, `handle_nudm_sdm_request`,
   `handle_nudr_dr_response` in both `ue_sm.rs` and `sess_sm.rs`) to a single `log::debug!`. Wiring
   the trio would therefore have delivered *routing to stubs*, not service.
3. **A new, independent reason found while doing the work — the path could not have answered a
   request even in principle.** `sbi_path::send_sbi_response` was a **logging placeholder**: it
   formatted one debug line and returned, with a comment saying a real implementation would look up
   the stream and queue the response. It was the sink for every error response `sbi_response.rs`
   appeared to send (400/403/404/405/504), and `sbi_response.rs` was reached only from this path. So
   even a hypothetical `UdmEvent::sbi_server` producer would have routed correctly and then sent
   nothing. This is not in the issue and is the strongest argument in the delete column.

## What was removed, in the issue's own safe order

| step | removed | lines |
|---|---|---|
| 1 | `nudr_handler.rs` | 809 |
| 2 | `sess_sm.rs`, `ue_sm.rs` — deleted whole, not halved (see below) | 436 + 420 |
| 2 | `udm_sm.rs`'s routing half: `handle_sbi_server_event`, `handle_nnrf_nfm_request`, `handle_nudm_request`, `handle_ue_request`, `handle_sess_request`, `handle_sbi_client_event`, `handle_nnrf_nfm_response`, `handle_nnrf_disc_response`, `handle_nudr_dr_response`, `handle_nudr_ue_response`, `handle_nudr_sess_response`, `ue_sm_init/fini`, `sess_sm_init/fini`, the `ue_sms` / `sess_sms` maps, `extract_supi` | ~490 |
| 3 | `UdmEvent::sbi_server` / `::sbi_client`; `UdmEventId::SbiServer` / `::SbiClient`; and the payloads that existed only for them — `SbiEventData`, `SbiRequest`, `SbiResponse`, `SbiMessage`, the `sbi` field, `with_sbi_message` / `with_sbi_data` / `with_sbi_state` / `with_stream_id`, `UdmEventId::from_signal` and the three `NEXTGCORE_FSM_*_SIG` constants only it read | ~215 |
| 4 | `nudm_handler.rs`'s `HandlerResult` + `http_status` (hex codec kept) | ~96 |
| extra | `sbi_response.rs` whole (every function callerless once step 2 lands) | 63 |
| extra | `sbi_path::send_sbi_response` (only callers were in `sbi_response.rs`) | ~23 |
| extra | `event.rs`'s `udm_ue_id` / `sess_id` fields, `with_udm_ue` / `with_sess`, `udm_event_get_name` | ~20 |

**2678 deletions, 221 insertions.**

### Why `ue_sm.rs` and `sess_sm.rs` went whole rather than halved

The issue says "the SBI halves of `sess_sm.rs` / `ue_sm.rs`". Removing only those halves leaves a
per-UE and a per-session FSM whose remaining content is an Initial → Operational → Final lifecycle
with **no trigger** — the maps that held them (`UdmSmContext::ue_sms` / `sess_sms`) are populated
only by `handle_ue_request` / `handle_sess_request`, which are in the deleted half, and
`ue_sm_init` / `sess_sm_init` had no caller before this change either. A per-UE state machine that
cannot be constructed is the same "reads as working" shape the issue is filed about, one level down.
`grep` confirms nothing outside `udm_sm.rs` and `lib.rs`'s re-exports ever named
`UdmUeSmContext` / `UdmSessSmContext`.

### Why `event.rs` now diverges from its twelve sibling NFs

Every other NF's `event.rs` carries the `SbiServer` / `SbiClient` kinds and the
`SbiEventData` / `SbiMessage` payloads, because their state machines really do serve requests
(`udrd`, `pcfd`, `ausfd`, `nrfd`, `bsfd`, `nssfd`, `seppd` all dispatch them). udmd's copy had the
same shape and no producer. **The divergence is the accurate description of the daemon and the
previous symmetry was the misleading part** — it is precisely what let 2100 lines read as a working
Nudm/Nudr path. The cost, stated plainly: if udmd is ever converted to an event-driven request path,
these types must be re-added. They should be, *with* their producer, which is the order this issue
argues for.

## One behaviour change, not asked for

The `SubscriptionValidity` and `SubscriptionPatch` timer arms logged only
`if let Some(subscription_id)`, and **nothing on the timer path populates one** —
`run_event_loop_async` attaches `with_nf_instance` and nothing else. So a subscription timer that
really did expire produced no output at all. Both arms now log unconditionally and name the missing
id. Four lines, inside a module already being rewritten, fixing the same invisible-state problem
this issue is about; called out here because it is not in the acceptance criteria.

The `SbiClientWait` arm's `send_gateway_timeout_response` is likewise replaced by a `log::error!`
that states why no 504 can be sent: its stream id came from `event.sbi`, which only the removed
`sbi_server` constructor populated, and its sink was the placeholder described above.

## Acceptance criteria

- [x] `udmd` has one request path, not two — the state machine's SBI half is gone; `app.rs`'s
      `udm_sbi_route` is the only thing that serves a Nudm request.
- [x] `nudr_handler.rs` is deleted.
- [x] `UdmEvent::sbi_server` / `::sbi_client` are removed, together with the `UdmEventId` variants
      and the payload types that existed only for them.
- [x] `cargo test -p nextgcore-udmd` and the workspace lint/test gate stay green.

## Verification

Workspace **5966 passed / 0 failed / 6 ignored** (baseline `5985` on `c296445`). `cargo clippy
-p nextgcore-udmd --all-targets` adds no warning (the 3 `MutexGuard held across an await point` are
pre-existing), `cargo clippy --workspace` has 0 errors, `cargo fmt --all -- --check` clean, and
`cargo doc -p nextgcore-udmd` adds no warning (the 3 private-item-link warnings are pre-existing —
confirmed by re-running it on stashed-clean `main`).

**The test count went DOWN by 19, and that is the honest headline of the change.** All 19 tested code
that could not execute:

| removed tests | what they asserted |
|---|---|
| 5 in `nudr_handler.rs` | types defined in that same file (`UdmSbiState`, `AuthenticationSubscription`, `AuthenticationVector`, `ProvisionedDataSets`) plus one dead function's not-found branch |
| 4 in `ue_sm.rs`, 4 in `sess_sm.rs` | that an unconstructable FSM reaches `Operational` and then `Final` |
| 4 in `nudm_handler.rs` | that `HandlerResult::ok()` has status 200, etc. |
| 1 in `sbi_response.rs` | an empty body with the comment "verifies the function compiles and runs" |
| 3 net in `event.rs` | the two removed constructors and the two removed id setters |

Two tests were added: `operational_state_handles_every_event_the_daemon_dispatches` (drives all
three event kinds and all seven timer ids, and pins the *exhaustive* match) and
`every_event_and_timer_id_has_a_distinct_name`.

Two reverts:

| revert | expected to break | result |
|---|---|---|
| re-add an `SbiServer` variant to `UdmEventId` with no producer | the exhaustive matches | **2 compile errors** — `event.rs:81` (`UdmEventId::name`) and `udm_sm.rs:107` (`handle_operational_state`), i.e. re-introducing an unreachable event kind now fails the build rather than adding a silent arm |
| restore `if let Some(subscription_id)` on the `SubscriptionValidity` arm | — | **not test-verifiable**; see ceiling below |

## Ceilings

* **The subscription-arm logging change is not verified by a test.** Nothing in this crate asserts on
  log output, and adding a capturing logger to prove one `log::error!` fires would be more machinery
  than the four lines it guards. Stated rather than dressed up as verified: the revert compiles and
  passes, because no test can see the difference.
* **The surviving timer branch still acts on nothing.** All four NF-instance arms and both
  subscription arms carry a "requires NRF integration" note and only log; `udmd` has no NF-instance
  FSM to dispatch to. That is unchanged by this PR and is a separate feature gap — the arms are kept
  because the timers genuinely expire and a logged expiry beats a silent one.
* **No test drives `app.rs::udm_sbi_route` end to end in this PR**, so "udmd has one request path"
  rests on the enumeration above (grep for every removed symbol) plus the existing 148 udmd tests
  staying green, not on a new integration test. The live path's own coverage is what it was.
* The `NEXTGCORE_FSM_ENTRY_SIG` / `_EXIT_SIG` / `_USER_SIG` constants were removed from udmd's
  `event.rs` because `from_signal` was their only reader and it had no caller. The canonical copies
  live in `libs/nextgcore-core/src/fsm.rs:85-87`; twelve other NFs still carry their own duplicates,
  which is a separate consolidation nobody has asked for.
* GitNexus impact analysis unrunnable (no MCP server connected — 41st consecutive PR). Blast radius
  established by grep: every removed symbol was searched across `src/` before deletion, and the only
  cross-crate surface was `lib.rs`'s re-exports of `UdmUeSmContext` / `UdmSessSmContext` /
  `UdmUeState` / `UdmSessState`, which no other crate imported.
