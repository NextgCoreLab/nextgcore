# Decide which session model the SMF owns, and wire the EPS procedures that make it real

**Issue:** nextgcore #223 (an `architecture` + `decision` split out of #77 criterion 2)
**Verified against:** nextgcore `main` @ `3813bd9`
**Spec basis:** TS 29.274 §7.2.3 (Delete Session Request/Response), §7.2.5 (Bearer Resource
Command), §7.2.7 (Modify Bearer Request/Response), §7.7 (cause values), Table 7.2.1-2;
TS 23.401 §5.4.4.1 (PDN-GW-initiated bearer deactivation), §5.4.5 (UE-requested bearer
resource modification), §5.3.2.1 (attach / address allocation).

## Read this first: the issue's own comment recommended option 2 for reasons that have since expired

The comment on #223 was written against `main` @ `71418a5` and concluded, verbatim:

> **Confirmed: `gtp_handler.rs` is dead on arrival.** None of its nine public functions has a
> caller.

and recommended **option 2** — two models by design, `SmfSess` marked as *scaffold awaiting
#52*, criteria 2 and 3 amended as unsatisfiable. Its stated deciding fact was:

> The deciding fact is that **#52 is open** and names smfd's PGW-C endpoint explicitly.

**Both halves are now false**, and the recommendation dies with them:

* **#52 is CLOSED**, and so are #62, #116 and #117 — all four issues the comment cited as
  reasons to keep the scaffold rather than decide. #52 landed a real PGW-C GTPv2-C endpoint in
  smfd.
* **`gtp_handler` has live callers**: `gtp_path.rs:1204` calls `dispatch_s5s8_response` and
  `gtp_path.rs:1209` calls `dispatch_s5s8_request`, both from `S5S8Server::handle_datagram`,
  which is driven by the receive loop `S5S8Server::open` spawns, installed from `main.rs:744`
  (`gtp_path::s5s8_open`).

So the decision this issue asks for was **settled by #52 landing**, not by anyone's judgement:
`SmfSess` is the EPC session model and it is live. Recording it is a matter of writing down
what the tree already does.

A second, larger correction the comment missed — and this one was already true at `71418a5`'s
descendants rather than a consequence of #52:

**`SmfSess` is live on the 5GC path too, via #78.** `main.rs:5433`
(`register_sm_context`) calls `sess_add_by_psi`, and `handle_sm_context_create` calls
`register_sm_context` at `main.rs:3014`. `main.rs:3561` then fills the registered session in
and `sess_update`s it. `#78` (`2918eb7`) landed **after** `71418a5`, which is why the comment
did not see it; `git merge-base --is-ancestor 2918eb7 71418a5` fails. So the issue's framing —
"two parallel session models, one dead" — was true when filed and is now wrong in both
directions: `PolicyBinding` and `SmfSess` are both live, on both paths, and they are
**complementary rather than parallel**.

### Why `grep "SmfSess {"` still shows only test constructors

Because no live path uses a struct literal. Both producers go through the context:
`sess_add_by_psi` (5GC) and `sess_add_by_apn` (EPC), each of which builds its session with
`SmfSess::new(id, index, smf_ue_id)` inside `context.rs`. Criterion 3 is written as a grep for
`SmfSess {`, and that grep **cannot see a live producer** — it is a test of construction
syntax, not of reachability. Restated rather than satisfied; see "Criterion 3".

## Verified against current main

| claim in the issue / its comment | site on `3813bd9` | still true? |
|---|---|---|
| `SmfSess` never constructed outside tests | `context.rs:1027` (def), `:1188` (impl), `:1294` (`Default`); literals only at `gsm_handler.rs:781`, `gsm_build.rs:1129`, both `create_test_sess` | **misleading.** Literal-only is true; *unreachable* is false — two live producers (below) |
| the live 5GC model is `PolicyBinding` keyed by `smContextRef` | `context.rs:1513`; populated `main.rs:3592`, read by update/release/N1 | yes — and it is **not** the only live model |
| `gtp_handler.rs` is dead on arrival, nine functions with zero callers | `gtp_path.rs:1204`, `:1209` → `dispatch_s5s8_response` / `dispatch_s5s8_request`; the latter → `create_session` → `handle_create_session_request` (`gtp_handler.rs:1194`) | **NO — void.** Closed by #52 |
| `SmfSess` has no producer on either path | `sess_add_by_apn` at `gtp_handler.rs:1135` (EPC, #52); `sess_add_by_psi` at `main.rs:5433` via `register_sm_context` (5GC, #78) | **NO — void.** Two live producers |
| `#52`/`#62`/`#116`/`#117` are open and intend to build on `gtp_handler` | `gh issue view`: all four **CLOSED** | **NO — void.** The comment's deciding fact |
| `gsm_build`'s `SmfSess` builders are test-only | 11 `pub fn`s take `&SmfSess`; `build_create_session_response` is called from `gtp_handler.rs:1253`, `build_delete_session_response`/`build_modify_bearer_response` were not | partly — **real**, and narrowed here |
| 6 `gsm_handler` fns take `SmfSess` | `gsm_handler.rs:171, 278, 339, 394, 504, 581` | yes |
| the three comments assert a GTP dispatch that does not exist | `smf_sm.rs:120`, `:139`, `gsm_sm.rs:441` (issue said `419`; it moved) | **each false in a different way** — see below |
| `handle_pdu_session_release_request` / `_modification_request` have no non-test caller | `gsm_handler.rs:339`, `:581`; grep → tests only | yes — **real**, and closed here |

### Found while verifying, and not in the issue: #52's `create_session` mutates a throwaway

This is the same defect #223 is about, one layer down, and it is why criterion 2's "observable
by the caller" wording matters more than it looks.

`sess_add_by_apn` returns a **clone** (`context.rs:2421`: `sess_list.insert(id, sess.clone())`
then `Some(sess)`). `create_session` then sets `sess.sgw_s5c_teid`, `sess.ipv4_addr`,
`sess.session_type` and `sess.session_ambr` on that clone, builds a local `SmfBearer` — and
**never calls `sess_update` or `bearer_add`**. So after a successful Create Session Request the
stored session has no UE address, no SGW TEID, no AMBR and no bearer at all: the response on
the wire is correct, and the SMF's own state does not know what it sent.

The consequence is exactly the one that blocks this issue. A later Delete Session Request or
Modify Bearer Request has nothing to act on — `sess_find_by_teid` would find a session whose
`sgw_s5c_teid` is 0, and no bearer exists to modify. **Criterion 2 cannot honestly be satisfied
without fixing this first**, because "reachable with observable mutations" requires a stored
session to mutate. Fixed here; a named test asserts read-back from the context.

## The decision (criterion 1)

**Two models, by design, with distinct and non-overlapping jobs. Neither is retired.**

* **`SmfSess` (+ `SmfUe`, `SmfBearer`) is the SMF's *session* model, on both accesses.** It is
  what the context stores and indexes: `sess_list` keyed by id, with secondary indices by
  `smf_n4_seid`, TEID, IPv4, IPv6, APN, PSI, charging id, `smContextRef` and
  `pdu_session_ref`. Every lookup a wire message can perform goes through it, because a GTPv2-C
  message carries a TEID and nothing else, and an N4 report carries a SEID and nothing else.
  Produced by `sess_add_by_psi` (5GC, #78) and `sess_add_by_apn` (EPC, #52).

* **`PolicyBinding` is the 5GC *policy-association* model**, keyed by `smContextRef`. It holds
  what the SBI procedures need and the session has no place for: the PCF `smPolicyId`, the
  EASDF DNS context id, the UDM SDM subscription id, the reported EAS list, and the per-session
  `GsmFsm`. These are 5GC-only by construction — there is no PCF, EASDF or UDM leg on S5/S8 —
  and they are *associations with other NFs*, whose lifetime is the SM context's, not the
  user-plane session's.

**Why not fold them (the issue's option 3).** `PolicyBinding`'s members are references into
other NFs that must be *deleted* at release, and the release path keys on `smContextRef`
because that is what the AMF sends. Folding them into `SmfSess` would put five nullable
5GC-only NF handles on every EPC session, and would make the EPC path carry a `GsmFsm` that
TS 24.501 does not run for it.

**Why not retire `SmfSess` (option 1).** It is the live, indexed session store on both
accesses, and the four issues that would have had to restart from nothing have all landed on
it.

**What this decision costs, stated plainly.** The two models are populated on the 5GC create
path and removed on the same release, and nothing enforces that they agree. `sm_context_exists`
(`main.rs:5437`) already accepts *either*, with a recorded rationale. That is the seam this
decision keeps, and it is the first place to look if a release leaves half a context behind.

## The three comments: each one false in a different way

The issue is right that these are what make the state actively misleading. None of them was
simply out of date.

* **`smf_sm.rs:120`** — "GTPv2 message parsing and dispatch handled by `gtp_handler` module",
  in `handle_s5c_message`, followed by five lines claiming message types are "routed to GSM FSM
  via event queue". The dispatch half is now **true but not through here**: `gtp_path.rs:1209`
  dispatches from the socket, and `SmfEvent::s5c_message` — the only constructor of the event
  this function handles — **has no caller at all**. So the function is the dead code, not
  `gtp_handler`, and the "routed to GSM FSM via event queue" claim is false for a second,
  independent reason: there is no such queue hop. Rewritten to say the real path and that this
  FSM arm is vestigial.

* **`smf_sm.rs:139`** — the same claim for **GTPv1/Gn**, and this one is false in a way the
  issue did not suspect: `gtp_handler.rs` is GTPv2-only (`use nextgcore_gtp::v2`). Gn is
  `gn_handler.rs`/`gn_build.rs`, and **those have no callers** — `grep` outside the two files
  finds only `mod gn_build;` / `mod gn_handler;` at `main.rs:38-39`. So the comment names the
  wrong module *and* the module it should have named is genuinely dead. Rewritten to name
  `gn_handler` and to say no transport binds a GTPv1-C socket.

* **`gsm_sm.rs:441`** (the issue cited `419`; it moved) — "Message type parsed from GTP header
  via `gtp_handler`", then "Delete Session Request -> transition to `WaitPfcpDeletion`". The
  parse half is true of `gtp_handler`; the **transition does not happen**, because
  `handle_s5c_operational` is only reachable from the uncalled `SmfEvent::s5c_message`. Since
  this change routes Delete Session on the real path, rewritten to point at
  `gtp_handler::delete_session` and to say where the teardown actually happens.

Not deleted, per the issue's instruction: each now describes the live path, so a reader
following it arrives somewhere real.

## Criterion 2: reachable, with mutations observable by the caller

Wired from the **EPC/GTPv2 side**, which the issue explicitly and correctly identifies as the
honest hook — synthesising an `SmfSess` from a `PolicyBinding` on the 5GC path would satisfy the
grep while changing nothing.

`dispatch_s5s8_request` answered `ServiceNotSupported` (TS 29.274 §7.7) to everything except
CREATE_SESSION_REQUEST. Three arms added, each using handler functions and builders that already
existed:

* **DELETE_SESSION_REQUEST → `handle_pdu_session_release_request`** (TS 29.274 §7.2.3,
  TS 23.401 §5.4.4.1). The stored session is found by the request's TEID, the **5GSM** release
  handler is called on it — which is what makes criterion 2's named function reachable — the N4
  session is deleted, the session is removed from the context, and a Delete Session Response is
  built with `build_delete_session_response`. `handle_delete_session_request` (the GTPv2 half)
  guards it first.

  The 5GSM handler is called on the EPS path deliberately, and it is not a category error:
  `ngap_state = DeleteTriggerUeRequested` is the SMF's *own* record that a peer asked for this
  session to go, and it is asserted read-back **from the context** before removal, so the
  mutation is observable by the caller and not applied to a temporary.

* **MODIFY_BEARER_REQUEST → `handle_modify_bearer_request` + the 5GSM
  `handle_pdu_session_modification_request`** (TS 29.274 §7.2.7). The GTPv2 handler updates the
  SGW's control TEID and the bearer's S5-U endpoint; the 5GSM handler is then driven over the
  same bearer array with a QoS-flow-description modification synthesised from the accepted
  bearer QoS, so `sess.qos_flow_to_modify_list` is populated from a real request. Both the
  session and the bearer are written back with `sess_update`/`bearer_update`.

* **BEARER_RESOURCE_COMMAND → `handle_bearer_resource_command`** (TS 29.274 §7.2.5,
  TS 23.401 §5.4.5). The UE-requested bearer resource modification. Its TFT/QoS decision is
  written back to the stored bearer, and the response is the Bearer Resource Failure Indication
  when the handler rejects.

A fourth, smaller correction: `create_session` now `sess_update`s the session it mutated and
`bearer_add`s the bearer it built, so the three procedures above have something to find.

## Criterion 3: restated, because the grep tests the wrong thing

**Not satisfied literally, and should not be.** `grep -rn "SmfSess {"` still returns the
definition, two `impl`s and two `create_test_sess` helpers, and it will keep doing so however
live the model gets, because every live producer calls `SmfSess::new` inside `context.rs`
rather than writing a literal.

The criterion's *intent* — "no model whose only constructors are test helpers" — is met, and is
checkable:

```
$ grep -rn "sess_add_by_psi\|sess_add_by_apn" src/bins/nextgcore-smfd/src/ | grep -v "fn sess_add_by\|#\[cfg(test)\]"
gtp_handler.rs:1135:  ctx.sess_add_by_apn(ue.id, &apn, req.rat_type)     # EPC, #52
main.rs:5433:         let sess = context.sess_add_by_psi(ue.id, psi)?;   # 5GC, #78
```

Both are production call sites on paths a socket reaches. That is the honest form of this
criterion, and it is what the PR claims.

## Criterion 4: void

"If `SmfSess` is retired, migrate or remove `gsm_build`'s builders and `gtp_handler`." `SmfSess`
is **not** retired — it is the model the decision names — so the conditional never fires.
Narrowed rather than ignored: `build_delete_session_response` and `build_modify_bearer_response`
gain their first production callers here, so two of the eleven `SmfSess`-taking builders leave
the test-only set. The remainder (the PGW-initiated Create/Update/Delete Bearer *requests*) stay
test-only, and honestly so: nothing in this tree triggers a network-initiated dedicated-bearer
procedure yet.

## Verification

**8 new tests.** Workspace 6689 → 6697 passed, 0 failed, 6 ignored; smfd 509 → 517.
`cargo fmt --all -- --check`, `cargo clippy --workspace` and
`cargo clippy -p nextgcore-smfd --all-targets` clean (zero warnings from the changed files;
the three pre-existing workspace warnings are in `nextgcore-nas`, `nextgcore-eesd` and
smfd's untouched `main.rs`). CI's non-default-feature jobs
(`cargo test -p nextgcore-easdfd --features dns-udp` and its clippy) pass.

**Flake check:** the smfd crate suite run 10× consecutively, 10/10 green at 12.15–12.28 s,
load average 4.10 falling to 1.56. Every new test binds port 0, so none joins the tree's 112
fixed-port bind sites. Each uses an IMSI and SGW TEID literal distinct from every other
(`0x31`–`0x37` / `0x31000001`–`0x37000007`), commented at the fixture, because the session
store is process-global and a shared IMSI would make two tests share a UE. All take
`PROCESS_STATE_TEST_LOCK` then a stand-in UPF, in that order. No new lock was declared.

**Revert-verified: 12 reverts, 10 bit.** Each change undone individually, the named test
watched to fail, then restored: `create_session`'s `sess_update`; its `bearer_update`; the
`handle_pdu_session_release_request` call; the `handle_pdu_session_modification_request` call;
each of the three dispatch arms separately; `modify_bearer`'s write-back;
`bearer_resource`'s `bearer_update`; `reject`'s sequence-number echo; the Flow QoS octet
layout; the Modify Bearer F-TEID instance.

**The two that did NOT bite are the useful part of the pass**, and both are recorded in the
code rather than papered over:

* **`session_for_teid`'s absent-TEID guard.** Changing `teid?` to `teid.unwrap_or(0)` broke
  nothing, because SEID 0 is never allocated — `n4_seid_generator` starts at 1. The guard is
  defence in depth against a future allocator change, not a live fix, and its doc comment now
  says exactly that instead of implying a vulnerability was closed. Not tested, because a test
  would have to reach into a private field to occupy SEID 0 and would then be asserting on its
  own fixture.
* **The Delete Session Linked-EPS-Bearer-ID parse.** Replacing it with `None` broke nothing,
  because `record_eps_release`'s fallback to the stored default bearer reaches the same
  identity for a single-bearer session — and no session in this tree has more than one bearer,
  since no dedicated-bearer procedure is originated. The *fallback* was symmetrically
  unguarded for the same reason, so a **new test** was added
  (`a_delete_session_request_with_no_linked_ebi_still_records_the_release`) which drives the
  no-LBI path; the fallback revert then bit. The parse itself stays redundant-but-correct, and
  its comment records that a revert cannot distinguish it today.

One test was also **rewritten because it caught a real race in itself**: the release
assertion originally polled the session store from a spawned task, and lost every time,
because `delete_session` answers the SGW-C and calls `sess_remove` within one scheduler tick
of the handler returning. `record_eps_release` was extracted so the mutation is asserted
deterministically, and the wire teardown is a separate test. The polling version would have
been a permanent 100 % failure, not a flake — but the same shape at a different speed is how
a 1-in-3 flake gets committed.

**Ceilings, stated rather than implied:**

* **No SGW-C, no UPF, no UE.** The new tests drive the real `S5S8Server` over a loopback UDP
  socket bound on port 0 (the same harness #52's tests use, and port 0 rather than a fixed port
  because this crate's suite runs in parallel), with `pfcp_path::stand_in::associated_upf` as
  the UPF. The N4 exchange is the stand-in's, not a real UPF's.
* **The TAD is not parsed.** `handle_bearer_resource_command`'s `has_packet_filters` argument
  exists because the pre-existing handler does not decode the Traffic Aggregate Description —
  its own comment says "would need to parse TAD to determine this properly". This change passes
  the flag from the presence of a Flow QoS IE rather than from decoded filters, and does not
  add a TAD decoder. So a Bearer Resource Command is routed, guarded and answered, and the
  *specific* TFT operation it requests is not distinguished. Named here because the honest
  alternative was a TAD decoder this issue did not ask for.
* **No GTPv1/Gn transport.** `gn_handler.rs` and `gn_build.rs` remain callerless. Recorded in
  the rewritten `smf_sm.rs:139` comment rather than fixed: binding a GTPv1-C socket is a
  separate interface, not a comment fix.
* **The two-model seam is unenforced**, as the decision says. Nothing asserts that a
  `PolicyBinding` and its `SmfSess` are created and destroyed together; `sm_context_exists`
  deliberately accepts either.
* GitNexus impact analysis was **not run** — no MCP server is connected.
