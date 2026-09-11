# fix(mmed): make the attach path reach S11 and the response reach the Attach Accept

Closes #329. Unblocks the MME half of #303 (whose remaining blocker is #328, the
"nothing can originate an S1AP attach" decision).

## What was broken

Two senders, both built and unit-tested, with **zero callers** — and, once wired, four
more breaks behind them. The EPS attach could not complete, and each layer was invisible
from the one above it.

| # | gap | site | how it presented |
|---|---|---|---|
| 1 | the NAS path never sent the Create Session Request | `nas_dispatch.rs:1322`, `:1386` | logged *"the S11 Create Session Request to the SGW is not implemented (#51)"* — and #51 was CLOSED |
| 2 | no SGW-UE context existed at request time | `context.rs:1957` | `send_create_session_request` → `ContextNotFound` for every attach |
| 3 | `mme_s11_teid` was never assigned | `context.rs:1039` | every CSR carried Sender F-TEID **0** |
| 4 | `mme_s11_teid_hash` had a reader and **no writer** | `context.rs:1480,2021` | `mme_ue_find_by_s11_local_teid` always `None`, so every Create Session Response was dropped as matching no UE |
| 5 | the PAA was parsed and discarded | `s11_handler.rs:291` | the UE's IP address never reached the session |
| 6 | the response could not tell which procedure it belonged to | `gtp_path.rs:545` | no create action reached the response path |
| 7 | the Attach Accept was unreachable | `nas_path.rs:266` | zero callers |
| 8 | a reachable panic on the accept path | `esm_build.rs:616` | `.expect("value expected")` on an absent subscription record |
| 9 | the accept named a fabricated EBI | `nas_path.rs:285` | `build_activate_default_bearer_context_request` invents `ebi: 5`, ignoring the real bearer |

Gaps 2-4, 8 and 9 are **not in #329's text**. Each was found by the previous one's fix
making the next line of code run for the first time — which is the pattern worth
recording: a chain of unreachable code hides its own defects, and they surface strictly
one at a time.

### Why 1 fell between two closed issues

#51's eight criteria are all about transport, sequencing and message construction, and
`specs/fix-mmed-s11-gtpc-endpoint.md:144-151` states the ceiling explicitly: *"the attach
procedure still does not complete… wiring the Create Session Response into an Initial
Context Setup plus an Attach Accept is #46's subject."* #46 then closed by satisfying its
criterion via the **TAU** path and left the attach half blocked. So the call sites were
each other's follow-up, and the log lines kept citing an issue that had already shipped
everything it promised.

## What changed

**`context.rs` — the UE gets its S11 identity when it is created.**
`mme_ue_add` now allocates `mme_s11_teid` (from the pool id, `+1` so it is never 0 —
which is what the broken state sent and what a peer reads as "no TEID") and registers it
in `mme_s11_teid_hash` in the same breath, so the index cannot drift from the field. It
also creates and associates the `SgwUe` context, because
`send_create_session_request` resolves it on the REQUEST path while the only previous
creator ran on the response path — the MME could not send the request whose response
would have created the context it needed to send it. `mme_ue_remove` removes the index
entry keyed by **the removed context's** TEID, the same discipline the IMSI line beside
it follows and for the same reason a previous defect there taught.

**`gtp_path.rs` — `PENDING_CREATES`, keyed by S11 sequence number.**
`send_create_session_request` already returned a `GtpXactData` carrying the create action
and the eNB UE id, and its (absent) caller was expected to hold it. The response path
receives only bytes, type, sequence and peer, so the create action had to travel
somewhere. Keyed by sequence number because that is what `match_response` already
correlates on — one notion of "which request is this the answer to" rather than two that
can disagree. Records are **taken**, not read, so a duplicated or retransmitted response
cannot drive the continuation twice.

**`nas_dispatch.rs` — the two call sites**, via one `send_s11_create_session` helper that
maps `esm_build::CreateAction` to `s11_build::GtpCreateAction`. A send failure is logged
and NOT turned into a reject: the ESM procedure is still open and its T3485/T3489 timers
govern the outcome, so synthesising a reject would race them.

**`s11_handler.rs` — the continuation.** `apply_create_session_response` now takes its
pending record, stores the PAA, and on `AttachRequest` **only** calls
`nas_eps_send_attach_accept`. The PDN type comes from the **response**, not from what the
UE requested: TS 29.274 §8.14 lets the network grant a narrower type, and honouring the
request would tell the UE it has an address family the PGW never allocated. An undefined
PDN type stores nothing rather than pairing a real address with a type no one can read.

**`nas_path.rs` / `esm_build.rs` — the accept says what it means.** The accept path now
calls `build_activate_default_bearer_context_request_with_params` with the real
`default_bearer` it was handed, instead of the simplified helper that fabricates EBI 5 —
otherwise the ESM message told the UE to bind EBI 5 while the E-RAB in the enclosing
Initial Context Setup (built from the same `default_bearer` a few lines down) could name a
different one. And the simplified helper's `.expect("value expected")` on
`sess.session` — absent for any session the HSS has not populated — becomes a default plus
a warning. A crashing MME is strictly worse than a default-QoS bearer, and that panic was
about to become reachable for the first time.

## Three parallel create-action enums

`esm_build::CreateAction` (what the ESM handlers take), `nas_path::GtpCreateAction` (what
the ESM builders take) and `s11_build::GtpCreateAction` (what the S11 builder takes). None
is a superset: `s11_build`'s has `UplinkNasTransport` and `PathSwitchRequest`, the others
have `InPdnConnectivityRequest` and `InHandover`. Unifying them is a separate change with
its own blast radius, so this maps explicitly in one readable place rather than leaving
the correspondence to be inferred. Recorded here because "count the implementations before
writing the abstraction" cuts both ways — three is the count, and the answer this time is
still not one.

## Verification

Whole workspace **6472 passed / 0 failed** (main: 6464). Clippy warnings unchanged at
**74**, all pre-existing. `cargo fmt --check` clean.

### Reverts, all of which bite

| revert | named test that failed |
|---|---|
| drop the `mme_s11_teid_hash` registration | `the_paa_from_a_create_session_response_reaches_the_session`, `an_attach_create_action_drives_the_attach_accept`, `a_tau_create_action_does_not_drive_the_attach_accept`, `the_activate_default_bearer_request_carries_the_stored_paa_and_real_ebi` |
| don't create the `SgwUe` with the UE | `the_pdn_connectivity_path_sends_a_create_session_request` |
| restore the "not implemented (#51)" log | `the_pdn_connectivity_path_sends_a_create_session_request` |
| drop the pending-create recording | `the_pdn_connectivity_path_sends_a_create_session_request` |
| drop the PAA store | three PAA/continuation tests |
| remove the create-action gate | `a_tau_create_action_does_not_drive_the_attach_accept` |
| use the simplified builder in the accept | `an_attach_create_action_drives_the_attach_accept` |
| restore the `.expect` on `sess.session` | `a_session_without_subscribed_qos_does_not_panic_the_esm_builder` |

### One revert did NOT bite the first time, and that is the finding

The builder-swap revert initially passed, because the EBI test called
`build_activate_default_bearer_context_request_with_params` **directly** and asserted on
the builder's own output — so it passed whichever builder `nas_eps_send_attach_accept`
chose. That is exactly the "the helper is tested and the wiring is not" shape, walked
into while fixing an issue about unreachable code.

The test now asserts the expected ESM bytes appear **as a subsequence of what the
production path buffered in `t3450.pkbuf`**, and uses **EBI 7** — with EBI 5 the
fabricated and real answers coincide, so the assertion could not have distinguished them.
With that, the revert fails.

### Observables are state, not logs

- the CSR is asserted from a **stand-in SGW-C socket's received datagram**, decoded with
  the library codec;
- the Sender F-TEID is asserted to **resolve back to the UE** through
  `mme_ue_find_by_s11_local_teid`, which is the lookup that was broken;
- the Attach Accept is asserted from **`mme_ue.t3450.pkbuf`** — the retransmission buffer
  the accept path fills — not from the S1AP send queue, because
  `s1ap_path::install_send_queue` is once-per-process and a sibling test already consumes
  that slot.

### One test installs the S11 server, deliberately

`S11_SERVER` is a `OnceLock`, so a second installer would silently use the first's socket
and assert about a sibling's traffic. `the_pdn_connectivity_path_sends_a_create_session_request`
is therefore the only installer and carries both the production-caller and the
correlation assertions; an earlier draft had a second install in `gtp_path`'s tests and it
was removed rather than left to race.

`S11_TEST_LOCK` was **promoted out of `gtp_path::tests`** to a `pub(crate)` static beside
the globals it guards, so `s11_handler`'s tests share the one agreement. Declaring a
second lock over the same variables is what #276 showed HANGS the suite rather than
merely flaking it.

20 consecutive `-p nextgcore-mmed` runs clean.

## Ceilings

- **Nothing can originate an S1AP attach.** There is no LTE eNB or UE simulator in this
  tree (`nextgsim` is 5G-only), so the chain is exercised from an uplink NAS PDU injected
  into `nas_eps_handle_uplink` rather than from a radio-side peer. That is #328's
  decision, and it is what still blocks #303.
- **The Modify Bearer Request is not driven from here.** TS 23.401 §5.3.2.1 continues past
  the Attach Accept to Initial Context Setup Response → Modify Bearer, and
  `send_modify_bearer_request` exists. It has its own trigger (the ICS Response) and is
  not on this path.
- **The EPS bearer identity is written as a whole octet** followed by the protocol
  discriminator (`esm_build.rs:559-560`) rather than packed into octet 1 as
  TS 24.301 §9.3.1 does. That is this build's existing convention across every ESM
  builder; the test follows the code's layout and says so rather than quietly asserting
  the spec's.
- **`build_activate_default_bearer_context_request`'s fabricated `ebi: 5` survives** for
  its other caller (`nas_path.rs:874`). Documented as a fallback for callers with no
  bearer to name; that caller should be given one, but it is a different path.
- **No E2E.** Every assertion is in-process, over loopback UDP where a socket is involved.

## References

- #329, #303 (blocked), #328 (the origination decision), #51 and its spec's Ceilings,
  #46 (closed via the TAU path)
- TS 23.401 §5.3.2.1; TS 29.274 §7.2.1, §8.14, §8.22; TS 24.301 §6.5.1.2, §9.3.1
- `context.rs:1957,1974,2020,2255`, `gtp_path.rs:619,545`, `nas_dispatch.rs:1322,1386`,
  `s11_handler.rs:291`, `nas_path.rs:266,285`, `esm_build.rs:605`
