# The AMF as UEContextTransfer consumer, and a 5G-GUTI that resolves

**Issue:** nextgcore #352 (split from #72, criteria 4-6; labelled `architecture` + `decision` + `needs-human`)
**Verified against:** nextgcore `main` @ `6cfcc1f`
**Spec basis:** TS 29.518 §5.2.2.2.1.1, §6.1.3.2.2, §6.1.3.2.4.4; TS 23.502 §4.2.2.2.2 steps 4-5;
TS 23.003 §2.10 (5G-GUTI construction); TS 23.501 §5.9.4; TS 24.501 §5.4.4.6; TS 29.510 §6.1.6.2.4.
Spec text read at `6g_docs/specs/{29518-k00,23502-k20,23003-k00,23501-k20,24501-j62}.txt` and
`6g_docs/specs/TS29518_Namf_Communication.yaml`; every quotation cites a line there.

## Read this first: the blocker this issue was handed back on is CLOSED

#352's own last comment (2026-09-19) hands the issue back with:

> So criteria 4 and 5 cannot be satisfied without choosing a store, and choosing one here would
> pre-empt #341 in the middle of a feature PR.

**#341 closed COMPLETED on 2026-09-19** via PR #374, *"feat(amfd): one authoritative UE store, with
derived resolvers"*. The handback is stale in exactly the way this project's conventions warn about.
Concretely, what #374 changed:

- `src/bins/nextgcore-amfd/src/ue_store.rs` is new. `UeStore::find_by_guti` (`:235`) **derives** the
  GUTI resolver by scanning the one live map, so there is no `guti_ue_hash` to be unwritten. The
  index whose absence the handback called "the load-bearing half" no longer exists to be missing.
- `AmfContext::amf_ue_find_by_guti` (`context.rs:1173`) now delegates to it, and its doc comment says
  so.
- `amf_ue_update_guti` and `guti_ue_hash` are **gone** from amfd (`rg guti_ue_hash
  bins/nextgcore-amfd` is empty; the surviving hits are `mmed`, a different daemon).

So the premise "a caller for the lookup would return `None` for every UE" is void. Whatever writes
`current_guti` into the store is automatically visible to `find_by_guti`, and the NGAP path already
writes it: `ngap_path.rs:1808` (Registration Complete) and `:1834` (Configuration Update Complete),
both through `ue_auth_state.with_mut`, which mutates the record **in the store**.

That leaves exactly one real gap on the lookup side, and it is not the one the handback named.

## Verified against current main

| claim | check on `6cfcc1f` | still true? |
|---|---|---|
| **C4:** `amf_ue_find_by_guti` has zero callers | `rg find_by_guti bins/nextgcore-amfd` → definition (`ue_store.rs:235`), wrapper (`context.rs:1173`), 2 store unit tests. **No production caller.** | yes — **real** |
| **C4:** the GUTI branch asks for SUCI unconditionally | `ngap_path.rs:2397` `log::info!("Registration with unknown 5G-GUTI: requesting SUCI")`, reached for *every* GUTI | yes — **real** |
| **C5:** `find_ue_by_context_id` handles only `imsi-`/`nai-` | `namf_server.rs:256-264`: `if ue_context_id.starts_with("imsi-") \|\| starts_with("nai-") { … } else { None }` | yes — **real** |
| **C6:** only the producer exists, no consumer client | producer `handle_ue_context_transfer` (`namf_server.rs:2364`), routed at `:105`. `rg` finds no outbound UEContextTransfer call | yes — **real** |
| `SbiServiceType` has no `Namf` variant | `sbi_path.rs:145-164`: 9 variants, none `Namf*` | yes — **real** |
| `resolve_nf_endpoint_async` returns `ServiceNotFound` outside its match | `sbi_path.rs:1529` `_ => return Err(SbiError::ServiceNotFound(...))` | yes — **real** |
| blocked on #341 | **#341 CLOSED COMPLETED, PR #374 merged** | **NO — void.** See above |
| `guti_ue_hash` unwritten, `amf_ue_update_guti` has zero callers | both **deleted** by #374 | **NO — void** |
| "the index is the missing piece, not the caller" | resolver is derived; there is no index | **NO — void** |
| `AmfUe.current_guti`/`next_guti` both maintained | `ngap_path.rs:1808`, `:1834`, `:3789-3793`, `:5907` | yes |
| T3555 abort keeps only the old GUTI, with a comment pointing here | `ngap_path.rs:5888-5907` | yes — **real** |
| the T3555 rule is **TS 24.501 §5.4.4.3** | §5.4.4.3 (`24501-j62.txt:25035`) is *"Generic UE configuration update accepted by the **UE**"* — UE-side behaviour, and says nothing about what the AMF keeps valid | **NO — wrong cite.** The rule is §5.4.4.6 (`:25900`). See below |
| `registration_request_from_old_amf` exists to decide "is this GUTI foreign" | `gmm_handler.rs:672`, compares `old_guti` against `served_guami` — correct, and has **only test callers** | **real, and not in the issue at all** |

### The issue's T3555 citation is wrong, and the correction narrows the rule

#352 says:

> TS 24.501 §5.4.4.3's fuller answer is that BOTH GUTIs stay valid after an aborted reallocation

§5.4.4.3 is the **UE's** side. The AMF's rule is §5.4.4.6 *"Abnormal cases on the network side"*,
case a) (`24501-j62.txt:25904`):

> The network shall, on the first expiry of the timer T3555, retransmit the CONFIGURATION UPDATE
> COMMAND message … on the fifth expiry of timer T3555, the procedure shall be aborted. In addition,
> **if the CONFIGURATION UPDATE COMMAND message includes the 5G-GUTI IE, the network shall behave as
> described in case b)-1) below.**

and b)-1) (`:25918`):

> if the CONFIGURATION UPDATE COMMAND message includes the 5G-GUTI IE, the old and the new 5G-GUTI
> shall be considered as valid until the old 5G-GUTI can be considered as invalid by the AMF.

with §5.4.4.6 b)-1) ii) (`:25985`):

> shall consider the new 5G-GUTI as valid **if it is used by the UE** and, additionally, the new TAI
> list as valid if it was provided with this 5G-GUTI

The substance is what #352 claimed — both stay valid — but the *mechanism* the spec prescribes is
narrower and more useful than "keep two GUTIs in a set": the AMF accepts **either**, and whichever
the UE actually presents becomes the sole valid one and the other becomes invalid. That is a
resolver rule plus a commit, not a dual-identity data structure. It is implemented that way here
(see "What changed", item 2), which is why the correction is load-bearing rather than pedantry.

### Found while verifying, and not in the issue: two more dead functions that already answer C4/C6

Neither is mentioned anywhere in #352, #72 or #341, and both change the size of this work:

1. `gmm_handler::registration_request_from_old_amf` (`gmm_handler.rs:672`) already implements
   "is this `old_guti` served by one of my GUAMIs?", including the all-zero-GUTI guard. Its only
   callers are its own tests (`:1133`, `:1157`). C6's stated open question — *"how the AMF learns that
   a GUTI belongs to a different AMF"* — is already answered in-tree by a function nothing calls.
2. `sbi_path::amf_id_hex` (`sbi_path.rs:1694`) already packs `AmfId` to the 6-hex-digit TS 23.003
   §2.10.1 form, and `guami_json` (`:1672`) already renders a whole GUAMI to TS 29.571 shape. The
   `5g-guti-…` path component and the `guami` discovery parameter both need exactly these, so neither
   gets a second renderer.

## The decision this issue asks for (C6): how the AMF finds the old AMF

#352 states the question and declines to answer it:

> plus the decision of how the AMF learns that a GUTI belongs to a *different* AMF (the AMF Set /
> Region in the GUTI, an NRF discovery, or configuration) — which is not stated in #72 and should be
> settled before coding.

**Decided: all three, in a fixed order, because TS 23.502 splits the question in two and the three
options answer different halves.** The spec text makes this not a choice between them:

> The new AMF **determines the old AMF using the UE's 5G-GUTI**. (TS 23.502 §4.2.2.2.2 step 4,
> `23502-k20.txt:3973`)

That sentence is about *identifying* the old AMF, and the 5G-GUTI is the only input it names. It says
nothing about *reaching* it. So:

1. **Is the GUTI foreign?** From the GUTI alone, against `served_guami` — no network round-trip.
   This is `registration_request_from_old_amf`, given its first production caller. TS 23.003 §2.10
   (`23003-k00.txt:2479`) makes this decidable locally: `<5G-GUTI> = <GUAMI><5G-TMSI>` where
   `<GUAMI> = <MCC><MNC><AMF Identifier>`, so the GUTI *contains* the identity of the AMF that
   issued it.
2. **Which AMF is it?** The GUAMI recovered from the GUTI, used as the NRF
   `guami` discovery parameter (`TS29510_Nnrf_NFDiscovery.yaml:237`, *"Guami used to search for an
   appropriate AMF"*). This is the only mechanism that scales: it needs no per-peer configuration and
   it is how the NRF is specified to be asked.
3. **Where is it?** The discovered profile's `namf-comm` endpoint, with an
   `AMF_PEER_SBI_ADDR`/`AMF_PEER_SBI_PORT` env fallback for a two-AMF bring-up that has no NRF —
   the same env-then-NRF shape every other `resolve_nf_endpoint_async` arm already has
   (`sbi_path.rs:1486-1530`), so no new resolution convention is introduced.

The AMF's own registered profile already carries `amfInfo.guamiList` (`sbi_path.rs:389`, added by
#92), so a peer AMF asking the NRF by GUAMI can be answered by *this* AMF today. The producer half of
discovery needs nothing.

### Rejected options, and what each costs

**A. Configuration-only (a peer-AMF table keyed by GUAMI).** Rejected. It is `O(n²)` operator
configuration across an AMF set, and it fails the case the feature exists for: an AMF added to the
set is invisible to every incumbent until each one is reconfigured and restarted. TS 23.502 names no
configured table. Kept **only** as the addressless fallback in step 3, where it buys a two-AMF
bring-up with no NRF and cannot silently substitute for discovery, because it is consulted after the
NRF and logged when used.

**B. Derive the address from the GUTI directly (e.g. an FQDN template over AMF Region/Set/Pointer).**
Rejected. TS 23.003 §2.10 defines the GUTI's *structure*, not a naming convention, and
`23003-k00.txt:2469` makes only the Set+Pointer combination unique, and only *within* a Region. Any
template is a local invention that would interoperate with nothing.

**C. Go via the UDSF (`Nudsf_UnstructuredDataManagement_Query`).** Rejected as out of scope, not as
wrong. TS 23.502 step 4 offers it as the alternative to UEContextTransfer — but only "If … new AMF
and old AMF are in the same AMF Set and UDSF is deployed" (`:3979`), and **there is no UDSF daemon in
this tree** (`ls src/bins` → 28 daemons, no `udsfd`). Choosing it would mean building a network
function to avoid a decision. #352 asks for the UEContextTransfer path by name.

**D. Query the NRF for every AMF and filter `amfInfo.guamiList` client-side.** Rejected. It works
today — `nrfd`'s `discover_profiles` would return the set and the GUAMI comparison is local — but it
moves a selection the NRF is specified to perform into every consumer, and it is how #92 was broken
from the other end (a consumer that could not identify an AMF fell back to the first one discovered).
The `guami` parameter exists precisely so this is server-side.

### The ceiling this decision accepts, stated honestly

`nrfd`'s `DiscoveryQuery` (`nnrf_handler.rs:1759-1788`) has **no `guami` field**, and
`profile_matches` (`:1958`) therefore cannot filter on it: `nf_info_for_type` (`:1843`) looks only at
`udmInfo`/`udrInfo`/`ausfInfo`. So against *this* tree's NRF, a `guami`-parameterised query is
answered with every registered AMF rather than the one asked for.

This is handled, not ignored, and not by widening `nrfd` (which is not in #352's scope and would let
this PR grow a second daemon's discovery filter): the consumer **sends** the conformant `guami`
parameter and then **verifies the answer** against `amfInfo.guamiList` client-side, selecting the
profile whose GUAMI matches and refusing to transfer if none does. Against a conformant NRF the
filter is server-side and the check is a no-op; against this one the check is what makes the
selection correct. The `guami`-aware NRF filter is filed separately rather than smuggled in here.

**Why verify rather than trust the first result:** transferring a UE context from the *wrong* AMF is
worse than not transferring it. It would import another subscriber's MM context under this UE's
identity. So the selection fails closed: no GUAMI match, no transfer, and the registration falls back
to identifying the UE by SUCI — which is the behaviour of `6cfcc1f` and is always safe.

## What changed

### 1. C4 — a locally-issued 5G-GUTI resolves, and a foreign one is recognised

`ngap_path.rs`, the `mobile_identity_type::GUTI` arm of `handle_registration_request_nas`. Three
branches replace one unconditional Identity Request:

- **Local GUTI, context found** (`find_by_guti` hits): the UE is identified without an Identity
  Request. TS 23.502 §4.2.2.2.2 skips steps 4-5 when the context is already held. The SUPI, SUCI and
  security context are adopted from the resolved record onto this registration's record.
- **Foreign GUTI** (`registration_request_from_old_amf` is true): the inter-AMF path, item 3 below.
- **Local GUTI, no context** (the AMF issued it but has since lost the record — a restart): the
  Identity Request, i.e. `6cfcc1f`'s behaviour, which is correct for this case and was merely being
  applied to all three.

The writeback hazard is live here: `ue_store::get` returns a clone
(`ue_store.rs:112`, deliberately, so no guard crosses an `.await`), and #361/PR #389 fixed this exact
handler discarding one. Every branch added here ends in an `insert`, and the local-hit branch is
asserted **positively** — the test checks the resolved SUPI is on the record in the store, which is
only reachable through the lookup.

### 2. C4/§5.4.4.6 — the T3555 abort, corrected

`ngap_path.rs`, the `NasProcTimer::T3555` abnormal-action arm. `6cfcc1f` sets
`next_guti = current_guti`, discarding the reallocated identity, with a comment deferring to this
issue. Per §5.4.4.6 a) → b)-1) both remain valid, so **neither is overwritten**: the record keeps
`current_guti` and `next_guti` distinct and the resolver accepts either. b)-1) ii) — "shall consider
the new 5G-GUTI as valid if it is used by the UE" — is the commit: when a registration presents the
UE's `next_guti`, that becomes `current_guti` and the old one stops resolving.

This is why the corrected citation mattered. Under the issue's reading ("both stay valid") the
natural implementation is a set of valid GUTIs with no rule for collapsing it; §5.4.4.6 b)-1) ii)
supplies the collapse rule, so the dual-validity window is bounded by the UE's next transaction
instead of living forever.

### 3. C6 — the outbound consumer

New in `sbi_path.rs`:

- `SbiServiceType::NamfComm`, naming the `namf-comm` service in the consumer direction.
  Deliberately **not** given a `resolve_nf_endpoint_async` arm: that resolver answers "where is
  *an* NF of this type" and returns `instances.first()`, which is the wrong question here — see
  the ceiling note below and `discover_peer_amf_by_guami`'s own doc comment.
- `discover_peer_amf_by_guami(&Guti5gs) -> Option<(String, u16)>`: queries
  `GET /nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=AMF&service-names=namf-comm&guami=…`
  with the GUAMI JSON-encoded through the existing `guami_json`/`amf_id_hex` renderers, then selects
  the profile whose `amfInfo.guamiList` contains that GUAMI. Fails closed.
- `call_amf_ue_context_transfer(...)`: `POST {peer}/namf-comm/v1/ue-contexts/{5g-guti-…}/transfer`
  with a `UeContextTransferReqData` — `reason`, `accessType`, and for `MOBI_REG` the
  integrity-protected Registration Request as a `multipart/related` binary part with a `contentId`
  the JSON references, which is what this tree's own producer requires (`namf_server.rs:2392-2403`)
  and what §5.2.2.2.1.1 step 1 mandates.
- `call_amf_registration_status_update(...)`: `POST …/transfer-update` with
  `transferStatus: TRANSFERRED`, closing the procedure at the old AMF per §5.2.2.2.2. Without it the
  old AMF holds the context on its implementation-specific guard timer (TS 23.502 step 5) and never
  learns the transfer succeeded.

`reason` follows §5.2.2.2.1.1: `INIT_REG` for an initial registration, `MOBI_REG` for a mobility
update, which is the registration type the UE sent.

### 4. C5 — `find_ue_by_context_id` resolves a `5g-guti-…` path component

`namf_server.rs`. The pattern is fixed by both the OpenAPI
(`TS29518_Namf_Communication.yaml:48`) and Table 6.1.3.2.2-1 (`29518-k00.txt:7675`):

    5g-guti-[0-9]{5,6}[0-9a-fA-F]{14}

parsed as 5-6 decimal digits of MCC+MNC (5 for a 2-digit MNC, 6 for 3) followed by 14 hex digits =
6 for the `AMF Identifier` + 8 for the 5G-TMSI, matching TS 23.003 §2.10's field widths (Region 8 +
Set 10 + Pointer 6 = 24 bits = 6 hex; 5G-TMSI 32 bits = 8 hex). Unpacked with the inverse of
`amf_id_hex` so the two cannot drift. A GUTI that parses but matches no UE is `404
CONTEXT_NOT_FOUND`, as for a SUPI.

This is what makes this AMF a usable *peer*: without it, the consumer built in item 3 would be
sending a request this tree's own producer answers `404` to, so the two halves are only jointly
testable.

## The #74 boundary

#74 (*"amfd namf: missing inter-AMF context, PWS/status-change, EventExposure targeting/emission and
Namf_Location→LMF routing"*) is open and its title overlaps. The boundary, from #74's own acceptance
criteria:

| belongs to **#352** (this PR) | belongs to **#74** |
|---|---|
| the **consumer** of `UEContextTransfer` — the outbound client, peer discovery, the GUAMI decision | the **producer** router arms for `PUT /ue-contexts/{id}` (CreateUEContext), `/release`, `/relocate`, `/cancel-relocate` |
| `5g-guti` in `find_ue_by_context_id` (needed by the consumer's peer) | `/non-ue-n2-messages/transfer` (PWS), `/subscriptions` (AMFStatusChange) |
| GUTI-indexed resolution in the registration path; the §5.4.4.6 T3555 correction | EventExposure `gpsi`/`pei`/`groupId` targeting; the 9 never-fired event types |
| `RegistrationStatusUpdate` **as consumer** (closing the procedure at the old AMF) | `namf-loc` `provide-loc-info`/`cancel-pos-info` routing; LMF-driven positioning |
| — | adding `namf-mt`/`namf-loc` to the NF profile |

The two do not overlap once split by **direction**. #352 is the AMF acting as a *consumer* of another
AMF; #74 is the AMF's *producer* surface. The one place they touch is `find_ue_by_context_id`, which
#74's CreateUEContext will also need — done here, so #74 inherits it.

**The gap neither issue claims, named so it is not lost:** the UE context this consumer *receives* is
logged and its SUPI adopted, but the received `sessionContextList` does not reconstruct PDU sessions
at the new AMF. That needs `Nsmf_PDUSession_UpdateSMContext` toward each listed SMF to move the N3
tunnel (TS 23.502 §4.2.2.2.2 step 21), which is the N2 handover machinery, not the context-transfer
consumer. #74's `/relocate` arm is its natural home. It is stated here rather than elsewhere because
both issues could otherwise assume the other has it.

## Ceilings

1. **`nrfd` cannot filter on `guami`.** Described above; mitigated by client-side verification
   against `amfInfo.guamiList`. Against a conformant NRF the query is already correct.
2. **A received `sessionContextList` is not re-established.** Above; belongs to #74's `/relocate`.
3. **Integrity verification of the transferred context is the old AMF's.** §5.2.2.2.1.1 has the old
   AMF verify the Registration Request MAC and answer `403 INTEGRITY_CHECK_FAIL`; the consumer sends
   the protected message and honours the verdict. It does not second-guess it, which is correct —
   only the old AMF holds the security context the MAC was computed under.
4. **No two-AMF E2E.** `a_foreign_guti_fetches_the_ue_context_from_the_old_amf` stands a real
   in-process `SbiServer` up on an ephemeral port as the old AMF, so the `5g-guti-…` path component,
   the `multipart/related` Registration Request and both legs of the procedure go over a real HTTP/2
   connection — but it is one process, and the peer is reached through the configured-peer fallback
   rather than a live NRF. Two `amfd` processes over a real NRF is a compose-topology change, and
   `Docker E2E` is gated to `schedule || workflow_dispatch` in this tree, so it would not run on a PR
   anyway.

5. **The GUAMI-keyed NRF query is unit-tested, not integration-tested.** `guami_json_eq` and
   `namf_comm_endpoint` are pinned directly (including that two GUAMIs which both omit `amfId` must
   NOT compare equal — the #92 shape); the HTTP round trip against an NRF that implements the
   `guami` filter cannot be tested here because this tree's NRF does not implement it.

## Found while implementing: two test-isolation defects, both pre-existing patterns

Neither is in #352, both cost real debugging, and both were caught by looping the crate suite rather
than by a single run — worth recording because the next agent in `amfd` will meet them.

1. **`set_sbi_profile_override` must not be reset.** The override is process-wide, and every
   loopback-plaintext test in this crate sets it to `Dev` and leaves it set. Calling
   `reset_sbi_profile_override()` at the end of the new peer-AMF test flipped siblings back to
   Production *mid-flight* — measured at 2 failures in 10 whole-crate runs, in `sbi_path`'s
   `ue_policy_create_carries_the_ue_policy_container_as_ue_pol_req` and `ngap_path`'s
   `setup_response_relays_every_pdu_session_not_just_the_last`. `smfd/src/main.rs:7426` records the
   identical finding for the identical reason; the reset is now omitted with a comment saying so.
   Note the corollary: the test passed *before* the override was added only because a sibling had
   left the profile on `Dev`, which is a green for the wrong reason.

2. **`handle_registration_request_nas` consults process-global congestion state.**
   `nas_congestion_backoff` reads `amf_ue_count()` off the shared context, so as sibling tests add
   UEs the count crosses `AMF_CONGESTION_*` and the registration is refused with 5GMM #22 **before**
   the GUTI arm. That produced ~3 failures in 10 whole-crate runs, always with a default `AmfUe` on
   the record. The affected test now drives the identification step directly; the two that still go
   through the whole handler assert on state written after that gate.

Both are the reason `resolve_registration_by_guti` ended up as identification-only rather than
ending in `start_authentication`: a step that does one thing can be observed on its own, and the
AUSF-failure arm of `start_authentication` releases the UE, which erased the very state the
criterion is about.
