# Fix ten NFs: ONE NRF registration per startup, advertising the surface each NF actually serves

**Issue:** nextgcore #392 (split out of #187, PR #391)
**Verified against:** nextgcore `main` @ `68f1003`
**Spec basis:** TS 29.510 §6.1.6.2.2 (`NFProfile`), §6.1.6.2.3 (`NFService`);
TS 23.501 §7.2.2 (AMF services), §7.2.3 (SMF), §7.2.25 (LMF), §8.2/§8.3 via TS 23.288 (DCCF).
Spec text read at `6g_docs/specs/29510-k00.txt` and `6g_docs/specs/23501-k20.txt`;
every quotation cites a line there.
**Precedent:** PR #237 (`32a091a`), which did this treatment for `pcfd`.

## Read this first: the issue's headline count is WRONG, and it changes the work

#392 says ten NFs "send **two separate NF registrations** to the NRF per startup, from two
independent code paths". Its evidence is a table of **`nf_instance_id` mint sites** — 3 for
`amfd`/`udmd`/`smfd`, 2 for the other seven. That table is accurate as a count of *mint sites*
and was re-verified below. But a mint site is not a registration site, and after PR #391 routed
every mint through the shared resolver most of those sites are not registrations at all: they are
the OAuth2 client constructor (`OAuth2Client::new`), the typed self-instance builder, and the
registration. Counting PUTs to `/nnrf-nfm/v1/nf-instances/{id}` instead gives a different answer.

**Exactly ONE of the ten has two live registration PUTs: `bsfd`.** The other nine already
register once. So "delete the second registration" — the fix the issue suggests for all ten —
is the right fix for one crate, and a no-op for nine.

That does not make the issue void. Its *stated defect* is real and worse than the count suggests:

> the profile the NRF ends up serving to discovery is now decided by whichever PUT lands last,
> and the two profiles do not carry the same attributes

The divergence is real in nine of ten crates, but it is not between two *registrations*. It is
between **what the NF routes and what its one registration advertises**. The NRF filters
discovery strictly on `nfServices[].serviceName` (`nnrf_handler.rs:1997-2016`: "the profile must
offer at least one requested service", and a non-offering profile is dropped from the
`SearchResult`). So a service that is routed and working but absent from the profile is
**undiscoverable** — the same consumer-visible failure #237 recorded for `pcfd`
("a consumer that discovered `policyauthorization` from the first got a profile with no port to
dial"), reached by a different route.

The sharpest instance is a live cross-NF break that #392 does not mention:

- `amfd` routes `namf-mbs-bc` (`namf_server.rs:187`) and `namf-mbs-comm` (`:174`), with real
  handlers (`handle_mbs_context_create` at `:2811` creates/looks up an MBS session context;
  `handle_mbs_n2_message_transfer` at `:2745` parses the TMGI and the N2 container).
- `mbsmfd` discovers the AMF **by that service name**: `namf_client.rs:54` issues
  `GET /nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=MB_SMF&service-names=namf-mbs-bc`.
- `amfd`'s registration advertises **`namf-comm` only** (`sbi_path.rs:375-388`).

So the NRF drops the AMF from that `SearchResult`, `mbsmfd` finds no AMF, and
`main.rs:587` logs "no AMF advertises namf-mbs-bc" — a correct diagnosis of a defect on the
*other* NF. MBS broadcast bring-up cannot work over discovery. This is the #92 shape (a profile
that omits what a discovering peer filters on) and it is fixed here.

## Verified against current main

Every cite in #392 re-located at `68f1003`. The issue verified at `6ba388d`, pre-#391.

| claim in the issue | check on `68f1003` | still true? |
|---|---|---|
| `amfd` 3 mint sites at `lib.rs:281`, `sbi_path.rs:288`, `:364` | `lib.rs:282`, `sbi_path.rs:289`, `:367` | yes (±3 lines) — but only `:367` registers |
| `udmd` 3 at `app.rs:282`, `:3588`, `sbi_path.rs:112` | `app.rs:283`, `:3591`, `sbi_path.rs:112` | yes — only `app.rs:3591` registers on the startup path |
| `smfd` 3 at `main.rs:200`, `:1248`, `udm.rs:80` | `main.rs:201`, `:1251`, `udm.rs:87` | yes; issue already flags the third as a fallback, not a registration |
| `ausfd` 2 at `app.rs:202`, `:1825` | `app.rs:203`, `:1835`, **plus `:1746`** | **drifted** — 3 now, not 2; `:1746` is a `nfInstanceId` in a Nudm auth-event body, not a registration |
| `bsfd` 2 at `lib.rs:287`, `:2653` | `lib.rs:288`, `:2654`, **plus `sbi_path.rs:69`** | **drifted** — 3 now; and this is the one crate that really does register TWICE |
| `dccfd` 2 at `main.rs:244`, `:276` | `main.rs:245`, `:279` | yes — `:245` is `OAuth2Client::new`, `:279` registers |
| `lmfd` 2 at `main.rs:195`, `:265` | `main.rs:196`, `:268` | yes — same split |
| `mbsmfd` 2 at `main.rs:177`, `:211` | `main.rs:178`, `:214` | yes — same split |
| `nssfd` 2 at `main.rs:548`, `:2843` | `main.rs:549`, `:2844` | yes — same split |
| `udrd` 2 at `main.rs:464`, `:4012` | `main.rs:465`, `:4015` | yes — same split |
| "ten NFs send TWO separate NF registrations per startup" | one `put_json` to `nf-instances/{id}` in each of nine; **two** in `bsfd` (`sbi_path.rs:101` from `bsf_sbi_open`, `lib.rs:2675` from `lib.rs:310`) | **NO — void for nine, real for `bsfd`** |
| `amfd` `sbi_path.rs:288` builds a typed `NfInstance` with "the four Namf services registered" | `:302` and `:309` add **two** (`namf-comm`, `namf-evts`); the comment at `:300` claims four | **partly void** — the comment is wrong; fixed here |
| `udmd/src/sbi_path.rs:45`'s "keep both in step" comment | `sbi_path.rs:45-53`, and it is accurate: `UDM_ADVERTISED_SERVICES` really is consumed by both builders | yes — **real**, and stays (see decision 3) |
| "each profile missing what the other had" (#237's finding, asserted to recur) | true for `bsfd`; for the other nine the divergence is profile-vs-router, not profile-vs-profile | **reframed — real, different axis** |

### Found while verifying: `udmd`'s second registration path is DEAD

`udmd::sbi_path::udm_nrf_register` (`sbi_path.rs:145`) PUTs a full NFProfile, and **nothing calls
it** — the only mention outside its own definition is the `pub use` re-export at `lib.rs:72`.
The startup path is `app.rs:534` → `register_with_nrf` → `register_with_nrf_id` (`:3617`). So
`udmd` has two *registration functions* and one *registration*. The issue counted it among the
"two registrations per startup" crates; it is not one. This is the tree's "correct but
unreachable" shape, and it is the reason the issue's grep-based count over-reported.

Deleted rather than wired: wiring it would create the very second PUT #392 wants removed.

## Decision

**One registration per NF per startup, advertising the union of what the NF actually routes** —
verified service by service against the router, and against the 3GPP service catalogue for the
name. Following #237: one table per NF as the single source of truth, one serialiser, one PUT.

Rejected alternatives, with costs:

1. **Delete `bsfd`'s `lib.rs` registration, keep `bsf_sbi_open`'s.** Cheapest, and wrong.
   `bsf_sbi_open`'s profile omits per-service `ipEndPoints` and `allowedNfTypes` entirely, and it
   fires **before the SBI listener accepts** (`lib.rs:266` precedes `sbi_server.start()` at
   `:302`), so it advertises an endpoint that would refuse the first consumer to dial it. #237 hit
   this exact trap and recorded the rule: register *after* the listener is up. Kept the `lib.rs`
   one for that reason, and moved the surviving profile onto a table.
2. **Keep two PUTs for `bsfd`, make the second an NFProfile *update*.** TS 29.510 does model a
   profile update (PUT or PATCH on the same resource — the `heartBeatTimer` row at
   `29510-k00.txt:7570` names "NF profile updates (PUT or PATCH)"), so this is spec-legal. But
   there is nothing to update: the two `bsfd` profiles describe the *same* surface at the *same*
   moment, differing only in completeness. An update whose only content is "the previous PUT was
   incomplete" is a defect dressed as a procedure. Rejected.
3. **Advertise every service the router mentions.** Rejected: it would have `udmd` advertise
   `nudm-niddau`/`nudm-rsds`/`nudm-ssau`/`nudm-ueid`, which are routed **only to answer 501**
   (`app.rs:700`, `route_nudm_unimplemented` at `:1089`). Advertising a 501 is worse than not
   advertising it — a consumer discovers the service, dials it, and fails, where before it would
   have found no producer and said so. Each added service below was checked to have a handler that
   does real work.
4. **Hoist the service table onto the shared `nextgcore_sbi::context::NfService`.** Rejected on
   #237's recorded reasoning (`specs/fix-pcf-event-exposure-nrf-profile-and-uav-authorization.md`
   "Deliberate scope limit"): `NfService` has no `allowed_nf_types` field, and adding one would
   touch every NF's serialiser in the workspace. Noted as a follow-up candidate, unchanged.

## Per-NF attribute enumeration — the evidence

"Routed" = a router arm with a handler that does real work. "Was advertised" = `nfServices[]`
in the one registration PUT at `68f1003`. **Bold** = added by this change.

| NF | routed services | was advertised | now advertised | other attribute changes |
|---|---|---|---|---|
| `amfd` | `namf-comm`, `namf-evts`, `namf-mt`, `namf-loc`, `namf-mbs-comm`, `namf-mbs-bc` (`namf_server.rs:73,89,118,130,174,187`) | `namf-comm` | + **`namf-evts`, `namf-mt`, `namf-loc`, `namf-mbs-comm`, `namf-mbs-bc`** | self-instance had `namf-comm`+`namf-evts` only, and its comment claimed four; both now from the table. `amfInfo.guamiList` preserved. |
| `bsfd` | `nbsf-management` (`lib.rs` router) | `nbsf-management` (twice, divergently) | `nbsf-management` (**once**) | **`bsf_sbi_open`'s PUT deleted.** Surviving profile keeps per-service `ipEndPoints` + `allowedNfTypes` (which `bsf_sbi_open`'s lacked) and gains `bsf_sbi_open`'s TLS-derived `scheme` (which the survivor hardcoded to `"http"`). |
| `dccfd` | `ndccf-datamanagement`, `ndccf-contextdocument` (`main.rs:117,150`) | `ndccf-datamanagement` | + **`ndccf-contextdocument`** | — |
| `lmfd` | `nlmf-loc`, `nlmf-broadcast`, `nlmf-dataexposure` (`main.rs:478,483,487`) | all three (fixed by #104) | unchanged | self-instance carried `nlmf-loc` only; now all three from the table. |
| `mbsmfd` | `nmbsmf-mbssession`, `nmbsmf-tmgi` | both | unchanged | self-instance carried `nmbsmf-mbssession` only; now both. |
| `nssfd` | `nnssf-nsselection`, `nnssf-nssaiavailability` | both | unchanged | already consistent; moved onto the table so it cannot drift. |
| `smfd` | `nsmf-pdusession`, `nsmf-event-exposure` (`main.rs:1728`) | `nsmf-pdusession` | + **`nsmf-event-exposure`** | self-instance carried `nsmf-pdusession` only; now both. |
| `ausfd` | `nausf-auth`, `nausf-sorprotection`, `nausf-upuprotection` | all three (fixed by #F-03) | unchanged | already consistent in both builders; moved onto the table. |
| `udmd` | `nudm-sdm`, `-uecm`, `-ueau`, `-ee`, `-pp`, `-mt` real; `-niddau`, `-rsds`, `-ssau`, `-ueid` 501-only | the six real ones (fixed by #85) | unchanged | **already correct — `UDM_ADVERTISED_SERVICES` is the #237 pattern.** Dead `udm_nrf_register` deleted. |
| `udrd` | `nudr-dr`, `nudr-group-id-map` (`main.rs:573`, fixed by #87) | `nudr-dr` | + **`nudr-group-id-map`** | — |

Three NFs (`amfd`, `dccfd`, `smfd`, `udrd` — four) were advertising strictly less than they serve.
`udmd` needed nothing but a deletion. The rest needed the self-instance and the profile put on one
table so the two cannot drift again.

### Why each added service is safe to advertise

- `namf-evts` — `handle_amf_event_subscribe` path at `namf_server.rs:73`, real subscription store.
  TS 23.501 Table 7.2.2-1 `Namf_EventExposure` (`23501-k20.txt:51100`).
- `namf-mt` — `handle_enable_ue_reachability` (`:2547`) checks the UE's RAN context and answers
  504 `UE_NOT_REACHABLE` when CM-IDLE; `handle_mt_ue_context_info` (`:2589`) enforces the
  mandatory `info-class`. TS 23.501 `Namf_MT` (`:51106`).
- `namf-loc` — `handle_provide_positioning_info` (`:2623`) validates the two mandatory IEs and
  returns the NGAP-derived NCGI + age. TS 23.501 `Namf_Location` (`:51109`).
- `namf-mbs-comm` / `namf-mbs-bc` — see the cross-NF break above. TS 23.501 `Namf_MBSBroadcast`
  / `Namf_MBSCommunication` (`:51114`, `:51119`), both referenced to TS 23.247.
- `nsmf-event-exposure` — real subscribe/get/put/delete against a store (`main.rs:1728-1751`).
  TS 23.501 Table 7.2.3-1 `Nsmf_EventExposure` (`:51144`). `dccfd` selects an event-exposure
  producer by matching `serviceName` against `eventexposure|evts|eventssubscription`
  (`coordination.rs:238-250`), so an unadvertised `nsmf-event-exposure` is invisible to the DCCF.
- `ndccf-contextdocument` — create/get/delete against `dccf_context_*_analytics_context`
  (`main.rs:150-176`). TS 23.501 `Ndccf_ContextManagement` (`:52161`), TS 23.288 §8.3.
- `nudr-group-id-map` — `handle_group_id_map` (`main.rs:187`) serves `nf-group-ids` from
  configured `udr.group_id_map` entries; #87 routed it and its HTTP test is at `:6469`.

`nsmf-callback` and `namf-callback` are **not** advertised: a callback path is dialled at an
absolute URI the NF handed a peer, not discovered by service name, and neither appears in the
TS 23.501 service tables.

## What changed

Per crate, the #237 shape: a `const` service table, one profile serialiser reading it, one
registration, and the typed self-instance built from the same table.

`bsfd` additionally loses a registration: `bsf_sbi_open` now publishes the self-instance and the
NRF URI and does **not** PUT. The surviving registration is `lib.rs:310`, after
`sbi_server.start()`.

`udmd` loses the dead `udm_nrf_register` and its `pub use`.

`sbi_path.rs:45`'s "ONE list, consumed by both" comment **stays and is extended** (criterion 3):
one profile is now the rule across all ten, and the comment is the record of why the list is
shared rather than duplicated. It is accurate at `68f1003` and remains accurate.

## Verification

### Acceptance criteria

1. *"either the second registration is removed, or documented as a deliberate re-registration"* —
   **real, met.** `bsfd`'s second is removed. Nine had no second registration to remove (the
   criterion's premise is void for them); `udmd`'s dead second registration *function* is deleted.
   `udmd`'s `register_with_nrf_id` NES-resume caller (`nes_driver.rs:164`) is a genuine
   *re*-registration on resume, not a startup duplicate — it is documented as such at
   `app.rs:3596-3599` and left alone, exactly the distinction #392 asks for.
2. *"a test per affected NF asserts exactly ONE registration PUT per startup ... and the full
   advertised service list — positive, not merely 'no second id'"* — **real, met.** Per-crate
   positive assertions that the profile CONTAINS each named service (a value only reachable if
   the table drives the serialiser), plus a workspace-wide source guard that each of the ten has
   exactly one PUT to `/nnrf-nfm/v1/nf-instances/`.
3. *"`sbi_path.rs:45`'s comment is removed or updated"* — **real, met** (updated; see above).

### Revert-verification

Every behavioural claim was made to fail and the NAMED test watched to fail, then restored.
Recorded in the PR body.

## Ceilings

- The per-service `allowedNfTypes` sets are this tree's existing values, carried across
  unchanged except where a newly advertised service needed one. They are operator policy, not
  derivable from the router, so they are not independently verified here.
- Asserted at the profile-builder and source-shape level, not against a live NRF: the Docker E2E
  is the only place a real PUT is counted on the wire, and it is `schedule || workflow_dispatch`.
  A dispatched run is read and reported in the PR.
- `nfServiceList` (the map form) is not emitted. TS 29.510 §6.1.6.2.2 (`29510-k00.txt:7572-7579`)
  marks `nfServices` **deprecated** in favour of it. Out of scope for #392 and a whole-workspace
  change (every NF plus the NRF's parser); called out as a follow-up candidate.
