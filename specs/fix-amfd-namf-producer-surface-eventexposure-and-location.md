# Fix amfd's Namf PRODUCER surface: inter-AMF UE-context ops, AMFStatusChange CRUD, EventExposure targeting/emission, and Namf_Location → LMF

**Issue:** nextgcore #74
**Verified against:** nextgcore `main` @ `8676976`
**Spec basis:** TS 29.518 §5.2.2.2.3 (CreateUEContext), §5.2.2.2.4 (ReleaseUEContext),
§5.2.2.2.5 (RelocateUEContext), §5.2.2.2.6 (CancelRelocateUEContext), §5.2.2.4.1
(NonUeN2MessageTransfer), §5.2.2.5.1.1/.2/.3 + §5.2.2.5.2 (AMFStatusChange
Subscribe/Modify/UnSubscribe), §5.3.2.2 (Namf_EventExposure Subscribe),
§5.5.2.2 (ProvidePositioningInfo), §5.5.2.4 (ProvideLocationInfo),
§5.5.2.5 (CancelLocation); TS 29.510 §6.1.6.2.3 (NFProfile enumerates services);
TS 23.273 §6.1 (the AMF invokes the LMF); TS 24.501 §5.3.7 (mobile-reachable expiry).
Spec text read at `6g_docs/specs/29518-k00.txt` and the OpenAPI at
`6g_docs/specs/TS29518_Namf_*.yaml`; every clause quoted below was read there, with
file:line.
**Precedent:** PR #390 (`6ba388d`, #352) built the **consumer** half of inter-AMF
mobility. This is its producer half, and it is scoped by #390's own boundary table.

## Read this first: the issue has EIGHT criteria, and three are already met or void

#74's `needs-human` comment (posted at `15e4c4d`) re-verified all eight as open and
recommended a four-way split. Two of those eight closed in the hours since, in PRs that
landed today, and a third is void on its own terms. The enumeration below is the
deliverable that determines the shape of this PR.

### Criterion-by-criterion, re-located at `8676976`

| # | criterion | cite in the issue | site at `8676976` | verdict |
|---|---|---|---|---|
| 1 | UE-context ops (`PUT`, `/release`, `/assign-ebi`, `/relocate`, `/cancel-relocate`) routed | `namf_server.rs:86-106` "only handles `n1-n2-messages`, `transfer`, `transfer-update`" | router `:89-111`. `assign-ebi` **IS** routed (`:104`, added by #117). `PUT` cannot reach the arm (`parts.len() >= 5`; a `PUT .../ue-contexts/{id}` is 4). `/release`, `/relocate`, `/cancel-relocate` reach the arm and fall to `send_method_not_allowed` | **partly void** — `assign-ebi` met; 4 of 5 real |
| 2 | `non-ue-n2-messages/transfer` (PWS) accepts a WriteReplaceWarning payload | `namf_server.rs:64-147`, "no arm" | no arm. And `grep -rn WRITE_REPLACE_WARNING src/` returns exactly ONE hit: `libs/nextgcore-asn1c/src/ngap/types.rs:101`, the bare procedure-code constant `= 51`. No NGAP `WriteReplaceWarningRequest` type, no builder, no parser, no `NgapMessage` variant (`libs/nextgcore-ngap/src/parser.rs:18-74`) | **real, but SPLIT** — see below |
| 3 | `/namf-comm/v1/subscriptions` CRUD | `namf_server.rs:64-147`, "no arm" | no arm | **real — implemented** |
| 4 | EventExposure accepts `gpsi` / `pei` / `groupId` | `namf_server.rs:556-560` reads only `supi`/`anyUE` | the guard is now `namf_server.rs:723-727`: `if supi.is_none() && !any_ue { return mandatory_ie_missing(...) }`. `gpsi`, `pei`, `groupId` are never read | **real — implemented** |
| 5 | each of 12 `AMF_EVENT_TYPES` can produce a notification | `AMF_EVENT_TYPES` `:452-465`, 3 emitters | list is now `:619-632`. Emitters still exactly three (`gmm_handler.rs:158`, `:159`, `:291`, `:292`, `:357`) | **real, partly SPLIT** — see below |
| 6 | `provide-loc-info` and `cancel-pos-info` routed | `namf_server.rs:125-127` matches only `provide-pos-info` | now `:130-132`, same | **real — implemented** |
| 7 | `provide-pos-info` drives the LMF | `:2132-2168`, "No LMF client path exists in this AMF" | now `:2623-2659`, same admission verbatim at `:2618-2621` | **real — implemented** |
| 8 | NF profile enumerates `namf-comm`, `namf-evts`, `namf-mt`, `namf-loc` | `sbi_path.rs:288-300`, `:356-374` | **CLOSED.** PR #394 (#392) rebuilt this from ONE table: `AMF_SERVICES` at `sbi_path.rs:301` carries six services including `NamfMt` (`:317`) and `NamfLoc` (`:322-325`), consumed by **both** `build_amf_nf_instance` and `amf_nf_profile_json` so they cannot drift. The comment at `:290-295` records the exact drift #74 names | **MET — nothing to do** |

### Two more items marked, to prevent duplicated or wrong work

* **The inter-AMF CONSUMER side is #352's, and it landed.** PR #390 implemented the
  outbound `UEContextTransfer` client, GUAMI-keyed peer discovery and 5G-GUTI-indexed
  resolution. Its own boundary table splits #352 from #74 **by direction**: "#352 is the
  AMF as a **consumer** of another AMF; #74 is the AMF's **producer** surface." So the
  consumer leg is **met**, and `5g-guti-…` already resolves in `find_ue_by_context_id`
  (`namf_server.rs:272-277`) — CreateUEContext inherits that rather than re-adding it.
* **The gap #390 named and neither issue claimed, which IS mine:** *"the received
  `sessionContextList` is carried and logged but PDU sessions are **not** re-established.
  That needs `Nsmf_PDUSession_UpdateSMContext` per SMF to move the N3 tunnels (TS 23.502
  step 21) — the N2 relocation machinery, whose natural home is #74's `/relocate`."*
  Addressed below, and deliberately NOT by pretending to move tunnels.

## The split, and why it CLOSES #74 rather than leaving it open

The project convention is one PR per issue. Two of eight criteria cannot honestly be
carried here, so they are filed as their own issues and #74 is closed — the
#141→#190 and #187→#392/#393 pattern.

**Filed as #396 (PWS) and #397 (the remaining event emitters).**

### Split 1 → #396: PWS / WriteReplaceWarning (criterion 2) — needs an NGAP procedure that does not exist

`/non-ue-n2-messages/transfer` is not "an SBI handler plus a send". TS 29.518
§5.2.2.4.1.3 ("Warning Request Transfer Procedure", `29518-k00.txt:198`) has the AMF
relay a **WRITE-REPLACE WARNING REQUEST** to every gNB and collect the
`PWSResponseData` (`TS29518_Namf_Communication.yaml:3777-3796`: `ngapMessageType`,
`serialNumber`, `messageIdentifier`, `unknownTaiList`, `n2PwsSubMissInd`). The NGAP
codec underneath is absent: procedure code 51 is declared and nothing else. The S1AP
side exists (`bins/nextgcore-mmed/src/s1ap_build.rs:616`
`build_write_replace_warning_request`) and is exactly the precedent for how much work
this is — Message Identifier, Serial Number, Warning Area List, Repetition Period,
Number of Broadcasts Requested, Warning Type / Security Info, plus the response's
Broadcast Completed Area List.

Writing the SBI arm first would produce **a caller of a transport that cannot encode
anything** — the "correct but unreachable" defect this tree keeps producing. An arm that
returns 200 and logs is indistinguishable from working until a real CBC is on the other
end, which makes it the worst available outcome. Filed separately, `architecture`-labelled
because "does amfd carry PWS at all" is a scope question, not an implementation one.

### Split 2 → #397: the nine never-fired event types (criterion 5) — three have honest sites here, six do not

An emitter wired to a plausible-but-wrong site is worse than a silent event type: it
produces notifications a consumer acts on at moments the spec does not define. So the
nine are triaged by whether THIS AMF has the state change the spec names.

Implemented here (each has a real, already-reached state change):

* **`LOSS_OF_CONNECTIVITY`** — §6.2 (`29518-k00.txt:24089`): *"identified when Mobile
  Reachable timer expires in the AMF... when the UE detaches and when AMF deregisters
  from UDM for an active UE."* The mobile-reachable expiry is already a live site:
  `ngap_path.rs::process_reachability_timers`, `ReachabilityPhase::MobileReachable` arm,
  driven by `poll()` on every NGAP tick.
* **`CONNECTIVITY_STATE_REPORT`** — §6.2 (`:24011`): CM-state change. CM-IDLE→CONNECTED
  at `ngap_path::handle_service_request_nas` (after the Service Accept egresses);
  CONNECTED→IDLE at `start_reachability_supervision`, the UEContextReleaseComplete path.
* **`ACCESS_TYPE_REPORT`** — §6.2 (`:23991`): access-type change, at
  `ngap_path::send_registration_accept` once the Accept has egressed.

### Found while implementing: EVERY existing `fire_*` call site is test-only-reachable

All three pre-#74 emitters are in `gmm_handler`, in `handle_registration_request`
(`:85`), `handle_service_request` (`:259`) and `handle_deregistration_request` — and
**each of those functions' only callers are inside `mod tests`**. `ngap_path` already
records this for the same module, about a different fix: *"The parser #116's text cites
(`gmm_handler`'s) has only test callers — its own `handle_registration_request` is
called from three places, all inside `mod tests` — so implementing this there would have
been a correct fix in an unreachable place."*

The live NAS path is `ngap_path`'s `*_nas` handlers, which build and send their own
messages and never call into `gmm_handler`. So `LOCATION_REPORT`,
`REGISTRATION_STATE_REPORT` and `REACHABILITY_REPORT` — the three #74 counts as
*working* — **never fire in production either**. The first draft of this PR put the new
emitters beside them and would have shipped three more dead ones; they were moved to the
live NGAP sites instead, and `the_mobile_reachable_expiry_fires_loss_of_connectivity_to_a_subscriber`
asserts the production site rather than the emitter.

Relocating the three PRE-EXISTING emitters is not done here: each needs its own live site
decided (which NGAP moment is "the UE deregistered"?), it changes behaviour for events
consumers already subscribe to, and it is not what any of #74's criteria ask for. Filed
with the criterion-5 remainder so it is not lost.

Split out (no honest site in this AMF):

* **`PRESENCE_IN_AOI_REPORT`** and **`UES_IN_AREA_REPORT`** need presence-area /
  area-of-interest state the AMF does not track at all. Feature work, not fire-point work.
* **`TIMEZONE_REPORT`** needs a UE time zone the AMF never learns:
  `gmm_build.rs:983-985` sets `local_time_zone: None`,
  `universal_time_and_local_time_zone: None`, `network_daylight_saving_time: None`. There
  is no value to report and no event to detect.
* **`COMMUNICATION_FAILURE_REPORT`** reports a `CommunicationFailure`
  (`TS29518_Namf_EventExposure.yaml:923-930`: `nasReleaseCode` / `ranReleaseCode`) and
  optionally filters on a PDU session's DNN+S-NSSAI (`29518-k00.txt:21732-21742`). The
  release-code plumbing to populate it does not exist.
* **`SUBSCRIPTION_ID_CHANGE`** / **`SUBSCRIPTION_ID_ADDITION`** are *not* subscribable
  events at all: §6.2 says of both *"This event needs no explicit subscription from an NF
  service consumer"* (`:24056`, `:24070`), and Table 6.2.6.2.5-1 (`:21886-21910`) fires
  them only *"during mobility registration and handover procedures involving an AMF
  change"*, carrying the newly-minted `subscriptionId` to a `subsChangeNotifyUri`. That
  URI is not even stored today (`EventSubscription`, `context.rs:719-737`, has no
  `subs_change_*` member), and the trigger is the CreateUEContext event-subscription
  takeover of §5.2.2.2.3.1 (`:2404-2432`) — a large piece of its own.

Criterion 5 as written ("each of the 12 can produce at least one notification") therefore
cannot be closed here, and the remainder is filed as **#397** with the above triage — plus
the unreachable-`gmm_handler` finding — so the next agent does not re-derive it.

## What is implemented

### A. Inter-AMF UE-context producer ops (criterion 1)

Router: the `namf-comm` / `ue-contexts` arm is widened from `parts.len() >= 5` to `>= 4`
so `PUT .../ue-contexts/{id}` can reach it at all, and four operations are added.

* **`PUT /namf-comm/v1/ue-contexts/{ueContextId}` — CreateUEContext (§5.2.2.2.3.1).**
  Mandatory members per `TS29518_Namf_Communication.yaml:3668-3672`: `ueContext`,
  `targetId`, `sourceToTargetData`, `pduSessionList`. On success **201 Created** with a
  `Location` header and a `UeContextCreatedData`
  (`:3701-3704` requires `ueContext`, `targetToSourceData`, `pduSessionList`).
  The created context is **inserted into the live store** — this is the observable effect
  the test asserts positively, and the reason a `Location`-header-only implementation
  would be a vacuous pass.
* **`POST .../{id}/release` — ReleaseUEContext (§5.2.2.2.4.1).** *"the target AMF shall
  return '204 No Content' with an empty content"* (`29518-k00.txt:2912`). Removes the UE
  context, so a subsequent read 404s.
* **`POST .../{id}/relocate` — RelocateUEContext (§5.2.2.2.5.1).** Mandatory:
  `ueContext`, `targetId`, `sourceToTargetData`, `forwardRelocationRequest`
  (`:3742-3746`). *"the target AMF shall respond with... '201 Created'... together with a
  HTTP Location header"* (`:2964`), body a `UeContextRelocatedData` (`ueContext` required,
  `:3753-3754`).
* **`POST .../{id}/cancel-relocate` — CancelRelocateUEContext (§5.2.2.2.6.1).** Mandatory:
  `relocationCancelRequest` (`:3764-3765`). *"the target AMF shall return '204 No
  Content'"* (`:3015`).

**The `sessionContextList` ceiling is declared, not papered over.** `/relocate` is
EPS→5GS handover with AMF re-allocation over **N26**, and this tree has no N26 leg at
all — `gmm_build.rs:593-605` states it outright (*"this AMF has no N26 leg — no GTPv2-C
toward an MME, no Forward Relocation, nothing"*) and advertises
`Iwk26::WithoutN26Supported` to every UE for exactly that reason. So a
`forwardRelocationRequest` cannot be decoded here, and the PDU re-establishment #390
named (`Nsmf_PDUSession_UpdateSMContext` per SMF to move N3 tunnels) has no source of
truth to drive it: there is no N26 Forward Relocation Request carrying the MME control
plane address and TEID that §5.2.2.2.5.1 (`:2951-2960`) says the consumer supplies per
PDU session. The handler therefore **records** each received `sessionContextList` entry
as an AMF session against the created context and logs the tunnels it is NOT moving,
with the clause cited. Inventing an `UpdateSMContext` from absent N26 data would move
tunnels to addresses nobody supplied.

### B. AMFStatusChange subscription CRUD (criterion 3)

* `POST /namf-comm/v1/subscriptions` → **201** + `Location` (§5.2.2.5.1.2,
  `:4570-4573`). Mandatory member `amfStatusUri`
  (`TS29518_Namf_Communication.yaml:2437-2438`); optional `guamiList`.
* `PUT /namf-comm/v1/subscriptions/{subscriptionId}` → **200** with the replaced
  representation. §5.2.2.5.1.3 is explicit that this is a *complete replacement*
  (`:4590-4593`) and that 200-with-body is the primary answer (`:4605`).
* `GET` on the individual subscription → 200 with the stored representation. Not a
  §5.2.2.5 operation; added because the criterion says "create/read/update/delete" and a
  CRUD round-trip test needs a read that is not the AMF's own store. Documented as a
  local read-back, not claimed as spec.
* `DELETE /namf-comm/v1/subscriptions/{subscriptionId}` → **204**, empty body
  (§5.2.2.5.2.1, `:4640`).

Stored in a new `amf_status_subscriptions` map on `AmfContext`, keyed by subscription ID,
alongside the existing `event_subscriptions` and following its lock discipline (single
lock, clone-out, never nested).

**This is wired to a producer, not left inert.** `AmfStatusChangeNotify` (§5.2.2.5.3) is
driven from `AmfApp::shutdown_async` — the AMF planned-removal procedure §5.2.2.5.1.1
names as this service's whole purpose (`:4543-4545`, TS 23.501 §5.21.2.2). It already
calls `deregister_self()` there for the NRF's benefit (#235); the status notification is
the peer-facing half of the same event, and goes out **before** the NRF deregistration so
subscribers hear it while the AMF can still send. Without this the CRUD would be a
registry nothing reads — this tree's most common defect.

### C. EventExposure targeting (criterion 4)

`handle_event_subscription_create`'s guard becomes: reject `MANDATORY_IE_MISSING` only
when **no** target IE is present. `AmfEventSubscription`
(`TS29518_Namf_EventExposure.yaml:534-594`) lists `supi` (`:553`), `groupId` (`:555`),
`gpsi` (`:577`), `pei` (`:579`) and `anyUE` (`:581`), and requires only
`eventList`/`eventNotifyUri`/`notifyCorrelationId`/`nfId` (`:589-593`) — so a GPSI-keyed
subscription is conformant and today gets a 400.

`EventSubscription` gains `gpsi`, `pei` and `group_id`. Resolution, and its limits:

* A `gpsi`/`pei` that matches a **currently-known** UE is resolved to that UE's SUPI at
  subscribe time, so the subscription keys the same way a SUPI one does. `AmfUe.gpsi`
  (`context.rs:2318-2325`) is populated from UDM SDM `am-data`
  (`ngap_path.rs:4153`), and `AmfUe.pei` from the registration path, so both are real
  lookups against live state.
* An **unresolvable** `gpsi`/`pei` is **accepted and stored unresolved**, not refused:
  TS 29.518 nowhere requires the target to be registered at subscribe time, and refusing
  it would swap one wrong rejection for another. `event_subscriptions_matching` gains the
  GPSI/PEI arms so such a subscription starts matching once the UE is known.
* `groupId` is stored and matched **only** against subscriptions the AMF can evaluate; no
  group membership source exists in this AMF (no `internalGroupId` on `AmfUe`), so a
  group subscription is accepted, stored and reported in the echo, and its notifications
  are ceiling-documented as not firing until a membership source exists. It is accepted
  because criterion 4 is about **accepting** the targeting key — refusing a conformant
  `groupId` with `MANDATORY_IE_MISSING` is precisely the bug — and silently claiming to
  deliver on it would be the other failure mode.

`build_event_report` additionally carries `gpsi` and `pei` when known, per
Table 6.2.6.2.5-1 (`29518-k00.txt:21951-21968`: `gpsi` "shall be present if available",
`pei` "may be included").

### D. Namf_Location: routing + the LMF round trip (criteria 6, 7)

* **`POST /namf-loc/v1/{ueContextId}/provide-loc-info` — ProvideLocationInfo
  (§5.5.2.4.1).** NPLI for a target UE, requested by e.g. the UDM. Request is a
  `RequestLocInfo` (`TS29518_Namf_Location.yaml:552-569`: `req5gsLoc`, `reqCurrentLoc`,
  `reqRatType`, `reqTimeZone` — **all optional**, so an empty body is valid and must not
  400). Response is a `ProvideLocInfo` (`:571-592`) carrying `currentLoc`, `location`
  (a `UserLocation`), `locationAge`, `ratType`. The spec's `reqCurrentLoc=true` handling
  (`29518-k00.txt:6689-6706`) requires a paging procedure or an NG-RAN Location
  Reporting Control round trip; neither exists here, so `currentLoc` is set **`false`**
  and the last known location returned — which is exactly what the spec prescribes when
  the current location cannot be obtained (*"the AMF shall provide the last known
  location and set `currentLoc` attribute to `false`"*). Honest by construction:
  `currentLoc: false` is a true statement about what was returned.
  `timezone` is omitted (the AMF has none — see the criterion-5 triage).
* **`POST /namf-loc/v1/{ueContextId}/cancel-pos-info` — CancelLocation (§5.5.2.5.1).**
  `CancelPosInfo` requires `supi`, `hgmlcCallBackURI`, `ldrReference`
  (`TS29518_Namf_Location.yaml:612-615`). *"AMF responds with '204 No Content'"*
  (`29518-k00.txt:6742`), and *"If the `nrppaPeriodicInd` IE with the value true is
  received, the AMF shall skip the cancel location procedures towards the UE"* (`:6743`)
  — honoured, and the LDR cancellation is otherwise relayed to the LMF.
* **`provide-pos-info` drives the LMF (§5.5.2.2.1).** The clause is unambiguous: *"The
  service operation triggers the AMF to invoke the service towards the LMF"*
  (`29518-k00.txt:6505`), and TS 23.273 §6.1 routes the positioning through it. `lmfd`
  already serves `POST /nlmf-loc/v1/determine-location`
  (`bins/nextgcore-lmfd/src/main.rs:376-378` → `handle_determine_location`), so the
  producer exists and had no consumer. The AMF now discovers an LMF
  (`SbiServiceType::NlmfLoc`, with the NRF query and an `LMF_SBI_ADDR` addressless
  fallback, mirroring `resolve_nf_endpoint_async`'s shape) and POSTs an `InputData`
  carrying the SUPI, the requested QoS and the NCGI it knows.
  The LMF-derived `locationEstimate` / `ageOfLocationEstimate` are returned when the
  round trip succeeds; **the stored-NGAP-cell answer is retained as the fallback** when
  no LMF is reachable, so the pre-#74 behaviour is what a deployment without an LMF still
  gets.
  **Runtime switch, not a cargo feature.** `AMF_NAMF_LOC_LMF=off` restores the
  NGAP-only answer. The issue suggests a cargo feature; that was rejected because a
  feature-gated path is outside `cargo test --workspace`, which is the CI gate, so the
  code would ship unexercised. `ue_policy_assoc_enabled` (`sbi_path.rs:2549-2559`) is the
  in-tree precedent for the env form, including its pure classifier.

## Decisions

1. **Widen the existing `ue-contexts` arm rather than add a second `namf-comm` arm.**
   A second arm matching `parts[2] == "ue-contexts"` would be shadowed by the first for
   every path it shares, which is how a route ends up unreachable. One arm, `>= 4`, with
   the `PUT`-on-4 case explicit.
2. **CreateUEContext inserts into the live store.** The alternative — answer 201 and
   record nothing — passes a routing test and fails every real handover. The insertion is
   what the test asserts, and what makes the revert-verification discriminating.
3. **`/relocate` records sessions and declares the tunnel ceiling.** Rejected:
   calling `Nsmf_PDUSession_UpdateSMContext` with invented tunnel endpoints. There is no
   N26 leg to supply the MME address/TEID the clause requires, and moving a tunnel to a
   fabricated address is worse than not moving it.
4. **AMFStatusChangeNotify fires from `shutdown_async`.** Rejected: CRUD with no
   producer. §5.2.2.5.1.1 names planned removal as the procedure this service exists for,
   and that path already exists and already notifies the NRF.
5. **An unresolvable `gpsi`/`pei` is accepted, not refused.** Rejected: 404/400 on an
   unknown external identity — nothing in §5.3.2.2 conditions the subscription on the UE
   being registered, and refusing it re-creates the bug in a new place.
6. **`groupId` accepted, delivery ceiling declared.** Rejected: both "refuse it" (the
   bug) and "claim to deliver" (silent non-delivery on a subscription the consumer
   believes is live).
7. **LMF positioning behind a runtime env switch, LMF-absent falls back.** Rejected: a
   cargo feature (untested by the CI gate) and an unconditional hard dependency on an LMF
   (breaks every bring-up without one).
8. **PWS and six of the nine emitters are split out and filed.** Rejected: an SBI arm
   over a non-existent NGAP codec, and emitters at guessed sites.

## Tests

All new tests take `crate::test_support::CONTEXT_GUARD` (never a new lock — two locks
over one process-global has hung this suite) and use **distinct literal keys** per test
with a comment saying why, because amfd's stores are process-global and two tests once
shared `78_001`.

Assertions are **positive and on state only the path under test reaches**:

* CreateUEContext: the created context is **readable from the store afterwards** by the
  `ueContextId` it was created under, carrying the SUPI from the request body — not
  "not a 404". A 404-absence assertion is satisfied by a parse error.
* ReleaseUEContext: the context is readable **before** and absent **after**, in one test,
  so the transition is what is asserted rather than a state that might never have existed.
* AMFStatusChange: a CRUD round trip where the `PUT`'s new `amfStatusUri` is read back,
  and the `DELETE` makes the subsequent `GET` 404 — the replacement is the positive
  assertion, not the 204.
* EventExposure targeting: one test per key (`gpsi`, `pei`, `groupId`) asserting **201 and
  that the echoed subscription carries the key that was sent**, plus the sibling
  asserting an empty-target body is still `MANDATORY_IE_MISSING` — so the pair
  discriminates between "accepts everything" and "accepts the right things".
* GPSI resolution: a GPSI-targeted subscription against a UE whose GPSI is in the store
  resolves to that UE's SUPI, asserted by the stored subscription's `supi`.
* Emitters: an in-process notification sink receives a `LOSS_OF_CONNECTIVITY` report
  carrying the **subscribed SUPI**, driven from the mobile-reachable expiry.
* Namf_Location: `provide-loc-info` returns `currentLoc: false` **and** the stored NCGI,
  so both halves of the honest answer are pinned. `cancel-pos-info` 204s and rejects a
  body missing `ldrReference`.
* LMF round trip: a real in-process `SbiServer` stands up as the LMF on an ephemeral
  port and records the request, so the assertion is **what the LMF actually received**
  (the SUPI, on the `/nlmf-loc/v1/determine-location` path) and that the AMF's response
  carries the position the LMF returned — a value that exists nowhere else in the
  fixture. `set_sbi_profile_override(Dev)` is set and **deliberately not reset**
  (process-wide; resetting it broke siblings mid-flight — PR #390 measured 2 failures in
  10 runs).

Every behavioural claim is revert-verified: the change is broken, the **named** test
watched to fail, then restored.

## Ceilings

1. **PWS / WriteReplaceWarning is not implemented**; filed as **#396** (`architecture`).
   The NGAP elementary procedure does not exist.
2. **Six of the nine silent event types are not implemented**; filed as **#397** with the
   per-type triage above. Three are implemented here.
2b. **The three PRE-EXISTING emitters are still test-only-reachable** and are #397's
   first criterion. Found here, not claimed by #74, and deliberately not fixed here: it
   changes behaviour for events consumers already subscribe to.
3. **`/relocate` does not move N3 tunnels.** No N26 leg exists to supply the endpoints.
   The received `sessionContextList` is recorded and the omission logged with the clause.
4. **`provide-loc-info` never returns `currentLoc: true`.** Neither the paging nor the
   NG-RAN Location Reporting Control round trip §5.5.2.4.1 requires exists.
5. **`groupId` subscriptions accept but do not notify.** No group-membership source in
   this AMF.
6. **The LMF round trip is single-process in test.** `Docker E2E` is
   `schedule || workflow_dispatch` and does not run on a PR; a dispatched `ci.yml` run is
   read because this change adds a cross-NF discovery dependency (AMF → LMF).
