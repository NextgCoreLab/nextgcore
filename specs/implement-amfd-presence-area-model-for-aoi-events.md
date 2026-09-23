# Give amfd a presence-area model: `PRESENCE_IN_AOI_REPORT` and `UES_IN_AREA_REPORT`

**Issue:** nextgcore #400 (split out of #397 criterion 5 by PR #402)
**Verified against:** nextgcore `main` @ `0dc01e4`
**Predecessor:** `specs/fix-amfd-namf-event-exposure-live-fire-points.md` (#397/PR #402),
which took production-reachable Namf event types from 0 to 10 of 12 and stated the
ceiling this spec lifts.

**Spec basis — every clause below was opened at the cited file:line, not taken from the
issue.**

* TS 29.518 (`6g_docs/specs/29518-k00.txt`, `TS29518_Namf_EventExposure.yaml`):
  §5.3.1 Presence-In-AOI-Report event definition (`:4858-4971`), UEs-In-Area-Report
  (`:5143-5190`), `AmfEvent.areaList` (`:21391-21397`, yaml `:604-608`),
  `AmfEvent.presenceInfoList` (`:21527-21535`, feature `MPRA`),
  `AmfEventReport.areaList` (Table 6.2.6.2.5-1, `:21923-21940`, yaml `:740-744`),
  `numberOfUes` (`:22006-22008`, yaml `:778`), NOTE 1 (`:22212`), NOTE 3 (`:22216-22218`),
  `AmfEventArea` (yaml `:1011-1024`), `uePosCap` (`:22154-22162`, feature `AIML_CN`),
  `reportingThreshold` (`:21720-21731`, feature `OBGAD`), `adjustAoIOnRa` /
  `ranTimingSynchroStatusChange` / `notifyForSupiList` (`:21630-21707`, feature `AOIEF`),
  the feature table (`:24665-24830`: `APRA` #2, `MPRA` #9, `AOIEF` #12, `OBGAD` #15 —
  **all four OPTIONAL**).
* TS 29.571 (`29571-k00.txt`, `TS29571_CommonData.yaml`): `PresenceInfo` §5.4.4.27
  (`:5171-5276`, yaml `:2707-2782`), `PresenceState` (yaml `:1858-1872`), `Tai`
  (yaml `:2298-2310`), `Tac` (yaml `:1340-1348`), `Ncgi` (yaml `:2342-2354`).
* TS 23.501 (`23501-k20.txt`): §5.6.11 Presence Reporting Area (`:13561-13686`),
  §5.3.4.4 UE mobility event notification (`:8232-8336`).
* TS 38.413 (`38413-j30.txt`) for the NGAP `UserLocationInformation` IE that is the
  AMF's only source of UE location.

---

## Read this first: the criterion table, re-located at `0dc01e4`

The issue's own body is the claim; this is the site. **One of its five model questions
had already dissolved, and one of its factual premises is FALSE.**

| # | the issue's claim | site at `0dc01e4` | verdict |
|---|---|---|---|
| 1 | *"A presence-area model exists and its source is named (configuration file or runtime env), with TA-list areas at minimum."* | Confirmed absent: `grep -rn 'PresenceInfo\|AmfEventArea\|presence_state' bins/nextgcore-amfd/src/` finds only the #402 ceiling COMMENT (`namf_server.rs:718-731`) and a dead `AreaOfInterest` struct (`namf_handler.rs:205`, see below). No area is parsed, stored or evaluated. | **real — implemented, but the SOURCE is not configuration.** See "The decision". |
| 2 | *"`PRESENCE_IN_AOI_REPORT` fires on a real IN/OUT transition from a LIVE NGAP site, carrying `areaList` ... a test drives the production path"* | Confirmed silent. `AMF_EVENT_TYPES` accepts it (`namf_server.rs:749`) and nothing emits it. | **real — implemented** at `send_registration_accept` and `handle_handover_notify`. |
| 3 | *"UNKNOWN is reported when the AMF genuinely does not know, rather than defaulted to OUT."* | — | **real — implemented**, and the spec sanction located (`29518-k00.txt:21927`, `TS29571_CommonData.yaml:1861`). |
| 4 | *"A PRA identifier naming a set reports both the subscribed identifier and the individual PRA(s), per TS 23.501 §5.6.11 — or that case is refused explicitly with the reason at the site."* | — | **real — REFUSED at the site with the reason**, which the criterion's own second arm permits. `APRA` is an OPTIONAL feature (`:24672-24688`) and the set membership is *"predefined in the AMF"* (`23501-k20.txt:13624-13627`) — configuration this tree does not have. |
| 5 | *"`UES_IN_AREA_REPORT` fires with a real `numberOfUes` ... and `reportingThreshold` is either honoured or declared unsupported at the site."* | — | **real — implemented** (`numberOfUes` counted off the live store); `reportingThreshold` **declared unsupported at the site** (`OBGAD`, optional). |
| 6 | *"The ceiling comment on `AMF_EVENT_TYPES` naming these two as non-firing is removed, because it has stopped being true."* | `namf_server.rs:716-733` | **real — implemented** (rewritten, not deleted: the narrower residual ceiling replaces it). |
| M1 | model question 1: *"Where do presence areas come from? ... amfd has no configuration surface for the former. A decision on `configs/amf.yaml` ... is a prerequisite."* | **PREMISE FALSE — this is not a prerequisite, and configuration would be the WRONG answer for the tractable case.** `AmfEvent.areaList` (`:21391`) is an `AmfEventArea` array *on the subscription*, and TS 23.501 §5.6.11 (`:13633-13636`) says for a **UE-dedicated** PRA *"the subscription for UE location change notification for an 'area of interest' **shall contain** the PRA Identifier(s) and the list(s) of TAs"*. The consumer supplies the area. Only the **CN-predefined** case needs AMF configuration (`:13637-13639`: *"shall contain the PRA identifier(s)"* — the identifier ALONE). | **VOID as stated / real for the CN-predefined half only.** No `configs/amf.yaml` change is made; see "Rejected options". |
| M2 | model question 2: *"a TAI-list area is the tractable first cut; an `sNssai`-named or LADN area is not, and neither is `nsiId`."* | Confirmed. `grep -rn 'ladn' bins/nextgcore-amfd/src/` → one `ladn_information: None` write (`gmm_build.rs:986`). No NS-AoS, no Partially-Allowed-NSSAI state. | **real — TAI list AND NCGI list implemented** (the tree holds `nr_cgi` too); LADN / `sNssai` / `nsiId` / `sliceAreaRestrictionInfo` refused at the site. |
| M3 | model question 3: *"The AMF learns location at exactly three live moments (the sites #397 wired `LOCATION_REPORT` to): the InitialUEMessage at registration, the Service Request, and `handle_handover_notify`."* | **FALSE — there are TWO, not three.** `ngap_asn1::parse_uplink_nas_transport_asn1` (`:741-770`) **discards** `UserLocationInformation`: the `nextgcore-ngap` parser decodes it as a MANDATORY IE and refuses the message without it (`libs/nextgcore-ngap/src/parser.rs:640-663`), but `UplinkNasTransportData` (`ngap_asn1.rs:731-738`) has no field for it, so the Service Request path **cannot learn a new location** — `handle_service_request_nas` fires `LOCATION_REPORT` off the TAI the *registration* stored. | **premise VOID.** Consequences in "Where the evaluation happens", and a follow-up filed. |
| M4 | model question 4: *"UNKNOWN is a real third state, not an error."* | Confirmed and cited. | **real** — see criterion 3. |
| M5 | model question 5: *"`UES_IN_AREA_REPORT` needs a reverse index. Counting UEs per area on every location change is O(UEs x areas) against `ue_store` unless the membership is maintained incrementally."* | **VOID on this tree's own established reasoning.** `ue_store`'s module docs (`ue_store.rs:28-38`) record the opposite decision for exactly this trade: *"An index maintained beside a collection that can disagree with it is the exact shape this tree keeps finding broken — #325, #365 and #363's own root cause — and deriving makes divergence impossible by construction rather than by discipline."* `max_num_of_ue` bounds n, and the count runs per *event*, not per NGAP message. | **VOID — derived by scan, deliberately.** See "Rejected options". |

Two further facts had to be established because the design turns on them:

* **The AMF genuinely knows a real TAI.** `state.amf_ue.nr_tai` is written from the
  InitialUEMessage's own `UserLocationInformation` (`ngap_path.rs:1586-1589`), and #402's
  Docker E2E asserts the delivered `LOCATION_REPORT` carries `mcc 999 / mnc 70 / tac 0001`
  off nextgsim's real gNB. So an IN/OUT comparison has real input.
* **`nr_cgi` is NOT written at registration.** `InitialUeMessageData` carries
  `nr_cell_identity` (`ngap_asn1.rs:326`) and `handle_initial_ue_message` writes only
  `nr_tai` (`ngap_path.rs:1586`) — the cell id is logged and dropped. The only production
  writer of `amf_ue.nr_cgi` is `handle_handover_notify` (`ngap_path.rs:7391-7392`);
  `gmm_handler.rs:154`/`:302` also write it but their callers are all inside `mod tests`
  (the #397 defect). **This is load-bearing for NCGI areas** and is why an NCGI area over a
  default `nr_cgi` must report `UNKNOWN` rather than `OUT_OF_AREA`.
* **No PCF leg delivers a PRA to the AMF.** `nextgcore-pcfd` has
  `PresenceReportingAreaInfo { pra_id, presence_state }` (`nudr_handler.rs:44-45`) read
  from the UDR's `am-data`, and `grep -rn 'PRESENCE_IN_AOI\|praId'` shows **no** path from
  pcfd to amfd. The PCF-provisioned route is genuinely absent; it is not needed for the
  subscription-supplied case, which is what §5.6.11 says (M1).

---

## The decision: **(A) the subscription already carries enough — implement it**, with one
## explicitly-refused sub-case

**The subscription carries the area.** This is the finding that decides the issue, and it
inverts model question M1. `AmfEvent.areaList` is *"array(AmfEventArea)"*, *"Identifies the
area to be applied"* (`29518-k00.txt:21391`), and `AmfEventArea.presenceInfo` is a TS 29.571
`PresenceInfo` (yaml `:1015-1016`) whose `trackingAreaList` is *"the list of tracking areas
that constitutes the area ... shall be present if the subscription or the event report is
for tracking UE presence in the tracking areas"* (`29571-k00.txt:5234-5242`). TS 23.501
§5.6.11 makes it explicit for the UE-dedicated case: *"the subscription for UE location
change notification for an 'area of interest' **shall contain** the PRA Identifier(s) and
the list(s) of TAs, or NG-RAN Node identifier and/or cell identifiers composing the Presence
Reporting Area(s)"* (`23501-k20.txt:13633-13636`).

So the AMF needs **no provisioned state at all** for a subscription that enumerates its
area. It needs the UE's TAI — which it has, from a real gNB — and a set comparison. That is
honest reporting, not a guess, and refusing to do it would be the mirror-image mistake of
the one #400 exists to prevent: declining to report something the AMF genuinely knows.

**What IS refused, with the reason at the site:** a `praId` with **no** enumerated
`trackingAreaList`/`ncgiList`. Per §5.6.11 that is the **Core-Network-predefined** form,
*"predefined in the AMF and composed of a short list of TAs and/or NG-RAN nodes and/or cells
identifiers"* (`:13624-13627`), resolved *"based on local configuration"* (`:13630-13632`).
This tree has no such configuration, so the AMF cannot know which TAIs the identifier names.
It reports **`UNKNOWN`** for that area — which is exactly what `PresenceState`'s `UNKNOWN`
means (*"it is unknown whether the UE is in the presence reporting area or not"*,
`TS29571_CommonData.yaml:1871`) — and echoes the `praId` back so the consumer knows which
area the verdict belongs to. **That is reporting what is knowable rather than fabricating**,
and it is what criterion 4's second arm ("or that case is refused explicitly with the reason
at the site") asks for.

### Why UNKNOWN rather than silence, for the unresolvable area

Three independent sanctions, all read at the text:

1. `AmfEventReport.areaList` *"represents the specified Area(s) of Interest the UE is
   currently IN / **OUT** / **UNKNOWN**"* (`29518-k00.txt:21925-21928`) — UNKNOWN is one of
   the three legal verdicts, listed beside the other two.
2. §5.3.1's own Notification line for the event: *"UE-ID(s), Area identifier, Presence
   Status (IN/OUT/**UNKNOWN**)"* (`:4954-4956`).
3. §5.3.1 NOTE 3 (`:4960-4971`) makes the *inability* to determine presence a first-class
   outcome with a defined behaviour: *"if ... the AMF cannot determine the current UE
   presence state in the AoI at the time of the subscription, the AMF sends a subsequent
   notification ... as soon as the AMF can determine"*.

A report that silently omitted the unresolvable area would leave the consumer unable to
distinguish "the AMF has no opinion" from "the AMF never evaluated this area", and §6.2's
`areaList` is `1..N` when present — so the array must carry every subscribed area or none.

### Why not (B) or (C)

**(C) "it cannot be done honestly at all"** is wrong, and the evidence is the `areaList`
IE itself plus a real gNB-sourced TAI. The issue reached for (C) because M1 assumed the area
must come from configuration; it does not. Holding the HIGH bar the operator asked for: the
claimed blocker dissolved on reading `:21391` and `23501-k20.txt:13633`.

**(B) "smallest real increment plus a stated ceiling"** is the right *shape* and is what
ships — but the increment is much larger than (B) implies. Both event types fire, both carry
real spec-shaped bodies, and the residual ceiling is narrow and named: four optional 3GPP
features (`APRA`, `MPRA`, `AOIEF`, `OBGAD`), three `AmfEventArea` alternatives that need
state the AMF does not hold, and the Service-Request location gap M3 exposed.

---

## What is implemented

### 1. The area model: `EventArea` on `EventSubscription` (`context.rs`)

`AmfEventArea` is a **choice of five** (yaml `:1011-1024`). Two are modelled, three are
refused-with-reason, which the type makes structural rather than conventional:

```
EventArea { pra_id, tracking_area_list, ncgi_list, unsupported_kind }
```

* `tracking_area_list` — `PresenceInfo.trackingAreaList`, an array of `Tai`
  (`29571-k00.txt:5234-5242`). The AMF holds `nr_tai` from a real gNB, so this is
  comparable.
* `ncgi_list` — `PresenceInfo.ncgiList`, *"the list of NR cell Ids that constitutes the
  area"* (`:5253-5259`). Modelled because the AMF holds `nr_cgi` — but see the `UNKNOWN`
  rule below, because that field has only one production writer.
* `pra_id` — echoed back verbatim. `PresenceInfo.praId` *"shall be present if the Area of
  Interest subscribed or reported is a Presence Reporting Area"* (`:5178-5188`), so a report
  that dropped it would not identify which area it answered about.
* `unsupported_kind` — which non-evaluable alternative the consumer sent (`ladnInfo`,
  `sNssai`, `nsiId`, `sliceAreaRestrictionInfo`). Stored rather than discarded, so the
  report can name it in the log and still answer `UNKNOWN` for that entry instead of
  silently dropping an area the consumer asked about.

`EventSubscription` gains `areas: Vec<EventArea>` and `any_ue_area_reported: ...` state.
**`presenceInfoList` (the `MPRA` map form, `:21527-21535`) is accepted and parsed into the
same `Vec<EventArea>`**, keyed by its `praId` map key as the IE requires, because it is the
same `PresenceInfo` type by a different container — and the IE's own rule *"When present,
the areaList shall be absent"* (`:21534`) is enforced.

### 2. The verdict function: `evaluate_presence` (`namf_server.rs`)

A **pure function**, separate from every handler, because this mapping IS the conformance
decision (the shape #402 used for `is_communication_failure_cause`):

| area shape | UE state | verdict | why |
|---|---|---|---|
| `trackingAreaList` contains the UE's `nr_tai` | TAI known | `IN_AREA` | the UE is in a TA that constitutes the area |
| `trackingAreaList` does not contain it | TAI known | `OUT_OF_AREA` | — |
| `ncgiList` contains the UE's `nr_cgi` | cell id non-default | `IN_AREA` | — |
| `ncgiList`, UE `nr_cgi` is the default | cell id `0` | `UNKNOWN` | **not `OUT_OF_AREA`**: `nr_cgi` has one production writer (`handle_handover_notify`), so a default means "never learned", not "not in the area". Reporting `OUT_OF_AREA` off an unwritten field is precisely the fabrication #400 forbids. |
| `praId` only, no enumerated elements | any | `UNKNOWN` | CN-predefined PRA; no local configuration (§5.6.11 `:13630`) |
| `ladnInfo` / `sNssai` / `nsiId` / `sliceAreaRestrictionInfo` | any | `UNKNOWN` | no LADN, NS-AoS or Partially-Allowed-NSSAI state in the tree (M2) |
| any area | UE TAI is the default `Tai5gs` | `UNKNOWN` | a UE whose location was never learned |

### 3. Fire points — both on LIVE paths, chosen by where the event occurs

`PRESENCE_IN_AOI_REPORT` and `UES_IN_AREA_REPORT` fire from the two sites where the AMF
**becomes aware of a location** (M3: two, not three):

* **`send_registration_accept`** (`ngap_path.rs:4364`), beside #402's three emitters and
  inside the same single `ue_auth_state.get`, so all five reports describe ONE consistent
  snapshot. This is where `nr_tai` was just written from the InitialUEMessage, and §5.3.1
  requires a first notification carrying *"the current presence status of the target UE(s)"*
  (`:4879-4882`).
* **`handle_handover_notify`** (`ngap_path.rs`), after the relocation has moved `nr_tai`
  **and** `nr_cgi` to the target. This is the only site where an **IN→OUT transition** can be
  observed, which is what §6.2 means by *"notification when a specified UE enters or leaves
  the specified area"* (`:24968-24972` / `:4860-4863`). Fired after the `with_mut` that
  writes the new location, so the comparison is against where the UE now is.

**Why not `handle_service_request_nas`.** #402 fires `LOCATION_REPORT` there, so symmetry
argues for it — but M3 established that the Service Request path **cannot learn a new
location**: `parse_uplink_nas_transport_asn1` drops the `UserLocationInformation` the NGAP
parser already decoded. A presence emitter there would re-evaluate the *registration's* TAI
and report an unchanged verdict as if it were news, and §5.3.1 requires that *"In subsequent
notifications, the AMF shall only report the UE(s) whose presence status has changed"*
(`:4895-4897`). Firing there would violate that clause. **Ceiling stated at the site, and
the parser gap filed as a follow-up** — it is a real defect with a wider blast radius than
this issue (it is also why `LOCATION_REPORT` at that site reports a stale TAI).

### 4. The transition rule: `presence_state_changed` guards subsequent notifications

§5.3.1 `:4895-4897` is a **shall**: subsequent notifications report only UEs whose status
*changed*. So the per-(subscription, area) last-reported `PresenceState` is stored on the
subscription and the emitter suppresses an unchanged verdict. Without this the handover site
would notify on every relocation inside one area — a notification the spec forbids, and the
"plausible-but-wrong moment" failure mode #400 was filed to avoid.

### 5. `UES_IN_AREA_REPORT`: `numberOfUes`, derived by scan

§5.3.1 (`:5143-5146`): *"A NF subscribes to this event to receive the number of UEs in a
specific area."* `UE Type: any UE` (`:5170`) — the type is **any-UE only**, so a SUPI-targeted
subscription for it is not what the clause describes. The count is `evaluate_presence ==
IN_AREA` over `ue_store.snapshot()`, derived rather than indexed (M5).

Two wire rules that are easy to get wrong, both pinned by tests:

* **NOTE 1 (`:22212`): *"SUPI, PEI and GPSI shall not be present in report for
  UES_IN_AREA_REPORT event type."*** The report is about an area, not a UE. So this type
  cannot go through `fire_ue_event`, which attaches all three identities — it needs its own
  emitter, and that is why `fire_ues_in_area_report` is separate.
* **NOTE 3 (`:22216-22218`)**: for a `PRESENCE_IN_AOI_REPORT` targeting any UE with no UE
  currently IN the AoI, *"the anyUe IE shall be present with the value true and IEs
  indicating UE IDs ... shall not be present; the areaList IE shall be present including the
  subscribed AOI with the Presence Status set to 'IN'"*. Counter-intuitive — the status is
  `IN` for an empty area — and implemented literally, with the clause quoted at the site.

### 6. `reportingThreshold`, `uePosCapRequestedInd` and the AOIEF filters: declared
### unsupported at the site

All four are **optional features** in the §6.2.8 table, and the AMF advertises
`supportedFeatures` it does not claim:

* `reportingThreshold` — `OBGAD` (`:24813`), and the IE is scoped to *"UEs subscribed to
  LCS Broadcast Assistance Type(s)"* (`:21720-21724`), state this AMF does not hold.
* `uePosCapRequestedInd` / `uePosCap` — `AIML_CN` (`:22154`). The report member is
  conditional on the capabilities being *"available in AMF"* (`:22161`), and
  `grep -rn 'pos_cap' bins/nextgcore-amfd/src/` finds nothing. Omitting it is the
  conformant answer, not a gap.
* `adjustAoIOnRa`, `ranTimingSynchroStatusChange`, `notifyForSupiList`,
  `notifyForGroupList`, `notifyForSnssaiDnnList` — `AOIEF` (`:24769`).
  `adjustAoIOnRa` would need the UE's Registration Area TA list and
  `ranTimingSynchroStatusChange` the UE 5GMM capability bit; neither is held.

Each is **accepted and logged, never refused**: they are optional IEs on a conformant
subscription, and a 400 would be wrong for the same reason #74 criterion 4 established for
`groupId`. What is refused is pretending to honour them.

---

## Rejected options, named

**A `configs/amf.yaml` presence-area block** (the issue's M1 prerequisite). Rejected
because it answers the wrong question for the tractable case: §5.6.11 puts the TA list **in
the subscription** for UE-dedicated PRAs (`:13633-13636`), so configuration would add an
unused surface while the honest path went unimplemented. It is genuinely required only for
the CN-predefined/`APRA` case — an optional feature — and adding a config knob no shipped
config sets, for a feature the AMF does not advertise, is the "correct but unreachable"
defect this tree names as its commonest.

**A reverse index of area→UEs** (the issue's M5). Rejected on `ue_store`'s own recorded
reasoning (`ue_store.rs:28-38`): an index beside a collection that can disagree with it is
the root cause of #325, #365 and #363. The scan is bounded by `max_num_of_ue` and runs per
event, not per NGAP message.

**Refusing a `praId`-only subscription with a 400.** Rejected: the subscription is
conformant, and #402's own reason for keeping these types in `AMF_EVENT_TYPES` was that
refusing a conformant subscription is a wrong 400. `UNKNOWN` is the spec's answer for an
area the AMF cannot resolve.

**Reporting `OUT_OF_AREA` when the UE's location is unknown.** Rejected — it is the exact
fabrication the issue forbids, and the `PresenceState` enum has a value for the real
situation.

**Firing from `gmm_handler`.** Rejected for #397's reason: every caller is inside
`mod tests`, so an emitter there fires zero times in production.

**An in-process stand-in gNB to reach the post-egress fire points.** Rejected: the owner
refused it on PR #402 (*"i am not supporting loopback gnb"*). `handle_handover_notify` is
reachable without one — it is a handler that takes the decoded PDU and does its location
write before any send — which is why it carries the transition test.

---

## Residual ceilings, stated at the declaration

The `AMF_EVENT_TYPES` doc comment is rewritten, not deleted: both types move to the "fires"
table and a narrower ceiling replaces the old one, naming the four optional features, the
three unmodelled `AmfEventArea` alternatives, and the Service-Request location gap.

**Filed as follow-up #406:** `parse_uplink_nas_transport_asn1` discards the
`UserLocationInformation` that `nextgcore-ngap`'s parser already decodes as a mandatory IE
(and refuses the message without). Fixing it makes the Service Request a third genuine
location-learning moment, which would let both presence emitters AND #402's
`LOCATION_REPORT` report a UE that moved while idle — today that report carries a stale
TAI. #406 also covers giving `nr_cgi` a second production writer, which is what would let
`ncgiList` areas resolve outside a handover.

---

## How every behavioural claim was revert-verified

Each named test below was made to fail by reverting the specific behaviour, then restored:

All twelve reverts below were actually applied, the named test observed to fail, and the
change restored. **One of them failed to fail on the first attempt and the test had to be
rewritten** — recorded in full afterwards, because it is the kind of hole that otherwise
ships as green-proving-nothing.

| claim | test | revert applied, and the observed failure |
|---|---|---|
| a TAI inside the area reports `IN_AREA`, one outside reports `OUT_OF_AREA` | `a_tai_area_reports_in_area_for_a_ue_inside_it_and_out_for_one_outside` | swapped the two arms of `evaluate_presence`'s TAI `contains` → **FAILED** |
| an unresolvable bare `praId` reports `UNKNOWN`, not `OUT_OF_AREA` | `a_pra_id_without_enumerated_elements_reports_unknown` | returned `PRESENCE_OUT_OF_AREA` from the non-evaluable arm → **FAILED** |
| a UE with no learned location reports `UNKNOWN` | `a_ue_with_no_learned_location_reports_unknown` | deleted the `ue_tai_is_known` guard → **FAILED** |
| an `ncgiList` area reports `UNKNOWN` until a handover writes `nr_cgi` | `an_ncgi_area_reports_unknown_until_the_cell_identity_is_learned` | deleted the `ue_ncgi_is_known` guard → **FAILED** |
| a handover out of the area reports the `OUT_OF_AREA` transition, from the PRODUCTION handler | `a_handover_out_of_the_subscribed_area_reports_the_transition` | deleted the `fire_presence_in_aoi_report` call in `handle_handover_notify` → **FAILED** (recv timed out) |
| an unchanged verdict is NOT re-notified (§5.3.1 `:4895-4897`) | `an_unchanged_presence_state_is_not_notified_again` | bypassed `event_subscription_record_presence` → **FAILED** (the duplicate arrived) |
| `numberOfUes` counts only the UEs IN the area | `ues_in_area_counts_only_the_ues_inside_the_area_and_names_none_of_them` | counted `ues.len()` → **FAILED** |
| the empty any-UE AoI reports status `IN` (NOTE 3 `:22216-22218`) | `an_empty_any_ue_area_reports_the_note_3_shape` | flipped `empty_any_ue_aoi_report` to `OUT_OF_AREA` → **FAILED** |
| an unevaluable `AmfEventArea` alternative is reported `UNKNOWN`, not dropped | `an_unevaluable_area_alternative_is_accepted_and_reported_unknown` | removed the `unsupported_kind` recording from `parse_event_area` → **FAILED** |
| the `MPRA` `presenceInfoList` map form is parsed | `the_mpra_presence_info_list_map_form_is_parsed_and_keyed_by_its_pra_id` | disabled the `presenceInfoList` branch of `parse_event_areas` → **FAILED** |
| the subscription echo carries the areas WITHOUT a `presenceState` | `a_subscription_echoes_its_areas_without_a_presence_state` | removed the `presenceState` strip → **FAILED** |
| a malformed `Tac` does not silently become a valid one | `a_malformed_tac_does_not_become_a_wildcard_area` | replaced `parse_tac`'s body with `Some(from_str_radix(s,16).unwrap_or(0))` → **FAILED** (see below) |

### The test that failed to fail, and what was wrong with it

`a_malformed_tac_does_not_become_a_wildcard_area` originally used a UE with **no learned
location** and a TAC of `"ZZZ"`, reasoning that a defaulted TAC of 0 would match the
default `Tai5gs`. Removing `parse_tac`'s guard and re-running produced **580 passed** —
the test could not tell the guard was gone.

The reason: `evaluate_presence` checks `ue_tai_is_known` *before* comparing, so a
location-less UE answers `UNKNOWN` whatever the area contains. The assertion was
satisfied by a different mechanism than the one it claimed to pin, and `"ZZZ"` is not
valid hex either, so `from_str_radix` would have failed on charset rather than length.

Rewritten to discriminate: the UE now has a **real** learned TAC of `0x0FAB`, and the
area's TAC is `"FAB"` — valid hex, invalid LENGTH (the pattern allows 4 or 6 digits,
`TS29571_CommonData.yaml:1341-1342`). Without the length guard `from_str_radix` reads it
as `0x0FAB`, which is exactly the UE's TAC, so the area silently becomes one that
CONTAINS the UE and the verdict flips to `IN_AREA`. Re-applying the revert against the
rewritten test now **FAILS**, as it must.

### Assertion discipline

Assertions are **positive and discriminating**: every test asserts the delivered
notification's `areaList[].presenceInfo.presenceState` and the area's identity (`praId`),
not the absence of an error. The `IN_AREA` test carries a **contrast area deliberately
OUTSIDE** the UE's TAI in the same subscription, so an emitter answering `IN_AREA`
unconditionally fails; `an_ncgi_area_...` asserts `UNKNOWN` then `IN_AREA` for the SAME
area across a learned cell identity, so an unconditional `UNKNOWN` fails too;
`an_unchanged_presence_state_...` asserts arrive / suppressed / arrive, so an emitter that
never fires fails the first and last.

The must-not-fire assertion **waits** (bounded 600 ms), because delivery is spawned and an
instantaneous check would pass with a notification in flight — the pattern #402 established.

Process-global state uses `crate::test_support::CONTEXT_GUARD`; no new lock was declared.
Every literal (SUPI `imsi-0010100004xxx`, TAC `0x04xx`, notify path, AMF-UE-NGAP-ID
`78_400`, associations `94_001`/`94_002`) is unique to its test, with a comment saying why
— two amfd tests once shared `78_001` and failed ~1 run in 3.

### Counts and flake check

`cargo test --workspace`: **6833 → 6845** (+12), zero failures. `cargo fmt --all --
--check` clean. `cargo clippy --workspace` (the CI gate, which does not pass
`--all-targets`) reports nothing for the production code. The amfd suite was looped **10×
and was green 10/10**, at `/proc/loadavg` 4.0–6.0 on the shared 48-core box.

Assertions are **positive and discriminating**: every test asserts the delivered
notification's `areaList[].presenceState` and the area's identity, each with its own literal
TAC and SUPI so a report assembled from a default or from a sibling test's state fails.
Each `PRESENCE_IN_AOI_REPORT` test that asserts `IN_AREA` pairs it with a **contrast UE or
area deliberately OUTSIDE** the subscribed TAI list, so an implementation that answered
`IN_AREA` unconditionally cannot pass.

Process-global state uses `crate::test_support::CONTEXT_GUARD` (no new lock), and every
test's literal keys (SUPI, TAC, subscription path) are its own with a comment saying why.
