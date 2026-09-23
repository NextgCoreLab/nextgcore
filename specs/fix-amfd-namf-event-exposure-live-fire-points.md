# Fix amfd Namf_EventExposure: give every honestly-emittable event type a PRODUCTION fire point

**Issue:** nextgcore #397 (split out of #74 criterion 5 by PR #398)
**Verified against:** nextgcore `main` @ `04266af`
**Spec basis:** TS 29.518 §6.2 (`AmfEventType` semantics), §6.2.5.2.1 (which callback a
notification goes to), §6.2.6.2.2 (`AmfEventSubscription`), §6.2.6.2.4
(`AmfEventNotification`), §6.2.6.2.5 (`AmfEventReport`), §6.2.6.2.11
(`CommunicationFailure`), §6.2.3.3.3 (methods on an individual subscription),
§5.2.2.2.3.1 (CreateUEContext, the event-subscription takeover); TS 23.502 table
4.15.3.1-1 (what "Communication failure" IS); TS 23.501 §5.6.2 (the AMF provides a UE
Time Zone to the SMF); TS 24.501 §5.5.1.2.4 (the UE enters 5GMM-REGISTERED on the
Accept), §5.5.2.2.2 (no Accept to a switched-off UE), §5.6.1.5 (Service Reject #9);
TS 38.413 §9.2.2.3 (UEContextReleaseRequest IEs), §9.3.1.2 (Cause).
Spec text read at `6g_docs/specs/29518-k00.txt`, `23502-k20.txt`, `23501-k20.txt` and
the OpenAPI at `6g_docs/specs/TS29518_Namf_*.yaml` / `TS29571_CommonData.yaml`; every
clause quoted below was read there, with file:line.
**Precedent:** PR #398 (`04266af`, #74) wired three previously-silent types at live NGAP
sites and established both the pattern and the naming. This finishes the job.

## Read this first: the headline is worse than #74 said, and one of #397's own claims is false

### Criterion-by-criterion, re-located at `04266af`

| # | criterion | cite in the issue | site at `04266af` | verdict |
|---|---|---|---|---|
| 1 | `LOCATION_REPORT`, `REGISTRATION_STATE_REPORT`, `REACHABILITY_REPORT` fire from code a production NGAP message reaches | `gmm_handler.rs:158-159`, `:299-300`, `:373`; callers at `:842`/`:870`/`:887` | **line numbers drifted, claim CONFIRMED.** Emitters at `gmm_handler.rs:158`, `:159`, `:299`, `:300`, `:368`. `mod tests` begins at `:788`; the only callers of all three handlers are at `:837`, `:865`, `:882`, `:901`, `:920` — every one inside it | **real — implemented** |
| 2 | `EventSubscription` stores `subsChangeNotifyUri`/`subsChangeNotifyCorrelationId`, and CreateUEContext's §5.2.2.2.3.1 takeover fires `SUBSCRIPTION_ID_CHANGE`/`_ADDITION` | `context.rs` has no `subs_change_*` member | confirmed: `EventSubscription` (`context.rs:729-768`) has eleven members and neither. `handle_create_ue_context` (`namf_server.rs:2973`) never reads `ueContext.eventSubscriptionList` | **real — implemented** |
| 3 | `TIMEZONE_REPORT` fires — "which requires the AMF to hold a UE time zone at all; say where it comes from" | `gmm_build.rs:983-985` sets all three time-zone IEs to `None` | confirmed verbatim at `:983-985`. And nothing anywhere PARSES a time zone: `grep -rn 'time_zone' bins/nextgcore-amfd/src/` returns only those three writes and the `provide-loc-info` omission | **real — CEILING STATED** |
| 4 | `COMMUNICATION_FAILURE_REPORT` fires with a real `nasReleaseCode` or `ranReleaseCode`, "not a placeholder" | *"Neither release code is plumbed anywhere the event could read it"* | **the issue's premise is FALSE for the RAN code.** `nextgcore_ngap::parser::parse_ue_context_release_request` (`libs/nextgcore-ngap/src/parser.rs:1005-1041`) decodes Cause as a MANDATORY IE and REFUSES the message without it (`:1036-1039`); `UeContextReleaseRequest.cause` (`types.rs:320`) carries it. `handle_ue_context_release` then discarded it | **real — implemented, premise partly void** |
| 5 | `PRESENCE_IN_AOI_REPORT` / `UES_IN_AREA_REPORT`: presence-area tracking lands, or they are split out with the model question stated | no presence-area state at all | confirmed. No `PresenceInfo`, no `AmfEventArea`, no area evaluation anywhere in amfd | **real — CEILING STATED, SPLIT to #400** |
| 6 | every new emitter's PRODUCTION site is asserted, "not just the `fire_*` function" | — | #398's `the_mobile_reachable_expiry_fires_loss_of_connectivity_to_a_subscriber` is the only such test in the tree | **real — implemented** |

### The headline count is wrong in the issue's favour, and worth stating exactly

#74 said "3 of 12". #397 corrected that to "zero of twelve fired in production before
#74's PR" — which is right, and it is also the whole point. This PR takes the
production-reachable count from **three (all added by #398) to ten**, and the three the
issue is named for go from **dead to live**.

| type | before #398 | after #398 (`04266af`) | after this PR |
|---|---|---|---|
| `LOCATION_REPORT` | dead (`gmm_handler`) | dead | `send_registration_accept`, `handle_service_request_nas` |
| `REGISTRATION_STATE_REPORT` | dead | dead | `send_registration_accept`, `finish_deregistration` |
| `REACHABILITY_REPORT` | dead | dead | `handle_service_request_nas` |
| `ACCESS_TYPE_REPORT` | silent | **live** (#398) | unchanged |
| `CONNECTIVITY_STATE_REPORT` | silent | **live** (#398) | unchanged |
| `LOSS_OF_CONNECTIVITY` | silent | **live** (#398) | + `finish_deregistration` (2nd/3rd trigger) |
| `COMMUNICATION_FAILURE_REPORT` | silent | silent | **live** — `handle_ue_context_release` |
| `SUBSCRIPTION_ID_CHANGE` | silent | silent | **live** — `handle_create_ue_context` |
| `SUBSCRIPTION_ID_ADDITION` | silent | silent | **live** — `handle_create_ue_context` |
| `PRESENCE_IN_AOI_REPORT` | silent | silent | **ceiling stated**, split to #400 |
| `UES_IN_AREA_REPORT` | silent | silent | **ceiling stated**, split to #400 |
| `TIMEZONE_REPORT` | silent | silent | **ceiling stated** (accepted, does not fire) |

**0 → 3 → 10 of 12.**

## Criterion 1: the three dead emitters, moved to where the event occurs

### Why MOVED, and not given a production caller

The tempting fix is to call `gmm_handler::handle_registration_request` from
`ngap_path`. It is the wrong fix and this project has a name for it: nextgcore #223's
criterion 2 refuses "correct but unreachable, now with a caller". `ngap_path` already
records the shape, for a different fix on this same module:

> *"The parser #116's text cites (`gmm_handler`'s) has only test callers — its own
> `handle_registration_request` is called from three places, all inside `mod tests` — so
> implementing this there would have been a correct fix in an unreachable place."*

The live NAS path (`handle_registration_request_nas`, `handle_service_request_nas`,
`handle_deregistration_request_nas`) builds and sends its own messages and never enters
`gmm_handler`. So the question is not *how do I reach that function* but *where does the
event honestly occur*, and the answer differs per type.

### The sites, and why each is the moment the event occurs

**`send_registration_accept`, after the ICS carrying the Accept has egressed —
`REGISTRATION_STATE_REPORT(REGISTERED)` + `LOCATION_REPORT`.**

§6.2 (`29518-k00.txt:24000-24008`) reports registration state *"when AMF becomes aware of
a registration state change"*. TS 24.501 §5.5.1.2.4 has the UE enter 5GMM-REGISTERED on
*receiving* the Accept, so the egressed Accept is the first moment the AMF can truthfully
say "registered" rather than "registering". `LOCATION_REPORT` joins it because
`amf_ue.nr_tai` was written from the InitialUEMessage's own `UserLocationInformation`
(`ngap_path.rs:1581`) — this is where the AMF became aware of the UE's location.

Placed beside #398's `ACCESS_TYPE_REPORT`, inside the same `ue_auth_state.get`, so all
three reports describe ONE consistent snapshot.

**`handle_service_request_nas`, after the Service Accept has egressed —
`REACHABILITY_REPORT(REACHABLE)` + `LOCATION_REPORT`.**

Reachability here is *demonstrated*, not inferred: the UE answered. It is also a genuine
CHANGE — `start_reachability_supervision` armed the mobile-reachable timer at the
previous N1 release precisely because the AMF could no longer reach it, and this is the
transition back. `LOCATION_REPORT` fires at BOTH this site and registration, deliberately:
§6.2's trigger is "when AMF becomes aware of a location change", the AMF becomes aware at
each, and reporting only one would silently drop the other.

**`finish_deregistration` — `REGISTRATION_STATE_REPORT(DEREGISTERED)` +
`LOSS_OF_CONNECTIVITY(DEREGISTERED)`.**

The COMMON TAIL, not either direction's handler: UE-initiated
(`handle_deregistration_request_nas:4759`) and network-initiated (`:1879`) both converge
here, so one call covers both and cannot drift. It also fires for the UE that switched
off — no Accept is sent to such a UE (TS 24.501 §5.5.2.2.2) but it is just as
deregistered, and a consumer that heard nothing would still believe it registered.

Placed BEFORE `ue_auth_state.remove`, because that is where the SUPI and location the
reports carry live — the same ordering constraint #291's EBI release records two lines up.

`LOSS_OF_CONNECTIVITY` is a bonus, not a stretch: §6.2 (`:24089-24098`) names THREE
triggers — *"when Mobile Reachable timer expires in the AMF..., when the UE detaches and
when AMF deregisters from UDM for an active UE"*. #398 wired the first. Deregistration is
the other two, and both happen here (the UDM purge runs in
`handle_deregistration_request_nas` immediately above). `DEREGISTERED` is the
`LossOfConnectivityReason` for it (`TS29518_Namf_EventExposure.yaml:1610`), distinct from
#398's `MAX_DETECTION_TIME_EXPIRED` — so a consumer can tell a detach from an
unreachable UE.

### `gmm_handler` now has ZERO emitters

Not one moved-and-also-left, not one wrapped in a flag: `grep -c 'fire_' gmm_handler.rs`
returns 1, and that one hit is the comment recording why. Three long comments replaced
them, naming the new site and the reason, so a future reader who wonders why an
event-exposure module has no event emitters finds the answer in place.

## Criterion 4: `COMMUNICATION_FAILURE_REPORT`, and the issue's false premise

The issue says *"Neither release code is plumbed anywhere the event could read it."* The
RAN one was — one call away. `nextgcore_ngap::parser::parse_ue_context_release_request`
decodes Cause as a mandatory IE and refuses the message without it; the value then reached
`handle_ue_context_release` and was thrown away. `extract_release_request_cause`
(`ngap_asn1.rs`) surfaces it as the `(group, value)` pair `NgApCause`
(`TS29571_CommonData.yaml:2554-2564`, both members `required`) wants. **Nothing new is
parsed off the wire.**

### Which releases are FAILURES — the conformance decision

TS 29.518 §6.2 (`29518-k00.txt:5126-5131`) defines the event by reference: the AMF reports
*"when the AMF becomes aware of a RAN or NAS failure event. This event implements the
'Communication failure' event in table 4.15.3.1-1 of TS 23.502, which is an unexpected
termination of the communication."* That table's row (`23502-k20.txt:28570-28577`) names
the detector and the mechanism: *"This event is detected when RAN or NAS level failure is
detected based on connection release and it identifies RAN/NAS release code"*, AMF as
detecting NF.

So the classification is NOT "did the RAN release the UE" — it always did, that is why the
message arrived — but "was the release **unexpected**". `is_communication_failure_cause`
is a pure function, separate from the handler, because this mapping IS the conformance
decision.

**An expected-cause ALLOWLIST, not a failure list.** `CauseRadioNetwork` has 47 values and
TS 38.413 §9.3.1.2 adds no "is this a failure" bit, so either direction is a judgement.
The allowlist is the safe one: an unclassified cause reports as a failure, which a consumer
can investigate; the inverse would silently swallow every future failure cause. Expected:
`user-inactivity` (20 — the AS release of TS 38.300 §9.2.1 and the normal path into
CM-IDLE), `successful-handover` (2), `ngran-generated-reason` (3), `5gc-generated-reason`
(4 — *this AMF asked*), `ho-cancelled` (5), `partial-handover` (6),
`ng-intra/inter-system-handover-triggered` (31/32), `xn-handover-triggered` (33),
`ue-context-transfer` (35), `redirection` (41). Everything else, and every non-radioNetwork
group, is a failure.

Firing on `user-inactivity` would tell a consumer a failure occurred **every time a UE went
idle**. That is the "plausible-but-wrong site" the issue warns about, and it is pinned by a
discriminating test.

### `nasReleaseCode` is deliberately OMITTED

Its pattern is `^(MM|SM)-[0-9]{1,3}$` (`29518-k00.txt:22465-22477`), a 5GMM/5GSM cause. A
RAN-initiated release carries no NAS cause. Inventing one would report a NAS failure that
did not happen.

## Criterion 2: `SUBSCRIPTION_ID_CHANGE` / `_ADDITION` and the §5.2.2.2.3.1 takeover

### These are not subscribable events, so they are not matched like one

§6.2 says of both that *"This event needs no explicit subscription form an NF service
consumer"* (`29518-k00.txt:24052`, `:24069`). No consumer ever lists them in an
`eventList`, so matching against `event_types` would find nothing. They fire for a
subscription whose `subsChangeNotifyUri` is set, whatever that subscription was for —
which is why `deliver_subscription_id_change` is a separate function and not a
`fire_ue_event` caller.

### The trigger, and the clause that defines it

Table 6.2.6.2.5-1's `subscriptionId` row (`:21886-21911`) gives the only trigger: the IE
*"shall be included when the event notification is for informing the creation of a
subscription Id at the AMF during mobility of a UE across AMFs"*, with
`SUBSCRIPTION_ID_CHANGE` for a *"UE specific"* subscription and `SUBSCRIPTION_ID_ADDITION`
for a *"group Id specific"* one, both *"during mobility registration and handover
procedures involving an AMF change"*.

§5.2.2.2.3.1 (`:2769-2772`) is where that happens: the target AMF shall *"for each created
event subscription, allocate a new subscription Id, if necessary... and if allocated send
the new subscription Id to the notification endpoint for informing the subscription Id
creation, along with the notification correlation Id for the subscription Id change."*
The subscriptions arrive in `ueContext.eventSubscriptionList`
(`TS29518_Namf_Communication.yaml:3050-3053`, items `ExtAmfEventSubscription` = an
`AmfEventSubscription` plus additional info, `:4049-4054`).

### Three wire details that are easy to get wrong, and are each pinned by a test

1. **Which callback.** §6.2.5.2.1 (`:20767-20771`): *"If the notification is to inform the
   change (or addition) of subscription ID and if the `subsChangeNotifyUri` was provided
   in the AmfEventSubscription, then this callback URI shall be the
   `subsChangeNotifyUri`... Otherwise, this callback URI shall be the `eventNotifyUri`."*
   Two sinks are stood up in the test so this is asserted, not assumed.
2. **Which correlation ID — exactly one.** Table 6.2.6.2.4-1 (`:21795-21833`) makes
   `subsChangeNotifyCorrelationId` and `notifyCorrelationId` mutually exclusive for a
   subscription-ID notification. Sending both would be wrong; the two tests take one
   branch each.
3. **`subscriptionId` is a URI, not an id.** §6.2.6.2.5: *"the URI of the created
   subscription resource at the AMF; this shall contain an absolute URI set to the
   Resource URI specified in clause 6.2.3.3.2."* And `state.active` must be `true`
   whenever it is present (`:21878-21881`).

### Decisions taken, and the alternatives rejected

**A NEW subscription ID is always allocated.** The NOTE at `:24100` permits reuse *"if the
mobility is between AMFs of same AMF Set"*, but `UeContextCreateData` carries no source
GUAMI, so this AMF cannot tell whether the source was in its own set. Allocating is the
unconditionally-correct branch.

**CreateUEContext only, not `/relocate`.** §5.2.2.2.5.1's `UeContextRelocateData` carries a
`ueContext` for a different purpose — the N26 EPS-interworking case, where the peer is an
MME with no Namf event subscriptions to hand over. Taking them over there would create
subscriptions for a procedure the clause does not describe.

**An entry missing a required member is skipped, not defaulted.**
`eventList`/`eventNotifyUri`/`notifyCorrelationId`/`nfId` are `AmfEventSubscription`'s
required members (yaml:589-593). A subscription with no notify URI could never be delivered
to, and inventing one would point notifications at an endpoint the consumer never gave.

**No `subsChangeNotifyUri` means no notification at all**, only a debug log. A consumer
that supplied none did not ask to be told, and posting the ID change to `eventNotifyUri`
instead would send it a report for a type it never subscribed to, down the channel it uses
for the ones it did.

**A present-but-unusable `subsChangeNotifyUri` is refused at subscribe time (400).**
Storing it would create a subscription whose `SUBSCRIPTION_ID_CHANGE` can never be
delivered, and the consumer would have no way to learn that.

## Ceilings: the three types that do NOT fire, and why that is the honest answer

The project convention is that a stated ceiling beats a stub that looks handled, and an
emitter at a plausible-but-wrong site is worse than a silent type — it produces
notifications a consumer acts on at moments the spec does not define. All three ceilings are
recorded in the doc comment on `AMF_EVENT_TYPES`, at the declaration, so they are found by
anyone asking "does this fire?".

### 1 + 2. `PRESENCE_IN_AOI_REPORT` and `UES_IN_AREA_REPORT` — no presence-area model exists

`AmfEventReport.areaList` (Table 6.2.6.2.5-1, `29518-k00.txt:21923-21940`) must report which
subscribed AoI the UE is *"currently IN / OUT / UNKNOWN"*, and for a PRA identifier naming a
SET it must additionally report *"the additional PRA identifier of the actually individual
PRA(s) where the UE is currently IN / OUT, as specified in clause 5.6.11 of TS 23.501"*.
`AmfEventArea` (`TS29518_Namf_EventExposure.yaml:1011-1024`) is a choice of `PresenceInfo`,
`LadnInfo`, `SliceAreaRestrictionInfo`, `sNssai` or `nsiId` — this AMF stores none of them
and evaluates the UE against none. `UES_IN_AREA_REPORT`'s `numberOfUes` (`:778`) needs the
same model plus a per-area count.

**Deciding that model is feature work, not fire-point work**, exactly as the issue says. It
is filed as **#400**, with five open model questions stated: where presence areas come from
(no configuration surface exists), what an area concretely is (TA-list is tractable,
`sNssai`/LADN/`nsiId` are not), when the UE is evaluated (only the three live moments the AMF
learns location, which bounds what "enters or leaves" can mean), that UNKNOWN is a real third
state rather than an error, and that `UES_IN_AREA_REPORT` needs an incrementally-maintained
reverse index or counting is O(UEs x areas) per location change.

Both remain **ACCEPTED** in `AMF_EVENT_TYPES` rather than removed, for the reason `groupId`
subscriptions are accepted (#74 criterion 4): the subscription is conformant and refusing it
is a wrong 400. What is refused is fabricating the report.

### 3. `TIMEZONE_REPORT` — the AMF holds no UE time zone at all

A different kind of gap, and worth separating from the other two. `gmm_build.rs:983-985`
sends `local_time_zone: None`, `universal_time_and_local_time_zone: None` and
`network_daylight_saving_time: None` in every CONFIGURATION UPDATE COMMAND, and nothing ever
parses one in — the time zone is **network-to-UE** information (NITZ, TS 22.042
`23501-k20.txt:3253`), so there is no uplink IE to learn it from.

TS 23.501 §5.6.2 (`23501-k20.txt:11296`) has the AMF *"also provide the corresponding UE
Time Zone"* to the SMF, which confirms the AMF is meant to HOLD one — it comes from operator
configuration keyed on the serving TAI, and this tree has no such configuration. §6.2's
trigger is *"when AMF becomes aware of a time zone change of the UE"*: with no value there is
neither a value to report nor a change to detect.

**Reporting the AMF HOST's zone would be a fabrication** — the host is wherever the core
runs, not where the UE is. `provide-loc-info` already omits `timezone` for this reason
(`namf_server.rs`), with a test asserting the omission; this is the same ceiling reached from
the event side, and the two now agree.

### Not widened: the 13 `AmfEventType` values the AMF does not declare

`AmfEventType` defines 25 values (`TS29518_Namf_EventExposure.yaml:1513-1543`);
`AMF_EVENT_TYPES` accepts 12. The issue notes this and says whether to widen is a separate
question. It is, and the answer here is no: the 13 absent ones (`SUBSCRIPTION_TERMINATION`,
`5GS_USER_STATE_REPORT`, the trends and measurement reports, ...) need state this AMF does
not hold, and accepting a subscription it can never notify is precisely what an
event-exposure producer must not do. The subset is now documented as deliberate rather than
incidental.

## How the tests assert the PRODUCTION site, not the emitter

#398's report records that one of ITS OWN tests initially called the emitter directly and
would have passed with the wiring deleted. Every test here drives a production function and
observes the notification at a real in-process `SbiServer`.

**The egress-ordering property is proven in the cross-repo Docker E2E, NOT by an
in-process peer.** The registration and service-request emitters fire AFTER
`send_to_association(..).await?` — deliberately, since the event is "the Accept has
egressed", not "the Accept was built". With no association that `?` returns first and the
fire point is never reached, so a unit test with no transport would be asserting an
unreachable site and could not tell working wiring from deleted wiring. That is a real
constraint, and the first revision of PR #402 answered it the wrong way — see the next
section.

**Reports are collected into a map keyed by type, not read positionally.** The emitters spawn
one task per subscriber, so several reports fired from one site arrive in non-deterministic
order; `rx.recv()` positionally would be flaky for a reason unrelated to what is under test.

**Assertions are positive, and on values that exist nowhere else in their fixture.** Each
test's SUPI, TAC and NGAP cause value are its own, so a report assembled from a default or
from a sibling's state fails. The `COMMUNICATION_FAILURE_REPORT` value comes off a real
APER-encoded PDU through the production decoder, so a hardcoded report could not produce it.

**Every "must not fire" test waits.** Delivery is spawned, so an instantaneous check would
pass even with a notification in flight. Both use a bounded 600ms wait.

## The in-process stand-in gNB was REMOVED, and why that is the right answer

The first revision of PR #402 met the egress-ordering constraint above with
`connect_stand_in_gnb`: a helper in amfd's `mod tests` that stood up a real SCTP
association against the NGAP server's own listener, so two unit tests
(`the_live_registration_accept_fires_registration_state_and_location_reports`,
`the_live_service_request_fires_reachability_and_location_reports`) could reach a fire point
that sits after a transport send.

**The repository owner refused it:** *"i am not supporting loopback gnb. we already have gnb
in other repo. we can evaluate it with that."* The facts back him, and they are checkable:

* `.github/workflows/ci.yml`'s `Docker E2E` job already checks out
  `NextgCoreLab/nextgsim`, and `docker/rust/Dockerfile.builder` already compiles its
  `nr-gnb` (with `--features kernel-sctp`) out of that checkout.
* `docker/rust/docker-compose.yml` already declares `gnb` and `ue` services on the core
  network, pointed at the AMF's N2 address.

So an in-process synthetic SCTP peer inside nextgcore duplicated a peer that exists properly
in the sibling repo, and left this tree owning two RAN implementations. **The helper and both
tests are deleted.** The other eight event types' unit tests are untouched: none of them
depends on a transport, because none of their fire points sits behind a transport send.

### Where the coverage went

`src/libs/nextgcore-sbi/examples/namf_event_probe.rs`, driven by three new `Docker E2E` steps
against nextgsim's REAL gNB and UE. Same pattern as #187/#393's `cca_token_probe`: an example
rather than a test, because it needs a live AMF and a live NG-RAN and `cargo test` has
neither; extracted from the builder image into `binaries/` and run inside a container, because
the AMF POSTs the notification to the callback URI it was handed and that has to be an address
on the core network.

It asserts, POSITIVELY and on notification BODIES:

| assertion | why it discriminates |
|---|---|
| `REGISTRATION_STATE_REPORT.supi` == the registering SUPI | not another UE the AMF serves |
| `rmInfoList[0].rmState` == `REGISTERED` | TS 24.501 §5.5.1.2.4 — the state the egressed Accept reports |
| `rmInfoList[0].accessType` == `3GPP_ACCESS` | `RmInfo` requires both members (`TS29518_Namf_EventExposure.yaml:908-910`) |
| `LOCATION_REPORT` `tai.plmnId.mcc`/`mnc`/`tac` == `999`/`70`/`0001` | the values the gNB reported; a report from a default `Tai5gs` says `000`/`000`/`0000` |
| `ACCESS_TYPE_REPORT.accessTypeList[0]` == `3GPP_ACCESS` | N2 from an NG-RAN IS the 3GPP access |
| every notification's `notifyCorrelationId` == this subscription's | a report cannot satisfy it by belonging to somebody else |
| a control subscription for a SUPI that never registers receives NOTHING | an AMF that broadcast to every subscriber would otherwise pass |

Three ordering and vacuity constraints had to be established rather than assumed:

1. **Something must subscribe first.** Nothing in the compose deployment subscribes to
   `namf-evts` — checked; the only NF-to-NF Namf subscription surface in use is
   `namf-comm`'s AMFStatusChange. So the probe creates the subscription itself over the
   AMF's real `POST /namf-evts/v1/subscriptions`, and prints `SUBSCRIBED`. The gNB and UE
   are started only after that line appears, **not after a sleep**:
   `event_subscriptions_matching_ue` matches against STORED subscriptions, so a registration
   that lands first is delivered to nobody and the stage would fail for a reason that is not
   the wiring.
2. **The registration is asserted separately from the delivery.** A middle step requires
   `NG Setup Response` in the gNB log and `Registration Accept` in the UE log. Without it, a
   missing notification would be unattributable between "the UE never registered" and "the
   emitters are not wired".
3. **The verdict must be readable.** The probe is detached (it must be listening before the
   UE starts), and a detached `docker compose exec` discards its exit status — so the probe
   writes its own code to `/tmp/probe.rc` and the final step fails if that file never
   appears. A step that cannot read the verdict is the green-proving-nothing outcome this
   whole assertion exists to avoid (#187's first CI attempt, which grepped for the absence of
   `invalid_client` and passed on a log with zero token requests).

### ~~CEILING: the SERVICE REQUEST fire point is NOT covered~~ — **CLOSED by #403**

**Superseded.** `REACHABILITY_REPORT` + `LOCATION_REPORT` from
`handle_service_request_nas` are now **proven** by a second phase of the same `Docker E2E`
job, against nextgsim's real gNB and UE. See
`specs/prove-service-request-namf-fire-point-e2e.md`.

The reasoning below is kept as the record of what was believed at the time, but **one of its
claims was false** and it matters which: it asserted that *"nothing in either repo can drive
an idle transition from outside the UE process"* and that a new `nr-ue` control surface would
be needed. It looked at the wrong node. nextgsim's **gNB** CLI already has `ue-suspend`,
which sends an `RRCRelease` carrying a `suspendConfig` (TS 38.331 §5.3.8.3) — RAN-local, so
the AMF keeps the NGAP UE context, the UE's NAS goes CM-IDLE, and a TUN write brings it back
through a real Service Request on an `UplinkNASTransport`. **No nextgsim change was
required.**

What the ceiling got right is that `ue-release` would *not* have worked: that one does tell
the AMF, both sides drop the NGAP context, and the UE returns on an `InitialUEMessage` —
which `handle_initial_ue_message` answers with Service Reject cause #9 unconditionally. That
remains a real nextgcore gap, recorded as a ceiling in the #403 spec.

> The E2E asserts the REGISTRATION fire point only. `REACHABILITY_REPORT` +
> `LOCATION_REPORT` from `handle_service_request_nas` are **not proven by any test after
> this change** — the deleted
> `the_live_service_request_fires_reachability_and_location_reports` was their only
> coverage.
>
> Reaching that site needs the UE to enter CM-IDLE and then either originate uplink data or
> answer a page. nextgsim's `nr-ue` does trigger a Service Request on both (a TUN write
> while idle, and `NasMessage::Paging` — `nextgsim-ue/src/main.rs`), but neither happens
> unprompted in a compose bring-up, and nothing in either repo can drive an idle transition
> from outside the UE process. Building that control surface is nextgsim work, not nextgcore
> work, which is exactly the owner's point restated.
>
> Filed as **#403**. Until it lands, the honest statement is: the registration emitters are
> proven live against a real gNB; the service-request emitters are wired at a site the
> reader can verify by inspection and are **unproven by automated test**.

### Revert-verification: eight changes broken, the NAMED test watched to fail, restored

Recorded as originally performed. The first two rows no longer name a `cargo test` test,
because the tests that caught them were deleted with the loopback gNB — but **both are now
caught by the `Docker E2E` job instead**, so they are no longer weaker claims and the
strike-through has been lifted (#403 criterion 4). The assertion that catches them is
stronger than what it replaced: it runs against nextgsim's real gNB rather than a synthetic
in-process peer.

| reverted | test that failed | discriminating sibling that stayed GREEN |
|---|---|---|
| registration emitters removed | `Docker E2E` → *Assert the AMF DELIVERED the registration Namf event notifications* (`namf_event_probe --phase registration`; replaced the deleted `the_live_registration_accept_fires_registration_state_and_location_reports`) | the service-request phase |
| service-request emitters removed | `Docker E2E` → *Assert the AMF DELIVERED the SERVICE REQUEST Namf notifications* (`namf_event_probe --phase service-request`, #403; replaced the deleted `the_live_service_request_fires_reachability_and_location_reports`) | the registration phase |
| deregistration emitters removed | `the_live_deregistration_fires_deregistered_and_loss_of_connectivity` | — |
| classifier forced to `true` (fire always) | `a_ran_release_for_user_inactivity_fires_no_communication_failure` | `a_ran_release_with_a_failure_cause_...` |
| comm-failure emitter removed | `a_ran_release_with_a_failure_cause_fires_communication_failure_report` | `..._for_user_inactivity_...` |
| takeover call replaced with `0` | `create_ue_context_takes_over_subscriptions_and_fires_subscription_id_change` **and** `a_transferred_group_subscription_reports_subscription_id_addition` | — |
| event type forced to always-`CHANGE` | `a_transferred_group_subscription_reports_subscription_id_addition` | the CHANGE sibling |
| correlation ID forced to always-`notifyCorrelationId` | `create_ue_context_takes_over_subscriptions_and_fires_subscription_id_change` | the ADDITION sibling |

Six of eight have a sibling that stayed green, so the pairs discriminate rather than both
depending on one wire.

## Test isolation

Followed the recorded rules. Every new test takes the existing
`crate::test_support::CONTEXT_GUARD` — **never a new lock** (a second lock hung the suite
once). Distinct literal SUPI / AMF-UE-NGAP-ID / TAC per test with a comment saying why:
`ue_auth_state`, the subscription store and the UE store are all process-global, and two
amfd tests once shared `78_001` and failed ~1 run in 3. Every test removes its subscription
afterwards, because a leftover is still scanned by every sibling's `fire_*`.

`set_sbi_profile_override(Dev)` is set and **deliberately not reset** — the override is
process-wide and PR #390 measured 2 failures in 10 whole-crate runs from resetting it
mid-flight.

## Verification

`cargo fmt --all -- --check`, `cargo clippy --workspace` (**0 errors**; CI's form) and
`cargo test --workspace` all pass. **6835 → 6833 tests, zero failures** — the two deleted
tests are the whole difference.

The amfd crate suite was looped **10 consecutive times, 568/568 every run**, at loads
0.95–3.76 on a 48-core box.

The E2E probe was verified locally against a real `nextgcore-amfd` process (release build,
`NEXTGCORE_SBI_PROFILE=dev`, the deployed `configs/5gc/amf.yaml` rehomed to loopback):

* the SUBSCRIBE half **works against the production `namf-evts` surface** — it returned 201
  with a `subscriptionId` for both the main and the control subscription, so the probe is
  not asserting against a route that answers 404;
* with no gNB and therefore no registration, the probe **FAILED with exit 1** and named the
  three missing report types. So the assertion is falsifiable by construction: a run in
  which the emitters do not deliver is a run in which this step is red.

The positive half needs 5G-AKA, and therefore the AUSF/UDM/UDR the compose stack provides,
so it was proven by a dispatched run.

### The dispatched run

<https://github.com/NextgCoreLab/nextgcore/actions/runs/35836705248> (`9d43ba2`,
`workflow_dispatch`) — **all seven jobs green, `Docker E2E` included.** A PR run cannot say
this: `Docker E2E` skips on `pull_request`.

The two new middle-step waits matched nextgsim's real log lines, so the registration really
happened before the delivery was asserted:

```
nextgsim-gnb | INFO nextgsim_gnb::ngap::task: Received NG Setup Response from AMF 0: name=nextgcore-amf0
nextgsim-ue  | INFO nextgsim_ue::nas::mm::orchestrator: Received Registration Accept: UE is now
               MM[RM-REGISTERED, CM-CONNECTED, 5GMM-REGISTERED.NORMAL-SERVICE, U1-UPDATED]
```

and the probe then reported, in the job log:

```
SUBSCRIBED main=sub-0669f958-... control=sub-3329b0e3-...
received REGISTRATION_STATE_REPORT
received LOCATION_REPORT
received ACCESS_TYPE_REPORT
  ok /supi == "imsi-999700000000001"
  ok /rmInfoList/0/rmState == "REGISTERED"
  ok /rmInfoList/0/accessType == "3GPP_ACCESS"
  ok /location/nrLocation/tai/plmnId/mcc == "999"
  ok /location/nrLocation/tai/plmnId/mnc == "70"
  ok /location/nrLocation/tai/tac == "0001"
  ok /accessTypeList/0 == "3GPP_ACCESS"
PASS: nextgsim's gNB registered imsi-999700000000001 over real N2 and the AMF DELIVERED
REGISTRATION_STATE_REPORT (REGISTERED / 3GPP_ACCESS), LOCATION_REPORT (mcc 999 mnc 70
tac 0001) and ACCESS_TYPE_REPORT to the subscribed callback, and delivered NOTHING to the
control subscription for imsi-999709999999999
```

So this is a **positive, value-level, end-to-end** result: the `tac 0001` and `mcc 999` came
off the InitialUEMessage the real gNB sent, not from a default `Tai5gs` (which would have
read `0000`/`000`), and the control subscription's silence shows the delivery was TARGETED
rather than broadcast. Combined with the local no-gNB run exiting 1, the assertion is shown
to distinguish both directions.

The run also caught one real defect before it shipped, which is the case for dispatching:
the middle step's log greps were originally `NG Setup Response` and `Registration Accept`,
GUESSED rather than read out of nextgsim. Both were substrings of the real text and would
have matched — but `NG Setup Response` also appears in a `warn!` about an unexpected PDU
while waiting for one, so the gate could have been satisfied by a failure. Corrected to the
exact `info!` text at the emitting line (`9d43ba2`).

Production reachability was re-verified by grep after the deletion — every `fire_*` call
site, classified PRODUCTION or TEST by whether it sits inside `mod tests`:

```
ngap_path.rs:4364  fire_access_type_report                       [PRODUCTION]
ngap_path.rs:4365  fire_registration_state_report(.., true)      [PRODUCTION]
ngap_path.rs:4366  fire_location_report                          [PRODUCTION]
ngap_path.rs:4581  fire_connectivity_state_report(.., true)      [PRODUCTION]
ngap_path.rs:4582  fire_reachability_report(.., true)            [PRODUCTION]
ngap_path.rs:4583  fire_location_report                          [PRODUCTION]
ngap_path.rs:4904  fire_registration_state_report(.., false)     [PRODUCTION]
ngap_path.rs:4905  fire_loss_of_connectivity(.., "DEREGISTERED") [PRODUCTION]
ngap_path.rs:6317  fire_connectivity_state_report(.., false)     [PRODUCTION]
ngap_path.rs:6358  fire_loss_of_connectivity (timer, #398)       [PRODUCTION]
ngap_path.rs:8502  fire_communication_failure                    [PRODUCTION]
gmm_handler.rs     (none — 1 grep hit, and it is the comment)
```

Deleting the two tests removed no production emitter: all eleven sites above survive, and
the three at `:4364-4366` are precisely the ones the new E2E probe now observes over the
wire.

## CI gating

`Docker Build` / `Docker E2E` / `EPC bring-up` are gated to `schedule || workflow_dispatch`
and SKIP on a PR. The emitted notifications go to subscriber URIs a consumer supplied, over
the same `notify_client` path #398's three emitters already use; the only new inbound surface
is two optional members on an existing request body. The overlay bring-up path is untouched.

**That gating is now load-bearing in a way it was not before, and it cuts against this
change.** The registration emitters' only remaining proof is the `Docker E2E` probe, which
**cannot run on a PR**. So a green PR on #402 says nothing about it, and the split recorded
in `specs/cross-repo-e2e-gating.md` (#349) applies here with one half genuinely empty: there
is no per-PR in-process equivalent, because building one is the loopback gNB the owner
refused. The per-PR guarantee for these three types is therefore **inspection plus the
`fire_*`-site grep above**, and the automated guarantee arrives on the nightly schedule or on
a dispatch. That is stated rather than papered over.

A dispatch is consequently MANDATORY for any change to these emitters or to the probe. This
PR's own dispatch is
<https://github.com/NextgCoreLab/nextgcore/actions/runs/35836705248> — all seven jobs green,
with the probe's per-value output quoted in the Verification section above. Three new steps
join the job:

* `Build the nextgsim gNB + UE images (the REAL RAN, #397)` — the builder image already
  compiled `nr-gnb`/`nr-ue`, but this job never turned them into images, so **no stage here
  had ever originated a registration**; the baseline stage was bring-up plus `/healthz`. It
  fails loud if either binary is absent, because `Dockerfile.builder` tolerates a nextgsim
  compile failure with `|| true` and would otherwise hand this step a silent gap.
* `Start the namf-evts notification sink and SUBSCRIBE (before any UE)`.
* `Register a REAL UE through nextgsim's gNB over N2`, then
  `Assert the AMF DELIVERED the registration Namf event notifications`.
