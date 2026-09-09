# nextgcore #106 (eesd): five unrouted service APIs, ACT status subscriptions, and the dead ACInfoNotification

Verified against `main` @ `143406a` (after #65/#272). The issue's cites are from `76ea248`; #105 has
since rewritten large parts of eesd, so every line number drifted.

## Verified against current main

| claim in the issue | check on `143406a` | still true? |
|---|---|---|
| no dispatch arm for `eees-easinfoprov`, `eees-session-with-qos`, `eees-tie`, `eees-ueidentifier`, `eees-uelocation` | `grep -n '\["eees' main.rs` → 21 arms, none of those five | yes |
| only `request-eelacr` is served on the EEL-managed ACR API | `main.rs:482`; no `/subscriptions` arm; no `ACTStatusSubsc` type anywhere | yes |
| `handle_acinfo_create` stores and answers 201 with no callback arranged | `main.rs:1774` (cite drifted ~240 lines) | yes |
| `ACInfoNotification` is constructed only in tests | `grep -rn 'ACInfoNotification' src/` → the struct, its doc, and `services.rs` tests. **No production constructor** | yes |
| `services.rs` module docs mark SessionWithQoS and TIE as DEFERRED | `services.rs:24-28` | yes |
| production `notifier::enqueue` emit sites are `EasDiscoveryNotification`, `AcrMgntEventsNotification`, `ACRInfoNotification` | unchanged; `ACInfoNotification` absent from all of them | yes |

The five API roots in the issue match the vendored YAMLs exactly
(`servers: - url: '{apiRoot}/eees-easinfoprov/v1'` etc.), so the paths were taken from the YAMLs
rather than from the issue text.

## The operation surface, taken from the YAMLs

| yaml | paths | operations |
|---|---|---|
| `TS24558_Eees_EASInformationProvisioning` | `/declare` | `declare` |
| `TS29558_Eees_UEIdentifier` | `/fetch`, `/get` | `FetchUEId`, `GetUEId` |
| `TS29558_Eees_UELocation` | `/fetch`, `/subscriptions`, `/subscriptions/{id}` | fetch + subscription CRUD |
| `TS29558_Eees_SessionWithQoS` | `/sessions`, `/sessions/{id}` | create/list + read/update/modify/delete |
| `TS29558_Eees_TrafficInfluenceEAS` | `/instances`, `/instances/{id}` | create + read/update/modify/delete |
| `TS29558_Eees_EELManagedACR` | `/subscriptions`, `/subscriptions/{id}` | `GetACTStatusSubscriptions`, `CreateACTStatusSubsc`, `GetACTStatusSubscription` |

Note the individual ACT status subscription resource defines **only GET** — no PUT, PATCH or DELETE.
The handler answers 405 with an `Allow` header for the others rather than inventing them.

## Decision 1: three APIs answer 501, and that is the deliverable for them

`eees-uelocation`, `eees-session-with-qos` and `eees-tie` all need a 5GC exposure leg that does not
exist in this tree. nefd (after #111) serves `3gpp-monitoring-event`, `3gpp-device-triggering` and
`nnef-eventexposure` — there is no `AsSessionWithQoS`, no UE-ID service and no traffic-influence
service to call. So:

* **Not 404.** A 404 says the resource does not exist, which is false — it is part of the API this
  EES claims to serve, and a conformant consumer cannot tell a missing route from a typo.
* **Not a 2xx.** Answering `201` to `CreateIndSessionWithQoS` while actuating no QoS anywhere is
  fabricated success: the caller would believe a QoS flow exists. The same argument rules out
  accepting `eees-uelocation` subscriptions — a subscription that can never fire is worse than a
  refusal, because the failure is silent. That is exactly the defect #106 reports for
  AppClientInformation, which this change fixes.
* **501, not 503.** 503 invites a retry that can never succeed. TS 29.500 §5.2.7.2 gives
  `NOT_IMPLEMENTED` for a capability the deployment does not have. Each 501 carries a
  ProblemDetails naming the missing leg, so an operator reading a log does not have to guess.

If a NEF leg lands later, the honest answer changes to a 2xx and these tests are what must be
inverted — stated here so the 501s are not mistaken for permanent design.

## Decision 2: `eees-easinfoprov` and `eees-ueidentifier` are served for real

Both can be answered from this EES's own state, so neither gets a 501 dodge.

**`easinfoprov /declare`** switches on `reqType`:

* `ACR_SCENARIO_SELECTION_ANNOUNCEMENT` → 204 (the yaml lists 204 alongside 200).
* `ACR_SCENARIO_SELECTION_REQUEST` → 200 with `selAcrScenarioList`, the intersection of what the EEC
  asked for with `EES_SUPPORTED_ACR_SCENARIOS`, **in the EEC's order** so its preference is honoured.
  An empty intersection is `404`, not a 200 with an empty list — an empty selection dressed as
  success is the same lie as a fabricated 201.
* `EAS_SELECTION` → 200 with `instEasInfo` for the first `selEasIds` entry actually registered here;
  `404` for an EAS that never registered.
* absent or unknown `reqType` → 204, because the enumeration is open (`anyOf` with a
  forward-compatibility string) and refusing a future value would break it.

`EES_SUPPORTED_ACR_SCENARIOS` is derived from **implemented code**, not copied from the enumeration:
`EEC_INITIATED` (appctxtreloc), `EEC_EXECUTED_VIA_TARGET_EES` (the §5.10 context *pull* landed in
#105), `SOURCE_EAS_DECIDED` (acr-param + acrstatus-update) and `EEL_MANAGED_ACR` (request-eelacr).
`EEC_EXECUTED_VIA_SOURCE_EES` and `SOURCE_EES_EXECUTED` are deliberately **absent**: both need this
EES to act as *source* and push an EEC context, and only the pull half exists (the push counterpart
is a known open gap). Advertising a scenario we would then fail to execute is worse than advertising
fewer, and `unsupported_acr_scenarios_are_not_advertised` pins that.

**`ueidentifier /fetch` and `/get`** return an `edgeUeId` — an *edge-enabler-layer* identifier the EES
is entitled to assign, unlike `afSpecUeId`, which is a GPSI that would have to come from the CN.
`edge_ue_id()` is SHA-256 over a domain-separated, length-prefixed `(gpsi, easId)`, truncated to 128
bits, which makes it stable (usable as a key), per-EAS (two EASes cannot correlate a user by
comparing identifiers) and opaque (the GPSI is not recoverable). Two refusals, deliberately distinct:
an IP-only request is `501` (mapping an IP to a subscriber needs the CN), and a GPSI no EEC has
registered is `404` — minting an identifier for any input would make the API an oracle that tells the
caller nothing.

`afSpecUeId` is never populated. Echoing back the GPSI the requestor supplied would dress a value it
already had as a CN resolution that never happened.

## Decision 3: `ACInfoNotification` filter semantics, and what is not evaluated

The schema states `ACFilters` only as a list of optional members, so the semantics are a choice:

* **no filters** (absent or empty) matches everything — otherwise an unfiltered subscription would be
  the one shape that never fires;
* **across entries: OR** — a list of filters is a set of alternatives;
* **within one entry: AND** over the present members, each an OR over its own list.

Only `acIdsList` and `acTypesList` are evaluated. `svcArea`, `maxAcKpi`, `minAcKpi` and the schedule
members are passthrough `serde_json::Value`s with no comparable counterpart on `AcProfile`, and an
unparsed blob cannot be compared without inventing a comparison. A present-but-unevaluated member is
treated as **not constraining** rather than as a non-match: over-notifying a subscriber who asked for
a narrower set is recoverable at the consumer, whereas never notifying is the exact defect being
fixed. Stated in the function docs and here so it is not mistaken for a complete filter.

Only the **matching** profiles are reported, not the whole registration — asserted, because reporting
everything would also satisfy a naive "a notification arrived" test.

## Decision 4: the ACT status notification goes to `{notificationUri}/act-status`

The yaml's callback is `'{$request.body#/notificationUri}/act-status'`, not the bare URI. Getting
this wrong is invisible in-process: a POST to the bare URI would be accepted by this tree's own test
consumers and rejected by a conformant one. Trailing slashes are trimmed so `http://eas/cb/` does not
produce `//act-status`.

Notifications fire only on a **terminal** ACT outcome (`SUCCESSFUL`/`FAILED`), because
`ACTStatusNotif.actStatus` is an `ACTResult` and an in-progress ACR has nothing to report. Selection
is by `easId`, the only selector the schema offers.

## What was added / changed

| area | change |
|---|---|
| `capabilities.rs` (new, 470 lines) | `EasInfoProvReq`/`EasInfoProvResp`/`InstantiatedEasInfo`, `UserInfo`/`UeId`/`UeIdInfo`, `edge_ue_id`, `is_known_ue`, `resolve_ue_ids`, `UeIdError`, `select_acr_scenarios`, `instantiated_eas`, `EES_SUPPORTED_ACR_SCENARIOS` |
| `acr.rs` | `ACTStatusSubsc`, `ACTStatusNotif`, `ACT_STATUS_CALLBACK_SUFFIX`, `ACT_RESULT_SUCCESSFUL`/`_FAILED` |
| `context.rs` | `act_status_subscriptions` store + create/find/list/count; `notify_act_status_subscribers`; `notify_acinfo_subscribers`; `ac_profile_matches_filters` |
| `main.rs` | 11 new dispatch arms; `handle_eas_info_prov`, `handle_ue_identifier`, `handle_act_status_sub_{create,list,read}`, `not_implemented`; the `ACInfoNotification` hook in `handle_eec_register`; the ACT-status hook in `handle_acr_status_update`; `EEL_ACR_SUBSCRIPTIONS_PATH` |
| `auth.rs` | five new OAuth2 scopes |
| `types.rs` | `cause::NOT_IMPLEMENTED` |
| `services.rs` | `Default` on `ACInfoSubscription`; module docs corrected |
| `Cargo.toml` | `sha2` (for `edge_ue_id`) |

## Verification

Every guard revert-verified: undo the change, watch the **named** test fail, restore.

| guard | revert applied | result |
|---|---|---|
| `test_acinfo_notification_fires_through_the_router` | the `notify_acinfo_subscribers` call removed from `handle_eec_register` | FAILED ✓ |
| `test_capability_apis_are_routed_and_never_404`, `test_eas_info_prov_*` | the `eees-easinfoprov` arm removed | FAILED ✓ |
| `test_acinfo_notify_fires_once_on_a_matching_registration` | report every profile instead of only the matching ones | FAILED ✓ |
| `test_act_status_subscription_and_notify` | the `easId` selector dropped (notify every subscriber) | FAILED ✓ |
| `test_act_status_subscription_and_notify` | POST to the bare `notificationUri` instead of `{uri}/act-status` | FAILED ✓ |
| `test_act_status_notification_fires_from_a_status_update` | the terminal-state gate replaced by `None` | FAILED ✓ (see below) |

### The revert that found a hole in my own coverage

Replacing the ACT terminal-state gate in `handle_acr_status_update` with `None` — i.e. never
notifying — **compiled and the whole suite still passed**. The context test covers
`notify_act_status_subscribers` directly and says nothing about whether any handler calls it: "the
helper is tested and the wiring is not", for the third time in this repo's history.
`test_act_status_notification_fires_from_a_status_update` was added to close it, and the revert then
failed.

### And a flake I caused, twice

The new router test failed on its first run with `left: 2, right: 1`: `test_act_status_subscription_lifecycle`
leaves a subscription for the same `easId` in the **process-global** EES context, so both were
notified. `GLOBAL_STATE_TEST_LOCK` serialises these tests but does not isolate them. Fixed by giving
the test an `easId` and callback URI unique to it and filtering the drained queue by that URI — data
isolation rather than a lock. The same shape bit the lifecycle test's `list.len() == 1`, which is a
property of the harness and not of the API; it now asserts the created resource is *present* in the
collection. 5 consecutive full-suite runs green.

## Workspace state

`6071 passed / 0 failed` (main: `6052`), `cargo clippy --workspace --all-targets` 0 errors,
`cargo fmt --all --check` clean.

## Ceilings

* **The three 501s are the answer, not an implementation.** `eees-uelocation`,
  `eees-session-with-qos` and `eees-tie` do nothing but refuse honestly. Anyone reading "five APIs
  routed" as "five APIs working" would be wrong: two are served for real, three are conformant
  refusals.
* **`edgeUeId` is not a CN-resolved identity.** It is an edge-layer identifier this EES assigns. An
  EAS that needs the subscriber's GPSI still cannot get one from this EES, and `afSpecUeId` is never
  populated.
* **No IP→UE binding.** `eees-ueidentifier` cannot answer an IP-only request at all; that needs
  Nnef_UEId.
* **ACT status subscriptions are in-memory and lost on restart**, like every other subscription
  family in this context, and there is no DELETE — the yaml defines none, so a subscription lives
  until the process ends.
* **AC-information filters are partially evaluated** (`acIdsList`, `acTypesList` only), erring toward
  over-notification. A subscriber filtering on service area or KPI receives more than it asked for.
* **`ACInfoNotification` fires only on EEC *registration*.** An EEC update (PUT/PATCH) that adds an
  AC profile does not notify. §5.5 arguably wants it; the registration path is where #106 named the
  gap, and extending it to updates would need its own decision about de-duplicating repeat
  notifications for an unchanged profile.
* **No wire interop.** Verified in-process against this tree's own router and notifier queue. No EAS
  or EEC peer exists in this stack, and the docker E2E is `workflow_dispatch`-only.
* **`easinfoprov` stores nothing.** The announcement is accepted and logged; the selected scenarios
  are not persisted against the EEC. Nothing in the issue asked for that, and the response is a pure
  function of the request plus the EAS registry.
* GitNexus impact analysis unrunnable (no MCP server connected — 48th consecutive PR). Blast radius
  by grep: `notify_acinfo_subscribers` and `notify_act_status_subscribers` are new with one caller
  each; `ACInfoSubscription` gained a derive (additive); the 11 new dispatch arms sit before the
  fallthrough and match paths no existing arm claims (`grep '\["eees'` enumerated all 21 pre-existing
  arms); no crate outside `nextgcore-eesd` names any type touched here.
