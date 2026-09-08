# nextgcore #105 (eesd): EAS discovery, EEC registration and ACR conformance

Verified against `main` @ `93cd775` (after #205, #242, #95, #204, #215, #111, #267). Every cite
in the issue still holds.

## Verified against current main

| claim in the issue | check on `93cd775` | still true? |
|---|---|---|
| `EasDiscoveryFilter.eas_chars` is a single `Option<EasCharacteristics>` | `types.rs:176-179`, with the comment calling the cardinality a "documented simplification" | yes |
| `EasCharacteristics` invents `ac_ids` | `types.rs:203` — no counterpart in `EASCharacteristics` (yaml:530-582) | yes |
| the filter has no `acChars` / `appGroupProfile` | grep found neither in `types.rs` | yes |
| `EasDiscoverySubscription.notification_uri` is a non-`Option` mandatory field | `types.rs:317`; `handle_disc_sub_create` hard-required it at `main.rs:923` | yes |
| the subscription drops `eecId`/`easEventType` | grep found neither | yes |
| `PATCH .../subscriptions/{id}` falls through to `405` | `main.rs:412-421` routed only GET/PUT/DELETE | yes |
| `EecRegistration` drops the six relocation IEs | `eec.rs:19-41` | yes — and also `ueMobilityReq`/`ueType`/`unfulfil*` |
| `handle_eec_register` never pulls and never reports unfulfilled profiles | `main.rs:1029-1073` | yes |
| relocation transport types exist but are unreachable from registration | `services.rs:448-461` | yes |
| `acr_determine` picks an EAS whose `easId` **differs** | `context.rs:574-577` | yes |

## Read this first: the issue asks for a `422`, and the spec does not have one

The issue's suggested approach and its sixth acceptance criterion ask for **`422` with
`unfulfilledAcProfs`** when AC profiles cannot be matched, citing
`TS24558_Eees_EECRegistration.yaml:298-299`. Those two lines are not a response envelope —
they are the `unfulfilledAcProfs` property and the `not: required: [...]` constraint **inside
the `EECRegistration` schema**. Checked directly:

* `grep -c "'422'" TS24558_Eees_EECRegistration.yaml` → **0**. The API declares no `422` for
  `CreateEECReg`, `UpdateIndEECReg` or `ModifyIndEECReg`.
* `EECRegistration` *is* the `201` response body (yaml:41-47), and `unfulfillAcProfs` /
  `unfulfilledAcProfs` are its members (yaml:288-300).
* TS 24.558 §5.2.2.2 is explicit: *"the EES shall return the EEC registration information in
  the response message ... The URI of the created resource shall be returned in the "Location"
  HTTP header. If the EEC registration request contains AC Profile(s), and the EES determines
  that the requirements indicated in the AC profile(s) cannot be fulfilled for **some of** the
  AC profile(s), the EES shall include "unfulfillAcProfs" or "unfulfilledAcProfs" attribute"*.

So partial fulfilment is reported **in a successful registration**. Emitting `422` would fail a
registration the spec says succeeds, and would do it with a status the API does not declare — a
conformant EEC may treat an undeclared 4xx as a hard failure.

The same clause **does** define a refusal, for the total case: *"When a matching EAS is not
identified for even one AC profile, the EES shall reject the request message by sending an HTTP
response to the EEC with a status code set to 404 Not Found and indicate the
"RESOURCE_NOT_FOUND" error"*. That is implemented. Reading it as "any one profile fails" would
make `unfulfillAcProfs` dead by construction, since a partial failure would already have been
refused.

**Delivered instead of the criterion as written:** `404`/`RESOURCE_NOT_FOUND` when nothing
matched, `201` carrying the partial-fulfilment report otherwise. Stating it up front rather than
letting the PR read as if the criterion was met verbatim. Same shape as #204, where the issue
named `sm-data` and the answer was `smf-select-data` because `DnnConfiguration` has no default
flag.

## What was added

| area | change |
|---|---|
| `types.rs` | `eas_chars: Vec<EasCharacteristics>` + `ac_chars: Vec<AcCharacteristics>` (both via `one_or_many`), typed `app_group_profile: Option<AppGroupProfile>`; new `AcCharacteristics` + `AppGroupProfile` with `matches`; `EasCharacteristics.ac_ids` **removed**; `EasDiscoverySubscription` gains `eec_id`/`eas_event_type` (mandatory) and optional `notification_destination` (alias `notificationUri`), `eas_dyn_info_filter`, `eas_svc_continuity`, `websock_notif_config`; new `EasDiscoverySubscriptionPatch` + `apply_patch`; `cause::RESOURCE_NOT_FOUND` |
| `eec.rs` | the six relocation IEs plus `ueMobilityReq`/`ueType`; `unfulfill_ac_profs` / `unfulfilled_ac_profs` with `set_unfulfilled` / `unfulfilled`; `UnfulfilledAcProfile` + `unfulfill_reason`; `relocation_source()`; `AcProfile.eass: Vec<EasDetail>` replacing the non-spec `easIds`, plus `ac_svc_cont_supp` and `exp_ac_geo_serv_area` (was mis-spelled `expsacInfo`); new `EasDetail` + `AcServiceKpis` |
| `relocation.rs` (new) | `PullRequest`, `PullOutcome`, `pull_eec_context`, `parse_api_root`, the `PullHook` test seam, `set_self_ees_id` / `self_ees_id`, `PULL_TIMEOUT` |
| `context.rs` | `match_ac_profiles` + `AcProfileMatch` (`fulfilled` / `unfulfilled` / `selected`, `none_matched`), `eas_suffices_kpis`; `acr_determine` predicate inverted to same-`easId` |
| `main.rs` | `apply_ac_profile_matching`, `retrieve_relocated_eec_context`, both wired into `handle_eec_register` in §5.2.2.2 step order and the matching also into `handle_eec_update`; `handle_disc_sub_patch` + the `PATCH` router arm; `relocation::set_self_ees_id` at startup |

## Decision 1: the AC-profile matching rule is conditioned on `eass`

§5.2.2.2 step 1 ii) opens *"For each AC Profile, **if "eass" attribute is included** in the AC
Profile, the EES identifies the matching EAS"*. A profile without `eass` therefore states no
requirement the EES can fail, and counts as fulfilled.

This is load-bearing, not a shortcut. `ACProfile.acId` is the only mandatory member, and every
`acProfs` body in this tree's own tests (and the matched simulator's) omits `eass`. Treating
those as unfulfilled would refuse them with `404` — the revert that tries it breaks
`test_eec_register_lifecycle_router`, a test that predates this change.

`expectedSvcKPIs` deliberately does not participate: NOTE 1 of the same clause leaves its
bearing on matching to the implementation, so treating an *expectation* as a hard requirement
would refuse EASes the spec permits.

## Decision 2: `EAS_NOT_AVAILABLE` and `REQ_UNFULFILLED` are kept distinct

The named `easId` not being registered at all is `EAS_NOT_AVAILABLE`. An `easId` that **is**
registered but does not suffice the profile's `minimumReqSvcKPIs` is `REQ_UNFULFILLED`. They are
different remedies for the EEC — go find another EES, versus relax the requirement or wait for
capacity — and collapsing them would tell an EEC to look elsewhere for an EAS that is right
here.

`respTime`, `avail` and `reqRate` are compared against the EAS's `maxRespTime`, `availability`
and `maxReqRate`. `connBand` is **not**: it is a `BitRate` string (`"100 Mbps"`) on both sides
and a lexical comparison would rank `"9 Kbps"` above `"100 Mbps"`. An absent comparison is
better than a wrong one here, because a wrong one refuses EASes that do satisfy the requirement.
A KPI absent on either side is "not constrained" — inventing a failure from a missing
advertisement would refuse every EAS that registered without KPIs.

## Decision 3: NOTE 2 decides which of the two report members is used

`unfulfilledAcProfs` (singular object) and `unfulfillAcProfs` (array) are mutually exclusive by
`yaml:299-300`'s `not: required: [both]`, and NOTE 2 says the singular *"can only be provided if
there is only a single unfulfilled AC profile"*. `EecRegistration::set_unfulfilled` is the only
writer: one entry → singular, two or more → array, none → neither, and it always clears the
other member first. A body carrying both is invalid against the schema, so a conformant EEC may
reject it outright — which would turn a partial-fulfilment report into a failed registration.

## Decision 4: step order — refuse, then pull, then create

§5.2.2.2 numbers the steps: (1) AC-profile matching, (2) EEC-context retrieval, (3) resource
creation. `handle_eec_register` follows that literally, and a test asserts the ordering
(`pulls == 0` on a `404`). The order is the point: a registration that will be refused must not
have asked a source EES for a context first, and must not leave a resource behind.

## Decision 5: a failed context pull does not fail the registration

§5.2.2.2 orders the retrieval before resource creation but never makes it a precondition. The
EEC is registering here and now; refusing it because an unrelated source EES is unreachable
would deny service on the strength of another node's availability. Every non-retrieval is logged
at `warn` with the reason and the registration proceeds — and the pull is bounded at 3 s, since
it happens inside the registration request and an unreachable S-EES would otherwise hold the
EEC's registration open for the transport's own timeout.

## Decision 6: `srcEesId` is addressable only as an absolute `http(s)` URI

TS 24.558 prose says *"an EEC context ID, a source EES endpoint"*, but the OpenAPI has only
`srcEesId: type: string` (yaml:262-264) and **no** companion endpoint member. There is no
EES-level NRF discovery in this tree to resolve a bare identifier. So `srcEesId` is used as the
source `apiRoot` when it parses as an absolute `http(s)` URI, and reported
`NotAddressable` otherwise. Guessing a host from an opaque id would issue requests to an address
the operator never configured.

The retrieved context is stored under **its own** `cntxId` (mandatory in `EECContext`), not
under a freshly minted id: the source EES and the EEC both know it by that id, and re-keying it
would make this EES's copy unreachable by the only id anyone can ask for. Minting a new EEC
context id is a "may" in §5.2.2.2 and is not done — see Ceilings.

## Decision 7: `easSelReqInd` gates the EAS selection

Step 1 iii) B) has the EES return its selection in `discoveredEas`, and the IE's own description
says *"Set to false to indicate the EES shall not select the EAS"*. So the selection is returned
**only** on `easSelReqInd: true`; otherwise `discoveredEas` is left as the EEC sent it.
Answering with a selection anyway would override the EEC's decision to do its own discovery.

## Decision 8: the single-object `easChars` body is still accepted

`easChars`/`acChars` deserialise through `one_or_many`, so both the conformant array and the
matched simulator's single object are read; serialisation always emits the array, so this EES's
own output is conformant. Accepting only the array would trade a conformance defect for a
regression in the one stack this surface currently interoperates with.

## Decision 9: `appGroupProfile` narrows on `easId`, not on the declaration store

`AppGroupProfile` requires `appGrpId` **and** `easId` (yaml:529-531), so the filter narrows on
the `easId` and, when present, on `e2eRespTime` against the EAS's advertised `maxRespTime`.
`appGrpId` is **not** cross-checked against the `eees-cea` declared-common-EAS store:
`EasDiscoveryFilter::matches` is a pure predicate over one `EasProfile`, and making discovery
depend on a `POST /declare` having happened would hide every EAS in a deployment that does not
use common EASs.

## Acceptance criteria

- [x] A discovery request whose `easChars` is a JSON array is accepted and matched; `acChars`
      and `appGroupProfile` are honoured; `acIds` is gone —
      `a_spec_shaped_discovery_filter_is_accepted_and_every_member_narrows` exercises each
      member as the **sole** discriminator (two-entry `easChars` OR-match, `acChars` include vs
      exclude, `appGroupProfile` by `easId` and by `e2eRespTime`), plus all three together.
- [x] A subscription with `eecId` + `easEventType` and no `notificationUri` is accepted; one
      missing either is rejected `MANDATORY_IE_MISSING` —
      `a_discovery_subscription_missing_a_mandatory_ie_is_rejected` (four refusal cases:
      each member absent and each empty) and `test_disc_subscription_create`.
- [x] `PATCH .../subscriptions/{id}` applies an `EasDiscoverySubscriptionPatch` and returns
      `200` — `a_discovery_subscription_patch_is_routed_and_leaves_unmentioned_members_alone`,
      which also asserts the unmentioned mandatory IEs survive and an unknown id is `404`.
- [x] `EecRegistration` (de)serialises the six relocation IEs —
      `relocation_ies_deserialize_from_a_spec_shaped_body`, which deserialises a **hand-written**
      spec-shaped body rather than round-tripping our own struct (a self round trip passes even
      when every field name is wrong). It found one: serde's `camelCase` emits
      `minimumReqSvcKpis`, the spec spells it `minimumReqSvcKPIs`.
- [x] A registration presenting `(eecCntxId, srcEesId)` triggers the EEC-context pull —
      `eec_registration_with_a_relocation_pair_pulls_the_source_context`, which observes the pull
      through the `PullHook` seam, asserts the retrieved context is then servable from this EES's
      own pull route, **and** asserts a registration with no pair performs no pull.
- [x] Unmatchable `acProfs` are reported — **as `201` + `unfulfillAcProfs`, not `422`**; see the
      second section. `unmatched_ac_profiles_are_reported_in_the_created_registration` covers the
      partial case and both reasons; `a_registration_with_no_matchable_ac_profile_is_refused_before_anything_is_created`
      covers the total case (`404`/`RESOURCE_NOT_FOUND`, nothing created, no pull attempted).
- [x] `acr_determine` returns a same-`easId` target at a different endpoint and
      `NoTEasAvailable` only when no same-application alternative exists —
      `test_acr_determine_selects_the_same_application_elsewhere`, `test_acr_determine_returns_t_eas`.
- [x] Full `nextgcore-eesd` suite and workspace lint pass.

## Verification

Workspace **6021 passed / 0 failed / 6 ignored** (baseline `6002` on `93cd775`; +19 tests, eesd
136 → 155). `cargo clippy --workspace --all-targets` 0 errors and 0 warnings on
`nextgcore-eesd`, `cargo fmt --all -- --check` clean. The eesd suite was looped **12 times**, all
green, because this change adds a second piece of process-global test state (see below).

Twenty-one reverts:

| revert | expected to break | result |
|---|---|---|
| `relocation_source` accepts either half of the pair | `a_half_present_relocation_pair_is_not_a_relocation` | **1 failed** |
| `set_unfulfilled` always uses the array member | `set_unfulfilled_honours_note_2...` | **1 failed** |
| ...and the handler guard for the same | `unmatched_ac_profiles...` | **1 failed** (`must use the singular member (NOTE 2)`) |
| `retrieve_relocated_eec_context` never pulls | the relocation guard | **1 failed** (`must drive exactly one pull`) |
| the pulled context is not stored | same | **1 failed** (`a pull nobody can use`) |
| pull unconditionally, ignoring the pair | same | **1 failed** (`must NOT pull`) |
| `none_matched` never refuses | the refusal guard | **1 failed** (201 vs 404) |
| the pull runs **before** the matching | same | **1 failed** (`step 1's refusal must precede step 2`) |
| `eas_suffices_kpis` always true | `unmatched_ac_profiles...` | **1 failed** (`NOT 'EAS not available'`) |
| select EASes regardless of `easSelReqInd` | `eas_selection_is_returned_only_when...` | **1 failed** |
| a profile with no `eass` counts as unfulfilled | `..._refused_before_anything_is_created` + `test_eec_register_lifecycle_router` | **2 failed** |
| `acr_determine` picks a **different** `easId` again | 3 ACR tests | **3 failed** |
| `matches` ignores `ac_chars` | the filter guard | **1 failed** |
| `matches` ignores `app_group_profile` | same | **1 failed** |
| only the first `easChars` entry is consulted | same | **1 failed** |
| `AppGroupProfile` ignores `e2eRespTime` | same | **1 failed** |
| single-object `easChars` no longer accepted | 4 tests incl. 2 pre-existing | **4 failed** |
| drop the `eecId` requirement | the subscription guard | **1 failed** — *see below* |
| drop the `easEventType` requirement | same | **1 failed** |
| require `notificationUri` again | same | **1 failed** (`notificationDestination is OPTIONAL`) |
| remove the `PATCH` router arm | the PATCH guard | **1 failed** (405) — *see below* |
| `apply_patch` drops an unmentioned member | same | **1 failed** |

**Two reverts found holes in the coverage, both of the same shape as the false guards the #210
and #215 sessions recorded.**

1. **Criterion 2's refusal half had no guard at all.** Neutering the `eecId` mandatory-IE check
   broke **zero** tests out of 153. `test_disc_subscription_create` sends a body with *every*
   member set, so it passes whether or not the requirement is enforced — it pins the accept side
   and nothing else. Fixed by adding
   `a_discovery_subscription_missing_a_mandatory_ie_is_rejected` (each mandatory member absent
   **and** empty, plus the accept case with `notificationDestination` omitted) and re-running
   all three reverts against it: 1 failed each, with the named messages.
2. **Criterion 3 had no test whatsoever.** `handle_disc_sub_patch` and its router arm were
   written with no guard; `grep 'patch(format!("/eees-easdiscovery'` found nothing. Fixed by
   adding `a_discovery_subscription_patch_is_routed_and_leaves_unmentioned_members_alone`, which
   asserts the PATCH *semantics* rather than only the status — a handler that replaced the whole
   subscription would also answer `200` while silently dropping the mandatory IEs a consumer did
   not re-send.

**A third piece of process-global test state.** The `PullHook` slot is process-global, so the
first two `relocation` tests raced: one's `clear_pull_hook` landed between the other's
`set_pull_hook` and its pull, and the pull fell through to a real DNS lookup
(`failed to lookup address information`). Fixed with a module-level `PULL_HOOK_LOCK` held by
every test that touches the slot, in `relocation.rs` and in `main.rs`. This is the same technique
the `SGWU_QER_ENFORCEMENT` race needed in #215, and the third occurrence in three sessions —
the pattern is now recorded as a convention.

## Ceilings

* **The `422` the issue asked for is not implemented, deliberately.** See the second section. If
  a downstream consumer was built against the issue's reading rather than the spec's, this is a
  behaviour change for it.
* **`ueMobilityReq` and `ueType` are stored and drive nothing.** §5.2.2.2 step 4 would have the
  EES subscribe to UE location or analytics via NEF/NWDAF on `ueMobilityReq: true`; this binary
  has no such path. `ueType` has no policy consuming it. They are modelled so the wire body is
  lossless, no more.
* **`easBundleInfos` is not modelled**, so EAS-bundle matching and ECSP-triggered EAS
  instantiation (step 1 iii A / B) are absent entirely.
* **No new `eecCntxId` is minted.** §5.2.2.2 step 3 has the EES *"assign and store a new EEC
  context ID"* and the response *"may include"* it; this EES does neither. The consequence is
  that the relocation chain only works while the EEC keeps presenting the id its original EES
  issued.
* **`appGrpId` is not cross-checked** against the declared-common-EAS store — Decision 9.
* **`connBand` / `reqComp` / `reqMem` / `reqStrg` are not compared** in KPI matching. The first
  needs a `BitRate` parser; the rest are free-form strings with no ordering, so any comparison
  would be invented.
* **The pull has no retry.** One attempt, 3 s, then the registration proceeds without the
  context. Adding retry would mean either blocking the registration longer or completing the
  relocation after the response, which needs a background reconciler like the one #111 added to
  nefd — worth its own issue if EEC relocation is ever exercised for real.
* **No EEC-context push.** This EES receives pushes and now performs pulls; it never *pushes* a
  context to a target EES, so it can act as a T-EES in a relocation but not as an S-EES that
  initiates one.
* **The EES↔EES paths are untested end to end.** The pull is verified through the `PullHook`
  seam and against this EES's own pull handler, not against a second running eesd; the docker E2E
  is `workflow_dispatch`-only and has no second EES.
* GitNexus impact analysis unrunnable (no MCP server connected — 45th consecutive PR).
  `nextgcore/CLAUDE.md`'s mandate to run `gitnexus_impact` before editing stays unsatisfiable.
  Blast radius by grep: `EasDiscoveryFilter`/`EasCharacteristics`/`EasDiscoverySubscription`/
  `EecRegistration`/`AcProfile` construction and field-access sites were enumerated and all
  updated (`notifier.rs`'s test was the only one outside the four files changed), and nothing
  outside `nextgcore-eesd` names any of them.
