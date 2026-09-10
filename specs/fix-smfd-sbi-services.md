# nextgcore #79 (smfd): UDM interaction, a real `Nsmf_EventExposure`, and an honest H-SMF

Verified against `main` @ `1447dcc`.

## Verified against current main

| claim in the issue | site on `1447dcc` | still true? |
|---|---|---|
| `policy.rs` has no UDM client | `rg -i udm bins/nextgcore-smfd/src/policy.rs` → nothing | yes |
| no `Nudm_UECM_Registration` anywhere | `rg smf-registrations src/` → **nothing** | yes |
| no `sm-data` retrieval; QoS from `config_default_for_dnn` | `main.rs` config-default arm | yes |
| **the dead `nudm-sdm` FSM arm** | **removed by #204**, with a comment explaining why | **false** |
| `handle_event_subscribe` ignores the body, returns `{subscriptionId}`, persists nothing | as described | yes |
| `handle_event_unsubscribe` returns `204` for any id | as described | yes |
| no `GET`/`PUT` on `/subscriptions/{subId}` | router had `POST` and `DELETE` only | yes |
| H-SMF create returns `201` with `{"cause": "REL_DUE_TO_HO"}` | as described | yes |

**Criterion 3 is void, not met.** It asks that "the dead `nudm-sdm` branch in `gsm_sm.rs` is
reached by a real response". #204 deleted that branch and recorded why: the SMF's real
`Nudm_SDM_Get` (for the subscribed default DNN) has to complete *before* the session exists,
because the DNN is an input to creating it, so it returns on a direct `await` rather than as an FSM
event — and dispatching it in the FSM as well would put one decision in two places. #79's
criterion was written against the pre-#204 tree. Nothing is added to `gsm_sm.rs`.

#204 also left behind exactly the infrastructure this issue needs: a NRF-based UDM discovery
routine and a working SDM client pattern. The discovery function is generalised here from
`nudm-sdm`-only to any named `nudm` service, because a UDM may advertise `nudm-uecm` on a
different port — which `udm_service_endpoint_from_search_result` already prefers a service's own
`ipEndPoints` in order to honour.

## Decision 1: the subscription is a baseline; the PCF still outranks it

TS 23.503 §6.1.3.2 has the PCF *authorise* the session-AMBR and default QoS, taking the
subscribed values as input. So the precedence is **PCF, then subscription, then config default**,
and `apply_subscribed_baseline` is called on the config-default arm only. Overlaying the
subscription on top of a PCF answer would override an authorisation with its own input — a
conformance defect rather than a degradation.

Applied **per member**, not as a struct swap: a subscription stating a session-AMBR and no 5QI
leaves the configured 5QI in place. A whole-struct replacement would make an absent subscribed
member silently mean `0`, and a session-AMBR of 0 polices a subscriber to nothing.

For the same reason `parse_bit_rate` returns `None` rather than `0` for an unrecognised unit. A
subscription meaning gigabits, enforced as bits, is worse than no override at all.

## Decision 2: a runtime switch (`SMF_UDM=1`), off by default

#79 asks for the UDM enforcement to be gated and default-off, and gives the reason: the E2E
harness has no conformant UDM, and enforcing subscription data nothing supplies would regress the
matched-sim data-plane path CI does gate on. A **runtime** switch rather than a cargo feature, for
the reason recorded across this daemon's other switches — CI builds default features, so a gated
path is left uncompiled and rots, and criterion 5's "unchanged when disabled" becomes a claim
about a build CI never performs.

The `smfInstanceId` the UDM records is seeded from the value **NRF registration used**. A
separately minted uuid would have the UDM's serving-SMF record point at an instance nothing else
in the deployment can resolve, which is the failure this operation exists to prevent.

`plmnId` comes from the serving PLMN the AMF supplied, and a request without one sends **no
registration at all**: the member is `required`, and inventing a PLMN would record the session as
served somewhere it is not.

## Decision 3: the H-SMF `/pdu-sessions` service answers 501 — all three operations

#79 offers a choice: implement Create/Update/Release conformantly, or `501` rather than a
fabricated `201`. `501` is taken.

What it replaces was actively misleading, not merely incomplete. Create answered `201` with
`{"pduSessionRef": "1", "cause": "REL_DUE_TO_HO"}` — **a release cause on a create success**, at a
hardcoded reference, with no session created. A partner V-SMF parsing that is told "your session
was established, and it was released for handover", about a session that does not exist.

Home-routed roaming is not implemented here: nothing establishes an H-SMF session, and
`PduSessionCreatedData` requires `pduSessionType`, `sscMode` and one of
`hSmfInstanceId`/`smfInstanceId` (a `oneOf`) — every one of which would be invented. This
project's recorded rule for that case is that a spec-defined resource whose dependency is absent
answers `501`, never a `404` and never a fabricated `2xx`.

All three operations answer the same way. A partner that cannot create through this service can
never legitimately update or release through it, and leaving those at `2xx` would say otherwise.
The old Release was worse than incomplete: it removed a session by `pduSessionRef` — a reference
space this SMF does not populate — so it could only ever match state some other path had
registered, i.e. it let a partner delete state it did not own.

## Decision 4: which events fire, and saying so

`PDU_SES_EST` and `PDU_SES_REL` are emitted. The other twenty `SmfEvent` values name occurrences
this SMF does not detect (`UP_PATH_CH`, `QOS_MON`, `DISPERSION`, …); subscribing to one is
**accepted and stored** — refusing a conformant request would be wrong — and it simply never
fires. That is written in the module header rather than left for a consumer to infer from silence.

A subscription's filters scope it: an absent `supi`/`pduSeId` matches anything (`anyUeInd`
semantics), a present one must match exactly. The negative direction is the one that matters — a
SUPI-scoped subscription that matched every UE would leak one subscriber's session events to a
consumer authorised for another, which is a subscriber-data leak rather than a reporting bug.

## Acceptance criteria

- [x] On SM-context create, smfd issues `Nudm_UECM_Registration` and `Nudm_SDM_Get sm-data` before
      PFCP establishment — `the_smf_registers_with_the_udm_and_fetches_sm_data` asserts both on the
      wire against a loopback UDM, including all four `required` members of `SmfRegistration`, the
      `PUT` method, the per-PDU-session resource path, `nudm-sdm` **v2**, and the `dnn` scoping
      (read from `http.params`, because the shared SBI server strips the query from `header.uri`).
- [x] The subscribed default-5QI and session-AMBR are applied, `config_default_for_dnn` only as
      fallback — `subscribed_values_win_over_the_config_default_per_member`, covering full,
      partial and empty subscriptions.
- [ ] ~~The dead `nudm-sdm` branch in `gsm_sm.rs` is reached by a real response~~ — **void**: #204
      removed that branch deliberately. Nothing added to `gsm_sm.rs`; the reasoning is above.
- [x] `POST /subscriptions` persists the parsed subscription and returns an `NsmfEventExposure`;
      `GET` retrieves it; `DELETE` on an unknown id is `404` —
      `event_subscriptions_are_a_real_resource_with_get_put_and_a_404`, through the **router**
      (half of what was missing was routing), plus `PUT` (which does not create at a
      consumer-chosen id) and the three `required`-member rejections.
- [x] An `Nsmf_EventExposure_Notify` is emitted to the subscribed URI on a subscribed occurrence —
      `a_released_session_notifies_its_event_subscriber`, captured on a real loopback consumer, and
      asserting that a subscription scoped to a **different** SUPI is not notified.
- [x] H-SMF `POST /pdu-sessions` answers `501`, never a release cause on a create —
      `the_hsmf_pdu_sessions_service_answers_501_and_never_a_release_cause`, over all three
      operations, asserting the body does not contain `REL_DUE_TO_HO`.
- [x] clippy and the smfd suite pass — smfd at **zero** clippy warnings.

## Verification

Workspace **6258 passed / 0 failed** (baseline 6241 on `1447dcc`; +17), easdfd's `dns-udp` feature
still 51/0. `cargo clippy --workspace --all-targets` and `cargo fmt --all -- --check` clean.

| revert | expected to break | result |
|---|---|---|
| subscriptions are parsed but not stored | 3 tests | **3 failed** |
| the `supi` filter is ignored | the filter test + the notify test | **failed** |
| the UECM registration is never transmitted | the UDM wire test | **1 failed** |
| the subscribed 5QI is not applied | the per-member test | **failed** |
| H-SMF create answers `201 REL_DUE_TO_HO` again | the 501 test | **1 failed** |
| the notify call removed from the release handler | the notify test | **failed** |
| `DELETE` answers `204` for an unknown id | the resource test | **failed** |

### A third instance of one lock per variable, in one session

`the_smf_registers_with_the_udm_and_fetches_sm_data` flaked: it passed alone and failed in roughly
one full-suite run in six. Two distinct causes, both process-global state:

1. **A second lock over the same variable.** `main.rs`'s tests already had a `UDM_ENV_TEST_LOCK`
   over `UDM_SBI_ADDR`/`UDM_SBI_PORT`/`NRF_URI`; the new test set the same variables without it.
   A sibling re-pointed `UDM_SBI_PORT` at its own loopback UDM between the registration and the
   `sm-data` fetch, so the fetch reached a server that answers `201` to everything. The lock is
   now declared at the **crate root**, beside the function that reads the env, so `udm.rs` and
   `main.rs` take the same one.
2. **A `find()` that could match someone else's request.** Even with the env locked, the loopback
   UDM is reachable by any sibling test whose create path fetches a subscribed default DNN. Both
   lookups now match on the **SUPI** as well as the resource, and the final "no registration was
   sent" assertion is scoped the same way instead of asserting the server saw no traffic at all.

That is the third time in this run of five issues that a process-global needed one agreement
rather than two — after the EASDF context in #276 (which manifested as a **hang**) and the
event-subscription store here (which made `a_released_session_notifies_its_event_subscriber` fail
in the full suite while passing alone). Eight consecutive clean full-suite runs afterwards.

## Ceilings

* **Both UDM call sites are inspection-only**, like #117's and for the same reason: they sit in
  `handle_sm_context_create`, which no test can drive past its N4 leg (#289). What *is* verified is
  both operations end to end against a loopback UDM, and the per-member application of what they
  return. Same for the `PDU_SES_EST` notification — `PDU_SES_REL` was chosen for the wiring test
  precisely because the release handler is reachable.
* **No `Nudm_SDM_Subscribe`.** #79's suggested approach mentions it alongside `Get`; the criterion
  does not, and a subscription with no notification handler on this side would be a resource the
  SMF creates on the UDM and then ignores. The UDM would send `Nudm_SDM_Notification` to a callback
  this SMF does not serve. Worth its own issue, together with the deregistration this PR also does
  not send.
* **No UECM deregistration on session release.** The registration is per PDU session and nothing
  removes it, so a UDM accumulates serving-SMF records for released sessions. Same shape as the EBI
  leak (#291) and worth the same treatment.
* **The `503`/retry posture is "log and continue".** Every UDM and notification failure is
  non-fatal with no retry queue, which is right for the session and means a transient UDM outage
  silently costs subscription enforcement for the sessions established during it.
* **Only two of twenty-two `SmfEvent` values fire.** Documented in the module header.
* **`altNotifIpv4Addrs`/`altNotifFqdns` are stored and never used.** A notification failure does
  not fall back to the alternates a consumer supplied. Parsed only in the sense that they
  round-trip in the stored document; no code reads them.
* GitNexus impact analysis unrunnable (no MCP server connected). Blast radius by grep:
  `udm_service_endpoint_from_search_result` gained a parameter (1 production + 4 test call sites,
  all updated); `build_establishment_accept` untouched here; the three H-SMF handlers have one
  router call site each.
