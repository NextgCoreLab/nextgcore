# Fix pcfd: Npcf_EventExposure, the NRF profile, and UAV flight authorization

Closes nextgcore #90.

## Scope

Three deliverables the issue names, in one PR because #90 is an umbrella and the
project convention is that an umbrella closes on a whole-issue PR. A fourth
defect was found during verification and is fixed here too, because it makes
deliverable 2 wrong in a way the issue did not detect.

All cites below were RE-LOCATED against `main` at `efe5b62`; the issue's own
cites were verified at `76ea248` and had drifted, and one (`build_nf_instance` at
`sbi_path.rs:71-79`) no longer exists at all — PR #232 removed it, so the
issue's suggested "serialise the `NfService` set already built there" approach
was not available as written.

## 1. NRF profile: the PCF registered TWICE, with two different service sets

### What was wrong

The issue reports that the registered profile omits `npcf-policyauthorization`
and that `allowedNfTypes` excludes AF/NEF. Both true. But the cause is worse
than an omission: **pcfd had two NRF registration paths and both ran on every
startup.**

- `sbi_path.rs` `pcf_sbi_open` (called from `app.rs:406`) built an `NfInstance`
  with a fresh UUID, spawned a task, and PUT a profile that DID include
  `npcf-policyauthorization` but carried **no** `allowedNfTypes` and **no**
  per-service `ipEndPoints`.
- `app.rs:439` then minted a **second** fresh UUID and PUT a divergent JSON
  literal that carried `allowedNfTypes: ["AMF","SMF","SCP"]` and `ipEndPoints`
  but **omitted** `npcf-policyauthorization`.

So the NRF held two PCF records per startup, under two ids, each missing what
the other had. Only the second was heartbeaten (the heartbeat worker took
`app.rs`'s id), so the first aged out via the no-heartbeat timer while still
being discoverable in the interim — and a consumer that discovered
`npcf-policyauthorization` from it got a profile with no port to dial. The
`pcfId` published to the BSF was the second id, so the code comment claiming
"the same instance id is used for the NRF NFProfile below so pcfId ==
nfInstanceId" was false.

### What changed

- One table, `PCF_SERVICES` in `sbi_path.rs`, is the single source of truth for
  which services this PCF serves and which NF types may consume each.
- One serialiser, `pcf_nf_profile_json`, emits the NFProfile: per-service
  `ipEndPoints` and `allowedNfTypes`, plus an NF-level `allowedNfTypes` that is
  the **union** over the services (a type barred at NF level can never reach any
  service).
- `pcf_sbi_open` no longer registers. It publishes the self-instance and the NRF
  URI only. Registration happens **once**, from the new
  `pcf_register_with_nrf()`, called from `app.rs` after the SBI listener is up —
  registering before the port accepts advertises an endpoint that would refuse
  the first consumer to dial it.
- `app.rs` no longer mints its own UUID; it reads the published self-instance id,
  so `pcfId == nfInstanceId == the heartbeaten id == the deregistered id`.
- The divergent 80-line JSON literal in `app.rs` is deleted.

`npcf-policyauthorization` is allowed to `AF` and `NEF`. NEF is the one that
mattered in practice: without it the NRF issues no token scoped to the service,
so northbound QoS-on-demand cannot be onboarded at all.

### Deliberate scope limit

`allowedNfTypes` is held in a pcfd-local table rather than added to the shared
`nextgcore_sbi::context::NfService`, which has no such field. Adding it there
would require updating the profile serialiser of every other NF in the
workspace — a blast radius #90 does not need. Noted as a follow-up candidate.

## 2. Npcf_EventExposure (TS 29.523): new service

`route_npcf_request` had no `npcf-eventexposure` arm; the `Subscription*`
identifiers in `event.rs` are internal policy timers, not this service.

### Implemented

- `POST /npcf-eventexposure/v1/subscriptions` → 201 + `Location`.
- `GET`/`PUT`/`DELETE …/subscriptions/{subscriptionId}` → 200 / 200 / 204, 404
  when absent, 405 **with an `Allow` header** on a wrong method (the shared
  helper #229 added).
- New `npcf_eventexposure.rs` module; subscription store in `context.rs` as a
  primary list with a derived `subscription_id` index and a lifted allocator,
  following the house rules already documented on `restore_from`.
- Notification fan-out `pcf_report_pc_event` in `sbi_path.rs`, reusing the
  existing `deliver_notification` retry/alternate-endpoint path.
- Persisted, including `report_count`, so `maxReportNbr` cannot be reset by
  bouncing the PCF. Added as a new `eventSubs` snapshot key with **no**
  `SNAPSHOT_VERSION` bump: `records()` defaults a missing key to empty, so a v1
  snapshot restores with no subscriptions rather than failing, and bumping would
  have made every existing state file unloadable for a purely additive field.

### Judgment call: which events are reportable

`PcEvent` enumerates thirteen tokens. **Four have a real producer in this tree**
and are implemented:

| Event | Producer |
|---|---|
| `AC_TY_CH` | SM policy update whose `accessType` differs from the session's stored one |
| `PLMN_CH` | AM policy update whose GUAMI PLMN genuinely moved |
| `SUCCESS_UE_POL_DEL_SP` | UE-policy MANAGE UE POLICY COMPLETE |
| `UNSUCCESS_UE_POL_DEL_SP` | UE-policy MANAGE UE POLICY COMMAND REJECT |

The other nine are **not faked**. `SmPolicyUpdateContextData` carrying
`accessType`, `ratType`, `addAccessInfo` and `relAccessInfo` — exactly the
members `PcEventNotification` defines — is what confirms `AC_TY_CH` belongs to
the SM update path rather than the AM one (`PolicyAssociationUpdateRequest` has
`accessTypes` plural, an allowed-list, not a current value).

Two consequences, both deliberate and both flagged for review:

- A subscription naming **only** unreportable events is refused with **400
  `EVENT_NOT_SUPPORTED`**. TS 29.523 defines no per-item failure report on this
  resource (unlike Nsmf/Nnwdaf `failEventReports`), so there is nowhere
  conformant to say "kept, but cannot serve token X" — and a subscription that
  can never fire leaves the consumer waiting forever. 400 with a cause naming
  the criterion follows the precedent set for the `SubscrCond` gate in #68
  rather than inventing a new answer. **Accepted cost: a conformant consumer
  subscribing only to, say, `APPLICATION_START` receives a 400 for a legal
  request.**
- An **unrecognised** token is NOT rejected, and round-trips. `PcEvent` is
  `anyOf [enum, free-form string]`, so an unknown token is forward-compatibility
  with a later release; rejecting it would break a conformant future consumer.
  A subscription mixing a reportable event with an unknown one is accepted.

`eventNotifs` is not populated on the create response: that would be an
immediate report, and all four reportable events are change/outcome events with
no current-state form, so emitting one would mean inventing an event that did
not happen.

## 3. UAV flight authorization: fail-open bypass, now fail-closed

`authorize_uav_session` called `grant_authorization("CAA-PCF-DEFAULT", 3600)`
**unconditionally** and gated against a hardcoded 37..38°N / -123..-122°W box,
with `PCF_UAV_POSITION` defaulting to `(37.5, -122.5)` — which is inside that
box. So the network self-granted every flight, and an unknown position
authorised it.

Now: a UAV session is refused unless the operator has provisioned **all three**
of `PCF_UAV_AUTHORIZATION`, `PCF_UAV_ZONE` and `PCF_UAV_POSITION`. There is no
default for any of them. A missing authorisation decision is a missing
**credential**, and this repo's recorded policy is to fail closed on those — the
opposite direction from a missing **filter**, where absence conventionally means
"no restriction". An inverted zone (min > max) is refused rather than silently
matching nothing.

**This is a behaviour change, stated plainly:** a deployment that configured a
UAV DNN and relied on the self-grant will now have those sessions refused until
it provisions the three variables. Not gated behind a switch — a switch
defaulting to the old value leaves the bypass in place for everyone who does not
know to flip it, and one defaulting to the new value is this with extra steps.
Scope is naturally limited: only a DNN named by `PCF_UAV_DNN` reaches this path.

There is still **no UAS-NF client**, so this is not the TS 23.256 USS/UTM
exchange; `PCF_UAV_AUTHORIZATION` is an operator-provisioned stand-in. The
honest framing is that the self-grant is removed and the decision is now the
operator's, not that USS/UTM integration exists.

### Session leak

The UAV reject path returned after `sess_add` + `sess_update` with no
`sess_remove`, leaking one `PcfSess` (plus its `sm_policy_id_hash` entry and its
id in `ue_sm.sess_ids`) per refused attempt — so a repeatedly-denied UAV would
grow the context until `max_num_of_sess` was reached and then break **non-UAV**
session creation too. Now removed on every reject path.

### `sess_add` dedupe

`sess_add` minted a fresh id and a fresh `sm_policy_id` on every call with no
`(ue_sm_id, psi)` check, so a retransmitted `SmPolicyCreate` created a second
session for the same PDU session. TS 29.512 §4.2.2.2 makes the SM policy
association one-per-PDU-session, so the pair is deduped, scanned inline while
the write guard is held (calling `sess_find_by_psi`, which read-locks the same
map, would deadlock — std `RwLock` is not reentrant, the hazard the six
documented inversion fixes in this file exist for).

## Verification

- Workspace: **5902 tests pass, 0 fail**; `cargo clippy --workspace` clean;
  `cargo fmt --all --check` clean.
- **19 behavioural claims individually revert-verified** — each fix reverted in
  turn, with the named test required to FAIL.
- Two reverts initially did NOT bite, and both were real test weaknesses rather
  than defence in depth:
  - The three UAV guards were mutually absorbing: reverting any one left the
    all-three-unset test green because the other two still refused, so it proved
    "refused" but not "refused for THIS reason". Fixed by
    `each_uav_guard_refuses_on_its_own`, which withholds exactly one input per
    case.
  - The PLMN change-detection revert was masked because that test's subscriber
    listened to a DIFFERENT event, so the subscription filter swallowed the
    spurious notification before it was recorded. Fixed by asserting the
    re-sent-unchanged-GUAMI case in the test whose subscriber IS subscribed to
    `PLMN_CH`.
- One revert was genuine defence in depth and is recorded as such: removing the
  create-time `access_type` baseline left `access_type_change_notifies_a_subscribed_consumer`
  green, because the `previously_known` guard then suppresses the first update's
  report and the second reports off the value it recorded. That protects against
  a FALSE report but silently loses a TRUE one — a session created on 3GPP whose
  **first** update moves it to non-3GPP would report nothing. Pinned by the new
  `first_update_after_create_reports_a_genuine_access_type_change`, against which
  the revert does bite.

### Verification ceilings

- The single-registration fix is asserted against a **mock NRF that counts
  PUTs**, which is the only assertion that fails if a second registration path
  returns. It is not exercised against a real NRF.
- `SUCCESS_UE_POL_DEL_SP` / `UNSUCCESS_UE_POL_DEL_SP` producers are wired into
  `handle_ue_policy_n1_notify` and type-checked, but are **not** covered by a
  test that drives a real UPDP container through to a notification. The existing
  strict-peer UPDP tests drive that handler; extending them to observe the event
  feed is the obvious next step and is called out here rather than left implied.
- GitNexus impact analysis was **not run**: no GitNexus MCP server is connected
  in this environment, so `nextgcore/CLAUDE.md`'s mandate remains unsatisfiable
  (18th consecutive PR).

## Files

- `src/bins/nextgcore-pcfd/src/npcf_eventexposure.rs` (new)
- `src/bins/nextgcore-pcfd/src/context.rs` — subscription store, `PcfSess.access_type`, `sess_add` dedupe, snapshot/restore
- `src/bins/nextgcore-pcfd/src/sbi_path.rs` — `PCF_SERVICES`, `pcf_nf_profile_json`, `pcf_register_with_nrf`, `pcf_report_pc_event`
- `src/bins/nextgcore-pcfd/src/app.rs` — routing, event producers, UAV fail-closed, leak fix, dead literal removed
- `src/bins/nextgcore-pcfd/src/lib.rs` — module declaration
- `docs-book/src/configuration/pcf.md` — the docs documented the removed in-zone default and the old three-service profile
