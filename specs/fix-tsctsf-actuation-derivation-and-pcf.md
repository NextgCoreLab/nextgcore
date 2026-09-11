# nextgcore #284: make a stored TSCTSF configuration do something

Verified against `main` @ `5343503`.

#284's diagnosis is accurate and every "current state" claim below still held.
What it gets wrong is one of its own acceptance criteria, and the reason is in
TS 29.514 rather than in the code.

## Verified against current main

| claim in the issue | site on `5343503` | still true? |
|---|---|---|
| tsctsf stores typed records and "nothing reads those records outside the SBI handlers" | `context.rs` + `main.rs`; no other reader | yes |
| no PCF client exists in the crate | `rg 'Npcf_PolicyAuthorization\|policy-authorization' bins/nextgcore-tsctsf/` → nothing | yes |
| no PMIC/UMIC/TSCAI derivation exists anywhere in the tree | confirmed workspace-wide | yes |
| upfd's `tsn_bridge` is `None` and never referenced from tsctsf or smfd | `upfd/context.rs:1204`, init `None` at `:1223`, one unit-test reference at `:1851` | yes |
| "There is no PFCP TSC container codec" | **sharper than that**: the IE type *constants* exist — `CreateBridgeInfoForTsc = 194`, `CreatedBridgeInfoForTsc = 195`, `TscManagementInformation{Smr,Smrsp,Srr} = 199/200/201` (`pfcp/ie.rs:205-212`) — with **zero users**, and `UpFunctionFeatures.tscu` is encoded and decoded but never acted on | yes, and the identifiers-without-codec state is worth naming |
| `CapsNotify` has no in-tree producer of a capability change | `admin/capability-change` was the only trigger | yes |
| criterion 2: "a **time-sync** create issues `Npcf_PolicyAuthorization_Create`" | **not literally satisfiable for every such create** — see Decision 3 | **partly false** |

## Decision 1: the derivation is pure, and its verdicts are three-valued

`derive_tsn_management` takes a stored `TimeSyncExposureConfig` and returns the
DS-TT ports (one per SUPI), the NW-TT port (one, for the `upNodeId`), the bridge
container, whether the grandmaster is enabled, and a clock-quality verdict. No
peer, no clock, no I/O — which is why criterion 1's three cases can be asserted
exactly.

Three choices inside it are not obvious and each is pinned by its own test:

- **An absent `gmEnable` is NOT activation.** TS 23.501 §5.27.1.8 makes activation
  explicit; defaulting it on would start distributing time for a configuration that
  never asked.
- **A configuration with no SUPIs still derives the N6 termination.** That port is
  a property of the user-plane node, not of any UE — the asymmetry criterion 1 asks
  to be covered, stated as its own case rather than implied by the multi-UE one.
- **Clock quality is three-valued.** `NoCriteria` is distinct from `Satisfiable`: a
  caller collapsing them into a boolean would report "criteria met" for a
  configuration that stated none, inventing a guarantee. Both permit actuation;
  only `Unsatisfiable` stops it.

`Unsatisfiable` carries **every** reason, not the first, so an operator fixing one
and re-submitting does not discover the rest one round trip at a time.

## Decision 2: "cannot be met" is a static check against IEEE 1588, not a measurement

Criterion 1 asks for "a configuration whose clock-quality acceptance criteria
cannot be met". With no measured clock in this tree, the only honest reading is
*unsatisfiable by any clock*, which IEEE 1588-2019 makes checkable:

| criterion | rule | source |
|---|---|---|
| `clockClass` | must be one of `{6,7,13,14,52,58,187,193,248,255}`; everything else in 0..=255 is Reserved | §7.6.2.5 Table 4 |
| `clockAccuracy` | must be `0x20`..=`0x31`, or `0xFE` (unknown). Demanding better than `0x20` (25 ns) asks for an accuracy the standard cannot report | §7.6.2.6 Table 5 |
| `synchronizationState` | must be `SYNCHRONIZED` or `NOT_SYNCHRONIZED` | TS 23.501 §5.27.1.8 |
| `offsetScaledLogVariance` | every `u16` is representable, so nothing here can be unsatisfiable | named in code rather than omitted, so the absence is visibly deliberate |

Authorising a configuration whose criteria can never be met would commit the
TSCTSF to a service it cannot deliver — the failure mode #284 calls out — so it is
declined with the reasons logged, while the 201 and the stored record are
unaffected.

## Decision 3: criterion 2 is not literally satisfiable, and the gap is in TS 29.514

`AppSessionContextReqData` (TS 29.514) has exactly the members this needs —
`tsnBridgeManCont` (documented as "Contains the UMIC"), `tsnPortManContDstt`,
`tsnPortManContNwtts` (an array, `minItems: 1`), `tscNotifUri`, `tscNotifCorreId`,
`supi` — **and it also requires `oneOf [ueIpv4, ueIpv6, ueMac]`**.

A TS 23.502 §5.2.27.2.2 time-synchronization configuration's mandatory inputs are
a notification target, a `upNodeId`, and SUPIs. **No UE address.** So a time-sync
create cannot build a schema-valid `AppSessionContextReqData` from its mandatory
inputs, and criterion 2 as written cannot hold for every such create.

Three options were available and two are worse:

1. Send a body that omits the `oneOf` member. The PCF answers 400, which looks
   like a PCF problem.
2. Invent an address. A revert that does exactly this is in the table below,
   precisely because it is the tempting version.
3. Read an optional UE address when the consumer supplies one, and **decline with
   a named reason** when it does not.

(3) is what this does. `ueMac` is checked first: a DS-TT behind an Ethernet PDU
session has one, which is the TS 23.501 §5.28 case. A QoS/TSC session needs none
of this — §5.2.27.3.2 makes a UE address a required input — so its actuation is
unconditional, and that asymmetry is the honest shape rather than a shortcut.

As in #113, `TS29565_Ntsctsf_*.yaml` is not vendored here, so the three added
optional member names are the camelCase form of Stage-2 parameter names rather
than a spelling verified against a Stage-3 schema. Same caveat #113 recorded.

## Decision 4: the capability source is derived state, and it fires on a change

Criterion 5 asks for "a capability change from a real source". The source is the
**derived capability set** — the union of time domains and PTP profiles across
stored configurations, whether any enables a grandmaster, and a count of
configurations with unmeetable criteria — recomputed on every configuration change.

It fires only when the set **differs** from the last reported one. A create that
alters nothing must not wake every subscriber; that is what makes it a change
trigger rather than a per-request one, and it is the difference from #113's admin
poke. A revert that always reports "changed" fails the test that asserts the
second identical create is silent.

What this is **not** is a 5GS capability report: the gNB and UPF do not report
their (g)PTP capability into this tree at all. Stated in the function's own doc.

`admin/capability-change` is **kept and documented as a test-only shim**, which
criterion 5 permits explicitly. Kept rather than removed because #113's
subscribe/notify/unsubscribe test drives the fan-out through it and it lets an
operator force a fan-out while diagnosing; the doc says plainly that anything
relying on it in a deployment is relying on a shim.

## Decision 5: the crate's test lock moved out of `mod tests`

`GLOBAL_TEST_LOCK` lived inside `main.rs`'s `mod tests`, so no sibling module
could reach it. `actuation`'s tests flip a process-global switch that `main`'s
handlers read, so they would have had to declare a **second** lock over the same
ambient state. #308 established that two locks over one state are two disjoint
agreements, and #276 showed that shape *hangs* the suite rather than merely
flaking it.

The static is now `context::PROCESS_STATE_TEST_LOCK`, declared beside the context
it guards, and `main`'s `lock_globals()` delegates to it. Relocation only; no test
changed.

## Verification

| claim | how it was made to fail | result |
|---|---|---|
| an absent `gmEnable` is not activation | default it to `true` | **fails** `an_absent_grandmaster_flag_is_not_activation` |
| the N6 termination is independent of having UEs | return early with no NW-TT port when `supis` is empty | **fails** `a_configuration_with_no_ues_still_derives_the_n6_termination` |
| impossible clock-quality criteria are detected | always return `Satisfiable` | **fails 4 tests**, including the end-to-end "not actuated" one |
| the OFF switch is honoured | ignore it in `actuate_time_sync_create` | **fails** `the_switch_off_makes_no_outbound_request` |
| a delete retracts the PCF authorisation | drop the `policy_authorization_delete` call | **fails** `the_switch_on_issues_policy_authorization_create_and_delete` |
| `CapsNotify` fires on a *change* | always report "changed" | **fails** `a_derived_capability_change_drives_caps_notify_and_an_unchanged_set_does_not` |
| a missing UE address declines rather than fabricates | fall back to `ueIpv4: "0.0.0.0"` | **fails** `a_configuration_with_no_ue_address_is_not_actuated` |

Criterion 2 and 3's assertions are on the **outbound HTTP request** against a stub
PCF — method, path and body, including that `tsnBridgeManCont.bridgeManCont` is a
base64 string and that the DS-TT/NW-TT port numbers are 1 and 0 — which is what
criterion 2 demands instead of a log line. The `appSessionId` is read from the
stub's `Location` header, so the delete path proves the create recorded the right
identifier.

Criterion 3's "byte-identical" half is asserted by running the *same* create with
the switch off and on and comparing the whole 201 body (minus the minted id and
`self`, which differ by construction). A weaker test would let actuation quietly
add a member to what the consumer gets back.

Gates: `cargo test -p nextgcore-tsctsf` **52 passed / 0 failed** (was 33);
workspace **6396 passed / 0 failed**; `cargo clippy --workspace` and
`--all-targets` 0 errors; `cargo fmt --all --check` clean.

## Ceilings

- **Criterion 4 is NOT met: the UPF's `tsn_bridge` is still `None`.** This is the
  one criterion left open, and it is stated first. Driving it needs the N4 leg —
  a PFCP TSC container codec, an `smfd` path that carries it, a `upfd` consumer —
  and #284's own suggested approach makes piece 4 "only meaningful once (3)
  exists". The codec does not exist: the IE type constants at `pfcp/ie.rs:205-212`
  have **zero users** and there is no `TscManagementInformation` struct, encoder or
  decoder anywhere. Filed as **#321** with the verified evidence and a criterion
  list. Criterion 4 also instructs that if this cannot be verified in-process the
  PR must say so and state what *is* verified instead: what is verified is that
  the derivation produces exactly the PMIC/UMIC payload such a leg would carry,
  and that the PCF receives it over `Npcf_PolicyAuthorization`.
- **The PMIC/UMIC octet strings are this build's own TLV encoding**, not IEEE
  802.1Q clause 12 — no 802.1Q managed-object codec exists here. Said in
  `PortManagementInfo::container`'s own doc, and the tests read the containers back
  by tag rather than by byte offset so a real encoder can replace it without
  rewriting the assertions.
- **Only `medComponents["0"]` is built for a QoS/TSC session.** One media
  component per session, keyed `0`. A session describing several flows with
  different patterns would need one component each, and nothing in `QosTscSession`
  models that split.
- **`suppFeat` is `"0"`**, so no optional TS 29.514 feature is negotiated. Claiming
  one this consumer does not implement would make the PCF send responses it cannot
  read.
- **The PCF is given the AF's own notification URI.** This TSCTSF serves no
  TSC-notification receiving route; pointing the PCF at a 404 would be worse than
  pointing it at the consumer that asked. A real deployment wants a TSCTSF-side
  callback, which needs a route this build does not have.
- **`appSessionId` lives in a process-global map**, not on the stored record.
  tsctsf has no durable store, so it is exactly as durable as the record it keys —
  but a restart loses the ability to retract an authorisation the PCF still holds,
  which is #193's defect in a different NF.
- **The ASTI service is not actuated.** `AstiConfig` (access-stratum time
  distribution) stores and answers as before; TS 23.501 §5.27.1.8 routes its
  activation through the AMF/gNB, which is a different peer from the PCF and a
  different issue.
- **`derive_tscai` maps Stage-2's single `survivalTime` to `surTimeInTime`**, the
  duration, not to `surTimeInNumMsg`, the message count. TS 29.514 has both and
  Stage-2 has one; the mapping is asserted in a test with the reasoning in the
  message, because getting it wrong would silently change the unit.
- **No E2E.** Every assertion is a loopback request in one process. The Docker jobs
  remain `workflow_dispatch`-only, and no compose service sets
  `TSCTSF_ACTUATION`, so the default E2E path is unchanged — which is also what
  makes the switch's default safe.
