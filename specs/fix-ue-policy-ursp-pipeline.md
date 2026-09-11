# fix(nas,amfd,pcfd): the UE Policy (URSP) provisioning pipeline

Closes #91. All eight criteria in one PR.

#91's suggested approach says to implement it "as at least three tracked issues", but its
acceptance criteria are one list and none is marked separable, so the whole-issue
convention applies: an umbrella split across PRs stays open. The eight criteria are also
not independent — criterion 3's PSI diff has nothing to diff against until criterion 1's
NAS decode and criterion 2's `uePolReq` exist, and it has nothing to *skip* until
criterion 5's sections exist.

## Claim-vs-site-vs-still-true

Re-located against `1d8f450`. Every claim held. **Two of the issue's own statements are
wrong**, and one criterion is void.

| # | #91's claim | site now | still true? |
|---|---|---|---|
| 1 | `RegistrationRequest` has no Payload container IE | `message.rs:133` ended at `nas_message_container` | **yes** |
| 2 | `call_pcf_ue_policy_create` sends no `uePolReq` | `sbi_path.rs:1952` body | **yes** |
| 3 | pcfd ignores UE STATE INDICATION `0x04` | `ue_policy.rs:596` `other =>` arm | **yes** |
| 4 | `handle_ue_policy_update` returns a canned 200 | `app.rs:1520` | **yes** |
| 5 | `build_manage_ue_policy_command` emits one section, `upsc` hard-coded to 1 | `ue_policy.rs:840`, `app.rs:1258` | **yes** |
| 6 | `parse_td` accepts only match-all/DNN/FQDN; `map_td_component` fail-closes on the rest | `ue_policy.rs:986`, `:771` | **yes** |
| 7 | the create runs at registration step 3b, before Registration Accept | `ngap_path.rs:2807`, Accept at `:3004` | **yes** |

### What #91 gets wrong

**The UPDP codec already exists.** #91's suggested approach reads as if UE STATE
INDICATION needed writing; `nextgcore-nas`'s `ue_policy.rs` already has
`UeStateIndication` with `encode`/`decode`, `UpsiList`, `UpsiSublist` and
`UePolicyClassmark`, and the full TS 24.526 Table 5.2.1 `TrafficDescriptorComponent` set
including `OsIdOsAppId`, `Ipv4RemoteAddress`, `Ipv6RemoteAddress`, `ProtocolIdentifier`,
`SingleRemotePort` and `RemotePortRange`. Criteria 3 and 6 are therefore **wiring**, not
codec work — which is why this change adds no new NAS encoders.

**Criterion 6's S-NSSAI clause is VOID.** #91 lists "S-NSSAI" among the traffic-descriptor
components to support, and its Spec basis attributes it to TS 24.526 §5.2 Table 5.2.1.
That table defines **no S-NSSAI traffic-descriptor component type**, and says "all other
values are spare. If received they shall be interpreted as unknown"
(`6g_docs/specs/24526-i50.txt:2467-2498`). S-NSSAI is a **route selection descriptor**
component, which `map_rsd` already emits. The pre-existing `map_td_component` comment
already said this; the issue text is what is wrong. `SNssai` therefore still fail-closes,
with the spec line cited, and the test asserts that it does — closing a void criterion by
explaining it rather than inventing work.

## Criterion 1 — the Payload container

TS 24.501 Table 8.2.6.1.1 (`24501-j62.txt:65069-65078`) gives REGISTRATION REQUEST two
optional IEs this tree did not model: **`8-` Payload container type** (TV, 1 octet,
half-octet IEI) and **`7B` Payload container** (TLV-E, 4-65538).

Both are added to `nextgcore_nas::RegistrationRequest`, plus a
`ue_policy_container()` accessor **gated on the type**: a container of some other type is
not a UE policy container, and routing an SMS container into the PCF's UPDP decoder would
be worse than dropping it. They are encoded together or not at all — a type with nothing
to type is meaningless, and a container with no type cannot be interpreted.

An **unknown** type value decodes to `None` rather than failing the message
(`PayloadContainerType::from_u8`): §9.11.3.40 leaves values spare, and an otherwise valid
Registration Request must not be rejected over a payload the AMF does not recognise.

`amfd` has its own hand-rolled `parse_registration_request_pdu`, a third layer, and it
already *skipped* `0x7B` correctly — the TLV-E arm advanced past it and kept nothing. It
now captures the bytes (bounds-checked, since `len` comes off the wire) and the type from
the `8-` nibble, with the same type-gated accessor.

## Criterion 2 — `uePolReq`

`TS29525_Npcf_UEPolicyControl.yaml:450` makes `uePolReq` a `UePolicyRequest`, which
`:911` resolves to TS 29.571 `Bytes` — base64. So the UE's UPDP message travels verbatim,
base64'd, and the PCF is the node that decodes Annex D.

The member is **omitted** rather than sent empty when the UE sent no container: an empty
`uePolReq` claims the UE reported an empty installed set, which is a different statement
from "the UE reported nothing". `base64` moves from a dev-dependency to a real one in
`pcfd` for the decode side; no new crate enters the tree.

## Criterion 7 — the ordering, enforced rather than assumed

The create moves from registration step 3b to the **end of `send_registration_accept`**,
both branches (the ICS that carries the Accept, and the update path's DL NAS transport).
Moving the create moves the delivery, because the create *is* the PCF's trigger — so this
needs no new protocol and no new flag.

But a call-site convention is not an invariant, so `UeNasContext` gains
`registration_accept_sent` and `create_ue_policy_association` **refuses** while it is
false. The function returns a `UePolicyCreate` decision (`Skipped(reason)` /`Attempted`)
rather than only logging, which is what makes the ordering assertable with no SCTP peer
and no live PCF — the decision/transmission split recorded for #70.

## Criterion 5 — fragmentation

`build_manage_ue_policy_delta` partitions the rules across as many sections as they need,
one instruction per section inside the PLMN sublist (which is how D.6.2.4 expresses more
than one section for one PLMN), each with its own UPSC counting up from the first.

Partitioning is done on **encoded** size, one rule at a time: a rule's encoded length
depends on its components and cannot be predicted from the count, so encoding each
candidate group is the only way to know it fits. The bound is
`MAX_UE_POLICY_PART_CONTENTS` = `u16::MAX - 1`, from Figure D.6.2.7's 2-octet contents
length and Table D.6.2.1 NOTE 2's rule that it also covers the part-type octet.

A **single** rule that exceeds a whole section is still an `Err`: there is nothing left to
split, and looping would be worse than saying so.

## Criterion 3 — the PSI diff

`apply_ue_policy_ul_container` now decodes `0x04`. It is **not** a delivery result, so
D.2.1.6's PTI correlation does not apply — the PTI is recorded rather than matched and the
delivery state is left alone. A new `StateReported(n)` outcome says so, distinct from the
`Ignored(t)` it used to return.

The UPSI list is flattened to `(mcc, mnc, upsc)` triples, **keeping the PLMN with each
UPSC**: the PLMN is carried per sublist and the same code means different content in a
different PLMN (Table D.6.2.1), so a bare UPSC could not be compared safely.
`installed_upscs_for_plmn` filters to the serving PLMN for exactly that reason.

Delivery then omits sections whose UPSC the UE already reports. Two decisions worth
naming:

- **Skipped sections do not renumber.** UPSCs are assigned over *all* sections including
  omitted ones, so a section keeps its code when a neighbour is skipped. Renumbering would
  make the UE's reported UPSI refer to different content on the next delivery — worse than
  re-pushing.
- **An empty delta is `Ok(None)`, not an empty PDU.** A MANAGE UE POLICY COMMAND whose
  sublist has no instructions is not conformant (D.6.2.3 requires at least one), and it
  would arm a T3501 the UE has no reason to answer. The association is marked `Delivered`,
  because the UE *has* the policy; leaving it `Pending` would fail it on T3501 for a
  delivery that was correctly not made.

`uePolReq` is ingested **before** delivery is spawned. Order matters: the delivery task
computes the delta from it, so ingesting afterwards would race and the first delivery
would always be full.

## Criterion 4 — the update leg

`handle_ue_policy_update` now applies `notificationUri`, `uePolReq`, `uePolDelResult` and
`triggers`, then re-evaluates and re-delivers, and reports what it did.

- **`notificationUri` first**, because a re-delivery may notify, and notifying the *old*
  URI after being told it changed is what the member exists to prevent.
- **`uePolDelResult`** goes through the same `apply_ue_policy_ul_container` as the N1
  notify callback, so the same PTI correlation applies — which is what stops a stale
  result from a previous command flipping this association's state (D.2.1.6).
- **Re-delivery is driven by the trigger**, not by the fact of an update: an update that
  changes only a notification URI must not re-push policy to the UE. A fresh PTI, because
  this is a new delivery procedure and reusing the old one would make the UE's answer
  indistinguishable from an answer to the previous command.
- **A 404 has no side effects**: the association is resolved before anything is applied.

## Revert-verify

Nine reverts, each confirmed applied before the test ran, each biting:

| revert | test that fails |
|---|---|
| amfd drops the `0x7B` capture | `registration_request_payload_container_is_captured_and_type_gated` |
| the NAS accessor stops gating on the type | `gmm_registration_request_payload_container_type_gates_the_accessor` |
| `uePolReq` omitted from the create body | `ue_policy_create_carries_the_ue_policy_container_as_ue_pol_req` |
| UE STATE INDICATION back to logged-and-ignored | `ue_state_indication_records_the_reported_upsi_list` |
| the delta ignores the installed set | `the_delta_omits_sections_the_ue_already_has` |
| no partitioning: one section only | `an_over_length_policy_is_partitioned_into_multiple_sections` |
| `parse_td` returns on the first match | `traffic_descriptor_components_cover_table_5_2_1` |
| the update leg back to discarding the body | `ue_policy_update_applies_the_request_instead_of_answering_a_canned_200` |
| the ordering guard removed | `ue_policy_association_is_not_created_before_registration_accept` |

Two tests are pinned to a *measured* fixture rather than a guessed one:
`the_partition_fixture_limit_really_fits_exactly_one_rule` asserts that one rule of the
two-rule set is ≤ 60 octets and both are > 60. A first attempt used 40, which one rule
already exceeded (41 octets), so the partitioning tests failed for the wrong reason — the
guard test exists so that cannot recur silently.

One pre-existing test changed meaning: `apply_undecodable_container_dropped` asserted that
a truncated `0x04` container was `Ignored(0x04)`. It was — because `0x04` was never
decoded, so a malformed one and a valid one were indistinguishable. It is now
`Undecodable`, and the test asserts that plus a genuinely out-of-loop type.

## Verification

- Workspace **6513 → 6525** tests, 0 failures.
- `cargo clippy --workspace` 0 errors; `nextgcore-nas`, `nextgcore-amfd` and
  `nextgcore-pcfd` all at **0 warnings**. `cargo fmt` clean. Gated
  `easdfd --features dns-udp` clean.

## Ceilings, stated rather than implied

- **The UE half does not exist.** #91 carries a cross-repo coupling note naming
  nextgsim#47 and #48: the UE has no UE STATE INDICATION encoder and its
  RegistrationRequest cannot carry the policy container, and it stores delivered URSP
  rules without evaluating them to bind traffic. Reading the *evidence* of that note
  rather than its conclusion: every criterion here is a property of the core alone and is
  unit-testable without a peer, but **no real UE will send a `uePolReq` until nextgsim#48
  lands**, so the diff path will take its "UE reported nothing → full delivery" branch in
  any end-to-end run today. That branch is correct, and it is not the one that needed
  building.
- **The delta is per-section, not per-rule.** A UE holding section 1 whose *contents* have
  since changed still reports UPSC 1 installed, so the change is not delivered. TS 24.501
  Annex D's remedy is a new UPSC for changed content, which needs content-addressed UPSC
  assignment rather than the monotonic-from-1 scheme here. Out of scope for #91's
  criteria and worth its own issue.
- **No ANDSP part.** #91's gap 3 mentions one alongside fragmentation.
  `UePolicyPartType` models it, but this build has no ANDSP policy source to fill one
  from — the URSP rules come from `PCF_URSP_RULES` or the UDR `urspRules` extension, and
  neither carries non-3GPP access selection policy. Emitting an empty ANDSP part would be
  a claim without content.
- **`AppId`/`IpDesc`/`NonIp`/`Ethernet` still fail closed.** They are the pcfd model's
  *unstructured* variants; the structured ones added here are the encodable path. Leaving
  them is deliberate: silently mapping an opaque `AppId` onto a fabricated OS Id would
  provision a rule that matches a different application.
- **A pcfd test flake observed once and not reproduced** during this work
  (`each_uav_guard_refuses_on_its_own`, a session-leak assertion) is filed as **#338** with
  the evidence and the loop counts. It is on the UAV path, which this change does not
  touch.
