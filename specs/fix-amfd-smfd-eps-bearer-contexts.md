# nextgcore #117 (amfd/smfd): EBI assignment, Mapped EPS bearer contexts, and a real `ueEpsPdnConnection`

Verified against `main` @ `aeeb19d`.

## Verified against current main

| claim in the issue | site on `aeeb19d` | still true? |
|---|---|---|
| the `namf-comm` router has no `assign-ebi` arm | `bins/nextgcore-amfd/src/namf_server.rs:86` | yes |
| no `AssignEbiData`/`AssignedEbiData` type and no EBI pool anywhere | `rg 'assign-ebi\|AssignEbiData\|AssignedEbiData'` → **nothing** in the whole tree | yes |
| `SmfBearer.ebi` exists but only the GTPv2 path writes it | `context.rs` `pub ebi: u8`; sole writer `gtp_handler.rs` | yes |
| the three `gsm_build` builders emit no IEI `0x75` | `rg '0x75' src/bins/` → only crypto test vectors | yes |
| `handle_sm_context_retrieve` omits `ueEpsPdnConnection` | **NO — #78 added it** (`main.rs` `build_ue_eps_pdn_connection`) | **false** |

So criterion 4's first branch was already met by #78, which is why this PR extends that
function rather than writing it. The other four criteria were unmet.

## The precondition the issue's approach assumes and that does not exist

#117's suggested approach says to emit the IE "from `build_pdu_session_establishment_accept`,
`..._extended`, and `build_pdu_session_modification_command`". **None of those three has a
production caller.** The live establishment path builds its N1 message with
`policy::build_establishment_accept`; the `gsm_build` trio belongs to the `SmfSess`/`SmfBearer`
model that issue #223 is about ("two parallel session models, one dead").

Emitting the IE only where the issue points would therefore have been a correct encoder that no
UE could ever receive. The IE is emitted from **all four** builders — the three the criterion
names, so the criterion is met as written and the dead model is not left behind when #223 revives
it, and `policy::build_establishment_accept`, so a real UE gets it. Both call the same
`encode_mapped_eps_bearer_context`, so the two paths cannot drift.

## Decision 1: a runtime switch, not the cargo feature the issue suggests

#117 advises a single `eps-interworking` cargo feature. This uses `SMF_EPS_INTERWORKING=1`
(default off; smfd has no clap `Args`, so all its switches are env vars), for this project's
recorded reason: CI builds default features, so a cargo-feature-gated path is left uncompiled and
rots. A runtime switch is compiled always and exercised in **both** states by one `cargo test`
run — which is what makes criterion 5 ("behaviour unchanged when disabled") a thing a test asserts
rather than a claim about a build CI never performs.

Note the contrast with #276, merged one PR earlier, which *is* a cargo feature: that one binds a
privileged port and changes the process's network posture. The distinguishing factor is network
posture, not optionality. This one changes which IEs an N1 message carries.

## Decision 2: the EBI pool is per-UE, and exhaustion is an answer rather than an error

TS 24.301 §9.3.2 reserves EBI 0 ("no EPS bearer identity assigned") and 1..=4, so the assignable
space is **5..=15 — eleven per UE**, which is also the most EPS bearers a UE can hold. The pool
therefore lives on `AmfUe`, not per session: a per-session pool could hand the same EBI to two
sessions of one UE.

Eleven being small makes exhaustion a real outcome, and TS 29.518 models it rather than erroring:
`AssignedEbiData.failedArpList` carries the ARPs that got nothing. So a **partial** failure is a
`200` with both lists, and only "every ARP failed and none was assigned" is the `403 +
AssignEbiError` the operation defines. Allocation is lowest-free rather than round-robin so a
released EBI is reused promptly; an allocator that kept climbing would exhaust the space after
eleven session *lifetimes* instead of eleven concurrent bearers.

The order of operations inside one request is **release → modify → assign**, and it is
load-bearing: a request that releases EBI 5 and asks for one more must be able to hand 5 straight
back out. A revert that moves the release after the assignment fails two tests.

## Decision 3: pre-emption members are checked for presence, not for value

`Arp` requires `priorityLevel`, `preemptCap` and `preemptVuln`. `priorityLevel` is range-checked
(1..=15) because it is a plain integer with declared bounds. The other two are
`anyOf[enum, string]` in TS 29.571 — **extensible** enums — so a value outside the two named ones
is permitted by the schema and refusing it would reject something conformant. They are stored and
echoed verbatim. Pinned by a test that posts `SOME_FUTURE_VALUE` and asserts `200`.

## Decision 4: a 5QI with no EPS equivalent omits the QoS parameter rather than inventing a QCI

TS 23.501 Table 5.7.4-1 gives standardised 5QIs 1..=9 the same numeric QCI, which is what makes
mapping possible for them. For anything else — a non-standardised 5QI, or a delay-critical value
like 82 — there is **no defined QCI**. `qci_for_5qi` returns `None` and the bearer context is
emitted with an **empty parameters list** and the `E` bit clear, which is legal (it is exactly the
IE's 7-octet minimum). An MME *enforces* whatever QCI it is handed, so guessing one is worse than
omitting it; the EBI is still conveyed, so the bearer identity is agreed even where the QoS
mapping is not expressible.

## Decision 5: `ueEpsPdnConnection` names the EBI, and is otherwise byte-identical to #78's

#78 deliberately emitted a minimal descriptor with no bearer contexts, because there was no EBI
assignment in the tree and a fabricated bearer list would have an MME trying to use bearers this
SMF never established. #117 changes that precondition and nothing else: when an EBI **was**
assigned the descriptor appends it, and when none was the output is byte-for-byte what #78
produced. Appended rather than inserted, so a peer parsing the earlier form reads the same prefix.

The `403 EPS_IWK_NOT_SUPPORTED` alternative criterion 4 offers is **not** taken: #78's first
branch is already met, and switching a working `200` to a `403` when a runtime switch is off would
regress a deliberate decision of a merged issue for no conformance gain.

## Acceptance criteria

- [x] `POST /namf-comm/v1/ue-contexts/{ueContextId}/assign-ebi` is routed in amfd and returns
      `AssignedEbiData` with EBIs from a per-UE pool —
      `assign_ebi_allocates_from_a_per_ue_pool_and_answers_assigned_ebi_data`, driven **through the
      router** (a test calling the handler directly would pass with the routing arm absent), with
      the shape asserted against the yaml: the two `required` members present, `assignedEbiList`
      items as `EbiArpMapping`, and the three `minItems: 1` lists **absent rather than empty**.
      Plus `..._releases_before_it_assigns...`, `..._reports_exhaustion_rather_than_inventing_an_ebi`,
      `..._rejects_a_malformed_request_and_an_unknown_ue`, `..._modifies_a_held_ebi_and_409s_one_it_does_not_hold`.
- [x] smfd invokes `Namf_Communication_EBIAssignment` and the EBI reaches `SmfBearer.ebi` without
      the GTPv2 path — `the_smf_requests_an_ebi_over_namf_and_stores_what_it_gets` (the recorded
      request path and body are the assertion, not just the return value: `assign-ebi` had no
      caller anywhere before this) and `the_assigned_ebi_reaches_smf_bearer_without_the_gtpv2_path`.
- [x] The three named builders emit IEI `0x75` and it decodes to the expected EBI and parameters —
      `establishment_accept_carries_mapped_eps_bearer_contexts_only_when_an_ebi_exists`,
      `the_extended_establishment_accept_also_carries_the_ie`,
      `the_modification_command_carries_one_context_per_flow_holding_an_ebi`,
      `a_five_qi_with_no_eps_equivalent_omits_the_qos_parameter_rather_than_inventing_a_qci`. **And
      the live path**, which the criterion does not name:
      `the_live_accept_carries_mapped_eps_bearer_contexts_when_an_ebi_is_assigned`.
- [x] `handle_sm_context_retrieve` returns `SmContextRetrievedData` with `ueEpsPdnConnection` —
      met by #78; extended here to name the EBI, pinned by
      `the_retrieved_ue_eps_pdn_connection_names_the_assigned_ebi`, which asserts the prefix is
      unchanged and exactly one octet is added.
- [x] With interworking disabled, establishment/modification and Retrieve are unchanged — all 425
      pre-existing smfd tests and all 428 pre-existing amfd tests pass untouched, and the
      disabled-state assertions are explicit (`a_disabled_leg_dials_nothing`, the off half of
      `the_smf_requests_an_ebi_over_namf_and_stores_what_it_gets`, and the no-EBI half of every
      encoder test).

## Verification

Workspace **6241 passed / 0 failed** (baseline 6224 on `aeeb19d`; +17), and
`cargo test -p nextgcore-easdfd --features dns-udp` still 51/0. `cargo clippy --workspace
--all-targets` and `cargo fmt --all -- --check` clean; amfd and smfd carry **zero** clippy
warnings, including four pre-existing `needless_borrow` warnings in smfd's #78 tests fixed in
passing.

| revert | expected to break | result |
|---|---|---|
| the `assign-ebi` routing arm removed | all five amfd tests | **5 failed** |
| release moved to after assignment | the reuse and exhaustion tests | **2 failed** |
| the allocator ignores already-held EBIs | the pool and exhaustion tests | **2 failed** |
| the **live** accept stops emitting the IE | the live-path test | **1 failed** *(see below)* |
| the `E` bit set with an empty parameters list | the no-EPS-equivalent test | **1 failed** |
| the Namf writer stops setting `SmfBearer.ebi` | the storage test | **1 failed** |
| Retrieve stops reading the binding's EBI | the `ueEpsPdnConnection` test | **1 failed** |

### The revert pass found a hole in my own work

Revert 4 initially passed: with the emit removed from `policy::build_establishment_accept` the
**entire 436-test smfd suite stayed green**, because every test touching the IE drove one of the
three `gsm_build` builders — and those have no production caller. The IE was covered exactly where
it does not matter and uncovered on the one path a UE receives. That is the same
correct-but-unreachable trap this PR's opening section describes, reproduced in the diff meant to
avoid it. `the_live_accept_carries_mapped_eps_bearer_contexts_when_an_ebi_is_assigned` was added
and the revert then failed.

A second, milder finding: revert 5 first appeared not to bite, which turned out to be a too-narrow
`cargo test mapped_eps` filter rather than a missing guard — the assertion lives in a test whose
name does not contain that substring. Re-run without the filter, it failed correctly. Worth
recording because "the revert did not bite" and "my filter did not select the guard" look identical
in the output.

## Ceilings

* **The create call site is verified by inspection, not by a test** — the same ceiling #276 hit and
  filed as #289. `handle_sm_context_create` cannot be driven past its N4 leg (no UPF stand-in), so
  neither the `eps_iwk::request_ebi` call nor the `record_mapped_eps_bearer` call is reachable from
  a test. The two functions themselves are covered, and the recording step was **extracted into
  `eps_iwk.rs` specifically so it has a reachable seam** rather than being an inline block that
  nothing can call. #289 names this exact call site as one of the three it would close.
* **One EBI per session, not one per QoS flow.** TS 23.502 §4.11.1.4.1 has the SMF request an EBI
  per flow that needs one; the live path authorises a single default flow per session, so one ARP
  is sent. A multi-flow session would need the `arpList` to grow with it, and the AMF side already
  handles an arbitrary-length list (tested to eleven).
* **`AssignEbiData.oldGuami` is parsed but unused.** It matters for an inter-AMF case (the EBIs a
  *previous* AMF assigned) that this tree has no handling for; ignoring it is what the current
  single-AMF behaviour amounts to, stated rather than silently dropped.
* **The Modification Command path emits the IE but has no production caller**, because
  `policy::build_modification_command` (the live one) has no EBI parameter — the live modification
  path does not re-authorise bearers. So a flow that gains an EBI *mid-session* is encodable and not
  yet conveyed. Left alone because no criterion asks for it and adding an argument to the live
  modification builder with no caller to pass it would be dead weight.
* **TS 24.501/24.301 are vendored as text, not as a schema.** The IE layout was read out of
  `6g_docs/specs/24501-j62.txt` §9.11.4.8 (figures 9.11.4.8.1–3 and Table 9.11.4.8.1) and
  `24301-k00.txt` §9.9.4.3 rather than inferred from the issue text — the 7-octet minimum length
  the spec states is what confirms the context-length field covers octet 7 onward. But there is no
  machine-checkable artifact, unlike the TS 29.5xx yamls the SBI shapes are checked against.
* **No EBI release on session release.** `AssignEbiData.releasedEbiList` is implemented on the AMF
  side and the SMF never sends one, so an EBI stays held for the UE's lifetime rather than its
  session's. Eleven-wide space plus lowest-free allocation makes this a real leak over enough
  session churn. Not in any criterion; worth its own issue.
* GitNexus impact analysis unrunnable (no MCP server connected). Blast radius by grep:
  `AssignedEbi`/`EbiArp` are new with one producer each; `build_establishment_accept` gained a
  parameter and has 1 production + 6 test call sites, all updated; `SmfBearer::assigned_ebi` has
  four callers, all new.
