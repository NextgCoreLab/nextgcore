# nextgcore #204 (smfd/amfd): select the subscribed default DNN instead of the literal `"internet"`

Verified against `main` @ `35475d5` (after #205, #242, #95). The issue was written at `d9aea74`; every
cite still holds, and the **suggested approach is unfollowable as written**.

## Verified against current main

| claim in the issue | cite | site on `35475d5` | still true? |
|---|---|---|---|
| `amfd` substitutes the literal | `ngap_path.rs:3470` | `ngap_path.rs:3585` `let dnn = dnn_override.unwrap_or("internet")` | yes |
| `amfd` retrieves only `am-data` from UDM SDM | `sbi_path.rs:1582` | `sbi_path.rs:1636` `call_udm_sdm_get_am_data` | yes |
| `smfd` never issues a `nudm-sdm` request | — | `grep -rn 'nudm-sdm' bins/nextgcore-smfd/src/` → **one** hit, the FSM arm | yes |
| the dormant FSM arm | `gsm_sm.rs:302` | `gsm_sm.rs:302` | yes |
| the producer side exists end to end | `udmd/app.rs:663` → `handle_get_sm_data` | `udmd/app.rs:839` routes `smf-select-data` → `:2125` → udrd `smf-selection-subscription-data` | yes |

Also re-verified, and **not** in the issue: `smfd` had no way to reach a UDM at all. It knows only its
NRF (for its own registration), performs no NF discovery, and the `smf` container in
`docker/rust/docker-compose.yml` sets no `UDM_SBI_ADDR`. Both had to be added for the criterion-1 path
to be reachable at all.

## The suggested approach cannot be followed: there is no "flagged as default" entry in `sm-data`

The issue says: *"select the `dnnConfigurations` entry **flagged as the subscribed default**"*. No such
flag exists.

- `sm-data` returns `SessionManagementSubscriptionData`, whose `dnnConfigurations` is a JSON **object
  keyed by DNN name**. TS 29.503 Table 5.5.2.4-1's `DnnConfiguration` carries `pduSessionTypes`,
  `sscModes`, `5gQosProfile`, `sessionAmbr` and friends — **no default indicator**. Selecting from it
  would mean picking an arbitrary key out of a map, which is the fabrication #204 exists to remove.
- The default-DNN flag is `DnnInfo.defaultDnnIndicator`, and `DnnInfo` lives in
  `SmfSelectionSubscriptionData` — the `smf-select-data` resource.

**So this reads `smf-select-data`, not `sm-data`.** Same service (Nudm_SDM), same producer chain, the
resource that can actually answer the question. Stated prominently because a reviewer comparing the
issue to the diff will otherwise think the wrong resource was used.

## Decision 1: the selection order, and what it refuses

`select_default_dnn`:

1. the `dnnInfos` entry with `defaultDnnIndicator: true`;
2. if exactly **one** DNN is subscribed for the S-NSSAI and none is flagged, that one — it is
   unambiguous, there is nothing else the default could be;
3. otherwise `AmbiguousDefault`, listing the candidates, and the session is **refused**.

Rule 3 is the point of the change. Picking the first, or the alphabetically-first, or `"internet"`
would all be deterministic and all be invented. A refused session is a visible operator problem; a
session on the wrong data network is an invisible one, and that is the defect being fixed.

The S-NSSAI key form is `{sst:02x}` or `{sst:02x}-{sd}` (matching udrd's `build_smf_selection_data`),
and an unmatched `sst-sd` key widens to the no-SD entry — a subscription provisioned without an SD
still applies to a request carrying one, the same widening `nsacfd`'s quota lookup does.

## Decision 2: four distinct failure causes, not one

`DefaultDnnError` has four variants and two ProblemDetails causes:

| variant | cause | why separate |
|---|---|---|
| `NoSubscribedDnn` | `MANDATORY_IE_MISSING` | the consumer named no DNN and the subscription supplies none — a provisioning gap |
| `AmbiguousDefault(Vec<String>)` | `MANDATORY_IE_MISSING` | same class, and the detail **names the candidates** so the operator knows what to flag |
| `NoUdmEndpoint` | `SUBSCRIPTION_DATA_NOT_AVAILABLE` | not the consumer's fault — the SMF cannot reach the data |
| `SdmRequestFailed(String)` | `SUBSCRIPTION_DATA_NOT_AVAILABLE` | same, with the transport/status detail |

Collapsing them would leave an operator unable to tell a provisioning gap from an unreachable UDM,
which have opposite remedies.

## Decision 3: no `single-nssai` query parameter, and it is not an oversight

TS 29.503 §5.2.2.2.1 lets the consumer scope the answer to one S-NSSAI, and the first draft did. It was
removed after the end-to-end test showed why it cannot work here: the value is JSON, so on the wire it
must be percent-encoded as an RFC 3986 query component — and **this tree's shared SBI server stores
query values verbatim without decoding them** (`libs/nextgcore-sbi/src/server.rs:583`, which is exactly
the gap issue #65 names). So a percent-encoded `single-nssai` reaches the in-tree UDM as the literal
`%7B%22sst%22...` and cannot be parsed, while sending it unencoded would be invalid on the wire.
Scoping is an optimisation, not a correctness requirement: `select_default_dnn` picks the S-NSSAI's
entry by key regardless. The test asserts the parameter is **absent**, so re-adding it before #65 lands
fails loudly rather than silently sending garbage.

## Decision 4: the dormant `nudm-sdm` FSM arm is removed, not wired

Criterion 2 offers either. Removed, because the request genuinely does not return there: the DNN is an
**input to creating the session**, so the fetch must happen before the session's GSM FSM exists. The
arm described a flow where the SMF fetched subscription data *during* the policy-association wait,
which never existed — and dispatching the response into the FSM as well would put one decision in two
places. (The sibling `npcf-smpolicycontrol` arm **is** live, via `fsm_dispatch_policy_response`, so
this is a genuine asymmetry rather than the whole handler being dead.)

## Decision 5: sequencing, which the issue calls load-bearing

The issue insists the SMF must be able to apply a subscribed default *before* the AMF stops sending
one. Both land in this PR, in one commit, so no intermediate state exists. Three things make the SMF
side genuinely reachable rather than nominally present:

1. `validate_sm_context_create_data` stops rejecting an absent `dnn` (it is optional per TS 29.502
   Table 6.1.6.2.2-1). Leaving it mandatory would have made the whole resolution path unreachable —
   the same class of defect as #242.
2. `discover_udm_sdm_endpoint`: NRF discovery first, `UDM_SBI_ADDR`/`UDM_SBI_PORT` as the fallback.
3. `UDM_SBI_ADDR` / `UDM_SBI_PORT` added to the `smf` container in
   `docker/rust/docker-compose.yml`. Without it a DNN-less session in the E2E would be refused.

Note what the *worst case* is: before this change, `smfd` refused any create with no `dnn`
(`MANDATORY_IE_MISSING` at the validator). After it, an unresolvable default also refuses — with a
better cause. So the failure mode for DNN-less requests is not a regression; the improvement is that a
resolvable default now succeeds and a wrong one is never invented.

`discover_udm_sdm_endpoint` deliberately does **not** populate the shared NF cache: `amfd` and `udmd`
each carry a full cache-populating discovery routine, and a third copy is a maintenance cost this issue
does not need. What the SMF wants is one address.

## Acceptance criteria

- [x] `smfd` retrieves subscription data and selects the subscribed default DNN when
      `SmContextCreateData` carries no `dnn`; a test asserts the subscribed default (not `internet`) is
      used — `select_default_dnn_uses_the_indicator_and_refuses_to_guess` (selection, including
      explicitly `assert_ne!(..., "internet")`) and
      `fetch_subscribed_default_dnn_queries_the_udm_and_returns_the_flagged_dnn` (the real HTTP request
      against a stub UDM, returning the flagged DNN over `internet`). **Reads `smf-select-data`, not
      `sm-data` — see above.**
- [x] The `nudm-sdm` response arm in `gsm_sm.rs` is reachable, or is replaced by whatever path the
      request actually returns on — **replaced**: removed, with the real path (a direct `await` in
      `handle_sm_context_create`) named at the removal site.
- [x] `amfd` omits `dnn` when the UE omitted it, and a test asserts the member is absent rather than
      defaulted — `n11_omits_dnn_when_the_ue_did_not_supply_one`, which asserts absent (not `null`, not
      `"internet"`) and that the unconditional members are still present.
- [x] A test covers the no-subscription-data case: the session is refused, not a silent `internet` —
      `dnn_less_create_with_no_udm_is_refused_not_defaulted` drives `handle_sm_context_create` over a
      DNN-less body with no UDM reachable and asserts `400` + `SUBSCRIPTION_DATA_NOT_AVAILABLE`, and
      that the response body does **not** contain the string `internet`.
- [x] Workspace lint and the smfd + amfd suites pass.

## Verification

Workspace **5982 passed / 0 failed / 6 ignored** (baseline `5976` on `35475d5`; +6 tests — smfd 392 →
397, amfd 427 → 428). `cargo clippy -p nextgcore-smfd -p nextgcore-amfd --all-targets` adds no
warning, `cargo clippy --workspace` 0 errors, `cargo fmt --all -- --check` clean.

Six reverts:

| revert | expected to break | result |
|---|---|---|
| `amfd` substitutes `"internet"` again | `n11_omits_dnn_when_the_ue_did_not_supply_one` | **1 failed** (`got {"dnn":"internet",...}`) |
| `smfd` falls back to the `"internet"` literal instead of refusing | `dnn_less_create_with_no_udm_is_refused_not_defaulted` | **1 failed** |
| `select_default_dnn` ignores `defaultDnnIndicator` and takes the first entry | `select_default_dnn_uses_the_indicator_and_refuses_to_guess` | **1 failed** (`the flagged DNN wins over position`) |
| several unflagged DNNs silently pick the first instead of refusing | same test | **1 failed** (`expected AmbiguousDefault, got Ok("internet")`) |
| the fetch queries `am-data` instead of `smf-select-data` | `fetch_subscribed_default_dnn_queries_the_udm...` | **1 failed** |
| the validator requires `dnn` again | `validate_sm_context_create_data_table`, `dnn_less_create...` | **2 failed** |

No false guards found. Two other things the work surfaced, both recorded because they cost time:

* **The first end-to-end test failed on TLS**, not on logic: the default `SbiProfile` is `Production`,
  so a loopback plaintext stub needs `set_sbi_profile_override(SbiProfile::Dev)`. There is a
  purpose-built helper and an in-crate precedent (`policy.rs:1733`).
* **Calling `reset_sbi_profile_override()` at the end of the test broke a sibling test.** The override
  is process-wide, and resetting it flipped `policy.rs`'s `sm_policy_lifecycle_http_round_trip` back to
  Production mid-flight. Every loopback-plaintext test in this crate sets Dev and leaves it set;
  matching that is what keeps them compatible. Tidying up global state was the wrong instinct.

## Ceilings

* **Nothing in this tree emits `defaultDnnIndicator`**, so against its own UDM/UDR the selection rests
  on rule 2 (the single-subscribed-DNN case). A subscriber with two or more DNNs on one S-NSSAI
  **cannot establish a DNN-less PDU session** — it is refused with the candidates named. The subscription
  DB (`NextgcoreSession`) has no such field and `udrd`'s `build_smf_selection_data` writes only the DNN
  name. Filed as **#264** (`decision`, `needs-human`) with three costed options and a recommendation,
  because the fix spans the DB schema, udrd and the WebUI. **This is the most likely thing to be
  mistaken for done.**
* **The docker E2E is not run by CI** (it is `workflow_dispatch`-only), so the `UDM_SBI_ADDR` addition
  and the DNN-less end-to-end path are verified by unit/stub tests and by reading the compose file, not
  by an E2E run. If the simulator's UEs omit the DNN IE, this is the change most likely to show up
  there first.
* **`single-nssai` is not sent** (see Decision 3), so the SMF receives every subscribed S-NSSAI's DNN
  list and filters locally. Correct, but more data on the wire than necessary, until #65 lands.
* **NRF discovery here is minimal on purpose**: it reads one address out of the `SearchResult` and does
  not populate the shared NF cache, honour `validityPeriod`, or handle multiple UDM instances beyond
  taking the first. A UDM set with per-instance routing would need the fuller routine `amfd` has.
* **No test drives a real AMF→SMF DNN-less create end to end.** The AMF side (omission) and the SMF side
  (resolution, refusal) are each tested, but the join is not: smfd's create path needs a PCF and a UPF
  past the DNN step, which no in-crate harness stands up.
* GitNexus impact analysis unrunnable (no MCP server connected — 43rd consecutive PR). Blast radius by
  grep: `build_create_sm_context_request` has one production caller
  (`call_smf_create_sm_context`), which has one (`ngap_path.rs`); `validate_sm_context_create_data` has
  one caller; nothing outside `smfd` reads the new functions.
