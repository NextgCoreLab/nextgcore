# nextgcore #103: make the LMF positioning core work in a deployment

Verified against `main` @ `bef8d58`.

#103's diagnosis is largely accurate, and **one of its seven criteria was already
met** — by work it does not mention. The rest were open, and the library codecs for
all of them already existed: the gap was wiring and a configuration surface, not
ASN.1.

## Verified against current main

| claim in the issue | site on `bef8d58` | still true? |
|---|---|---|
| cell coordinates are populated **only** via `set_cell_coord`, called exclusively from `#[cfg(test)]` code | `context.rs:924`; every caller in `main.rs` (4 of them) is inside `mod tests` at `:2833+` | **yes — this is the core defect** |
| no configuration or YAML surface loads coordinates | the only read of the config file was `oauth2_required` | yes |
| "depending on the code path it either falls back to a heuristic placeholder or returns no complete result" | **NO.** `measurement_report` (`context.rs:566-573`) returns `None` on an empty registry and the doc says so: "the old heuristic `compute_location_placeholder` lat/lon 0.0 fallback has been removed from the runtime path entirely (it now lives under `#[cfg(test)]`)" | **false — criterion 2's premise was fixed by lmfd-11/A7** |
| the NRPPa initiation builders exist only in the library and are referenced only by its own tests | `nrppa/pdu.rs:410`, `:560`; `rg` finds no other caller | yes |
| `namf_client` builds only an LPP N1 transfer; no NRPPa/N2 downlink builder | `build_n1n2_transfer_request` only | yes |
| the network-initiated leg always calls `build_lpp_ecid_request`, which hardcodes `nr_multi_rtt: None, nr_dl_tdoa: None` | `codec_glue.rs:58-59`, `main.rs:808` | yes |
| `positioning_qos_from_input` drives only the wait budget, never method selection | `main.rs:858-867`; the result went to `measurement_request`, not to the builder | yes |
| MO-LR `LOCATION_ASSISTANCE_DATA` logs and returns 204 with no LPP built | `main.rs:1126-1127` | yes |
| deferred area/motion LDRs are registered, answered 200, never armed | `main.rs:1170` comment: "SCOPED OUT — they need UE-side event detection" | yes |
| PERIODIC LDRs are genuinely implemented and out of scope | `spawn_periodic_ldr` | yes |

So criterion 2's stated failure mode — a fabricated coordinate — no longer existed.
What remained of it was that the refusal came *late* and said nothing useful, which
is what this PR changes.

## Decision 1: the coordinates come from the config file the daemon already reads

`lmf.positioning.cells` and `lmf.positioning.trps`, parsed out of the same YAML that
`oauth2_required` already probes. Not a new flag and not a second file: the file
exists, the reader exists, and a deployment that mounts `lmf.yaml` gains this with no
compose change.

Two lists rather than one because TS 38.455 §8.2.6 makes TRP information its own
exchange and an operator provisioning cells is not necessarily provisioning TRPs.
Both land in the one registry the solvers read, so the split is descriptive rather
than behavioural — and that is stated, because a reader could otherwise assume the
solvers treat them differently.

**A bad entry is rejected individually and named**, and the rest of the list still
loads. Rejecting the file would make one typo cost every cell; accepting a nonsense
coordinate would put a solver's output somewhere impossible and report it as a fix,
which is the class of defect #103 exists to remove. Each rejection names the list,
the index and the reason, so an operator can find the line.

## Decision 2: criterion 2 becomes "refuse early and name the fix"

The heuristic was already gone, so the remaining defect was *when* and *how* the
refusal happened: after AMF discovery, an LPP transfer and the whole wait budget, with
a problem detail saying "a measurement report was received but no location fix could
be solved" — true, and useless to the operator whose actual problem is unprovisioned
coordinates.

Now: an empty registry is refused at the top of `initiate_positioning`, before any
peer is contacted, with a detail naming `lmf.positioning.cells / .trps`. Plus one
startup warning per condition (nothing configured; fewer than three configured),
because a per-request error nobody reads is worse than a boot-time line.

## Decision 3: method selection is QoS × registry × capability, and the capability model is three-valued

Criterion 4 asks for selection from "LCS QoS + UE capabilities". The QoS part is
straightforward. The capability part is not, and the honest version is worth stating:

**the tree's `ProvideCapabilitiesR9` models exactly two members, `common` and
`ecid`.** So the wire cannot currently tell this LMF that a UE supports Multi-RTT or
DL-TDOA. A capability model with a bit per method would have two bits that can never
be set, which *reads as* "the UE does not support them" when the truth is "this build
cannot ask".

Hence `UeLppCapability` is three-valued: `Unknown` (no exchange, or an answer this
build cannot interpret), `EcidOnly` (the only value a decode can currently produce),
and `AdvancedMethods` (**not reachable from the wire here**, present so the selection
logic is written against the real question rather than around a missing one).

The rule, each branch pinned as the *sole* reason for its outcome:

| condition | method | why |
|---|---|---|
| < 3 reference points | E-CID | no QoS makes a multilateration solvable against two known positions |
| UE reported `EcidOnly` | E-CID | asking for a method the UE declined gets an empty report |
| `hAccuracy ≤ 10` or `EMERGENCY_SERVICES` | **Multi-RTT** | the RTT is two-sided and this LMF now solicits the gNB half over NRPPa |
| `LOW_DELAY` | E-CID | a statement about time; PRS scheduling is not fast |
| otherwise | E-CID | |

`Unknown` takes the high-accuracy branch rather than falling back, because answering a
≤10 m request with a Timing-Advance ring commits to an accuracy the method cannot
deliver — #103's own "any accuracy or QoS commitment is unmet". The absence of a
*retry* fallback when that request returns empty is a ceiling, not a hidden
assumption.

## Decision 4: the NRPPa downlink is a builder plus a body; the far end already existed

The AMF's `try_positioning_relay` already accepts an `n2InfoContainer.nrppaInfo` with
`ngapIeType: NRPPA_PDU` and a binary part, enqueues it, and the NGAP pump delivers it
over NGAP procedure 8 — echoing `nrppaInfo.nfId` into the RoutingID so the gNB's reply
routes back. So this side is small: `build_n2_nrppa_transfer_request` plus two calls
into library builders that had no caller.

Sent **before** the LPP transfer, because TS 23.273 §6.11.2 has the LMF initiate the
NG-RAN measurement and a report arriving before its request cannot be correlated.
**Best-effort and not fatal**: the NRPPa leg improves a fix; the LPP leg is what asks
for the measurements a fix needs at all, so a gNB declining NRPPa must not fail a
request the UE could still answer.

`ReportCharacteristics::OnDemand` rather than `Periodic`: a DetermineLocation is a
one-shot question, and this build has no
`E-CIDMeasurementTerminationCommand` builder to stop a periodic report.

## Decision 5: assistance data is a reference location, and only that

Criterion 5 asks for a non-empty `ProvideAssistanceData`. What this LMF actually
*knows* is where its reference points are, so the response carries
`gnssCommonAssistData.gnssReferenceLocation` at the centroid of the configured points,
with their spread as the uncertainty at 68% confidence.

That is genuine assistance — a coarse reference position is what narrows a UE's GNSS
search — and it is derivable with no external data source. Ephemerides, ionospheric
models and Earth-orientation parameters would all need a GNSS feed this build has no
client for; fabricating them would be worse than omitting them, and the doc says
which is which.

The response answers the UE's transaction with `initiator: TargetDevice` and
`end_transaction: true`. Using `LocationServer` would open a *second* transaction and
leave the UE's request unanswered.

## Decision 6: area/motion LDRs are refused with the spec's own cause

Criterion 6 offers "emit a real EventNotify on trigger **or** reject with a
spec-compliant error". Arming them needs UE-side event detection over LPP that does
not exist here, so: **501 `UNSUPPORTED_EVENT_TYPE`**, which TS 29.572 Table 6.1.7.3-1
defines as "the request for creation of a subscription is rejected because none of the
events is supported by the LMF". Not a 400 (the request is well-formed), not a 403
(nothing is forbidden) — the LMF has not implemented it.

A refused request leaves **no** LDR context behind, asserted, because a
half-accepted one would be cancellable and reportable.

`UE_AVAILABLE` still registers and is not reported, deliberately: its trigger source
is the AMF's reachability report, so the gap is an AMF subscription rather than a
missing UE capability, and refusing it would misattribute the gap. Named rather than
swept up.

## Two stale claims found in the existing code, and three flakes of my own

**`lmf_context_init` clears nothing.** `PROCESS_STATE_TEST_LOCK`'s own doc — written
by #308 — said it "clears the measurement, session and **cell-coordinate** registries
for the whole process". `LmfContext::init` early-returns when already initialized and
otherwise only records `max_measurements`; `fini` clears locations, measurements,
reports and LDR sessions and **not** the cell registry. So #308 recorded the wrong
mechanism for the lmfd flake it fixed. The doc is corrected and
`clear_cell_registry_for_test` added, because a test needing a known scene has to
remove whatever a sibling left.

**Three tests were silently coupled to that.**
`test_determine_location_unreachable_amf_504_unreachable_user`,
`test_determine_location_never_serves_another_ues_report` and
`test_determine_location_ageless_stored_fix_not_served` all reached AMF discovery only
because a *sibling* had seeded coordinates. Once this PR added a test that clears the
registry, they failed about 1 whole-workspace run in 8 — caught by a 25-run loop, not
by a single green run. All three now seed their own reference point.

**And the fourth exposed a real ordering bug in this PR.** The registry check was
placed at the top of `initiate_positioning`, *before* the target-identity check, so
`test_determine_location_no_target_identity_400` answered **500** instead of 400
whenever no sibling had seeded coordinates. A request carrying no target UE is a client
error whatever the deployment looks like; validating the REQUEST before the DEPLOYMENT
is the order a consumer can reason about. The check moved after the target resolution
and `a_request_with_no_target_is_400_even_with_an_empty_registry` pins the ordering so
it cannot regress silently.

**Then the class was closed rather than chased.** A fifth test surfaced on the next
loop, and patching them one at a time was clearly going to keep finding more: 35 tests
reach the determine-location path and 20 of them seeded nothing, so which ones mattered
depended on execution order. So `lmf_context_init` now clears the cell registry **in
test builds only** — which is what `PROCESS_STATE_TEST_LOCK`'s doc had claimed all
along. That makes the registry a function of each test's own seeding, so a test needing
coordinates fails *deterministically* without them. Running once after the change
produced exactly **two** failures, both fixed by seeding; production is untouched
because `lmf_context_init` runs once at startup, before
`site_config::load_into_context` fills the registry.

Three loops were needed to get here, and the sequence is the point: loop 1 found the
smfd lock gap and three coupled tests, loop 2 found the ordering bug loop 1 had masked,
loop 3 found the fifth coupled test — after which the class was closed structurally
instead of one test at a time.

**And a flake I introduced in #193, two PRs earlier.** The same loop caught
`smfd::restoration::two_references_on_one_seid_are_both_reconciled` failing about 1 run
in 12: those tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` **also** guards
(`teardown_association` → `clear_pfcp_sessions` wipes the map process-wide), and they
took only the ambient lock. All ten now take both, in the crate's documented order
(ambient first, N4 second). Fixed here rather than left on main for the next backlog
run to hit; it is out of #103's scope and is called out as such.

## Verification

| claim | how it was made to fail | result |
|---|---|---|
| config coordinates reach the solver | parse the config and load nothing | **fails** `coordinates_from_a_config_file_reach_the_solver` |
| nonsense coordinates are rejected | drop the ±90/±180 checks | **fails** `a_bad_entry_is_named_and_the_rest_still_load` |
| an empty registry is refused loudly | skip the check | **fails** `determine_location_with_no_reference_points_refuses_and_says_why` |
| the method follows QoS | return E-CID unconditionally | **fails** the selection test |
| the registry constrains the method | ignore the reference-point count | **fails** the selection test |
| the UE's reported capability is honoured | ignore it | **fails** the selection test |
| area/motion LDRs are refused | accept them again | **fails** `area_and_motion_ldrs_are_refused_with_unsupported_event_type` |
| the request is validated before the deployment | move the registry check above the target-identity check | **fails** `a_request_with_no_target_is_400_even_with_an_empty_registry` |
| test-build registry clearing makes coupling deterministic | it did: enabling it turned an order-dependent flake into 2 reproducible failures on the first run | the two are fixed by seeding |

Criterion 3's assertion decodes the emitted PDU and checks the **procedure code** (2
and 16), which is what the criterion asks for rather than "some bytes were produced",
and checks that the transaction id the caller was handed is the one on the wire.
Criterion 4's test additionally asserts the three methods encode to **different
bytes**, so a selection that changed only a log line would fail. Criterion 7's test
asserts the fix is near the configured cell **and** that it is not (0, 0), the
heuristic placeholder's signature.

One existing test's expectation was **inverted rather than deleted**:
`test_determine_location_assistance_data_204` asserted a bare 204 with no coordinates
configured, which is precisely the defect #103 names ("callers receive 2xx success for
MO-LR assistance-data requests that silently did nothing"). Pinning it would have
pinned the bug, so it is replaced by two tests covering both directions.

Gates: `cargo test -p nextgcore-lmfd` **185 passed / 0 failed** (was 173); workspace
**6433 passed / 0 failed** (was 6416); clippy `--workspace` and `--all-targets` 0
errors; fmt clean; **24 consecutive** whole-workspace runs after the class was closed structurally.

**The measurement that mattered was the loop, not the single run.** Every flake above
passed a first green `cargo test --workspace`. Four 20-to-25-run loops were needed, and
a single green run would have shipped five flakes.

## Ceilings

- **No fallback retry when an advanced method returns nothing.** A UE asked for
  Multi-RTT that cannot perform it answers with an error or an empty report, and the
  LMF reports no fix rather than retrying with E-CID. Building that needs a
  per-session method-attempt history and a second measurement campaign; requesting the
  advanced method for a high-accuracy QoS is still the right first move, because the
  alternative is committing to an accuracy E-CID cannot deliver.
- **`UeLppCapability::AdvancedMethods` is unreachable from the wire.** The LPP
  `ProvideCapabilities` codec models only `common` and `ecid`. Extending it is ASN.1
  work no criterion asks for, and until then the only real values are `Unknown` and
  `EcidOnly`.
- **Nothing records a UE's capability yet.** `note_ue_lpp_capability` and
  `classify_ue_capability` exist and are correct, and no uplink path calls them —
  a `ProvideCapabilities` arriving on N1 is not routed to them. So in practice every
  selection sees `Unknown`. The plumbing is one call site; it is not written because
  the LMF never sends a `RequestCapabilities`, so nothing would arrive to record.
- **The LMF sends no `RequestCapabilities`.** #103's suggested approach lists it; the
  selection is written to consume the answer, and the request is not sent. Adding it
  means a second LPP transaction per session before the measurement one, with its own
  wait budget, which changes the response-time arithmetic for every request.
- **The NRPPa reply is not consumed to fill the registry.** `handle_n2_info_notify`
  decodes an uplink NRPPa E-CID *measurement report*; a `TRPInformationResponse`
  carrying geographical coordinates is not parsed into `cell_registry`, so
  `build_trp_information` has a builder and no consumer for its answer. That is why
  the configuration surface is the criterion-1 answer rather than TRP discovery.
- **The NRPPa transaction id wraps at 256** (an `AtomicU8` behind a `u16` IE), and the
  `LMF-UE-MeasurementID` is fixed at 1 rather than allocated per session. Both are
  stated in their own docs with the reasoning.
- **`UE_AVAILABLE` LDRs still register and are never reported.** See Decision 6.
- **The PMIC-style assistance is a reference location only.** See Decision 5.
- **The E-CID solver still uses an unsigned UE Rx–Tx magnitude** (`nrrstd_to_ns`'s own
  note): a pre-existing simplification of the Multi-RTT RTT model, untouched here, and
  now reachable by more requests because Multi-RTT is actually selected.
- **`lmf_context_init` now clears the cell registry in TEST builds.** That is a
  deliberate asymmetry between test and production behaviour, which is normally worth
  avoiding — the justification is that the alternative is an order-dependent registry
  that produced five flakes, and that production's single `init` call happens before
  anything fills the registry so the clear is a no-op there. A test that wants to
  inherit a scene across `init` no longer can.
- **No E2E.** Every assertion is in-process. The Docker jobs remain
  `workflow_dispatch`-only, no compose service sets `LMF_NRPPA_DOWNLINK`, and the
  shipped `lmf.yaml` has `positioning` commented out — so the default E2E path is
  unchanged, which is also what makes the new gates safe.
