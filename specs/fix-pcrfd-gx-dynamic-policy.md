# nextgcore #57: pcrfd reacts to what the PCEF reports, and Gx sessions survive a restart

Verified against `main` @ `96034a7`.

Closes #57. The `origin_state_id()` defect #57 asked to track separately is filed
as **#280**.

## The defect

Two independent halves.

**(1) Gx was write-once provisioning.** `parse_ccr` read Session-Id,
Auth-Application-Id, Origin-Host/Realm, Destination-Realm, CC-Request-Type/Number,
Subscription-Id, Called-Station-Id, Framed-IP{v4,v6} and Network-Request-Support —
and nothing else. Event-Trigger, RAT-Type, QoS-Information and
Charging-Rule-Report were never parsed anywhere in the crate. The
`UPDATE_REQUEST` branch checked only that the session existed and fell through to
re-provisioning, so `build_cca_success` re-emitted the same static
Default-EPS-Bearer-QoS, QoS-Information and armed Event-Triggers on every update
irrespective of the request. The PCRF armed QOS_CHANGE, RAT_CHANGE,
UE_IP_ADDRESS_ALLOCATE and UE_IP_ADDRESS_RELEASE and had no handler for any of
them, and `PcrfGxSession::rat_type` was hardcoded `0` with no writer.

**(2) No restart story.** All Gx/Rx state was in-memory with no persistence and no
rebuild, so after a pcrfd restart every CCR-U and CCR-T was answered
`DIAMETER_UNKNOWN_SESSION_ID` (5002) indefinitely.

Both premises re-verified against `main` before starting.

## Spec grounding, and one hypothesis that did not survive it

TS 29.212 §4.5.1: *"the PCEF shall supply within the PCC rule request the specific
event which caused the IP-CAN session modification (within the Event-Trigger AVP)
and any related data affected by the IP-CAN session modification. Any change in PCC
rule status shall be supplied to PCRF within the Charging-Rule-Report AVP."* The
PCRF's decision is meant to be a function of that.

Every AVP code was taken from the vendored `29212-j10.txt` §5.3 table rather than
from memory: Charging-Rule-Report 1018 (M,V, grouped), PCC-Rule-Status 1019 (M,V),
Rule-Failure-Code 1031 (M,V), RAT-Type 1032 (**V must, M may** — so the test builds
it V-only, which is what a conformant PCEF sends and which the parser must not
depend on).

**A hypothesis that failed the check, recorded because it shaped the design:** I
expected `Default-EPS-Bearer-QoS` to be EPS-only, which would have made a
RAT_CHANGE to GERAN observably drop it — a clean, spec-derived difference. The §5.3
table says its applicable access type is **All**. So the RAT dimension gives no
per-RAT payload rule here, and the observable difference comes from *whether* the
PCRF re-authorizes at all, not from a RAT-specific payload.

## The change

### What an update's answer carries

New `GxProvisionDecision { qos, install_rules, triggers }`, threaded into
`build_cca_success`. `GxProvisionDecision::for_update` derives it from the report:

| Reported | Answer |
|---|---|
| `RAT_CHANGE` | re-authorize (Default-EPS-Bearer-QoS + QoS-Information + re-arm) |
| `QOS_CHANGE`, reported QoS **diverges** from authorized | re-authorize with the **authorized** values |
| `QOS_CHANGE`, reported QoS **agrees** | nothing — the PCEF already holds the right policy |
| no recognized trigger | nothing |
| anything, on an update | never `Charging-Rule-Install` |

The authorized values are re-derived from the subscription on **every** request
rather than replayed from the initial answer, so an administrative change between
the initial CCR and an update is visible in the update's answer.

`ReportedQos::diverges_from` treats an **absent** member as "not stated" rather
than as a mismatch: otherwise every partial report would look like a violation and
trigger a pointless re-authorization.

### State the PCRF now keeps

`apply_update_triggers` records the RAT (whenever reported, not only under
RAT_CHANGE — a PCEF that reports the value without arming the trigger still told us
where the UE is), installs the mapping on `UE_IP_ADDRESS_ALLOCATE`, and clears it
on `UE_IP_ADDRESS_RELEASE`. The release takes the address from the **session**, not
from the CCR: a release report need not echo the address it is releasing, and
dropping only what the CCR happened to carry would leave the mapping behind — the
stale-mapping half of the trigger being inert.

`PcrfGxSession` gains `reported_rat` (so `0` = WLAN is distinguishable from "never
reported") and `installed_rules` (so a failure report has something to act on).

### Rule failure handling (§4.5.12)

`apply_rule_reports` withdraws an `INACTIVE` rule from the installed set and from
every bound Rx session; an Rx session left with **no** rule gets an ASR, reusing
the existing `RxAbortTarget` → `pcrf_rx_send_asr_for_target` plumbing.

Four choices, each with its reason in the code:

* **`INACTIVE` only.** §5.3.19 defines `TEMPORARILY INACTIVE` as temporarily
  disabled, e.g. loss of bearer, so the rule is expected back. Acting on it would
  tear down an AF session that is about to work again.
* **No `Charging-Rule-Remove` is sent back.** §4.5.12's own NOTE: *"When the PCRF
  receives PCC-Rule-Status set to INACTIVE, the PCRF does not need request the PCEF
  to remove the inactive PCC rule."*
* **The AF is told only when its service has nothing left enforcing it.** An Rx
  session still holding another rule is degraded, not dead. An Rx session with no
  remaining rule is precisely the harm #57 names: "the AF believes an unenforced
  service is active".
* **`Charging-Rule-Base-Name` is logged, not resolved.** It names a
  PCEF-preconfigured group, and this PCRF provisions no base names
  (`build_charging_rule_install_avp` emits Charging-Rule-Definition only), so it has
  no membership list. Guessing which local rules a base name covers could remove a
  rule the PCEF never reported.

Gated by `PCRF_ASR_ON_RULE_FAILURE`, a **runtime** switch (not a cargo feature, per
this project's recorded convention, so CI compiles both states), defaulting **on**:
off reproduces the defect.

### Restoration model, and why persistence over signalling

#57 offered either persistence or clean restart signalling. **Persistence**, using
the shared `nextgcore-core::state_store::StateStore` — because the signalling option
has no working foundation: `origin_state_id()` recomputes wall-clock on every call,
so it is not a per-instance restart indicator at all (now #280). Choosing signalling
would have meant fixing a diameter-layer defect #57 explicitly scoped out.

**Deviation from the suggested approach:** #57 suggested persisting to "the existing
MongoDB". This tree's established restoration model is `StateStore` (seven NFs use
it), and pcrfd never initialises a Mongo client at all — `build_subscriber_session_data`'s
DB lookup always fails and falls back to the default profile, which the docs already
record. Persisting to a client the binary does not create would not have worked.

**One thing pcrfd does differently from every other adopter, and it is load-bearing:
the index hashes ARE persisted.** `gx_session_remove` and `rx_session_remove` drop
only the hash entry and leave a **tombstone** in the vector, because a Gx session's
`rx_sessions` and an Rx session's `gx_session_idx` are positional indexes that
compacting would re-point. So the hash — not the vector — is the record of which
sessions are live, and it is *not derivable from the list*. Rebuilding it from every
vector entry would resurrect every session ever terminated and answer CCR-Us for
them. Only the live sid **set** is stored; the indexes are re-derived from position,
so a persisted index cannot disagree with the list it points into. The IP maps stay
derived, and only from live sessions.

For the same positional reason the vectors are deserialised **whole**, not
per-record: skipping one malformed record would shift every later index. An
unreadable table restores as empty (the pre-#57 behaviour) rather than as a silently
re-indexed one.

## Verification

Every guard revert-verified: fix broken, **named** test watched to fail, file
restored (`md5sum` checked against a pre-revert baseline). Three of these are worth
stating rather than filing under "green".

| Guard | Revert | Result |
|---|---|---|
| `a_rat_change_reauthorizes_and_a_triggerless_update_does_not` | `for_update` always re-authorizes (the pre-#57 replay) | FAILED ✓ |
| same | `for_update` never re-authorizes | FAILED ✓ |
| `a_qos_change_reauthorizes_only_when_the_report_diverges` | `diverges_from` always `false`; and always `true` | FAILED ✓ both ways |
| `test_handle_ccr_lifecycle_initial_update_termination` | `for_update` always re-authorizes | FAILED ✓ |
| `a_temporarily_inactive_report_withdraws_nothing` | `reports_removal` accepts any status | FAILED ✓ |
| `an_inactive_rule_report_withdraws_the_rule_and_aborts_the_af` | `reports_removal` always `false` | FAILED ✓ |
| `a_rule_report_leaving_another_rule_does_not_abort_the_af` | abort ignores surviving rules | FAILED ✓ |
| `rat_type_is_populated_from_the_ccr` | RAT not recorded | FAILED ✓ |
| `ue_ip_address_release_clears_the_mapping` | release branch inert | FAILED ✓ |
| `parse_ccr_reads_every_modification_input` | only the first Event-Trigger instance read | FAILED ✓ |
| `a_terminated_session_is_not_resurrected_by_a_restore` | tombstone filter removed; `gx_session_remove` persist removed | FAILED ✓ both |
| `an_aborted_rx_session_stays_gone_across_a_restart` | `rx_session_remove` persist removed | FAILED ✓ |
| `the_last_mutation_before_a_crash_is_durable` | `gx_session_update` persist removed | FAILED ✓ |
| `an_rx_binding_added_and_nothing_else_is_durable` | `rx_session_add` persist removed | FAILED ✓ |
| `a_newer_snapshot_is_refused_and_not_overwritten` | version comparison short-circuited | FAILED ✓ |

### The revert pass found a real defect in my own work

`a_pre_restart_session_still_resolves_after_a_simulated_restart` **passed with
`gx_session_update`'s persist removed**, because the snapshot is a full-store
document and the `rx_session_add` that followed captured the update's changes
anyway. So that test proved "something persisted", not "this mutator persisted".
Chasing it found that **`rx_session_add` had no persist at all** — an edit lost
between two scripted patches — which the same test also masked, for the same
reason. Both are now pinned by tests where the mutation in question is the *last*
thing before the restore, so nothing else can cover for it. Without the revert pass
this would have shipped as a silent durability hole behind a green test.

### An existing test was inverted, with the spec checked first

`test_handle_ccr_lifecycle_initial_update_termination` asserted that a CCR-U's CCA
**carries** Default-EPS-Bearer-QoS. Per this project's rule that the old test is
often right, I checked before touching it: TS 29.212 §4.5.5.9 says the PCRF *"**may**
provision the authorized QoS for the default EPS bearer"* — permissive, not
mandatory. The assertion was pinning this implementation's unconditional replay as
if the spec demanded it. Inverted, with the reason and the two replacement tests
named at the site.

Workspace: 6140 passed / 0 failed, `cargo clippy --workspace` and
`cargo fmt --all --check` clean.

## Ceilings

* **No wire interop.** All Gx behaviour is verified in-process against this tree's
  own Diameter codec, with a real encode/decode round trip on every message
  (`roundtrip()`), but no third-party PCEF. "Conformant" means "matches the vendored
  TS 29.212 text and AVP table".
* **The reacting policy is the default profile.** `build_subscriber_session_data`'s
  Mongo lookup always fails in this binary (documented, pre-existing), so
  "re-derived from the subscription" is exercised against the fallback profile.
  What the tests pin is the *decision logic* and that the CCA carries authorized
  rather than reported values — not a per-subscriber policy difference.
* **RAT_CHANGE re-authorizes but applies no RAT-specific policy.** Nothing in the
  subscription model is RAT-dependent, and inventing a per-RAT rule would be policy
  this project has not decided. The trigger is now honoured in the sense §4.5.1
  requires (the answer is a function of the report); a per-RAT authorization rule is
  a separate product decision.
* **No RAR is built for a rule change.** An update never re-installs rules; a
  genuine PCRF-initiated rule change goes out as a RAR, which this path does not
  build. Unchanged from before #57.
* **Durable state is not enabled in the shipped Docker EPC compose**, so the E2E
  path is unchanged and does not exercise it.
* **GitNexus impact analysis unrunnable** (53rd consecutive PR): the MCP server is
  not connected, so `CLAUDE.md`'s `gitnexus_impact` mandate could not be satisfied.
  Blast radius established by grep; the only signature change is
  `build_cca_success`, whose callers are `handle_ccr` and the tests.
