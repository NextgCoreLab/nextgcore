# nextgcore #78: the SM context lifecycle

Verified against `main` @ `23b7063`.

Closes #78 — all eight acceptance criteria.

## The defect

Four gaps, each re-verified against `main` before starting (this issue was filed at
`76ea248` and parts of `smfd` have moved since, so every cite was re-located):

1. **Retrieve always 404'd.** `sess_add_by_psi` / `sess_add_by_apn` still had **no
   caller in `main.rs`** — grep confirmed — so the create handler minted an
   `smContextRef` from `next_sess_index()` and registered nothing.
   `sess_find_by_sm_context_ref` therefore never matched, and every Retrieve answered
   `404 CONTEXT_NOT_FOUND` for a session that had just been created successfully. The
   body also omitted `ueEpsPdnConnection`, a **required** member of
   `SmContextRetrievedData`.
2. **Update and Release succeeded on unknown refs.** Neither checked that the
   reference resolved; `handle_sm_context_release` took no body argument at all, so
   `SmContextReleaseData` was unreadable.
3. **No N2 handover support.** `grep hoState` returned nothing in the whole crate, and
   `HANDOVER_REQUIRED` / `_REQ_ACK` / `_COMPLETE` / `_CANCEL` fell to the catch-all
   and were answered `400 N2_SM_ERROR` — so any inter-gNB N2 handover was refused at
   the SMF and the UE lost its PDU session on mobility.
4. **The Downlink Data Report only logged.** `n4_handler`'s
   `trigger_service_request` flag was reachable only from its own unit test, and the
   live handler in `main.rs` logged "triggering UP connection re-activation" and
   returned. One thing the issue got out of date on: `send_n1_n2_message_transfer`
   **does** now exist (added for the 5GSM timer path), so the gap was the trigger and
   the N2-shaped body, not the sender.

## The change

### Create registers, and the reference has one source

`register_sm_context(context, supi, psi) -> Option<(String, u64)>`: finds-or-adds the
UE, registers the session, and returns the reference **read back out of the session**.

That last part is load-bearing. `sess_add_by_psi` mints `sm_context_ref` from the
context's `sess_index`, and the handler computed its reference from
`next_sess_index()` — the **same counter**. Doing both consumes it twice and leaves
the handler's reference one behind the session's, so the value handed to the AMF
resolves to nothing, or worse to the next session. One source, by construction.

It is extracted rather than inline **so the invariant is testable**: the create
handler's success path needs a PFCP-responding UPF no harness here has, so no test can
observe the reference the handler returns — but it can observe this function's.

**A create that fails after registration rolls it back.** The existing `release_ip`
closure became `rollback`, which also un-registers, and the one failure path that runs
before the closure exists un-registers explicitly. An abandoned registration is an SM
context the AMF never learned about and will never release.

The session's fields are filled in **after** the PFCP establishment settles, because
`upCnxState` is only `ACTIVATED` once the user plane exists; an earlier update would
advertise an activated connection for a session with no N4 leg.

### `ueEpsPdnConnection`

The minimal PDN-connection descriptor derivable from the 5GS session: APN
(length-prefixed as TS 24.301 §9.9.4.1), PDN type, UE address, default-bearer QCI,
base64-encoded as the yaml's `Bytes`.

**Deliberately not a mapped EPS bearer-context list.** This tree has no EBI
assignment and no Mapped EPS bearer context IE at all — that is #117, not this issue.
A fabricated bearer list would be *worse* than a minimal descriptor: the AMF would
forward it to an MME that would then try to use bearers this SMF never established.

### Unknown references, and the ProblemDetails body

`sm_context_exists` checks the session list **or** the binding map. Requiring both
would make a reference the SMF can plainly act on look unknown if one half was lost,
which is a worse answer than acting on the half that survived.

The Update check is placed before any branch, so no arm can skip it. The Release check
runs only for an AMF-driven release: the PCF-driven path passes a reference it read
out of the binding map itself, so re-checking would be checking our own read.

`problem_response` was extracted from `problem_400`, and the SM context 404s now use
it — the old body was a bare `{"status","cause"}` at `application/json`, which gives a
consumer deserialising ProblemDetails nothing typed to work with.

### N2 handover (TS 29.502 §5.2.2.3.4)

`hoState` is read, and the four N2 SM info types are handled.

**PREPARING and PREPARED deliberately do not touch the user plane.** Until the UE has
actually moved, the source gNB is still serving it, and re-pointing the UPF then would
black-hole downlink traffic for the whole handover-execution window.
`HANDOVER_COMPLETE` switches the DL tunnel — through the same `pfcp_session_modify`
call the `PATH_SWITCH_REQ` arm uses, so a handover completion and a path switch cannot
drift apart — and **logs a warning when the request carried no decodable target
F-TEID**, because a bare 200 would leave an operator unable to tell a switched tunnel
from an unswitched one. `HANDOVER_CANCEL` has nothing to undo, which is precisely why
the earlier states do nothing.

### DLDR → paging (TS 29.244 §7.5.8.2 → TS 23.502 §4.2.3.3)

The live DLDR branch now calls `trigger_network_initiated_service_request`, which
resolves the reported SEID back to its SM context and asks the serving AMF to page.

**The N2 form, not the N1 form.** §4.2.3.3 step 3a has the SMF send *N2 SM
information* so the AMF can re-establish the user plane; there is no NAS message to
deliver to a sleeping UE. So this does not reuse `send_n1_n2_message_transfer`, whose
body is an `n1MessageContainer`; it posts an `n2InfoContainer` carrying the QFI the
UPF reported, so the gNB knows which flow to restore.

A DLDR for a session whose UP connection is **not** `DEACTIVATED` does not page:
§7.5.8.2 scopes the report to a deactivated connection, and paging a connected UE is a
spurious service request.

## Verification

**19 guards revert-verified** — fix broken, **named** test watched to fail, file
restored. The revert pass found three holes in my own work, which is the whole reason
it exists:

| Guard | Revert | Result |
|---|---|---|
| `register_sm_context_returns_the_reference_that_resolves_to_it` | ref computed separately from the same counter; registration returns an unregistered ref | FAILED ✓ both |
| `retrieve_answers_200_with_ue_eps_pdn_connection` | `ueEpsPdnConnection` removed | FAILED ✓ |
| `retrieve_of_an_unknown_ref_is_404_problem_details` | 404 body back to bare status/cause at `application/json` | FAILED ✓ |
| `update_rejects_an_unknown_ref_and_still_serves_a_known_one` | check disabled; check inverted to 404 everything | FAILED ✓ both |
| `release_rejects_an_unknown_ref_and_parses_release_data` | check condition inverted | FAILED ✓ |
| `sm_context_release_data_parses_its_members_and_an_empty_body` | `cause` not parsed; `vsmfReleaseOnly` not parsed | FAILED ✓ both |
| `n2_handover_states_are_processed_not_refused` | handover arms removed (back to the 400 catch-all) | FAILED ✓ |
| `a_failed_create_leaves_no_registered_sm_context` | rollback does not un-register | FAILED ✓ |
| `a_downlink_data_report_pages_the_ue_via_the_amf` | DLDR does not call the trigger; paging uses `n1MessageContainer`; QFI not forwarded | FAILED ✓ all three |
| `a_downlink_data_report_for_an_active_connection_does_not_page` | deactivated check removed | FAILED ✓ |

### Three holes the revert pass found

1. **No test guarded the create handler at all.**
   `retrieve_answers_200_with_ue_eps_pdn_connection` passed with the create's
   registration deleted, because it seeds a session directly — it guards Retrieve, not
   create. Fixed by extracting `register_sm_context` and testing its invariant, plus
   `a_failed_create_leaves_no_registered_sm_context` driving the real handler.
2. **My registration leaked a session on every failure path.** Discovered while
   working out what the create test could assert: five post-registration failure paths
   returned without un-registering. That is the rollback change, and it now has a
   test that fails without it.
3. **The paging test called the helper, not the wiring.** It invoked
   `trigger_network_initiated_service_request` directly, so it passed with the call
   **removed from the DLDR handler** — exactly the "assert the outbound call, not
   merely the log line / `trigger_service_request` flag" the issue's criterion 6
   warns about, and the fourth time this session that "the helper is tested and the
   wiring is not" has bitten. Rewritten to build a wire-format PFCP Session Report
   Request and drive `handle_pfcp_session_report`.

### A test failed for a reason unrelated to its claim, twice

- The paging test first failed because `sbi_peer_client_config` resolves
  `SbiProfile::Production` by default, which refuses a loopback plaintext peer. Fixed
  with the explicit `set_sbi_profile_override(Dev)` this repo's sibling tests use, and
  the comment says why rather than leaving it looking like boilerplate.
- The create test first asserted an absolute session count, which the
  process-global context makes a race against sibling tests rather than an assertion.
  Rewritten to assert per-SUPI.

Workspace: **6184 passed / 0 failed**, `cargo clippy --workspace` and
`cargo fmt --all --check` clean.

## Ceilings

* **The create handler's success path is unreachable in this harness.** It needs a
  PFCP-responding UPF, and no test in this tree establishes an N4 session. So the
  create is covered by the registration function's invariant plus the rollback
  contract, and the lifecycle test seeds a registered session rather than creating
  one. Both facts are stated in the test doc comments, and both tests say what to
  rewrite if the harness ever gains a UPF.
* **`ueEpsPdnConnection` is a descriptor, not a bearer list** (see above). #117 owns
  the EPS bearer contexts.
* **`vsmfReleaseOnly` is parsed and logged, not honoured.** This SMF has no
  V-SMF/H-SMF split on the `sm-contexts` path (`is_home_routed_roaming_in_vsmf` keys
  on `pdu_session_ref`, which that path never sets), so acting on the flag would mean
  pretending to a split that does not exist.
* **The handover states are acknowledged, not fully actuated.** `HANDOVER_REQUIRED`
  returns no target-side N2 SM container, because building one is amfd/NGAP work
  (#70). The session is held through the procedure rather than the handover being
  refused, which is the defect #78 names; a complete N2 handover needs the AMF side.
* **No wire interop.** The paging assertion is against a fake AMF spawned by this
  crate's own SBI server, and the DLDR is a locally built wire message decoded by this
  tree's own parser.
* **GitNexus impact analysis unrunnable** (55th consecutive PR): the MCP server is not
  connected. Blast radius by grep — `handle_sm_context_release` gained a parameter
  (callers: the router, the PCF-terminate path, two tests) and `problem_400` now
  delegates to `problem_response`.
