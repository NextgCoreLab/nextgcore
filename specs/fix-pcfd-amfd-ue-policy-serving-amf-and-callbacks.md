# nextgcore #92 (pcfd + amfd): UE-policy delivery targets the serving AMF, and the callbacks exist

Verified against `main` @ `3c5c7f5`.

TS 29.525 §4.2.2.2, §4.2.4; TS 29.518 §5.2.2.3.1; TS 23.502 §4.2.4.3; TS 29.500 §6.1;
TS 29.510 §6.2.3.2.3.1.

## The stated blocker is VOID

#92 carries a `needs-human` comment declining to start, on the grounds that it "must land together
with **#91**, which is labelled `architecture` — i.e. it needs a maintainer decision before
implementation — plus nextgsim#47 and nextgsim#48".

**#91 is CLOSED as COMPLETED.** Merged as PR #339, commit `ea1d082`, on `main` since 2026-09-11 —
before the comment that declares #92 blocked by it. So the one in-repo half of the declared unit has
landed, and the architecture decision the comment was waiting on has been made and shipped.

The nextgsim halves (#47, #48) remain outside this repository, and they bound **what can be observed
end to end**, not what can be implemented or tested here. #92's own comment says so: *"Criteria 1, 2,
3, 5 and 6 are self-contained in nextgcore and independently testable here … Criterion 4's pcfd half
is small given the AMF half exists. What genuinely needs the nextgsim ends is the URSP outcome."* The
URSP *outcome* is #91's subject matter, and #91 shipped without the nextgsim ends. All nine of #92's
criteria are delivery-leg and callback work, every one of which is assertable in-process here.

So the issue is implemented rather than re-deferred. What is NOT claimed is an end-to-end URSP effect
on a real UE — stated in Ceilings, as #92's comment asks.

## Verified against current main

Cites re-located; #92's were taken at `76ea248` and its own comment re-located them at `32a091a`. Both
have drifted again.

| criterion | site on `3c5c7f5` | status |
|---|---|---|
| 1. `UePolicyAssociation` persists serving-AMF `guami`; deliver/subscribe/unsubscribe select by it | `pcfd/sbi_path.rs:1539`, `:1570`, `:1617` all call `pcf_discover_endpoint("AMF", "namf-comm")` — type-only. `UePolicyAssociation` (`ue_policy.rs:268`) has no `guami`/`serving_nf_id`; the only mention is a doc line at `:281`. `pcf_deliver_ue_policy`'s own doc comment admits it: *"for multi-AMF, the PolicyAssociationRequest `guami`/`servingNfId` must be honoured … that is flagged, not solved here."* | **real** |
| 2. `handle_ue_policy_update` POSTs a `PolicyUpdate` to the stored `notificationUri`; terminate emits one too | `handle_ue_policy_update` (`pcfd/app.rs:1577`) is **no longer a stub** — #91 implemented it (applies `notificationUri`, `uePolReq`, `uePolDelResult`, `triggers`, re-delivers). But it still notifies **nobody**: `grep` finds no UE-policy notification sender in pcfd. The AM-policy leg has one (`sbi_path.rs:535`, TS 29.507) and is the model. | **real** (the issue's "acknowledges with 200 but never notifies" holds; its "parses only to validate" no longer does) |
| 3. AMF registers an absolute `notificationUri`; `namf_server` routes `.../ue-policy-notify` | still relative: `amfd/sbi_path.rs:1956` emits `"/namf-callback/v1/{supi}/ue-policy-notify"`. `namf_server.rs:139` matches `dereg-notify` **only**; anything else falls to the 404 arm at `:143`. | **real** |
| 4. `build_ue_policy_n1n2_request` includes `n1n2FailureTxfNotifURI`; a CM-IDLE delivery arms a connectivity retry | `build_ue_policy_n1n2_request` (`pcfd/sbi_path.rs:1506`) carries only `n1MessageContainer`. No `CON_STATE_CH` anywhere in `bins/`. **The AMF half is DONE** — `namf_server.rs:1411` and `:1550` read the member and POST the failure callback, with tests at `:3160`/`:3750`. So this is pcfd-side only, exactly as #92's comment corrects. | **real, smaller than written** |
| 5. Callback URI scheme derived from config | `ue_policy_notify_callback_uri` (`pcfd/app.rs:1427`) still hardcodes `http://`. | **real** |
| 6. `context_ursp_for` read in production or removed | `ue_policy.rs:236`; readers are still only `:1914` and `:1920`, both tests. | **real** |
| 7. two-AMF fixture test | none exists | **real** |
| 8. update-notification test | none exists | **real** |
| 9. CM-IDLE failure-URI + retry test | none exists | **real** |

No criterion is void or already-met. One (4) is **smaller than the issue states**, because the AMF-side
async failure notification it asks for already exists — which #92's own comment establishes and this
re-verification confirms.

## Decision 1: GUAMI targeting is query param AND client-side verification, not one or the other

TS 29.510 §6.2.3.2.3.1 defines `guami` as an `Nnrf_NFDiscovery` query parameter, so the conformant move
is to send it. But **this tree's own NRF does not implement it**: `DiscoveryQuery`
(`nrfd/nnrf_handler.rs:1758`) parses `target-nf-type`, `service-names`, `snssais`, `dnn`,
`target-plmn-list`, `target-nf-instance-id`, `target-nf-fqdn`, `limit`, `supi`, `gpsi`,
`routing-indicator`, `group-id-list` — and no `guami`. (The `guamiList` handling at
`nrfd/sbi_path.rs:780` is *subscription-condition* matching for NFStatusNotify, a different feature.)

Sending the parameter alone would therefore change nothing against this deployment: an NRF that ignores
an unknown query parameter answers with every AMF, and pcfd would pick the first one again — the
"correct but ineffective" shape this backlog keeps finding.

So both halves land:

1. **The `guami` query parameter is sent**, so a conformant third-party NRF filters server-side and the
   PCF does not download every AMF profile to discard most of them.
2. **pcfd verifies the answer client-side** against each candidate's `amfInfo.guamiList`, and selects
   the instance that actually serves the UE. This is what makes the fix work against *this* NRF, and
   against any NRF that treats the parameter as advisory.

Client-side verification is not redundant belt-and-braces: TS 29.510 lets the NRF return instances it
could not fully constrain, and "the NRF said so" is not something a PCF can check. Reading
`amfInfo.guamiList` is.

**Correction to this spec, found during implementation:** the paragraph above originally asserted that
"this tree's AMFs do register `amfInfo.guamiList`". **They did not.** amfd's NRF registration carried no
`amfInfo` at all, so the client-side verification this decision makes load-bearing had nothing to match
against — criterion 1 would have been inert in this deployment, which is exactly the "correct but
ineffective" shape the decision above warns about. So a third change lands: amfd now publishes
`amfInfo.guamiList` (TS 29.510 §6.1.6.2.4) from its configured GUAMIs, and logs a warning when it has
none to publish, because a PCF that cannot see an AMF's GUAMIs cannot target it. This is the kind of
unstated precondition the verification pass is supposed to catch and this one missed until the code was
written.

**Fallback is explicit and logged**, not silent: with no GUAMI stored (an association created before
this change, or an AMF that sent none) or no candidate matching, the first `namf-comm` endpoint is used
and the log says which case it was. That preserves the single-AMF matched-sim behaviour #92 asks be
preserved, and makes the difference between "targeted" and "guessed" visible in an operator's log
rather than inferable only from source.

## Decision 2: the UE-policy notification is modelled on the AM-policy one, not invented

pcfd already has a policy-update notification sender for the AM-policy association
(`pcf_send_am_policy_update_notify`, TS 29.507 §4.2.4.2: `POST {notificationUri}/update` with a
`PolicyUpdate`). TS 29.525 §4.2.4 has the same shape for UE policy. So the new sender follows it
exactly — same path convention, same body kind — rather than inventing a second convention for the
same idea in the same daemon.

**Terminate is a `DELETE`-flavoured notification to `{notificationUri}/terminate`**, per §4.2.4's
modelling of termination as the PCF requesting the consumer release the association. The alternative —
the PCF simply deleting its own state — is what happens today and is why an AMF can hold an association
the PCF has forgotten.

## Decision 3: the AMF's callback URI is absolute and scheme-derived, from the same source as its other callbacks

`amfd/sbi_path.rs` already builds an absolute, scheme-correct `deregCallbackUri` for the Nudm_UECM
leg — #92's References name it as the model. The UE-policy `notificationUri` now uses the same
self-URI helper, so the two cannot drift, and the scheme follows the configured SBI transport security
rather than a literal `http://`. Same change on the pcfd side for `ue_policy_notify_callback_uri`
(criterion 5).

## Decision 4: `context_ursp_for` is WIRED, not deleted

Criterion 6 offers either. Wiring it is the better answer: the function returns the URSP rules a SUPI's
association holds, and the E6 delivery-result path has a real use for it — when a MANAGE UE POLICY
COMPLETE arrives, the rules that were delivered are what the installed UPSC now denotes. Deleting it
would also delete the documented intent, leaving a future reader to re-derive it.

## Decision 5a: the retry is woken by a connectivity-state subscription, not by the failure callback

`n1n2FailureTxfNotifURI` cannot by itself trigger a retry, and the first draft of this spec implied it
could. The AMF invokes that URI when a transfer **fails**; nothing invokes it when the UE later becomes
reachable, which is the event a retry needs. So the delivery is *parked* on the CM-IDLE failure and the
wake-up comes from an `Namf_EventExposure` `CONNECTIVITY_STATE_REPORT` subscription (amfd already
supports the event), whose notification re-drives the parked delivery.

The failure callback is still supplied and served — it is what makes a transfer the AMF accepted and then
could not complete visible at all — but it deliberately does **not** retry: the synchronous 504 already
parked the delivery, and retrying on the failure notification would re-attempt against a UE still known
to be unreachable.

The parked PDU lives in its own store rather than on `UePolicyAssociation`, so a several-hundred-byte
UPDP command is not cloned on every `ue_policy_find`.

## Decision 5: no cargo feature; the retry needs no switch of its own

#92 suggests gating the reachability-retry behind an off-by-default feature. Declined, for this
project's recorded reason (a cargo-gated path is outside `cargo test --workspace` and rots). No runtime
switch is needed either: the whole UE-policy delivery path is **already** behind the
`ue_policy::delivery_enabled()` kill-switch, and the retry is reachable only through a delivery that
switch permits. Supplying `n1n2FailureTxfNotifURI` changes nothing unless the AMF invokes it, which it
does only on a delivery that actually failed.

## Acceptance criteria

All nine **real**; see the table above. Delivered as:

- [x] 1 — `UePolicyAssociation.guami`/`serving_nf_id`, populated from the create body; all three AMF
      legs select by it, with a logged fallback.
- [x] 2 — `pcf_send_ue_policy_update_notify`, called from `handle_ue_policy_update`; terminate notifies
      on association delete.
- [x] 3 — absolute scheme-derived `notificationUri` in amfd, and a `ue-policy-notify` route beside
      `dereg-notify` answering 204.
- [x] 4 — `n1n2FailureTxfNotifURI` in the N1N2 body, and a connectivity-state subscription armed on a
      CM-IDLE failure so delivery is retried on return to CM-CONNECTED.
- [x] 5 — both callback URIs scheme-derived from config.
- [x] 6 — `context_ursp_for` read on the production E6 path.
- [x] 7, 8, 9 — the three tests, each driving the real handler/router.

## Verification

`cargo test --workspace`: **6663 passed / 0 failed** (baseline 6654 on `3c5c7f5`; pcfd 226 → 235,
amfd 495 → 496, plus three new integration test binaries). `cargo clippy --workspace` and
`--all-targets` introduce **no new warning** in either crate (baseline 3+3 `await_holding_lock` in test
code, unchanged). `cargo clippy -p nextgcore-easdfd --features dns-udp --all-targets` clean;
`cargo fmt --all -- --check` clean; `cargo test -p nextgcore-easdfd --features dns-udp` green.

| revert | expected to break | result |
|---|---|---|
| the delivery leg goes back to `pcf_discover_endpoint("AMF", "namf-comm")` | `delivery_targets_the_amf_matching_the_stored_guami` | **1 failed** (the serving AMF recorded 0 transfers) |
| the **subscribe** leg alone goes back to it | `subscribe_targets_the_same_serving_amf_as_delivery` | **1 failed**, and the delivery test **still passed** — the two legs are independently guarded |
| `pcf_send_ue_policy_update_notify` becomes a no-op returning `true` | `update_posts_a_policy_update_to_the_recorded_notification_uri` | **1 failed on the WIRE assertion**, not on the handler's own `notified: true` self-report |

Three reverts run, three bites, including the one that matters most: the subscribe revert failed only
the subscribe test, so a fix to one call site does not read as a fix to both — which is what #92's own
comment asks be distinguished.

**The remaining five reverts were not run**: the tooling that runs them became unavailable mid-sweep.
Stated rather than implied, because an unverified guard is exactly what this table exists to disclose.
The five are: terminate-notify, the amfd `ue-policy-notify` route, `n1n2FailureTxfNotifURI` presence,
the CM-CONNECTED retry, and `amfInfo.guamiList`. Each is asserted positively on a recorded request body
or a routed status code, and each has a control (see below), but "asserted" is a weaker claim than
"made to fail".

### An independent review found a behaviour with NO test, and it was the load-bearing one

`amfInfo.guamiList` — the thing pcfd's client-side GUAMI verification matches **against** — had no test
anywhere in the repo. `served_guami_list_json` was called only from production startup; `nextgcore-amfd`
has no `tests/` directory; and the `amfInfo` in the two new pcfd integration tests is **stub-NRF fixture
data those tests write themselves**, not amfd output.

So both sides of the GUAMI comparison were hand-shaken through fixtures that assume the format. The
consequence is precise and severe: had amfd's `amfId` packing or its MNC filler-nibble handling
disagreed with what amfd puts in the `PolicyAssociationRequest`, **every test on this branch would still
be green** while `AmfSelection::GuamiUnmatched` fell back to the first endpoint on every delivery — #92's
defect, restored, invisibly.

Closed two ways, structurally and by assertion:

- The two renderings now go through **one** `guami_json` / `amf_id_hex`. `ngap_path` had **two** inline
  copies of the `{:06x}` Region/Set/Pointer packing; both now call the shared packer, so a divergence is
  no longer expressible.
- `the_registered_guami_list_and_the_policy_request_guami_render_identically` pins the rendering (MCC
  `001`, MNC `01` with the 0xF filler dropped, `amfId` `020040`) and asserts the profile's `amfId` and
  the request's `amfId` are the same string, with a 3-digit-MNC case so the filler rule is about the
  filler and not about truncation.

### Review findings on the rest

- **No unpaired negative assertions.** Each of the three checked (`wrong.transfers() == 0`,
  `wrong.subscribes() + wrong.transfers() == 0`, `guami` absent from the fallback query) has a
  positive control on the same fixture. `DeliveryState::Pending` is paired with
  `a_non_reachability_failure_is_still_terminal`, which proves `Failed` is reachable on the same path.
- **One near-miss, caught and fixed during implementation**: the stub NRF read query strings from
  `header.uri`, which holds the path only, so it recorded `[""]` and the fallback test's "no `guami`
  parameter" assertion passed **vacuously**. It now reads decoded `http.params`. Recorded because it is
  the same class of defect as the one above — a harness that lies in the shape of a passing test.
- **No new `unwrap`/`expect` on a production path.**
- **One accepted duplication**: `pcf_discover_amf_endpoint` repeats ~30 lines of transport (NRF-URI
  fetch, client, status check, body parse) from `pcf_discover_endpoint`. Keeping the two *functions*
  separate is justified (five UDR/BSF/NWDAF call sites would otherwise carry an always-`None`
  argument), but the duplicated transport half is not; extracting a shared `discover_raw` is the right
  follow-up and is named here rather than left for a reader to notice.
- **A pre-existing flake, not from this change**: `ue_policy_create_get_update_delete_lifecycle` failed
  once then passed twice. `delivery_kill_switch` (`ue_policy.rs`) and a test at `app.rs` set the
  process-global `PCF_UE_POLICY_DELIVERY` env var **without** taking `CONTEXT_GUARD`. Both predate this
  change; `git diff` confirms neither was touched. Worth its own fix.

## Ceilings

- **No end-to-end URSP effect is claimed.** nextgsim#47 (the UE does not evaluate delivered rules) and
  nextgsim#48 (no UE STATE INDICATION encoder) are in another repository and unchanged. Every assertion
  here stops at this repo's boundary: the AMF a request was sent to, the body it carried, the route
  that answered it. That is the seam #92's own comment identifies, and it is stated rather than papered
  over.
- **The NRF does not filter by `guami`.** The parameter is sent for conformance; the selection that
  actually works is client-side. Teaching `nrfd` the parameter is its own change with its own tests.
- **Paging a CM-IDLE UE is not implemented.** #92 asks for "paging (or an async failure notification)";
  the AMF already does the second, and this adds the PCF-side retry. Actual paging is an NGAP procedure
  with its own state machine.
- **No E2E.** The Docker jobs are `workflow_dispatch`-only.
