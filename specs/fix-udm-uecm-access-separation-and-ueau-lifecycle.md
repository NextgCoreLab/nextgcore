# nextgcore #84 (UDM): UECM access separation, the missing reads, spec deregistration, and the UEAU auth-event lifecycle

Verified against `main` @ `c414dac`. Every defect the issue describes was still present as written;
the line cites had drifted by a few lines but named the right code.

`Closes #84`.

## Gap 1: `amf-non-3gpp-access` was not a resource, it was an alias (criteria 1, 2)

The load-bearing defect, and the one with a real deployment consequence. `handle_amf_non3gpp_registration`
parsed the body and then called `process_amf_registration`, which called `amf_context_put`, which
formatted `.../context-data/amf-3gpp-access`. So a non-3GPP registration:

* read the UE's **3GPP** registration as its "prior",
* wrote itself over the **3GPP** UDR record,
* emitted a `DeregistrationData` with `accessType: 3GPP_ACCESS` to the 3GPP AMF's callback,
* answered `200` (update) instead of `201` (create), and
* returned a `Location` naming `amf-3gpp-access`.

For a UE registered over both accesses — a routine N3IWF/TNGF case — the non-3GPP registration therefore
tore the live 3GPP registration down, and amfd's real dereg-notify consumer *keys on* `accessType`
(`test_dereg_notify_strict_peer_non_3gpp_no_enqueue` exists precisely because it discriminates), so the
3GPP AMF obediently started a network-initiated deregistration for a UE that had not gone anywhere.

### The fix is a type, not a branch

`UecmAccess` (`uecm.rs`) carries the access through every step that names a resource: the UDR
`context-data` path, the local cache slot, the `Location` header, the validation schema and the
`DeregistrationData.accessType`. `process_amf_registration` takes it as a **required parameter** rather
than defaulting, because the defect was exactly a caller forgetting which access it was serving. The
router (`route_uecm_registrations`) is now the only place that maps a path segment to an access.

`UdrClient` lost its per-resource accessors (`amf_context_get/put/patch`, `smf_context_get/put`) in
favour of `context_get/put/patch/delete(supi, resource, ...)`. That is the same "there is nowhere left
to hardcode it" argument: the bug lived inside a helper whose name did not mention the resource it
hardcoded.

### Decisions worth review

* **The local cache gained a second slot per access** (`non_3gpp_amf_instance_id`,
  `non_3gpp_dereg_callback_uri` on `UdmUe`) rather than being keyed by a composite. A UE registered over
  both accesses has *two* serving AMFs; answering the non-3GPP "who was the old AMF?" question with the
  3GPP AMF is how a spurious deregistration gets sent.
* **Deregistering one access does not drop the UE context.** The old code removed the whole `UdmUe` on
  any deregistration. It is now removed only once neither access holds a registration, or the surviving
  access loses the cached serving AMF that its next re-registration needs to notify.
* **The non-3GPP schema is validated as itself.** `AmfNon3GppAccessRegistration` additionally requires
  `imsVoPs`, so a body that is a valid 3GPP registration is now refused for non-3GPP access with
  `400 MANDATORY_IE_MISSING`. This is stricter than before on a route that previously accepted anything
  the 3GPP validator accepted. It is what the schema says, and nothing in this repo sends a non-3GPP
  registration — amfd only ever registers on `amf-3gpp-access` — so the strictness costs no existing
  caller. Flagged because it is the one place a conformant-but-sloppy peer would newly get a 400.

## Gap 2: the mandatory UECM reads returned 405 (criterion 3)

There was no `GET` arm for any UECM resource. Added, all as read-through to the UDR `context-data`
resource, plus the two operations the UDM has to compose itself:

| Operation | Route | Answer |
|---|---|---|
| `Get3GppRegistration` | `GET .../registrations/amf-3gpp-access` | stored `Amf3GppAccessRegistration` |
| `GetNon3GppRegistration` | `GET .../registrations/amf-non-3gpp-access` | stored `AmfNon3GppAccessRegistration` |
| `GetSmfRegistration` | `GET .../registrations/smf-registrations` | `SmfRegistrationInfo` |
| individual SMF | `GET .../registrations/smf-registrations/{psi}` | stored `SmfRegistration` |
| `GetLocationInfo` | `GET .../registrations/location` | composed `LocationInfo` |
| SMSF (both accesses) | `PUT`/`GET`/`DELETE .../registrations/smsf-{3gpp,non-3gpp}-access` | `SmsfRegistration` |
| IP-SM-GW | `PUT`/`GET`/`DELETE .../registrations/ip-sm-gw` | `IpSmGwRegistration` |

Three shape decisions:

* **`GetSmfRegistration` wraps, it does not forward.** The UDR collection resource answers with a bare
  JSON array (TS 29.505); the UECM operation is defined to return `SmfRegistrationInfo` with its
  `smfRegistrationList` member. The wrap happens in the UDM rather than hoping the consumer is lenient.
  An **empty** list is a `404`, because `smfRegistrationList` has `minItems: 1` — "registered for
  nothing" is not a representable answer.
* **`LocationInfo` is composed from the AMF registrations, not read from a resource.** That is what the
  IE holds: a list of `RegistrationLocationInfo`, each naming a serving AMF and the access types it
  serves. One AMF serving both accesses yields **one** entry with two `accessTypeList` members, not two
  entries — which is also what keeps the list inside its `maxItems: 2` bound.
* **A UDR fault is `503`, never `404`.** `read_context_resource` distinguishes "UDR says 404" from "UDR
  could not answer", because a `(H)GMLC` told `404` stops looking for the UE. `a_udr_fault_on_a_uecm_get_is_503_not_404`
  pins all seven read paths.

`LocationInfo.gpsi` is left absent rather than derived from the SUPI: they are different subscriber
identities. The `cached_gpsi` hook returns `None` today and is documented as waiting on the UDM's
identifier translation (#85).

### Known limitation, and it is not this PR's to fix

These resources are written to and read from UDR `context-data/{resource}`, which is correct
(TS 29.505 §5.2.2). **udrd only implements `amf-3gpp-access` and `smf-registrations`** — every other
`context-data` resource answers `404 Unknown context resource`
(`bins/nextgcore-udrd/src/main.rs:853-863`). So against nextgcore's own UDR, the non-3GPP, SMSF and
IP-SM-GW registrations are accepted (the write degrades, per the existing `udr_write_outcome` policy)
and then read back as `404`. That is **#87**, which names `amf-non-3gpp-a...` in its own title. The
tests here use a mock UDR that implements the resources generically, so they prove the UDM's half and
say nothing about the UDR's. Stated plainly because this is the same shape as #226: a producer that
reports state a consumer cannot yet read.

## Gap 3: deregistration used a verb the spec does not define (criterion 4)

`DELETE /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access` was routed. TS 29.503 defines `PUT`, `GET`
and `PATCH` on that resource and puts deregistration on a custom operation:
`POST .../amf-3gpp-access/dereg-amf` with an `AmfDeregInfo`. The `DELETE` arm is gone (it now `405`s,
which is what the method set says) and `dereg-amf` is routed.

`AmfDeregInfo.deregReason` is **validated, not ignored**: it is the only thing distinguishing this from
an accidental POST, and a `204` for a bodyless request reports a deregistration the consumer did not
describe.

**`purgeFlag: true` on the update PATCH is now a deregistration**, per TS 29.503 §5.3.2.4.2. This is not
a hypothetical shape — it is exactly what this repo's own AMF sends
(`bins/nextgcore-amfd/src/sbi_path.rs:1950`, `{"purgeFlag": true}`). Before this change the UDM answered
`204`, patched the flag into the stored document and kept the registration, so the UDM went on naming a
serving AMF that had already released the UE.

The GUAMI ownership check is deliberately kept **conditional**: `Amf3GppAccessRegistrationModification`
marks `guami` required, but amfd sends a bare purge with no GUAMI, and refusing that would convert a
working deregistration into a `400`. An absent GUAMI is accepted; only a *disagreeing* one is refused
with `403 INVALID_GUAMI`.

### One existing test changed shape

`test_amf_registration_update_matching_guami_returns_204_and_patches_udr` used `purgeFlag: true` in its
PATCH body while asserting a UDR **PATCH** was issued. With purge now meaning deregistration, that body
exercises the wrong branch, so the body was changed to a real field modification (`pei`) — the test
still proves precisely what it was written to prove (GUAMI match ⇒ 204 + UDR PATCH), and the purge
branch got its own test. Its twin, the GUAMI-mismatch test, was **strengthened**: it now asserts neither
a PATCH nor a DELETE is issued.

## Gap 4: `ausfInstanceId` was validated and then thrown away (criterion 5)

`handle_generate_auth_data` required the IE, checked it was non-empty, and never stored it. `sor.rs` and
`upu.rs` read `ue.ausf_instance_id`, always found `None`, and fell through to "any cached AUSF
instance" — so in a multi-AUSF core the SoR/UPU MAC was computed by an AUSF that does not hold this
UE's `K_AUSF`, and the UE's verification of `SoR-MAC-IAUSF` / `UPU-MAC-IAUSF` fails
(TS 33.501 §6.14.2.1 / §6.15.2.1).

One line stores it on the live path. The test registers **two** AUSF instances, records the second, and
asserts both the SoR and the UPU protection request reached the recorded one and that the first
received nothing — the "prefer the stored AUSF" branch at `sbi_path.rs` firing, rather than the
arbitrary-first-instance fallback.

**The dead `udm_nudm_ueau_handle_get` is deleted** (criterion 8). It was the *only* code that stored
`ausf_instance_id`, it had no caller anywhere in the tree, and it was a second unreachable
implementation of resynchronisation. Its two request structs (`AuthenticationInfoRequest`,
`ResynchronizationInfo`) went with it since nothing else constructed them; a comment at the site records
what was there and why. The rest of `nudm_handler.rs` is the same shape of C-port dead code — see
"Follow-ups".

## Gap 5: `DeleteAuth` was unrouted and its identifier was thrown away (criterion 6)

`ConfirmAuth` minted `uuid::Uuid::new_v4()`, put it in the `Location` header and dropped it, so the
`authEventId` an AUSF is told to address could never be matched again. `PUT /{supi}/auth-events/{authEventId}`
was unrouted.

The identifier is now pinned on the UE before the response is built (the same value in the header and in
the context — a value that only ever reaches a header cannot be matched), and `DeleteAuth` is routed. A
mismatched or unknown id is a **404, not a silent 204**: the AUSF is addressing a resource this UDM does
not hold, and `204` would tell it an authentication result was revoked while the real one stayed. The
revocation is single-use — the pinned id is cleared, so a replay finds nothing — and it also reaches the
UDR (`DELETE authentication-status`), best-effort, matching the ConfirmAuth write it undoes.

The request body is a mandatory `AuthEvent`, so it is validated to the same standard as ConfirmAuth's
rather than accepted unread.

## Gap 5b: a failed SQN advance still issued the AV (criterion 7)

`handle_generate_auth_data` withheld the AV on a 5xx or a transport error from the UDR SQN `PATCH`, but
a **non-5xx** failure logged `degraded — AV issued anyway` and returned a vector built from the
un-advanced SQN. Because `ue.sqn` is re-read from UDR on every call, an unpersisted advance means the
next authentication computes an AV from the *same* SQN — the reuse TS 33.102 §6.3.2 exists to prevent,
and a replay window for anyone holding the earlier AV. A `404` is both the likeliest such status and the
least alarming-looking, which is why it was the one being tolerated.

Now **any** failed advance withholds the AV (`503`).

### Why no flag

The issue suggests gating the stricter behaviour "behind review with the existing strict-peer tests, or
a feature flag if a staged rollout is preferred". No flag, for three reasons:

1. The recorded decision (2026-09-07) is that an off-by-default cargo feature puts its tests outside
   `cargo test --workspace`, which is this repo's gate, so the gated path ships unexercised.
2. A runtime switch defaulting to the *lenient* behaviour leaves the SQN-reuse window open for every
   deployment that does not know to flip it — and this is an authentication-replay property, which is
   the one class where the repo's fail-closed precedent is unconditional.
3. The only stated justification for leniency was "UDR may not have the auth-subscription resource", and
   nextgcore's own udrd **does** implement `PATCH authentication-subscription`
   (`bins/nextgcore-udrd/src/main.rs:667`). There is no deployment here that legitimately needs the
   lenient path.

The cost, stated plainly: a UDR that answers the SQN PATCH with anything but 2xx now blocks
authentication entirely instead of degrading. That is the intended trade — a UE that cannot authenticate
is visible, an SQN silently reused is not.

## Verification

* Workspace `cargo test`: **5849 passed, 0 failed** (from 5834). `cargo clippy --workspace --all-targets`:
  0 errors, 0 new warnings. `cargo fmt --all --check`: clean.
* **Revert-verified**, each against the named test:
  * mapping `amf-non-3gpp-access` back to the 3GPP access → `test_http_uecm_registration_surface` fails
    (`left: 200, right: 201` — the create/update status is the tell that it read the 3GPP record).
  * pinning `accessType` to `3GPP_ACCESS` → `non_3gpp_reregistration_notifies_the_non_3gpp_amf` and
    `get_location_info_composes_one_entry_per_serving_amf` fail.
  * removing the `purgeFlag` branch → `purge_flag_patch_deregisters_rather_than_patching` fails.
  * dropping the `ausf_instance_id` store → the AUSF-pinning assertion fails (`left: None`).
  * removing the `DeleteAuth` route arm → the DeleteAuth assertion fails with `left: 405`.
  * restoring the lenient non-5xx SQN branch → the withholding assertion fails (`left: 200, right: 503`).
* The two wire-level tests drive the **real router** over HTTP (`udm_sbi_request_handler` behind a real
  `SbiServer`) against mock UDR/AUSF servers, because "returns the stored resource rather than 405" is a
  routing claim that a handler-level test cannot falsify. Both follow the recorded stub-listener rules:
  the helper hands the server back so the caller keeps it alive, and polls `TcpStream::connect` before
  returning. Both declare the Dev SBI profile and serialize on `test_support::CONTEXT_GUARD`, since they
  set `UDR_SBI_*` and re-init the process-global UDM context.

## Not in scope

* `GET .../registrations` (`RegistrationDataSets`, §5.3.2.5.10) and the `nwdaf-registrations` resources
  still `405`. `pei-update` / `roaming-info-update` now answer `501` rather than `405`, which is at least
  an honest "not implemented" instead of an implied "wrong method".
* The UDR side of the new `context-data` resources — **#87**.
* SDM notifications for SMSF / IP-SM-GW registration changes: `notify_ue_context_change` covers AMF and
  SMF transitions only, and adding a `ue-context-in-smsf-data` event is a #83-shaped change, not this
  one.

## Follow-ups worth filing

`nudm_handler.rs` is a C-port module with **no external callers for any of its handlers**
(`udm_nudm_uecm_handle_amf_registration`, `..._update`, `..._get`, `..._smf_registration`,
`..._smf_deregistration`, `udm_nudm_sdm_handle_*`, `udm_nudm_ueau_handle_result_confirmation_inform`) —
verified by grepping the whole tree. Only its small helpers (`hex_to_bytes`, `bytes_to_hex`) are live.
This PR removed the one function criterion 8 named; the remaining ~700 lines are the same hazard the
recorded dead-code learning describes: they read as a working UECM/SDM implementation and will keep
attracting fixes that cannot run.
