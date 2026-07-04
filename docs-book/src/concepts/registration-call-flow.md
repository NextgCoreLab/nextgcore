# UE Registration Call Flow

This chapter traces the 5G initial-registration procedure as it is *actually*
implemented across the NextGCore network functions — not as TS 23.502 draws it,
but as the Rust code runs it. It follows a single UE from the gNB's NGAP
`InitialUEMessage` (carrying a NAS Registration Request), through 5G-AKA
authentication and NAS security-mode control, the three mandatory registration
SBI calls, the piggybacked Registration Accept, and finally the post-
registration UE-policy (URSP) push. Every step below names the file and the
function or struct that performs it, so you can open the source and read along.

The whole 3GPP-facing flow is driven by the AMF daemon
(`nextgcore-amfd`); the authentication maths lives in the AUSF
(`nextgcore-ausfd`) and UDM (`nextgcore-udmd`); post-registration policy comes
from the PCF (`nextgcore-pcfd`). The matched UE/gNB simulator that exercises
this path end-to-end is a **separate repository** — here it appears only as the
peer on the far side of the N2 (NGAP) association.

> **Honesty note:** This registration flow is validated by NextGCore's own unit
> tests and matched-simulator docker E2E (84/84 green as of 2026-07-02), **not**
> by third-party conformance certification. The implementation drives **5G-AKA
> only** on the live path (the AMF's EAP-AKA′ Authentication-Request builder is
> compiled but unreferenced — see *Simplifications and known gaps*), takes a
> number of documented wire-format and control-plane shortcuts, and matches a
> cooperative simulator peer rather than an arbitrary commercial UE/RAN. TS
> numbers are quoted only where they appear in this repo's source comments,
> phrased "per code comments".

## Components involved

| NF | Crate | Role in registration | Config page |
|---|---|---|---|
| AMF | `nextgcore-amfd` | N2/NGAP termination, GMM state machine, NAS security, SBI orchestration | [AMF](../configuration/amf.md) |
| AUSF | `nextgcore-ausfd` | `Nausf_UEAuthentication` (5G-AKA / EAP-AKA′), KSEAF disclosure | [AUSF](../configuration/ausf.md) |
| UDM | `nextgcore-udmd` | `generate-auth-data` (SIDF + Milenage), UECM registration, SDM am-data | [UDM](../configuration/udm.md) |
| UDR | `nextgcore-udrd` | System of record for auth-subscription + am-data (queried by UDM) | [UDR](../configuration/udr.md) |
| PCF | `nextgcore-pcfd` | `Npcf_AMPolicyControl`, `Npcf_UEPolicyControl` + URSP N1N2 push | [PCF](../configuration/pcf.md) |
| NSACF | `nextgcore-nsacfd` | Per-slice UE admission control (`Nnsacf_NSAC`) | [NSACF](../configuration/nsacf.md) |
| NRF | `nextgcore-nrfd` | On-demand NF discovery for every peer above | [NRF](../configuration/nrf.md) |

Supporting libraries: `nextgcore-nas` (5GMM message codec, SUCI, NAS security),
`nextgcore-ngap` + `nextgcore-asn1c` (NGAP/APER), and `nextgcore-sctp` (the N2
transport). The NSSF (`nextgcore-nssfd`) is listed here only to say what does
**not** happen: it is **not** consulted during registration (see step 12).

## The N2 transport underneath

The AMF terminates NGAP over SCTP through the `NgapTransport` enum and
`SctpBackend` selector in `src/bins/nextgcore-amfd/src/ngap_path.rs`
(`SctpBackend::parse`). Two backends exist:

- **`userspace`** (default, `Args.sctp_backend` in
  `src/bins/nextgcore-amfd/src/lib.rs`) — `sctp-proto` over UDP, matched to the
  nextgsim gNB. This is what the docker E2E uses.
- **`kernel`** — native Linux kernel SCTP for a standard external RAN, compiled
  only when amfd is built with the `kernel-sctp` feature (the `#[cfg(feature =
  "kernel-sctp")]` arms in `NgapTransport`). Requesting `kernel` without that
  feature is a hard startup error.

The registration handlers are backend-agnostic: everything below runs
identically over either transport once bytes arrive at `handle_ngap_message`.

## The initial NAS message

1. **gNB → AMF: `InitialUEMessage`.** The dispatcher in `ngap_path.rs`
   (procedure code 15) routes to `handle_initial_ue_message`, which parses the
   PDU with `crate::ngap_asn1::parse_initial_ue_message_asn1` into an
   `InitialUeMessageData` (RAN-UE-NGAP-ID, NAS-PDU, PLMN, TAC, NR-CGI). It
   allocates an AMF-UE-NGAP-ID, creates a `UeNasContext` (seeded with
   `crate::context::nas_security_canary()`), records the TAI and 3GPP access
   type, and switches on the inner NAS message type. A `REGISTRATION_REQUEST`
   (`0x7E … 0x41`) is dispatched to `handle_registration_request_nas` with
   `integrity_protected = false` — this is an unprotected initial NAS message.
   Logs `Initial UE Message from association …`.

   A `SERVICE_REQUEST` arriving in an `InitialUEMessage` with no stored context
   is rejected with 5GMM cause #9 (`build_service_reject`) — the code comment
   cites TS 24.501 §5.6.1.5.

2. **Registration Request parsing + cleartext gate.**
   `handle_registration_request_nas` (`ngap_path.rs`) runs
   `parse_registration_request_pdu`, then enforces the TS 24.501 §4.4.6 /
   TS 33.501 §6.4.6 cleartext-IE rule via
   `validate_initial_registration_cleartext` (per code comments): an
   *unprotected* initial Registration Request that carries a non-cleartext IE
   (e.g. Requested NSSAI) or a NAS message container is rejected with 5GMM #95
   before any IE touches UE state. It logs the E2E anchor line
   `Registration Request: type=…, ngKSI=…, identity_type=…, suci=…`.

   The UE security capability is stored **exactly as received**
   (`state.amf_ue.ue_security_capability`); when the IE is absent the code
   assumes null algorithms only (`ea/ia = 0x80`) rather than fabricating
   capabilities. The **Requested NSSAI is deliberately not read here** — it is a
   non-cleartext IE and is taken only from the integrity-protected replay in
   step 11.

   Identity branch:
   - **SUCI identity** → proceed to authentication (`start_authentication`).
     Optional Rel-17/18 handling (SNPN NID allow-list via `validate_nid`, UAV
     geofence authorization, RedCap AMBR capping) is applied here first.
   - **GUTI unknown to this AMF** → send an Identity Request for the SUCI
     (`gmm_build::build_identity_request`) and arm timer T3570. There is **no
     blanket Identity Request** otherwise — identification runs only when the UE
     gave a GUTI this AMF cannot resolve.
   - **Periodic updating** with a live security context → short-circuit straight
     to `send_registration_accept` (step 13).

## Authentication (5G-AKA)

```
UE            gNB           AMF(amfd)        AUSF(ausfd)      UDM(udmd)     UDR(udrd)
 |  Reg Req    |  InitialUE   |                 |               |            |
 |------------>|------------->| start_auth      |               |            |
 |             |              |  POST ue-authentications        |            |
 |             |              |---------------->| generate-auth-data          |
 |             |              |                 |-------------->| auth-sub GET |
 |             |              |                 |               |----------->|
 |             |              |                 |  Milenage AV  |<-----------|
 |             |              |  201 5gAuthData |<--------------|            |
 |  Auth Req   |              |<----------------|               |            |
 |<------------|<-------------|                 |               |            |
 |  Auth Resp (RES*)          | verify HXRES*   |               |            |
 |------------>|------------->|  PUT 5g-aka-confirmation         |            |
 |             |              |---------------->| RES* vs XRES* |            |
 |             |              |  200 kseaf,supi |<--------------|            |
 |             |              | derive Kamf/Knas|               |            |
```

3. **AMF → AUSF: `Nausf_UEAuthentication` create.** `start_authentication`
   (`ngap_path.rs`) resolves the AUSF endpoint through
   `resolve_nf_endpoint_async(NausfAuth)` — SBI discovery cache first, then an
   **on-demand NRF discovery** (`amf_nrf_discover`), then env/localhost fallback
   (`sbi_path.rs`). It builds the serving-network-name from the serving PLMN
   (`serving_network_name_from_plmn`) and calls
   `call_ausf_authenticate_with_resync` (`sbi_path.rs`), which POSTs
   `/nausf-auth/v1/ue-authentications` with `{ supiOrSuci, servingNetworkName }`
   (plus `resynchronizationInfo` on an SQN-resync retry). Logs the E2E anchor
   `Calling AUSF authenticate: …`.

4. **AUSF validates and asks UDM.** `handle_ue_authentication`
   (`src/bins/nextgcore-ausfd/src/app.rs`) validates the SNN shape
   (`validate_serving_network_name`, requiring the `5G:` anti-bidding-down
   prefix, per code comments citing TS 33.501 §6.1.2) and checks it is allowed
   for the requesting consumer (`snn_authorized_for_consumer` in
   `nausf_handler.rs`, **default-permissive** when no OAuth2 token carries a
   `plmnList`). It then calls `send_udm_generate_auth_data`.

5. **UDM builds the authentication vector.** `handle_generate_auth_data`
   (`src/bins/nextgcore-udmd/src/app.rs`) requires `servingNetworkName` and
   `ausfInstanceId`, de-conceals the SUCI via the SIDF
   (`context.deconceal_suci`, per code comment TS 33.501 §6.12.5), queries UDR
   for the auth subscription (`udm_nudr_dr_send_auth_subscription_get`), and
   selects 5G-AKA or EAP-AKA′ from the subscription's `authenticationMethod`
   (anything else → 501 `UNSUPPORTED_AUTHENTICATION_METHOD`). For 5G-AKA it runs
   `nextgcore_crypt::milenage::milenage_generate(opc, amf, k, sqn, rand)` to get
   `(autn, ik, ck, ak, res)`, then derives `kausf =
   nextgcore_kdf_kausf(ck, ik, snn, autn)` and `xresStar =
   nextgcore_kdf_xres_star(...)`, returning the AV `{ rand, autn, xresStar,
   kausf }`. (An SQN synch failure carrying AUTS is validated against `mac_s`
   here before a fresh vector is generated.)

6. **AUSF returns `5gAuthData` (HXRES*, not KSEAF).** Back in `app.rs`, the AUSF
   stores `rand/xres_star/autn/kausf`, computes HXRES* with
   `calculate_hxres_star()`, and answers **201** with
   `{ authType: "5G_AKA", 5gAuthData: { rand, hxresStar, autn }, _links,
   servingNetworkName }` and a `Location` header naming the auth context.
   **KSEAF is deliberately withheld** at this stage — it is disclosed only on a
   successful confirmation (step 8), per code comment TS 29.509 §6.1.6.2.8.

7. **AMF → UE: Authentication Request; UE → AMF: Authentication Response.** The
   AMF stores the vector, fixes the initial ABBA to `[0x00, 0x00]` (per code
   comment TS 33.501 Annex A.7.1), builds the NAS Authentication Request
   (`gmm_build::build_authentication_request`), sends it and arms T3560. When
   the Authentication Response arrives (via `handle_uplink_nas_transport` →
   `handle_authentication_response_nas`), the AMF extracts RES* (IEI `0x2D`) and
   performs the **SEAF-side** check: `HRES* = SHA256(RAND ‖ RES*)[16..32]`
   compared to the stored HXRES* (per code comment TS 33.501 §6.1.3.2.0). A
   mismatch sends an Authentication Reject and releases the UE.

8. **AMF → AUSF: 5G-AKA confirmation.** `call_ausf_5g_aka_confirm`
   (`sbi_path.rs`) PUTs
   `/nausf-auth/v1/ue-authentications/{ctxId}/5g-aka-confirmation` with
   `{ resStar }`. The AUSF confirmation handler (`app.rs`) does the
   **authoritative** check — a **constant-time** `compare_res_star`
   (`nausf_handler.rs`) of the received RES* against the stored XRES* (per code
   comment TS 33.501 §6.1.3.2 step 11; HXRES* is the SEAF's job, not the
   AUSF's). On success it computes KSEAF (`calculate_kseaf()`), refreshes the
   per-SUPI KAUSF anchor (`anchor_refresh`, for later SoR/UPU), fires a
   best-effort UDM auth-result notification, and returns **200**
   `{ authResult: "AUTHENTICATION_SUCCESS", kseaf, supi }` — `supi` included
   only when the original identity was a SUCI. Logs the E2E anchor
   `result=AUTHENTICATION_SUCCESS`.

## Key hierarchy and NAS security-mode control

9. **AMF derives the key hierarchy and selects algorithms.** Continuing in
   `handle_authentication_response_nas`, the AMF takes the SUPI and KSEAF from
   the confirmation and derives:
   - `Kamf = nextgcore_crypt::kdf::nextgcore_kdf_kamf(supi, abba, kseaf)`;
   - NAS algorithm selection from the intersection of the UE's replayed
     capabilities and the AMF's **configured** order
     (`algorithm_order_to_mask` over `integrity_order`/`ciphering_order` from the
     AMF context) via `nas_security::select_integrity_algorithm` /
     `select_encryption_algorithm`. Integrity selection is **fail-closed**: an
     empty NIA intersection returns `None`, and the AMF **rejects the
     registration** rather than fabricating NIA2 the UE never advertised (per
     code comment TS 33.501 §5.5.2). Ciphering is asymmetric — NEA0 (null) is a
     permitted selection, so an empty NEA intersection stays NEA0.
   - `Knas_int / Knas_enc = nextgcore_kdf_nas_5gs(0x02 | 0x01, alg, Kamf)`.

   Logs the E2E anchor `[{supi}] keys derived; selected NIA{} / NEA{}`.

10. **AMF → UE: Security Mode Command (protected).** The plain SMC is built by
    `gmm_build::build_security_mode_command` (replaying the UE's *actual*
    capabilities and requesting IMEISV), then wrapped by
    `nas_security::nas_5gs_security_encode` with security-header type
    `INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT`. Sent, T3560 armed.
    Logs `Security Mode Command sent to UE …`.

11. **UE → AMF: Security Mode Complete + anti-bidding-down.**
    `handle_security_mode_complete_nas` (`ngap_path.rs`) extracts the UE's
    **replayed** initial Registration Request from the now-integrity-protected
    NAS message container (`extract_nas_message_container` +
    `parse_registration_request_pdu`) and compares the replayed UE security
    capabilities against the ones stored from the cleartext initial message. Any
    mismatch is treated as a downgrade attack: Security Mode Reject **#23**
    followed by Registration Reject and UE release (per code comments TS 24.501
    §4.4.2.4 / TS 33.501 §6.7.2). The **Requested NSSAI is populated here**, from
    the protected replay only. IMEISV (IEI `0x77`) is read from the SMC; if
    absent, the AMF sends a protected Identity Request (IMEISV) and arms T3570
    before completing.

## Registration SBI calls and acceptance

12. **The three mandatory registration calls (all fail-closed).**
    `complete_registration` (`ngap_path.rs`) — cited against TS 23.502
    §4.2.2.2.2 steps 14a/b/c/16 per code comments — runs, in order, and rejects
    the registration (Registration Reject + release) on *any* failure:

    1. **`Nudm_UECM_Registration`** — `call_udm_uecm_registration`
       (`sbi_path.rs`) PUTs
       `/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access`, registering an
       absolute `deregCallbackUri`. UDM `process_amf_registration` (`uecm.rs`)
       validates mandatory IEs, reads the prior registration, persists to UDR
       (`amf_context_put`), notifies the old AMF if the serving AMF changed, and
       answers 201 (create) or 200 (update).
    2. **`Nudm_SDM_Get` (am-data) + `Nudm_SDM_Subscribe`** —
       `call_udm_sdm_get_am_data` / `call_udm_sdm_subscribe`. UDM
       `handle_get_am_data` (`app.rs`) queries UDR am-data and, when a steering
       source is configured, injects a protected Steering-of-Roaming container
       (`sor::maybe_inject_sor_info`) via the AUSF's `Nausf_SoRProtection`
       service, and a UPU container (`upu::maybe_inject_upu_info`) via
       `Nausf_UPUProtection`. Both are **fail-closed**: on any AUSF failure the
       container is withheld and the UDR body is passed through byte-identical
       (per code comments TS 33.501 §6.14.2.1 / §6.15.2.1).
    3. **`Npcf_AMPolicyControl_Create`** — `call_pcf_am_policy_create`; the
       returned association id is stored on the UE context.
    4. **`Npcf_UEPolicyControl_Create`** (step 3b, Wave-6) — only when
       `ue_policy_assoc_enabled()` is true (kill-switch `AMF_UE_POLICY_ASSOC`).
       This one is **fire-and-forget**: a failure logs a WARN and never fails the
       registration. It is what later triggers the URSP push (step 15).

    **Allowed NSSAI is computed locally, not via NSSF.** `select_allowed_nssai`
    (`ngap_path.rs`) returns the UDM-subscribed S-NSSAIs if present, else the
    AMF's configured `plmn_support` default — the Requested NSSAI is never echoed
    back as authorization (per code comment amfd-06). An empty result is
    Registration Reject **#62**. There is **no `Nnssf_NSSelection` call anywhere
    in the registration path.**

    **NSACF admission** then runs per Allowed S-NSSAI via
    `call_nsacf_ue_admission` (`sbi_path.rs`), POSTing
    `/nnsacf-nsac/v1/slices/ues`. A denial (403, or 200 with this SUPI in
    `acuFailureList`) is Registration Reject **#69**. Note the real net behavior
    is **degrade-open**: `call_nsacf_ue_admission` catches transport errors and
    unexpected statuses and returns `admitted = true`, so an unreachable NSACF
    *admits* rather than blocks (see *Simplifications and known gaps*).

    Finally the AMF copies the subscribed UE-AMBR from am-data and mints a new
    5G-GUTI (`generate_new_guti`: this AMF's GUAMI + a CSPRNG 5G-TMSI).

13. **AMF builds and protects the Registration Accept.**
    `send_registration_accept` (`ngap_path.rs`) builds the message with
    `gmm_build::build_registration_accept` (carrying the new 5G-GUTI, Allowed
    NSSAI, etc.) and protects it with `nas_5gs_security_encode` using header
    `INTEGRITY_PROTECTED_AND_CIPHERED`. A periodic/mobility update on a UE that
    already has AS security is delivered over `DownlinkNASTransport`; an
    **initial** registration takes the InitialContextSetup path next.

14. **AMF → gNB: `InitialContextSetupRequest` (Registration Accept piggybacked).**
    The AMF derives `KgNB = nextgcore_kdf_kgnb_and_kn3iwf(Kamf, ul_count,
    access_type_distinguisher)` (per code comment TS 33.501 Annex A.9) and calls
    `ngap_asn1::build_initial_context_setup_request_asn1` to carry the GUAMI, the
    **replayed** UE security capabilities, the UE Security Key (KgNB), the Allowed
    NSSAI, the UE-AMBR, and — as the NAS-PDU — the protected Registration Accept.
    It sends this to the gNB and arms T3550 against the whole ICS PDU (so a
    retransmission re-delivers the Registration Accept). Logs the E2E anchor
    `Initial Context Setup Request sent … Registration Accept piggybacked …`.

    The gNB's `InitialContextSetupResponse` is handled by
    `handle_initial_context_setup_response`: it stops the T3550 retransmission
    and moves the reporting GMM FSM toward Registered
    (`gmm_fsm.transition_to_registered`). The UE's NAS **Registration Complete**
    (handled in `handle_uplink_nas_transport`, `REGISTRATION_COMPLETE` arm) sets
    `registered = true` and promotes `next_guti` to the current 5G-GUTI, logging
    `[{suci}] Registration Complete (5G-TMSI=0x…)`.

## Post-registration: UE policy / URSP delivery

This is wired end-to-end (Wave-6 E-series) and worth calling out because it is
what runs *after* the UE is registered.

15. **PCF pushes URSP over N1N2.** The AMF's step-3b
    `Npcf_UEPolicyControl_Create` reaches the PCF's `handle_ue_policy_create`
    (`src/bins/nextgcore-pcfd/src/app.rs`), which returns 201 and — when
    `ue_policy::delivery_enabled()` is true (kill-switch `PCF_UE_POLICY_DELIVERY`)
    — spawns `spawn_ue_policy_delivery`. That task assembles URSP rules
    (`src/bins/nextgcore-pcfd/src/ue_policy.rs`) and calls
    `pcf_deliver_ue_policy` (pcfd `sbi_path.rs`), which discovers the AMF and
    POSTs `/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages` as an
    `Namf_Communication_N1N2MessageTransfer` (multipart, `n1MessageClass` =
    `UPDP`).

16. **AMF relays the UPDP container to the UE.** The AMF's
    `handle_n1_n2_message_transfer_request`
    (`src/bins/nextgcore-amfd/src/namf_server.rs`) recognizes the UPDP class in
    `try_ue_policy_relay` and enqueues the payload for N1 egress
    (DownlinkNASTransport to the UE), logging
    `UE policy: enqueued UPDP downlink for N1 egress`. Delivery is only
    *confirmed* by a MANAGE UE POLICY COMPLETE from the UE (the E6
    delivery-result loop); a bare N1N2 200 is recorded as *accepted-for-transfer*,
    not *delivered* — `DeliveryState` starts `Pending` and is fail-closed to
    `Failed` if no COMPLETE arrives.

## Simplifications and known gaps

Grounded in the code, these are the honest deviations from a textbook TS 23.502
registration:

- **5G-AKA only on the live path.** The AMF's EAP-AKA′ Authentication-Request
  builder `build_eap_authentication_request` (`ngap_path.rs`) is marked
  `#[allow(dead_code)]` and carries a source comment that it is **not yet called
  by the live authentication path** — the EAP-AKA′ SBI looping is E2E-deferred.
  The AUSF (`app.rs`, `eap_aka_prime.rs`) and UDM both implement the EAP-AKA′
  surface, but a live registration only ever runs 5G-AKA.
- **NSACF admission is effectively degrade-open.** The fail-closed
  "unreachable ⇒ not admitted" branch in `complete_registration` is in practice
  unreachable: `call_nsacf_ue_admission` (`sbi_path.rs`) intercepts transport
  errors and unexpected HTTP statuses and returns `admitted = true`. So a
  down/missing NSACF **admits** the UE. Only an explicit 403 / `acuFailureList`
  denial blocks registration.
- **No NSSF slice selection.** Allowed NSSAI is chosen locally
  (`select_allowed_nssai`) from UDM subscription or AMF config; the NSSF is never
  queried during registration.
- **Identity procedure is normally skipped.** Because the matched UE sends its
  SUCI directly in the initial Registration Request, the AMF never runs an
  Identity Request/Response exchange on the happy path; it only issues one for an
  unknown GUTI (step 2) or a missing PEI (step 11). The E2E script explicitly
  removed the old Identity assertions for this reason.
- **NAS-security canary defaults OFF.** New UE contexts inherit
  `use_nextgcore_nas_security` from the process-wide canary
  (`context::nas_security_canary`), seeded at startup from
  `amf.nas.use_nextgcore_security` (default `false`) — see
  `context::resolve_nas_security_canary`. The canary lets an operator A/B the
  new NAS-security path without a code change.
- **Fire-and-forget policy legs behind kill-switches.** Both the UE-policy
  association (`AMF_UE_POLICY_ASSOC`) and its delivery (`PCF_UE_POLICY_DELIVERY`)
  can be disabled, restoring the pre-Wave-6 byte flow. Some inbound AMF SBI
  callbacks (am-policy-notify, sdm-subscription-notify) are noted in
  `sbi_path.rs` as "still-unserved".
- **Config loading is lenient.** An unreadable/unparsable `amf.yaml` logs a
  warning and continues with built-in defaults (`load_config` in
  `lib.rs`) — a running AMF is not proof your config was applied. See the
  troubleshooting table in [Observability & Troubleshooting](../observability.md).
- **Cooperative peer.** All of the above is exercised against the matched
  simulator, not an arbitrary commercial UE/gNB; the SMF-side PDU-session
  establishment that follows registration is covered by the
  [SMF](../configuration/smf.md) path, not here.

## How it is validated

**Unit tests (per-crate `cargo test`).** The wire builders and decision helpers
are golden- and property-tested independently of any network:

- `gmm_build.rs` — `golden_registration_accept_full`,
  `golden_registration_accept_no_guti_no_nssai`,
  `golden_registration_accept_3digit_mnc`, `golden_registration_reject`, plus
  `drift_registration_accept_*` round-trips through `nextgcore-nas`.
- `gmm_handler.rs` — `test_handle_registration_request_initial`,
  `test_handle_registration_request_with_guti`,
  `test_handle_registration_request_non_cleartext_rejected` (the §4.4.6 gate).
- `nausf_handler.rs` — `test_compare_res_star` /
  `test_compare_res_star_constant_time_xres` (constant-time RES*/XRES* compare),
  `test_validate_serving_network_name`, `test_snn_authorized_for_consumer`.
- `context.rs` — `test_resolve_nas_security_canary_precedence` (the canary
  env/yaml precedence). Additional AMF invariants live in
  `property_tests.rs`.

**Matched-simulator docker E2E.** The single entrypoint is
`nextgcore/docker/rust/e2e.sh` (which chains `preflight.sh` → `build.sh` →
`e2e-test.sh`). `e2e-test.sh` brings up MongoDB + the 5GC + the nextgsim gNB/UE
and asserts the registration flow through **source-anchored log lines** — the
same anchors named in this chapter, e.g. on `nextgcore-amf`:

```
Initial UE Message
Registration Request: type=
Calling AUSF authenticate
Calling AUSF 5G-AKA confirmation
result=AUTHENTICATION_SUCCESS
keys derived; selected NIA
Security Mode Command sent
Security Mode Complete
Registration Accept piggybacked
```

and on the simulator side `Sending Registration Request` … `Registration
Accept: UE is now …` … `Sending Registration Complete`. The suite then verifies
the data plane by pinging **through the UE's GTP-U tunnel** and finishes at
`UE PDU session 1 ACTIVE with IPv4 address`. The full baseline was **84/84 green
on 2026-07-02**. This is functional validation against a cooperative peer — it
is not third-party conformance certification.
