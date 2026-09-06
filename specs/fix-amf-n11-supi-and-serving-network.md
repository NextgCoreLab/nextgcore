# nextgcore #73 (AMF N11): convey the real subscriber and serving network on SmContextCreate

Verified against `main` @ `fa6ffff`. The issue's cites are from `76ea248`; all five defects
re-verified and all five still hold.

`Refs #73`, **not Closes**. Ships criteria 1, 2, 3 and 7 — the N11 identity chain, end to end.
Criteria 4, 5 and 6 remain open; see "Scope" below. The open count deliberately does not move.

## The defect shipped here

`build_create_sm_context_request` emitted only `pduSessionId`, `sNssai`, `dnn`, `n1SmMsg`,
`redcapIndication` and a **hardcoded** `servingNetwork: {mcc:"001", mnc:"01"}`. No `supi`,
`pei`, `guami`, `servingNfId` or `ueLocation` — even though `state.amf_ue.supi` was set and used
elsewhere in the same file.

`smfd` compensated by substituting `"imsi-unknown"`, warn-and-continue, commented *"lenient:
AMF support pending"*. That phantom identity then flowed into NSAC counters, policy association
and session lookup, so **every subscriber in the network collapsed onto one identity**. Charging
and slice admission were computed over a subscriber that does not exist — and because the
session still came up, nothing surfaced the loss.

## Decision 1: a struct, not six more positional parameters

`call_smf_create_sm_context` already took eight arguments. Adding six positional
`Option<String>`s is how a caller silently passes `pei` where `gpsi` belongs, so the identity is
grouped into `SmContextIdentity { supi, pei, guami, serving_plmn, serving_nf_id, ue_location }`,
built once at the call site from `state.amf_ue` and the AMF context.

## Decision 2: omit what the AMF does not hold — never placehold

Each member is emitted only when actually known. This matters most for `servingNetwork`: a
hardcoded `001/01` is **indistinguishable from a real 001/01 test network**, so the SMF cannot
tell "the serving PLMN is 001/01" from "the AMF did not know". Absent is checkable; wrong is
not. The serving PLMN is sourced from the UE's `nr_tai.plmn_id`, falling back to the AMF's own
`served_guami`.

`gpsi` is **not** emitted at all: amfd's UE context has no GPSI field and never retrieves one
from UDM, so there is nothing to convey. Criterion 1 lists it, but emitting a derived or blank
GPSI would be a fabrication of exactly the kind this issue exists to remove. Recorded as a
follow-up rather than faked.

`PlmnId` gained `mcc()`/`mnc()` accessors — the inverse of `PlmnId::new` was missing, which is
part of *why* `servingNetwork` was hardcoded: there was no way to render a real PLMN back to the
wire form. `mnc3 == 0xf` is the TS 24.008 filler for a two-digit MNC and is dropped, not
rendered as `15`.

## Decision 3: the SMF now rejects, and that is the point

The AMF fix alone would be unenforced — a future regression would silently return to
`imsi-unknown`. So `smfd` rejects a non-emergency `CreateSMContext` with no (or empty) `supi`
via `400 MANDATORY_IE_MISSING`. A session the SMF cannot attribute is one it cannot charge,
police or admit; refusing is the honest failure.

The rejection is asserted on **behaviour**, not by grepping the source for `imsi-unknown` — the
comment explaining this fix contains that literal, and a source-grepping guard would match its
own justification (a trap this repo has already been bitten by).

## Scope: criteria 4, 5 and 6 remain open

Split deliberately, stated up front rather than discovered late:

* **4 (PEI/IMEISV mis-decode)** and **5 (SUCI scheme ignored)** are self-contained and small,
  and were left only for want of session budget. Both are verified present:
  `decode_bcd_digits(&content[1..])` drops identity digit 1 (which shares octet 4 with the
  type field) and unconditionally prefixes `imeisv-` even for a 15-digit IMEI, at two sites;
  `supi_from_suci` never inspects the scheme id, so an ECIES-protected SUCI yields a bogus SUPI
  that seeds K_AMF derivation.
* **6 (default DNN from subscription data)** is a larger question than the criterion implies.
  amfd retrieves only `am-data` from UDM SDM, never `sm-data`, where `dnnConfigurations` lives —
  so this needs a **new southbound interaction**. And per TS 23.501 the **SMF**, not the AMF, is
  the NF that retrieves SM subscription data; the SMF already does. Implementing it in amfd
  would put subscription retrieval in the wrong NF. Worth deciding before building.

## Verification

Four new tests. Workspace **5722 passed / 0 failed**, `cargo test --workspace` exit 0, no
compile errors (checked for `^error`, not only a `test result:` line). fmt clean; `cargo clippy
--workspace --all-targets` exit 0 with no warning in any file touched.

**Revert-verified:**

| revert | test that fails |
|---|---|
| smfd substitutes `imsi-unknown` again | `create_sm_context_without_supi_is_rejected` |
| drop `supi` from the N11 body | `n11_create_carries_the_real_subscriber_identity` |
| hardcode `servingNetwork` again | `n11_serving_network_is_the_real_plmn` |

`n11_omits_identity_the_amf_does_not_have` pins Decision 2 — an unknown member is absent, not
placeheld.

**A stale test comment found:** smfd's `validate_sm_context_create_data_table` documents *"the
exact SmContextCreateData body the matched-sim AMF sends (no supi …) MUST still pass the strict
validator"*. It tests a separate validator, not the handler, so it did not break — but its
premise is now false, since the AMF does send `supi`. Left passing and noted rather than
silently rewritten, because the validator's leniency is a separate decision from the handler's.

**Not verified:** no real UE, gNB or SMF process was involved. The N11 body is asserted by
serialising the built request, not by observing an SMF receive it, and CI skips Docker E2E. The
`servingNfId` member is wired but not populated at the call site — the AMF's own NF instance id
is a local in `sbi_path::open`, not reachable from the NGAP path without threading it through
the context; the field is emitted when supplied and omitted otherwise.

## Definition of done

- [x] N11 body carries `supi`, `pei`, `guami`, `servingNetwork`, `ueLocation` from the UE context
- [x] `servingNetwork` is the real serving PLMN, not a literal
- [x] `smfd` rejects a non-emergency create with no `supi`; no `imsi-unknown` fabrication
- [x] Workspace clippy + amfd/smfd suites pass
- [ ] PEI/IMEISV decode (criterion 4) — **#73**
- [ ] SUCI scheme guard (criterion 5) — **#73**
- [ ] Default DNN from subscription data (criterion 6) — **#73**, and see the architectural note
- [ ] `gpsi` — no field exists in amfd; follow-up
