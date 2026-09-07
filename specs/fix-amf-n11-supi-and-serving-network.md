# nextgcore #73 (AMF N11): convey the real subscriber and serving network on SmContextCreate

Verified against `main` @ `fa6ffff`. The issue's cites are from `76ea248`; all five defects
re-verified and all five still hold.

**Two passes.** Pass 1 (`Refs #73`, commit `65cd2a3`, PR #203) shipped criteria 1, 2, 3 and 7 —
the N11 identity chain, end to end — and is documented below. Pass 2 (`Closes #73`) ships
criteria 4 and 5 and splits criterion 6 out to **#204** and the `gpsi` remainder to **#205**;
see "Pass 2" at the end of this document.

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
  the NF that retrieves SM subscription data. Implementing it in amfd
  would put subscription retrieval in the wrong NF. Worth deciding before building.

  > **Correction (pass 2).** This section claimed "the SMF already does" retrieve SM
  > subscription data. **That is wrong**, and it is corrected here so the next reader does not
  > build on it: `smfd` never issues a `nudm-sdm` request at all. Its only mention is a
  > response-handling FSM arm (`gsm_sm.rs:302`) that nothing can reach. The *producer* chain
  > does exist end to end (`udmd` serves `sm-data` at `app.rs:663` → `handle_get_sm_data`
  > `:950`, proxying `udrd`'s `build_sm_data` `:589` with `dnnConfigurations` `:677`) — it is
  > the SMF-side consumer that is missing. See #204.

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
- [x] PEI/IMEISV decode (criterion 4) — pass 2
- [x] SUCI scheme guard (criterion 5) — pass 2
- [-] Default DNN from subscription data (criterion 6) — split to **#204** (belongs in smfd)
- [-] `gpsi` — no field exists in amfd; split to **#205**

---

# Pass 2 (`Closes #73`): PEI decode, SUCI scheme gate, and two carve-outs

Verified against `main` @ `d9aea74`. Both remaining defects re-verified present.

## Criterion 4: one PEI helper, and the prefix comes from the wire

The defect is in **octet 4**. `content[0]` carries the type of identity in bits 1-3, the
odd/even indicator in bit 4, and **identity digit 1 in bits 5-8** (TS 24.501 §9.11.3.4). Both
sites decoded from `content[1..]`, so every PEI was one digit short. Independently confirmed:
the IMEISV test vector decodes to `234567890123456` under the old slice — 15 digits, digit 1
gone — against `1234567890123456` now.

New `decode_pei(content) -> Option<(String, String)>` returns the `Pei` string and the bare
digits. Three decisions:

* **The prefix is read from the type-of-identity field, never assumed.** The old code emitted
  `imeisv-` for both arms, so a 15-digit IMEI violated the TS 29.571 `Pei` pattern
  (`imei-[0-9]{15}` vs `imeisv-[0-9]{16}`).
* **The digit count must match the type, or nothing is emitted.** A malformed identity yields no
  PEI rather than one that breaks the pattern downstream — the same omit-never-placehold rule as
  Decision 2 above.
* **`decode_bcd_digits` was left alone.** It has four callers, and two of them are the SUCI
  parser (`parse_suci_identity`, routing digits and MSIN). Changing it to recover digit 1 would
  have corrupted SUCI parsing. The two PEI sites route onto the new helper instead, which is
  also what stops them diverging again — the divergence the issue explicitly asked to prevent.

One thing the issue's cite got slightly wrong, in the safe direction: at the Security Mode
Complete site the code **already** gated on `content[0] & 0x07 == IMEISV`, so its `imeisv-`
prefix was correct and only the dropped digit was a defect there. The Identity Response site
accepted `IMEI || IMEISV` and so had both defects.

## Criterion 4, second half: the consumer that would have broken

Emitting a correct `imei-` prefix for the first time **breaks two downstream sites** that assumed
the other form: `udrd` did `pei.strip_prefix("imeisv-").unwrap_or(pei)` in two places
(`main.rs:904`, `nudr_handler.rs:265`), which stores the literal `"imei-353…"` — prefix included
— as the equipment identity. Found by grepping the consumers before shipping the producer
change, not after.

Fixed with one shared `data_store::imeisv_from_pei`, used by both sites, because they were two
copies of the same three lines in two targets (the lib and the bin) — the same
count-the-implementations shape recorded in LEARNINGS.

## Criterion 5: the scheme id is the gate, not the digit check

`supi_from_suci` concatenated `parts[2]`/`parts[3]`/`parts[7]` without inspecting `parts[5]`, the
protection scheme id. For an ECIES SUCI `parts[7]` is hex-encoded **ciphertext**, so the result
was a fabricated SUPI — which then seeded `nextgcore_kdf_kamf` and UECM registration.

The signature became `-> Option<String>`, **mirroring `supi_from_suci` in nextgcore-udmd's
`context.rs`, which already returned `Option` for exactly this reason** — the sibling stack had
the right answer and the AMF had the wrong one.

The load-bearing detail: **an all-digit MSIN check alone is not sufficient**, because a hex
ciphertext can be all decimal digits by chance. So the scheme id is checked first and the tests
prove the attribution — the profile-A and profile-B rejection vectors use all-digit scheme
outputs, and a null-scheme SUCI of the *same shape* is asserted to still succeed.

Both callers now **fail closed**: registration reject + UE release, mirroring the NIA-selection
precedent already in the same function. Deriving KAMF under a fabricated identity would key the
entire NAS security context to the wrong subscriber (TS 33.501 §6.1.3).

## Verification

Six new tests. Workspace **5728 passed / 0 failed** (was 5722), `cargo test --workspace` exit 0,
checked for `^error` rather than only a `test result:` line. `cargo fmt --all --check` clean.
`cargo clippy --workspace` (the CI gate) exit 0, zero warnings.

**Revert-verified**, each one at a time, each failing on the value and not merely on a status:

| revert | test that fails | wrong value it produced |
|---|---|---|
| decode from `content[1..]` again | `decode_pei_recovers_digit_one_and_selects_the_prefix_by_type` | 15 digits, digit 1 dropped |
| hardcode the `imeisv-` prefix | same, plus `decode_pei_output_matches_the_pei_pattern` | `imeisv-123456789012345` |
| drop the SUCI scheme gate | `supi_from_suci_refuses_a_protected_suci` | `imsi-99970<ciphertext>` |
| strip only `imeisv-` in udrd | `imeisv_from_pei_strips_either_pei_prefix` | `imei-123456789012345` |

**Not verified — the ceiling, stated plainly:**

* The two **caller** rejection paths are *not* executed by any test. amfd has no harness that
  drives `handle_authentication_confirm` or `complete_registration` (there are zero tests for
  either today), and building one is disproportionate to this change. What holds them is
  structural, not tested: `let Some(supi) = … else { … return }` cannot fall through, so the
  compiler guarantees no path reaches key derivation with an unresolved SUPI. That is weaker
  than a test and is recorded as such.
* No real UE, gNB or AUSF was involved; PEI decoding is asserted on hand-built IE octets whose
  encodings were verified independently before use, not observed off a live radio link.
* `cargo clippy --workspace --all-targets` fails with 7 errors in `nextgcore-sbi` and
  `nextgcore-hssd` — **pre-existing**, confirmed identical on clean `main` by stashing, and
  outside every file touched here. CI gates on `cargo clippy --workspace`, which passes.
* GitNexus impact analysis, which this repo's CLAUDE.md mandates before editing a symbol, was
  **not run**: no GitNexus MCP server was connected in this session. Caller analysis was done
  with grep instead (4 `decode_bcd_digits` callers, 2 `supi_from_suci` callers in amfd plus a
  separate same-named function in udmd, 2 `Pei`-prefix consumers in udrd).

**A dead site, verified and deliberately left:** `gmm_handler::handle_security_mode_complete`
also formats `imeisv-{imeisv}` (`:504`). It has **no production caller** — only its own two
tests — and its input is an already-decoded `Option<String>` carrying no type information, so it
could not select a prefix even if wired. Its prefix is also *correct* for the path it models
(the Security Mode Complete carries the IMEISV specifically). Left untouched rather than folded
into the new helper, and noted here so it is not mistaken for a missed site.
