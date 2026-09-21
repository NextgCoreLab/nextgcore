# Decide whether an EMERGENCY registration survives an unreachable AUSF

**Issue:** nextgcore #361 (a `decision` follow-up to #359 / #356 / #115)
**Verified against:** nextgcore `main` @ `89cb764`
**Spec basis:** TS 33.501 §5.1.2 (requirement), §5.2.3 (NIA0 restriction), §6.7.3.6, §10.2.1.2,
§10.2.2.1, §10.2.2.2, §10.2.2.3.1; TS 23.501 §5.16.4.1, §5.16.4.3, §5.16.4.9, §5.16.4.9a;
TS 23.502 §4.2.2.2.2 step 8, §4.12.2.3; TS 23.401 §4.3.12.1; TS 24.501 §5.5.1.2.5, §6.4.1.1,
§9.11.3.6.
Spec text read at `6g_docs/specs/33501-k20.txt`, `23501-k20.txt`, `23502-k20.txt`,
`23401-k00.txt`, `24501-k00_3_Main-Body_s0505_s0506.txt`,
`24501-k00_4_Main-Body_s06_s08.txt`, `24501-k00_5_Main-Body_s09_s10.txt`. Every quotation
below cites a line there.

## Read this first: the issue's spec citation is wrong, and it changes the cost of every option

#361 grounds itself on **TS 33.501 §6.7.2**, six times, as the clause that "provides for
exactly that case". In TS 33.501 k20, §6.7.2 is **"NAS security mode command procedure"**
(`33501-k20.txt:6295`). It is the SMC round-trip; it says nothing about emergency services,
authentication failure, or unauthenticated access. The tree repeats the same mis-cite at
`nas_security.rs:920` and `ngap_path.rs:2709`.

The governing clauses are **§10.2.2** ("Unauthenticated IMS Emergency Sessions",
`33501-k20.txt:12233`) and **§6.7.3.6** ("Algorithm negotiation for unauthenticated UEs in
LSM", `:6550`). Reading them instead of §6.7.2 dissolves the issue's central cost estimate.

### The issue's largest stated cost does not exist

#361 rates option 2 "the largest of the three", and its first-named blocker is:

> It needs a security context with no key hierarchy (every downstream site assumes
> KAMF/KNASint exist)

§10.2.2.3.1 answers that directly (`33501-k20.txt:12388`), verbatim:

> When there has been no successful run of Primary authentication of the UE, the UE and the
> AMF **independently generate the K_(AMF) in an implementation defined way** and populate
> the 5G NAS security context with this K_(AMF) to be used when activating a 5G NAS security
> context. **All key derivations proceed as if they were based on a K_(AMF) generated from a
> successful Primary authentication run.**

and `:12393`:

> Even if no confidentiality or integrity protection is provided by NIA0 and NEA0, the UE and
> the network **treat the 5G security context with the independently generated K_(AMF) as if
> it contained a normally generated K_(AMF)**.

So there is no "security context with no key hierarchy" to build. The spec requires a
*normal-shaped* context whose root is locally generated instead of AUSF-derived. Every
downstream site that "assumes KAMF/KNASint exist" is correct to, and keeps working unchanged.
This is the single fact that moves option 2 from "its own epic" to one PR.

### The issue conflated two conditions the spec distinguishes — and the harder one is not ours

§10.2.1.2 (`:12154`) governs a **normally registered** UE whose authentication fails:

> If authentication fails for any reason, it shall be treated the same way as any registration.

That is the tree's current behaviour, and it is *correct* for a normal registration. §10.2.2.2
governs **Emergency Registration**, which is a different registration type carrying a different
UE intent (`:12335`): "the UE shall know of its own intent to establish an unauthenticated IMS
Emergency Session". The tree parses that type (`registration_type::EMERGENCY = 4`) and already
branches on it at `ngap_path.rs:2106`.

Within §10.2.2.2 the AMF's obligations are enumerated by condition (`:12358`):

> - **If the AMF cannot identify the subscriber, or cannot obtain authentication vector (when
>   SUPI is provided), the AMF shall send NAS SMC with NULL algorithms to the UE** regardless
>   of the supported algorithms announced previously by the UE.
> - After the unsuccessful verification of the UE, the AMF shall send NAS SMC with NULL
>   algorithms ...

"Cannot obtain authentication vector" is *precisely* an unreachable AUSF. The issue was right
that reachability and rejection are different conditions; it did not notice that the spec
addresses the reachability one **first and most explicitly**, and that it is the easier of the
two — no UE response has to be interpreted, because none has been solicited.

§10.2.2.1 (`:12238`) confirms the scope covers availability failure, not just LSM:

> b) UEs that have valid subscription but SN cannot complete authentication **because of
> network failure or other reasons**

## Verified against current main @ `89cb764`

| claim in the issue | check on `89cb764` | still true? |
|---|---|---|
| `start_authentication`'s `Err` arm treats AUSF failure identically for every registration type | `ngap_path.rs:2455-2475` — `gmm_cause_from_sbi_error` → `reject_and_release`, no read of `registration_type` | yes — **real**, and closed here |
| the quoted code block (`// ... reject, then release the UE`) | **stale.** #359 landed as `f969a62`; the arm now carries a 12-line comment and calls `reject_and_release` | code moved, defect unchanged |
| `state.amf_ue.registration_type` "is right there and carries the answer" | **NO — void, and decisively so.** The field is assigned at `:2163` onto a CLONE that `handle_registration_request_nas` never writes back, so at the AUSF-failure arm it was still `0`. A registration-type check there could not have matched EMERGENCY however it was written. See below | **NO — void**; fixed here because the issue cannot be closed otherwise |
| `nia0_permitted(registration_type)` gates NIA0 on emergency | `nas_security.rs:936`; enforced at `ngap_path.rs:2705` | yes |
| NIA0 machinery is "unreachable in practice for its actual purpose" | `select_integrity_algorithm` returns `Some(0)` only when the UE advertised NIA0 alone; no path ever *forces* NIA0 | yes — **real**, and closed here |
| `EmergencyContext::unauthenticated()` and `handle_emergency_registration(id, has_supi)` exist | `emergency.rs:91`, `:187` | yes |
| "the context half exists" | yes, but `has_supi` is computed from SUCI presence (`ngap_path.rs:2108`), which is **identity presence, not authentication outcome** — so a UE that presented a SUCI and then failed to authenticate was recorded `authenticated: true` | **real, and a second defect.** Fixed here |
| TS 33.501 **§6.7.2** permits NIA0/NEA0 for an unauthenticated emergency session | §6.7.2 is the SMC procedure (`:6295`). The permission is §5.2.3 (`:3038`), scoped by §10.2.2 | **NO — void cite.** Substance is right, clause is wrong |
| TS 23.501 §5.16.4 requires emergency support for unauthenticatable UEs where regulation demands | `23501-k20.txt:25188` | yes |
| TS 24.501 §5.5.1.2.5 "lists the emergency exceptions to registration rejection" | `24501-k00_3...:3574` — it lists congestion, CIoT redirection and NSSAA causes. **No emergency exception appears in it.** | **NO — void.** The exception lives in TS 23.502 §4.2.2.2.2 step 8 and TS 33.501 §10.2.2.2 |
| option 2 needs "a Registration Accept path that emits no 5G-GUTI derived from an authenticated identity" | **void.** §10.2.2.3.1 makes the context normal-shaped; `generate_new_guti` (`context.rs:3064`) is a CSPRNG 5G-TMSI plus the AMF's own GUAMI and never derived from subscriber identity | **NO — void** |
| option 2 needs "a decision about what SUPI to register at the UECM when there is none" | **void as a blocker.** TS 23.502 §4.12.2.3 (`23502-k20.txt:25504`): "if the UE was not successfully authenticated, the AMF **shall not update the UDM**" — so the UECM call does not happen and there is no SUPI to invent | **NO — void** |
| option 2 needs "PDU session establishment restricted to the emergency DNN with no UDM subscription" | yes — **real.** §5.16.4.9a (`23501-k20.txt:25599`) requires the *network* to reject non-emergency sessions, and the tree only *records* DNN match (`ngap_path.rs:4564`), never enforces it | yes — **real**, closed here |
| "it also opens an admission surface" | yes — **real**, and the reason for the config gate and the DNN enforcement |
| "§6.7.2 fences it to emergency bearers only" | correct substance, wrong clause: §5.16.4.9a and §5.16.4.9 do the fencing |
| recommendation: "1 now, 2 as its own epic" | superseded by the issue author's own comment, **"choose 2"**, and by the cost re-estimate above |

### Found while verifying: the registration handler DISCARDS everything it parses

Not in the issue, and it is the reason the issue's own premise could not have worked.

`handle_registration_request_nas` obtains the UE record at `ngap_path.rs:2159` via
`self.ue_auth_state.get(..)`, which returns a **clone** — deliberately, so no lock is held
across an `.await` (`ue_store.rs` module docs: "Returns a clone rather than a guard on
purpose"). It then assigns roughly forty fields on that clone and **never writes it back**.
An exhaustive grep of the function's whole body (lines 2020–2392) for `ue_auth_state`,
`with_mut` or `update` finds only the two reads.

So every field the Registration Request contributes was thrown away at the end of the
function: `registration_type`, `suci`, `ue_security_capability`, `gmm_capability.s1_mode`,
`ue_policy_container`, `mapped_eps_guti`, `old_guti`, the SNPN and UAV contexts, the RedCap
indication and its capped UE-AMBR. `start_authentication` opens by *taking* the record out of
the store, so it read the pre-registration context every time.

This makes #361's central claim false as written:

> `state.amf_ue.registration_type` is right there and carries the answer

The field is assigned at `:2163`, but the assignment is to a doomed clone. At the
AUSF-failure arm `registration_type` was still `0`, so **a registration-type check there could
never have matched EMERGENCY, however it was written.** Option 2 was not merely unimplemented;
it was unreachable.

Found by probing rather than by reading — the new branch looked correct and simply never
fired. A temporary test printed `reg_type=None` after driving a live EMERGENCY registration;
after the fix the same probe prints `Some(4)`. Verified against `89cb764` before any of this
change's edits, so it is pre-existing.

Fixed here because #361 cannot be closed without it, in the two identity arms that continue a
procedure (SUCI → authentication, GUTI → Identity Request). The unsupported-identity arm
deliberately still drops the clone: that arm refuses the registration, and persisting a partial
context would leave a UE recorded as mid-registration with no procedure running.

The blast radius is larger than #361 — `s1_mode` gates the §5.5.1.2.4 IWK-N26 indication
(#116), `ue_security_capability` is what the SMC replays for the anti-bidding-down check, and
the RedCap cap fed the N11 SM Context Create (#204). Those are all improved by this fix and
none of them is separately tested here; they are named so the next reader knows the fix is
load-bearing well beyond the emergency path.

### Found while verifying: `has_supi` records identity presence, not authentication outcome

Not in the issue. `ngap_path.rs:2108-2113` computes:

```rust
let has_supi = self.ue_auth_state.get(..).and_then(|s| s.amf_ue.supi.clone()).is_some()
    || req.suci.is_some();
```

At that point in the procedure `supi` is always `None` (it is written only from the AUSF
confirmation at `:2632`), so the predicate reduces to `req.suci.is_some()`. Every emergency
registration that presented *any* SUCI — including one the AUSF then refused, or could not be
asked — was recorded `EmergencyContext::authenticated()`, i.e. `authenticated: true`,
`reg_type: EmergencyWithSupi`. `is_emergency_only()` reads `reg_type`, so it answered `false`
for exactly the UEs §10.2.2 calls unauthenticated.

This matters beyond tidiness: it is the field an operator and a PSAP query to know whether the
caller's identity was verified. TS 33.501 §10.2.2.1 (`:12250`) requires the "unauthenticated
SUPI retained in the network for recording purposes" to be distinguishable from an
authenticated one. It was not.

## The decision: implement §10.2.2, gated on operator configuration, defaulting ON

Option 2, with the configuration gate the issue itself required — and the default is **ON**
(`allow_unauthenticated: true`), which the issue left open.

On an AUSF failure during a registration whose type is EMERGENCY, the AMF now proceeds to a
**limited-service, emergency-only registration** instead of refusing:

1. NIA0 + NEA0 are **forced**, not selected, per §6.7.3.6 (`:6557`): "the AMF **shall** use
   NIA0 and NEA0 as the integrity and ciphering algorithm respectively" — "regardless of the
   supported algorithms announced previously by the UE" (`:6567`). The existing
   `select_integrity_algorithm` negotiation is bypassed for this session only.
2. K_AMF is generated locally from the OS CSPRNG, per §10.2.2.3.1's "implementation defined
   way", and K_NASint / K_NASenc are derived from it by the **unchanged** Annex A.8 KDF —
   §10.2.2.3.1: "All key derivations proceed as if they were based on a K_(AMF) generated
   from a successful Primary authentication run."
3. The UDM, PCF and NSACF steps are **skipped**, per §4.12.2.3 (`23502-k20.txt:25504`): "if
   the UE was not successfully authenticated, the AMF shall not update the UDM. Also for an
   Emergency Registration, the AMF shall not check for access restrictions, regional
   restrictions or subscription restrictions", and `:25508`: "AM and UE policy for the UE are
   not required for Emergency Registration."
4. The Allowed NSSAI is **empty and the IE omitted**, per §4.12.2.3 (`:25468`): "NSSAI shall
   not be included by the UE. The AMF shall not send the Allowed NSSAI in the Registration
   Accept message." The existing 5GMM #62 refusal on an empty Allowed NSSAI is therefore not
   applicable to this path.
5. The Registration Accept carries **Emergency registered = 1** (TS 24.501 §9.11.3.6 octet 3
   bit 6, `24501-k00_5...:4240`), so the UE knows it is emergency-registered and must not
   request a non-emergency session (§6.4.1.1, `24501-k00_4...:8124`).
6. The UE's security capabilities conveyed to the gNB are **narrowed to the null set**, per
   §6.7.3.6 (`:6570`): "Set the UE 5G security capabilities to only contain EIA0, EEA0, NIA0
   and NEA0 when sending these to the gNB/ng-eNB in ... NGAP UE INITIAL CONTEXT SETUP ...
   NGAP HANDOVER REQUEST".
7. A PDU session request on any DNN other than the emergency DNN is **refused**, per
   §5.16.4.9a (`23501-k20.txt:25601`): "the network shall reject any PDU Session Establishment
   request for normal service from the UE on this Access Type".

The `EmergencyContext` is corrected to record the authentication **outcome**.

### Why the default is ON, from the spec and not from convenience

The three candidate defaults are "refuse" (today), "allow", and "no default — startup fails
without an explicit setting". The spec chooses between them.

**TS 33.501 §5.1.2 is a requirement on the system, not a permission** (`33501-k20.txt:2937`):

> **Unauthenticated Emergency Services:** In order to meet regulatory requirements in some
> regions, the 5G system **shall support** unauthenticated access for emergency services.
> This requirement applies to **all MEs** and only to those serving networks where regulatory
> requirements for unauthenticated emergency services exist. Serving networks located in
> regions where unauthenticated emergency services are forbidden **shall not support** this
> feature.

Two obligations, in one paragraph, pointing opposite ways. That is what makes this a config
knob rather than a behaviour — and it is also what decides the default, because the two
obligations are not symmetric in *who can discharge them*:

- The "shall not support" side names a **deployment property**: a network located in a region
  where the feature is forbidden. An operator deploying there knows that fact and must set the
  knob. The spec expects a per-deployment decision, and §10.2.2.2 makes it explicit (`:12310`):
  "It shall be possible to **configure** whether the network allows or rejects an emergency
  registration request".
- The "shall support" side names a **capability of the software**, applying to all MEs. A core
  that defaults OFF does not merely adopt a conservative posture — in a
  mandatory-E911 jurisdiction it ships a build that is non-conformant out of the box, and it
  fails in the one direction where the failure mode is a caller who cannot reach a PSAP.

The asymmetry of *consequence* settles it. The failure of a wrong ON is that an
unauthenticated device obtains an emergency-only, null-ciphered, single-DNN,
no-subscription session — bounded by items 4–7 above, which is exactly the fence §10.2.2 and
§5.16.4.9a specify for it. The failure of a wrong OFF is an emergency call that does not
connect. These are not comparable, and no amount of caution makes them so.

This also matches the house convention recorded in
`specs/decide-oci-shedding-default-and-producer-metric-source.md` — defaults ON except where
the behaviour drops traffic. Here the default ON is what *stops* dropping traffic.

The knob is `amf.emergency.allow_unauthenticated` (bool, default `true`), with
`AMF_EMERGENCY_ALLOW_UNAUTHENTICATED` as a docker-friendly env override. An operator in a
forbidding jurisdiction sets it `false` and gets today's behaviour exactly: refuse and release.

### Rejected options, costed

| option | why not |
|---|---|
| **Option 1 — do nothing, write the ceiling down** (the issue's own recommendation) | Rejected on its own stated reasoning, which no longer holds. Its "For" was "free", and its cost estimate rested on a blocker §10.2.2.3.1 explicitly removes: K_AMF is "implementation defined" and all derivations proceed normally, so the key-hierarchy work it feared is a CSPRNG call. Beyond that, §5.1.2's "shall support" makes "unsupported" a conformance claim this tree would be choosing to make while the enabling machinery (#115's NIA0 gate, #356's `EmergencyContext::unauthenticated`) already sits in the tree unreachable. Documenting a mandatory capability as absent, when it is four spec-quoted steps away, is not honesty — it is deferral with a comment on it. |
| **Option 3 — refuse, but keep the N1 connection for a cheap retry** | The issue's own verdict is right and is adopted: it "does not make an emergency call work; it makes the retry cheaper". It is also *worse than it looks*: §10.2.2.2 obliges the AMF to send a NAS SMC with NULL algorithms in this exact condition, so holding the connection open while refusing the registration performs the procedure's setup and then declines its one required action. A UE that retries into an AUSF that is still down retries forever. |
| **Default OFF, opt-in** (the issue's implied preference: "defaulting it ON in a country that forbids it is as wrong as defaulting it OFF in one that requires it") | The symmetry the issue asserts is real for *legality* and false for *consequence*, and false for *who holds the knowledge* — see above. An operator in a forbidding region knows they are in one; a shipped default cannot know. Also rejected because a default-OFF capability is a capability CI exercises in one state and operators discover in production. |
| **No default — refuse to start without an explicit setting** | Considered seriously, because it is the only option that never guesses a jurisdiction. Rejected because it converts a missing optional YAML key into a failed AMF start, and this config loader is deliberately, documented-ly lenient (`docs-book/src/configuration/amf.md`: "a missing config file, YAML parse error, or missing `amf:` section logs a warning and starts the AMF with defaults — it does not abort"). Making one key fatal in a loader whose contract is "never fatal" trades a stated-and-overridable default for an inconsistent surface. |
| **Skip authentication entirely for EMERGENCY registrations** (the other branch §4.2.2.2.2 step 8 permits: "the AMF skips the authentication **or** the AMF accepts that the authentication may fail") | Rejected. Both are conformant; "try, and fall back" strictly dominates. A UE with a working USIM and a reachable AUSF gets a *real* security context and a real SUPI, and §10.2.2.2's NOTE (`:12345`) relies on that: "In case of authentication success the AMF will send a NAS SMC selecting algorithms with a non-NULL integrity algorithm". Skipping unconditionally would downgrade every emergency call in a healthy network to NIA0 — degrading the common case to simplify the rare one. |
| **Extend this to authentication *failure* (5GMM #20 MAC failure, AUSF `AUTHENTICATION_FAILURE`), not just AUSF unreachability** | Deliberately **not** done here, and recorded as a ceiling rather than a gap — see below. It is conformant and required by §10.2.2.2's second and third bullets, but it is a different condition with a UE-visible interaction (`:12338`: the UE "shall accept a NAS SMC selecting NEA0 and NIA0 algorithms", and §10.2.1.2 case (a)/(b) offers the AMF two behaviours). #361 is scoped to the unreachable AUSF, and that is the condition §10.2.2.2 names first and least ambiguously. Mixing them would put an unreviewed decision about interpreting UE failure messages inside a PR about an availability failure. |
| **A cargo feature instead of a runtime knob** | A gated module rots uncompiled and CI exercises one state. The tree's recorded preference is a runtime switch. |

## Relationship to the EPC/MME decision (`specs/fix-mmed-attach-tau-accept-correctness.md` Decision 4)

The MME side recorded the opposite answer for the 4G equivalent: attach type 3 sets
`MmeUe::emergency_attach` (`nas_dispatch.rs:504`), answers an EPS-only attach result, and logs
at `warn` that "emergency bearer services (unauthenticated access, EIA0/NIA0, emergency APN)
are not implemented, so this attach follows the normal path".

**These are now deliberately different, and the difference is defensible per-spec.** The MME
decision was reached inside a PR about attach/TAU *accept encoding*; it recorded a gap rather
than choosing a policy, and it had no configuration surface to hang a jurisdiction on. The 5GS
answer here is the fuller one because §10.2.2.3.1 gave it a cheap key hierarchy and #115/#356
had already built the NIA0 gate and the emergency context.

**The EPC decision now deserves revisiting, and is not revisited here.** TS 23.401 §4.3.12.1
(`23401-k00.txt:4528`) defines the same four network behaviours TS 33.501 §10.2.2.1 imports by
reference, so the EPC path is under the same regulatory obligation via the same text. Doing it
here would mean a second daemon, a second config surface, EIA0/EEA0 forcing in EMM, and an
emergency-APN restriction — and it would bury a 4G policy decision in a 5G PR, which is the
mistake #361 was filed to avoid in the first place. Filed as a follow-up rather than folded in.

## What changed

### `bins/nextgcore-amfd/src/ngap_path.rs` — the prerequisite fix

- `handle_registration_request_nas` now **persists** the record it mutates, in both identity
  arms that continue a procedure. Without this nothing the Registration Request carried
  survived the function, and the §10.2.2.2 branch below could not fire. The
  unsupported-identity arm still drops it, deliberately: that arm refuses the registration.

### `bins/nextgcore-amfd/src/emergency.rs`

- `handle_emergency_registration`'s second parameter is renamed `has_supi` → `authenticated`,
  because that is what the `EmergencyContext` field it writes means, and the live caller now
  passes `false` unconditionally — nothing is authenticated when a Registration Request
  arrives. `mark_authenticated` / `mark_unauthenticated` promote and demote it as the
  procedure learns the outcome; `is_unauthenticated_emergency` is the predicate the
  downstream restrictions branch on.
- `EmergencyPolicy` resolves `amf.emergency.allow_unauthenticated` and the
  `AMF_EMERGENCY_ALLOW_UNAUTHENTICATED` override, defaulting ON. It is seeded into a
  process-global (`set_allow_unauthenticated_emergency`) because `load_config` runs in
  `AmfApp::init` while the `EmergencyHandler` is built later in `NgapServer::new` — the same
  arrangement, for the same reason, as `context::NAS_SECURITY_CANARY`.
- `EMERGENCY_POLICY_TEST_LOCK` is declared at module scope beside the global it guards, as
  `#[cfg(test)] pub(crate)`, so `ngap_path`'s tests take the same one.

### `bins/nextgcore-amfd/src/ngap_path.rs` — the decision

- `start_authentication`'s `Err` arm consults `state.amf_ue.registration_type`. For EMERGENCY
  with the policy allowing, it calls the new
  `continue_unauthenticated_emergency_registration`; for EMERGENCY with the policy forbidding
  it logs the refusal *and names the setting*, then refuses exactly as before; otherwise it is
  unchanged.
- `continue_unauthenticated_emergency_registration` forces NIA0/NEA0, generates K_AMF from
  the OS CSPRNG, derives K_NASint/K_NASenc through the unchanged Annex A.8 KDF, marks the UE
  `unauthenticated_emergency`, and sends the SMC — rejoining the ordinary path at
  `handle_security_mode_complete_nas`, so the UE-facing flow is the standard one §10.2.2.2(a)
  describes.
- `handle_authentication_response_nas` calls `emergency.mark_authenticated` on 5G-AKA success.
- `complete_registration` skips the UECM/SDM/PCF/NSACF block, and the empty-Allowed-NSSAI
  5GMM #62 refusal, for an unauthenticated emergency UE — while still assigning a 5G-GUTI.
- `handle_5gsm_message` refuses a PDU session on a non-emergency DNN for an
  emergency-registered UE (5GSM #29, TS 24.501 §9.11.4.2), **before** the SMF is dialled.
- `ue_caps_to_ngap_for_ue` narrows the conveyed UE security capabilities to the null set at
  the two converted egress sites; the ICS site narrows the NAS octets it hands `ngap_asn1`.

### `bins/nextgcore-amfd/src/context.rs`

- `AmfUe::unauthenticated_emergency` (default false), the one flag every restriction reads.
- `generate_local_kamf()`, §10.2.2.3.1's "implementation defined way", from the OS CSPRNG.

### `bins/nextgcore-amfd/src/gmm_build.rs`

- `build_registration_accept` sets the **Emergency registered** bit for an EMERGENCY
  registration (keyed on the type, since the restriction it signals applies to an
  authenticated emergency registration too), and forces the Allowed NSSAI source empty for an
  unauthenticated one. The second is not redundant with clearing `allowed_nssai`: the builder
  falls back to `requested_nssai`, which is populated from the integrity-protected SMC replay.

### `libs/nextgcore-nas/src/fiveg/types.rs`

- `RegistrationResult` gains `emergency_registered` (octet 3 bit 6) and round-trips it. The
  field existed in the IE and not in the codec, so the bit could not be sent at all.

### Configuration and documentation

- `configs/amf.yaml` and `docker/rust/configs/5gc/amf.yaml` carry the key explicitly at its
  default, so it reads as a decision rather than an omission.
- `docs-book/src/configuration/amf.md` gains an **Unauthenticated emergency service** section
  stating what each setting does, why the default is `true`, and the four ceilings below.

### Mis-cite corrections

`nas_security.rs` (three sites) and `ngap_path.rs` (three sites) cited §6.7.2 for the NIA0
emergency restriction. Corrected to §5.2.3 (the restriction) and §10.2.2 (the scope). The
§6.7.2 cites that genuinely refer to the SMC procedure and the anti-bidding-down check are
left alone — they are correct.

## Tests

Every behavioural claim below was revert-verified: the change was broken, the NAMED test was
watched to fail, and the change restored.

| test | what it pins | broken by |
|---|---|---|
| `an_emergency_registration_reaches_the_emergency_handler` (rewritten; **it used to assert the opposite**) | the whole §10.2.2.2 continuation: live context, `unauthenticated_emergency`, persisted `registration_type`, NIA0/NEA0, non-zero K_AMF and K_NASint | the policy gate; the persistence fix |
| `an_emergency_registration_is_refused_when_the_operator_forbids_unauthenticated_service` | `false` really refuses, and the branch was reached first | — |
| `the_unauthenticated_emergency_policy_defaults_on_and_env_outranks_yaml` | the default is ON; env > YAML > default, both directions | — |
| `an_emergency_context_records_the_authentication_outcome_not_the_identity` | promote/demote, and that absence is reported rather than silently succeeding | — |
| `a_registration_accept_reports_emergency_registered_and_omits_the_nssai_when_unauthenticated` | the wire bit and the omitted IE, each with an ordinary-registration control | each half independently |
| `an_unauthenticated_emergency_registration_skips_the_udm_pcf_and_nsacf` | no SBI calls, GUTI still assigned, with an authenticated control that IS released | the skip |
| `the_ngap_capabilities_narrow_to_the_null_set_for_an_unauthenticated_emergency_ue` | §6.7.3.6 narrowing, with an ordinary control | the narrowing |
| `an_emergency_registered_ue_is_refused_a_session_off_the_emergency_dnn` | zero SMF requests for a non-emergency DNN, one for the emergency DNN | — |
| `the_config_loader_seeds_the_unauthenticated_emergency_policy` | the YAML reaches a handler built *after* `load_config` | the seed call |
| `gmm_registration_accept_emergency_registered`, `prop_registration_result_round_trip` | octet 3 bit 6 on the wire, and that the two flags in that octet are independent | the bit position |

`an_emergency_pdu_session_is_recorded_only_when_it_is_the_emergency_session` (#356) had its
third arm updated: it asserted that a non-emergency-DNN request was forwarded and merely not
recorded, which is what §5.16.4.9a forbids.

Workspace: **6703 → 6712** passed, 0 failed, 6 ignored. `nextgcore-amfd` re-run 10× at load
average 2.7–2.8: 513/513 every time.

## Ceilings, stated honestly

- **Authentication *failure* is still refused.** Only AUSF unreachability (and any other
  `Nausf_UEAuthentication` error) takes the new path. A UE that answers with 5GMM #20, or an
  AUSF that answers `AUTHENTICATION_FAILURE`, is still refused. §10.2.2.2 requires NULL
  algorithms there too. Scoped out deliberately; filed as a follow-up.
- **No PEI-only (UICC-less) registration.** §10.2.2.1 behaviour (b) "All UEs are allowed"
  admits UEs with only a PEI. `parse_registration_request_pdu` (`ngap_path.rs:8133`) handles
  SUCI and GUTI identities and ignores IMEI, so a truly credential-less UE cannot register at
  all — it is refused before the emergency branch is reached. This tree therefore implements
  §10.2.2.1 behaviour (a), "IMSI required, authentication optional", and not (b). Stated
  rather than silently approximated.
- **No IMS leg.** The emergency PDU session is established on the emergency DNN and the
  P-CSCF address is configurable, but there is no IMS core here, so no SIP INVITE reaches a
  PSAP. That is pre-existing and orthogonal.
- **No AS-layer null-algorithm enforcement in the RAN.** The AMF narrows the capabilities it
  conveys per §6.7.3.6, which is its obligation; whether the gNB honours them is the gNB's.
- **The EPC/MME path is unchanged**, as discussed above.
