# fix(amfd,udmd,udrd,ausfd,crypt): NIA0 emergency-only, TUAK, key zeroization, SNPN SN name

Closes #115, all four parts.

## The issue's cites had drifted, and the load-bearing one was wrong about the mechanism

#115 was written against `76ea248`. Re-verified at `2e1d985`:

| #115's claim | still true? |
|---|---|
| `udmd/app.rs:1749-1750` AV generation is MILENAGE-only, no branch | **YES**, now at `app.rs:3128` |
| `udmd/nudr_handler.rs:719-720` — a second unconditional call site | **NO** — gone; there is exactly one |
| `nextgcore-crypt` has no `tuak.rs` | **YES** |
| `udrd/main.rs:2185-2201` stores no f1-f5* identifier | **YES**, now at `main.rs:994-1010` |
| `amfd/ngap_path.rs:1975` — the live SMC path calls `select_integrity_algorithm` directly | **NO** — that line does not exist; the live path is `ngap_path.rs:2149-2190` inside `handle_authentication_response_nas` |
| `nas_security.rs:907-908` returns `Some(0)` for a NIA0-only UE | **YES**, now `:908` |
| `amfd/context.rs:1933-1948` keys in plain arrays | **YES**, now `:1971-1985`, and there is a SECOND copy at `:2234-2263` (`AmfUeMemento`) that #115 does not mention |
| no `zeroize` anywhere in amfd/udmd; `ausfd` already zeroizes | **YES** |
| `ausfd/context.rs:192-207` `derive_kausf_with_nid` is a no-op stub with zero callers | **YES**, and worse than described — see below |

### The NIA0 defect is real, by a different route than #115 states

#115 says the live path "applies whatever it returns" with no fail-close. That is not so: the
path already rejects the registration on an empty NIA intersection
(`ngap_path.rs:2168-2183`), and it builds the AMF mask as
`algorithm_order_to_mask(&ctx.integrity_order, 0x0E)` — a mask with NIA0 excluded.

So the natural reading is "already fixed". It is not, and the reason is one line:
`algorithm_order_to_mask` (`ngap_path.rs:6880`) returns its `default_mask` **only when the
configured order is empty**. A deployment that lists NIA0 in `integrity_order` gets bit 0
set, the intersection with a NIA0-only UE is non-empty, `select_integrity_algorithm` returns
`Some(0)`, and an ordinary registration runs with no NAS integrity protection at all.

Recorded because the corrected mechanism changes where the fix goes: not "add a fail-close",
which exists, but "add a session-level gate to a selection that legitimately returns NIA0".

## The four parts

### 1. NIA0 emergency-only gate (`nas_security::nia0_permitted`)

TS 33.501 §6.7.2 permits NIA0 only for an unauthenticated emergency session. The gate keys
on `amf_ue.registration_type == registration_type::EMERGENCY`, which is populated from the
Registration Request at `ngap_path.rs:1776` — before the SMC path at `:2149`, so the
information is there.

**A function, not an inline check**, and it is the only decision point. Inlining would leave
the rule untestable without an AUSF, an NGAP association and a UE; duplicating it into a test
would prove only that the copy agrees with itself.

**Not inside `select_integrity_algorithm`**: that is a pure function of two algorithm masks
with no session to consult. Masking NIA0 out there would report an *empty intersection*,
telling the operator their configuration is unsupported rather than that this request is
refused — a materially different message.

Permitted NIA0 is logged at warn: an emergency session with no NAS integrity is a deliberate,
spec-sanctioned exception, and an operator should be able to tell it from the defect.

#115's suggestion to route through `validate_algorithm_policy` /
`select_security_algorithms_with_policy` was **declined**. Those take a `NasCipheringPolicy`
with no notion of an emergency session, so routing through them would have answered a
different question (is null permitted by policy) than the spec asks (is this session an
emergency). `select_security_algorithms_with_policy` also writes `selected_*_algorithm`
itself and force-overrides to NIA2/NEA2 in one arm (`nas_security.rs:1018-1025`), which would
have re-fabricated exactly the algorithm the existing fail-close exists to prevent.

### 2. TUAK f1-f5* (`nextgcore-crypt/src/tuak.rs`)

Keccak-f[1600] plus TOPc derivation and f1, f1*, f2, f3, f4, f5, f5*, with a
`tuak_generate` returning the same tuple in the same order as `milenage_generate` so the two
are interchangeable at a branch.

**The whole difficulty is bit ordering.** TS 35.231 writes the permutation input as
`IN[0] .. IN[255] = TOPC[255] .. TOPC[0]` — read literally, a full bit reversal. It is not,
because §5.2 says inputs are mapped so that "bits of input and output should not need to be
reversed within bytes": `IN` is indexed LSB-first within a byte while 3GPP parameters are
numbered MSB-first, and the two reversals cancel. What survives is a **byte reversal**.

That was not reasoned out and hoped for — it was read off TS 35.232 §6.3's intermediate
values, which the tree vendors at `6g_docs/specs/35232-j00.txt`: for
`TOPc = bd04…40cccbff` the document shows `IN` beginning `ff cb cc 40`, and `ALGONAME`
"TUAK1.0" appearing as `30 2e 31 4b 41 55 54` — "0.1KAUT". The `INSTANCE` octet is the one
field with a genuine intra-byte bit reversal, because it lives entirely inside one byte and
so has no byte reversal to cancel against; the documented `0x08` (f1) and `0x88` (f1*) pin it.

`TuakError` rather than a reuse of `MilenageError`: that enum's variants are `AesError`,
`MacMismatch`, `SyncFailure` and `InvalidLength`, and the first cannot occur in a Keccak
algorithm. Only lengths are checkable, so there is one variant, and it names *which*
parameter was wrong.

### 3. Key zeroization (amfd)

`zeroize_keys()` plus `Drop` on **both** `AmfUe` and `AmfUeMemento` — the second is a copy of
the same keys taken so a failed procedure can be rolled back, so dropping it uncleared leaves
them recoverable. Covers `kamf`, `knas_int`, `knas_enc`, `kgnb`, `nh`, and also `rand`,
`autn`, `xres_star`, `hxres_star`: not keys, but retaining the challenge and expected
response beside cleared keys still leaves something to verify against.

**`Drop`, not a call in `amf_ue_remove`.** That function RETURNS the removed context and its
own body reads `removed.supi` afterwards, so zeroizing there would clear a value the caller is
about to use — or need sequencing after every caller's last read, which is the kind of
obligation that goes stale. `Drop` covers every teardown path, including ones a grep for
"remove" would not find.

**Deviation from #115's suggested approach, stated as the conventions require.** #115 says to
wrap the fields in `Zeroizing`. This uses the `Zeroize` trait on the existing arrays instead:
the fields are read at 75 sites across amfd and a wrapper needs `Zeroizing::new` at every
write, where a missed one is a silent regression the compiler cannot distinguish from an
intentional plain array. It also matches the precedent #115 itself cites as already-correct
(`ausfd::AusfUe::zeroize`). The security property the criterion asks for — cleared on drop,
not elided, test-asserted — is what `Zeroize` provides. `ausfd`'s plain `= [0u8; 32]` does
**not** provide the no-elision half and is worth converting separately.

`zeroize` 1.8.2 was already in amfd's dependency graph via `p256`/`elliptic-curve`, so this
declares a direct use of code already compiled in.

Adding `Drop` forbids `..Default::default()` on these types and moving fields out of them; 5
call sites were adjusted (3 `.and_then(|ue| ue.supi)` → `.clone()`, 2 test constructors built
then mutated).

### 4. SNPN serving network name — and why the stub was removed rather than implemented

`ausfd::AusfUe::derive_kausf_with_nid` was wrong in a way implementing could not fix:

- **The AUSF does not derive K_AUSF at all.** TS 33.501 §6.1.3.2 has the UDM/ARPF compute
  CK/IK and derive K_AUSF, then send the 5G HE AV to the AUSF — which is what this build does.
- It built `5G:{serving_network_name}:NID-{nid}` where `serving_network_name` already began
  with `5G:`, so `5G:5G:mnc….3gppnetwork.org:NID-x`: a duplicated service code and a `NID-`
  prefix the spec does not have.
- It had no callers.

The construction belongs to the SEAF (§6.1.1.4.3), so it now lives in amfd as
`snpn_serving_network_name`, built from the authoritative rule: §6.1.1.4.1 makes the name
`"5G" ":" SN Id`, and **Annex I.3.2 redefines the SNPN SN Id as `PLMN ID:NID`**. The live
`start_authentication` path uses `serving_network_name_for_ue`, which augments when
`amf_ue.snpn_nid` is set and is byte-identical to before when it is not.

Why it matters: everything derived from this string — K_SEAF, K_AUSF, CK'/IK', (X)RES* — is
bound to the serving network through it, so without the NID two SNPNs sharing a PLMN ID derive
the *same* anchor key and a UE authenticated to one would be accepted by the other. That is
what Annex I.3.1 means by the definition "needs modification".

`ausfd` keeps `serving_network_is_snpn` / `serving_network_nid`, which is what an AUSF can
honestly do with the string: recognise it.

### The `algorithmId` semantics #115 gets wrong, and it changes the design

#115 asks to "extend the UDR `AuthenticationSubscription` with an f1-f5* algorithm
identifier". TS 29.505 §5.2.3 says `algorithmId` "identifies a parameter set securely stored
in the UDM (ARPF) that provides details on the algorithm and parameters used to generate
authentication vectors. Values and their meaning are **HPLMN-operator specific**."

So it is not an enum and there is no standard value to match on. The UDR therefore stores and
returns it verbatim, and `udmd::av_algorithm` is the UDM-side parameter set the spec refers
to: it recognises `tuak` / `tuak1.0` / `milenage` case-insensitively and reads
`UDM_TUAK_ALGORITHM_IDS` for any others, so an operator whose sets are numbered does not need
a code change. `encTopcKey` was already in the vendored OpenAPI and is now stored, validated
and served.

**An absent or unrecognised `algorithmId` resolves to MILENAGE.** That is the only safe
default and the one thing that must not change: every subscriber provisioned before this
change has no identifier, and the members are OMITTED from the GET rather than served empty,
so those responses are byte-identical to before.

**A TUAK subscriber with no TOPc is refused (500), not served a MILENAGE vector.** OPc is
128-bit and TUAK's operator field is 256-bit, so there is no substitute; a MILENAGE vector
here would be one the UE can never verify, surfacing as a UE-side MAC failure that tells the
operator nothing about the provisioning gap.

## Verification

Whole workspace **6503 passed / 0 failed** (main: 6472). Clippy warnings **74, unchanged from
main** — 5 were introduced and all 5 fixed. `cargo fmt --check` clean.

### TUAK is byte-exact against vendored 3GPP test data

Not against its own encoder. 13 tests, all from `6g_docs/specs/35232-j00.txt` and
`35233-j00.txt`:

- **Keccak-f[1600] alone**, twice: §5.4's `80 00 …` state and §5.3's full pseudo-random state.
  Separate from every TUAK mapping, so a broken permutation says so itself instead of failing
  all the vector tests together with no clue which layer is wrong.
- **TOPc, f1, f1\*** from §6.3, and **f2, f3, f4, f5, f5\*** from §7.3.
- **The `IN` intermediate values** for both TOPc and f2-f5. Asserting the INPUT and not only
  the output is what localises a mapping error: a wrong byte order in `IN` and a wrong
  extraction from `OUT` can cancel in a round trip, and the permutation between them would
  hide both.
- The §7.3 vector uses a 32-bit RES, whose `INSTANCE[2..4]` is all-zero — the same length
  field the TOPc derivation uses — so it also proves the two are distinguished by
  `INSTANCE[0..1]` and not by the length bits.

### Reverts, all of which bite

| revert | named test that failed |
|---|---|
| `nia0_permitted` always true | `nia0_is_permitted_only_for_an_emergency_registration`, `the_gate_keys_on_the_emergency_registration_type_value` |
| remove `impl Drop for AmfUe` | `dropping_a_ue_context_clears_its_key_material`, `a_ue_removed_from_the_context_has_its_keys_cleared_on_drop` |
| UMIC/`INSTANCE`/carrier changes in TUAK | the relevant vector test, per the module's own tests |

### One test was NONDETERMINISTIC and was rewritten, which is the finding

The first zeroization test `Box`ed the context, kept a pointer, dropped it and read the
pointer back. That reads memory **returned to the allocator**, so whether the old bytes are
still there is the allocator's decision. It passed and failed on alternate runs against
unchanged code — worse than no test, because it would have reported the zeroization broken at
random and could equally have reported it working when it was not. It is also what made an
earlier revert-verify of the `Drop` impl invalid: the "failure" observed was the flake, not
the revert.

Rewritten with `MaybeUninit` + `drop_in_place`, which runs the same destructor over storage
**the test frame owns for its whole lifetime** — nothing can reuse it, so the read is
deterministic. Same destructor, sound observation. The `Drop` revert was then re-run and does
bite.

16 consecutive runs of all six changed crates clean.

## Ceilings

- **Cross-repo: nextgsim#31 and #32 are still required for the end-to-end posture.** #115
  carries a note that it must be scheduled with them, and that note is about the *radio* side:
  the UE never processes SecurityModeCommand and discards the derived AS keys, and the gNB
  drops K_UPenc/K_UPint and never decodes the SecurityIndication IE. The AMF's own decision —
  refuse NIA0 outside an emergency — is core-side and is what is verified here. **The DRBs
  still carry clear data regardless of this change**, and that is not fixed by anything in
  this PR.
- **TUAK is reachable only through `algorithmId`; nothing provisions it in this tree's
  configs or compose files.** The path is implemented and tested, not exercised by a running
  deployment.
- **TUAK's longer variants (256-bit K/CK/IK, 128/256-bit MAC and RES) are implemented and
  vector-tested at the function level, but `tuak_generate` fixes the 3GPP AV shape** — 64-bit
  MAC-A, 64-bit RES, 128-bit CK/IK — because that is what AUTN and the Nudm AV schema carry.
- **`ausfd`'s own zeroization is still the plain-assignment kind**, which the optimiser is
  permitted to elide. Converting it to `Zeroize` is a separate change; #115 explicitly scopes
  ausfd out.
- **No emergency-registration integration test.** `nia0_permitted` is unit-tested over every
  registration type, and the live path has exactly one call site, but no test drives a full
  emergency registration through `handle_authentication_response_nas` — that needs an AUSF, an
  NGAP association and a UE, and `amfd::emergency` is itself an unreferenced module.
- **`amfd::emergency` remains unused.** It declares `EmergencyContext`, `EmergencyHandler`
  and `is_emergency_only` and nothing in amfd calls any of them; the gate uses the
  registration type from the wire instead, which is what the live path actually has.
- **No E2E.** Everything in-process.

## Criterion table

| # | criterion | status |
|---|---|---|
| 1 | AV generation selects the algorithm from a per-subscription identifier; TUAK → TUAK AV, MILENAGE/absent → MILENAGE AV | **met** |
| 2 | TUAK f1-f5* validated byte-exact against TS 35.231 golden vectors, with a unit test | **met** — 13 tests from TS 35.232/35.233 |
| 3 | UDR stores and returns an algorithm identifier alongside `authenticationMethod`/`encPermanentKey` | **met** — plus `encTopcKey`, both validated |
| 4 | the live SMC path fail-closes on NIA0 for a non-emergency session; emergency still permitted | **met** — with the mechanism corrected |
| 5 | AMF key material cleared on drop and per-UE teardown, test asserts the buffer is zeroed | **met** — for `AmfUe` and `AmfUeMemento` |
| 6 | `derive_kausf_with_nid` implemented with a test, or removed with no dangling references | **met** — removed, and replaced in the NF that owns the construction |
| 7 | whole-workspace lint and tests pass | **met** |

## References

- TS 33.501 k20 (`6g_docs/specs/33501-k20.txt`): §5.9, §6.1.1.4, §6.1.3.2, §6.2, §6.7.2,
  Annex A.2, **Annex I.3.2**
- TS 35.231 j00, TS 35.232 j00 (implementers' test data), TS 35.233 j00 (design conformance
  test data) — all vendored under `6g_docs/specs/`
- TS 29.505 k00 §5.2.3 (`algorithmId`, `encTopcKey`); `docs/openapi/nudr-dr.yaml`
- #115; nextgsim#31, nextgsim#32 (the coupled radio-side halves)
