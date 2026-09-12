# fix(smfd,s1ap,mmed): the mapped EPS QCI, and S1AP's two interworking handover types

Closes #62. Splits its criteria 5 and 7 to **#347**.

## The split is the author's own, not a convenience

#62's suggested approach says: *"Consider splitting phases 2–3 (amfd+mmed N26 GTPv2-C + GUTI
mapping) into a follow-on issue."* So this follows the refinement recorded for #108 — when an
issue's own text scopes a part out, file it and close the parent on the rest, stating which
criteria moved and where.

**Split to #347: criteria 5 (N26 GTPv2-C Context Request/Response + Forward Relocation) and 7
(idle-mode TAU-with-N26).** Criterion 9's feature gate goes with them: it gates "the new N26
procedure", and nothing here adds one.

## Five of nine criteria were already met, and one named the wrong members

Re-verified at `54e5aa3`.

| criterion | state |
|---|---|
| 1. mapped EBI + mapped EPS QoS per PDU session | **half met.** #117 stores the EBI, QFI, 5QI and ARP (`eps_iwk::record_mapped_eps_bearer`). The mapped **QCI** had a defect — below |
| 2. `SmContextRetrieve` returns the EPS PDN connection | **met** — #78 added it, #117 made it name the EBI |
| 3. `handle_pdu_session_create` not hardcoded | **met** — #79 replaced the `pduSessionRef "1"` / `REL_DUE_TO_HO` stub with a deliberate `501` |
| 4. 5G-GUTI ↔ 4G-GUTI mapping | **met** — #116, `nextgcore_nas::interworking`, bijective and round-tripped |
| 6. `ho_type_to_s1ap` no longer collapses to `IntraLte` | **gap** — fixed here |
| 8. test | **met** via the `SmContextRetrieve` branch criterion 8 itself offers; extended here |

**Criterion 2 named members that do not belong to the response.** It asks for
`epsPdnCnxInfo`/`epsBearerInfo`. `TS29502_Nsmf_PDUSession.yaml` gives `SmContextRetrievedData`
a **required** `ueEpsPdnConnection` (an `EpsPdnCnxContainer`), and `EpsPdnCnxInfo` /
`EpsBearerInfo` are described as *"from H-SMF to V-SMF, or from SMF to I-SMF"* — a different
interface. The tree already implements the correct member. Recorded because implementing the
issue's spelling would have added two members no AMF reads while leaving the required one as
it was — the same class as #93's divergent config key.

## Criterion 1 — one wire fact with two spellings, and the untested one was wrong

`gsm_build::qci_for_5qi` already existed. `build_ue_eps_pdn_connection` was its **second call
site, and it did not call it**: it pushed `sess.session_qos.index` — the raw 5QI — under a
comment asserting that value "is what maps onto the EPS QCI".

For the standardised 5QIs 1..=9 that is true, which is exactly why it was invisible: every
default session (5QI 9) produced a correct octet. For anything else the container handed to
an AMF, and onward to an MME, **declared a QCI that TS 23.203 does not define**.

The two descriptions of one bearer therefore disagreed:

| audience | path | on a 5QI with no EPS equivalent |
|---|---|---|
| the **UE** | `gsm_build::encode_mapped_eps_bearer_context` → `qci_for_5qi` | omits the mapped-EPS-QoS parameter entirely |
| the **MME** | `build_ue_eps_pdn_connection` → raw 5QI | claims a QCI equal to the 5QI |

That is #335's and #340's shape — two copies of one fact, only the tested one right — and the
untested copy was the one on the interworking path.

**Spec basis.** TS 23.502 Annex C: *"For standardized 5QIs, the QCI is one to one mapped to the
5QI. For non-standardized 5QIs, the SMF+PGW-C derives the QCI based on the 5QI and operator
policy."* So the identity mapping is correct where it applies, and where it does not there is
no value to invent.

**A 5QI with no equivalent now encodes as QCI 0**, which TS 24.301 §9.9.4.3 reserves, with a
warning naming the consequence. The octet cannot simply be omitted the way
`encode_mapped_eps_bearer_context` omits its whole parameter, because #78's container layout
is positional — and a reserved value an MME must reject is a better answer than a plausible
wrong one that it would enforce.

`qci_for_5qi`'s domain (1..=9) is **unchanged** and is a stated ceiling: Annex C permits a 1:1
mapping for every standardised 5QI, and the standardised set (TS 23.501 Table 5.7.4-1) is
`1-10, 65-67, 69-76, 79, 80, 82-90`. #117 chose the conservative subset that certainly has EPS
equivalents. Widening it needs TS 23.203's QCI table to say which of those QCIs exist, and
guessing would put back exactly the defect this fixes.

## Criterion 6 — the two values were absent from the wire enum, not merely unmapped

`nextgcore_s1ap::types::HandoverType` had five values and stopped at `gerantolte`. TS 36.413
(`36413-j20.txt:30619`) says:

```asn1
HandoverType ::= ENUMERATED { intralte, ltetoutran, ltetogeran, utrantolte, gerantolte,
                              ..., eps-to-5gs, fivegs-to-eps }
```

So `mmed`'s `ho_type_to_s1ap` had nothing to map its own `EpsTo5gs`/`FiveGsToEps` onto, and
collapsed both onto `IntraLte` under the comment *"5GS interworking types never reach the S1AP
handover path"*. That framing makes it look like a harmless placeholder. It is not: if one did
reach it, the eNB was handed `intralte` for an inter-system move and would admit it as an
ordinary LTE handover — a wrong value **acted on**, which is worse than an unused branch. The
same collapse existed inbound (`ho_type_from_s1ap`), where it would have recorded the UE as
doing an intra-LTE handover, so every later decision about it concerned the wrong procedure.

**Being past the `...` marker is the interesting part.** These are extension additions, so
X.691 §14.6 encodes them as the extension bit plus a normally-small index — `eps-to-5gs` is
index **0** and `fivegs-to-eps` index **1**, not the constrained values 5 and 6. That works
without touching the codec because `HANDOVER_TYPE_CONSTRAINT` is already
`Constraint::extensible(0, 4)` and `encode_enumerated`/`decode_enumerated` already implement
the extension path (encoding `value - max - 1`, decoding back onto `max + 1 + index`). The
enum values 5 and 6 are internal; the wire form is the extension index.

## Tests

- `handover_type_interworking_values_round_trip_as_extension_additions` — asserts the raw
  octet: extension bit **set**, index 0 then 1, and the round trip. Asserting the byte rather
  than only the round trip is what makes it a conformance test; a round trip alone would pass
  with the values encoded as root 5 and 6, which a peer would read as out of range.
- `handover_type_root_values_are_unchanged` — the extension bit stays **clear** for all five
  root values. The guard that matters for this change: adding values past the marker must not
  shift anything already on the wire.
- `the_retrieved_ue_eps_pdn_connection_carries_a_mapped_qci_not_the_raw_5qi` — drives the real
  retrieve handler, decodes the container, and asserts 5QI 9 → QCI 9 and 5QI 82 → QCI 0. It
  also asserts the two descriptions now agree (`qci_for_5qi(82) == None`), which is the
  disagreement that made this a defect.
- `interworking_handover_types_are_not_collapsed_onto_intra_lte` — both directions, plus all
  five root mappings unchanged.

## Revert-verify

Three behavioural reverts, each grep-confirmed applied and restored, each failing its own
named assertion:

| revert | test that failed |
|---|---|
| `match Some(sess.session_qos.index)` instead of `qci_for_5qi(..)` | `..._carries_a_mapped_qci_not_the_raw_5qi` — "5QI 82 has no standardised EPS QCI, so the reserved QCI 0 goes on the wire" |
| `EpsTo5gs => S1apHandoverType::IntraLte` | `interworking_handover_types_are_not_collapsed_onto_intra_lte` — "must go on the wire as eps-to-5gs, not as intralte" |
| `Constraint::new(0, 6)` instead of `extensible(0, 4)` | `..._round_trip_as_extension_additions` — the extension-index assertion |

The third is the valuable one: making the constraint non-extensible still **round-trips
perfectly** through our own codec, and the test fails anyway — which is the proof that it pins
the wire form rather than self-consistency.

One test bug was found and fixed on the way, worth recording because it looked like a code
defect: the first version extracted the extension index as `(octet >> 1) & 0x3F`, which
reported 0 for both values. A normally-small non-negative is a single `0` bit followed by six
value bits, so after the extension bit the octet is `[ext=1][small=0][v5..v0]` and the index is
`octet & 0x3F`. The encoder was right; the assertion was reading the wrong bits — and it
"passed" for `eps-to-5gs` by coincidence, since index 0 reads as 0 either way.

## Ceilings, stated rather than implied

- **No N26 interface** — #347. Nothing here adds an inter-CN procedure, which is why there is
  no feature gate to add (criterion 9): the two changes are wire-correctness fixes to paths
  that already existed.
- **`qci_for_5qi` still maps only 1..=9**, as above.
- **The QoS octet is the only QoS in the container.** ARP, GBR and MBR are not carried, though
  Annex C says the EPS bearer's ARP/GBR/MBR come from the flow's ARP/GFBR/MFBR.
  `record_mapped_eps_bearer` stores the ARP; #78's container layout has no field for it, and
  widening a positional layout that a peer may already parse belongs with #347, which defines
  the real PDN Connection IE.
- **`ho_type_to_s1ap`'s two new values have no live producer**: nothing sets
  `context::HandoverType::EpsTo5gs` on an S1AP path yet, because that is the TAU/handover
  procedure in #347. The mapping is fixed now so that when a producer arrives it cannot emit
  `intralte` by default — the collapse was the kind of defect that only surfaces once something
  reaches it.

## Verification

- Workspace **6555 tests, 0 failures** (6550 + 5). `cargo clippy --workspace` 0 errors,
  `cargo fmt --all -- --check` clean.
- Wire values read out of the vendored specs: `36413-j20.txt:30619` (the ASN.1),
  `23502-k20.txt` Annex C (the QCI rule), `23501-k20.txt` Table 5.7.4-1 (the standardised 5QI
  set), `TS29502_Nsmf_PDUSession.yaml` (`ueEpsPdnConnection` vs `EpsPdnCnxInfo`).

## Files

- `src/bins/nextgcore-smfd/src/main.rs` — the container carries a mapped QCI; the test.
- `src/libs/nextgcore-s1ap/src/types.rs` — `EpsTo5gs`, `FiveGsToEps` with the extension note.
- `src/libs/nextgcore-s1ap/src/ie.rs` — decode arms; the two wire-form tests.
- `src/bins/nextgcore-mmed/src/s1ap_handler.rs` — both mapping directions; the test.
