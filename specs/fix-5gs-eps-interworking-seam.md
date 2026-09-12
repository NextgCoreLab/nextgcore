# fix(nas,amfd,smfd,docs): the 5GS↔EPS interworking seam, non-N26 path

Closes #116.

#116's criterion 6 is an explicit either/or: deliver the **N26** leg, **or** complete the
**non-N26** path "and document it as the supported mode". This takes the second branch,
which is also the order #116's own suggested approach asks for ("Deliver the lower-risk
non-N26 path first, then the N26 leg behind a feature gate"). The N26 leg is #62.

## Three of #116's cited sites were stale, and two of them would have made this unreachable

Re-verified at `bf57ddd` before any code was written. This is not pedantry: two of the
three would have produced a correct fix in a place nothing calls.

| #116 says | actually | consequence |
|---|---|---|
| criterion 2: populate `context.s1_mode` via the parser at `gmm_handler.rs:52-83` | that parser is **dead**. `gmm_handler::handle_registration_request` has three callers, all inside `mod tests` (`gmm_handler.rs:776`). `ngap_path.rs:6508` already says so: "Mirrors the (dead-code) gmm_handler logic" | done in `parse_registration_request_pdu`, the parser `handle_registration_request_nas` actually uses |
| criterion 7: `ngap_handler.rs:657-658` errors when `handover_type != 0` | **that reject no longer exists.** The only survivor is the `HO_TARGET_NOT_ALLOWED` constant at `:38` | see below — its absence was *worse* than the reject |
| `s1_mode` at `context.rs:1989` | now `context.rs:2070`, on `GmmCapability`, reached as `AmfUe.gmm_capability.s1_mode` | line drift only |

Also already present, contrary to the gap description: `bins/nextgcore-smfd/src/eps_iwk.rs`
(EBI assignment over `Namf_Communication`, from #117) and
`gsm_build::encode_mapped_eps_bearer_context`. So the mapped-EPS-bearer half of
interworking exists; what was missing is the seam #116 lists.

### Criterion 7 was not "an over-strict reject" but a silent mis-handling

With the reject gone, `handle_handover_required` logged the type and then passed
`required.handover_type` **straight into the `HandoverRequest`**. So a `fivegs-to-eps`
preparation was resolved against connected gNBs and either

- failed with `unknown-target-id` — a cause that describes an MME as an unknown gNB, and
  would send an operator hunting a RAN misconfiguration; or
- if some gNB's id happened to match, was **forwarded to a gNB** as a 5GS→EPS handover
  this AMF cannot carry out.

Now declined with `ho-target-not-allowed` (CauseRadioNetwork 8) plus local cleanup. The UE
keeps its registration and PDU sessions — the graceful degradation #116 asks for, not a
hard failure.

## The IWK N26 bit is inverted from the obvious reading

The single most important finding, and the reason the wire constants were read out of the
vendored spec rather than from memory.

`IWK N26` is **not** "N26 supported". TS 24.501 Table 9.11.3.5.1
(`24501-j62.txt:75100`) names it *"Interworking without N26 interface indicator"*:

| bit | means | UE behaviour (§5.5.1.2.4) |
|---|---|---|
| `0` | interworking without N26 **not** supported → the AMF **has** N26 | must use single-registration mode |
| `1` | interworking without N26 supported → the AMF has **no** N26 | may use dual-registration mode |

An implementation that sets the bit because "we support interworking" tells every UE the
exact opposite of the truth, and a UE believing it would expect session continuity on an
inter-system move this core cannot perform. It is also invisible to an encode/decode
test — the same symmetric-defect trap as #91's payload container type.

Two defences: the API is an `enum Iwk26 { N26Supported, WithoutN26Supported }` rather
than a `bool` (at a call site `WithoutN26Supported` cannot be misread the way `true`
can), and `iwk_n26_bit_matches_ts24501_table_9_11_3_5_1` asserts both encodings as
literals against the clause.

**Value shipped: `WithoutN26Supported` (bit SET)**, because this AMF has no N26 leg.

## Criterion 1 — the IE, emitted conditionally

`libs/nextgcore-nas/src/interworking.rs` adds `FiveGsNetworkFeatureSupport` (IEI `0x21`,
TLV, TS 24.501 Table 8.2.7.1), and `RegistrationAccept` gains the field, encoded in
§8.2.7 table order (after `0x11`/`0x31`, before `0x50`) with a decode arm that consumes
the whole contents field so the IE walk stays aligned.

`build_registration_accept` emits it **only to a UE that claimed S1 mode**, because that
is what §5.5.1.2.4 says: *"If the UE included S1 mode supported indication in the
REGISTRATION REQUEST message, the AMF supporting interworking with EPS shall set the IWK
N26 bit"*. A UE that never asked gets the IE omitted, not a bit it has no use for. That
makes criterion 1 depend on criterion 2, which is the right coupling.

Only the two octet-3 bits this core can honestly speak to are modelled; a contents length
of 1 makes the UE read octets 4-6 as zero (§9.11.3.5), and zero is the correct "not
supported" for every bit in them, so three octets of zeroes would assert the same thing
at greater length.

**Stated deviation from criterion 1**: "set according to configured capability" — there is
no config knob. `iwk_n26_posture()` is a constant. Its only other setting would advertise
an N26 interface that does not exist, and a configuration option whose non-default value
is always a lie is worse than a constant. When #62 lands, that function is the single
place that changes.

## Criterion 2 — S1 mode, in the live parser

The 5GMM capability IE (IEI `0x10`, TLV) was walked past by the default TLV arm. Now
parsed for octet 3 bit 1, recorded as `AmfUe.gmm_capability.s1_mode` — which had **no
writer at all** before this.

`claims_s1_mode` **delegates to `FiveGmmCapability`'s existing decoder** rather than
masking the bit itself. That type already derives `s1_mode` from the same octet with the
same mask, and a second `& 0x01` would be a second implementation of one wire fact, free
to drift — the shape that bit #335 (three modules spelling `Pdr` for different types) and
#340 (four hand-maintained wire tables wrong). A test asserts the two agree for **all 256**
octet-3 values, so they cannot diverge silently.

## Criterion 4 — a mapped GUTI is recognised as mapped

There is no separate identity *type* for a mapped 5G-GUTI: §9.11.3.4 has one `5G-GUTI`
value and a mapped one is structurally identical to a native one. That is exactly why
storing it as native was silent.

The discriminator is the **EPS NAS message container** (IEI `0x70`), which was previously
skipped:

- §5.5.1.2.2 requires a UE that maps its 4G-GUTI to include an ATTACH REQUEST in that IE;
- §5.5.1.3.4 case c.2 reads the same way round — *"has included the 5G-GUTI mapped from
  the 4G-GUTI in the 5GS mobile identity IE and not included an Additional GUTI IE"*.

So on a Registration Request carrying a GUTI **and** an EPS NAS message container:

- the mapped identity is reverse-mapped per §2.10.2.1.3 and stored in the new
  `AmfUe.mapped_eps_guti`, **not** in `old_guti` — keeping it where it cannot be mistaken
  for a native 5G-GUTI, and preserving the one identity an MME could be asked about;
- the **Additional GUTI IE** (`0x77`) is now *decoded* rather than merely counted, because
  per §5.5.1.2.2 that is the UE's native 5G-GUTI, and so it — and only it — may become
  `old_guti`;
- the container's presence and size are logged, and its contents are **not** interpreted.
  Decoding an EPS ATTACH/TAU REQUEST *is* the N26 leg (#62); claiming to have processed it
  would be worse than saying it was not.

## Criterion 5 — GUTI mapping in production code

`five_g_guti_to_eps_guti` / `eps_guti_to_5g_guti`, TS 23.003 §2.10.2. Previously the only
such arithmetic in the tree was in `libs/nextgcore-nas/tests` fixtures, so no NF could
perform it.

The mapping is a **bijection** — 8 + 10 + 6 = 24 bits of
`<AMF Region ID><AMF Set ID><AMF Pointer>` against 16 + 8 = 24 of
`<MME Group ID><MME Code>` — which is why it round-trips exactly, and it *has* to be
lossless for §2.10.2.1.3 to work at all (the old AMF must recover its **stored** 5G-GUTI
from the GUTI an MME sends).

The two-bit split of `<AMF Set ID>` across the Group-ID/Code boundary is the part that is
easy to get wrong, and a round-trip test would pass with that split at *any* bit boundary
as long as both directions agreed. So the field values are computed from the clause by
hand and asserted literally, with a separate round-trip over the field boundaries
(including all-ones, where a mask one bit too wide bleeds into a neighbour).

## Criterion 3 — the non-N26 bootstrap

`epsInterworkingInd` (TS 29.502) is parsed from `SmContextCreateData` — it was read
nowhere in smfd — as the four values the OpenAPI defines, not as a bool: `WITHOUT_N26` and
`WITH_N26` differ in *mechanism*, and `IWK_NON_3GPP` is a different interface again, a
distinction #62 will need. An unrecognised value is `NONE`, because the OpenAPI defines the
type as `anyOf [enum, string]` expressly for forward compatibility.

`pgwFqdn` (TS 29.503 `SmfRegistration`, verified against `TS29503_Nudm_UECM.yaml`) is then
added to the UECM registration when **both** hold: the AMF marked the session
EPS-interworking-capable, and `SMF_PGW_FQDN` is set. `IWK_NON_3GPP` deliberately does not
count — it is interworking with non-3GPP access, so no MME will ever look for a PGW-C+SMF
because of it.

**No FQDN is derived when the variable is unset.** TS 23.003 §19.4.2.8 fixes the zone
(`node.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`) and explicitly places it "into the
operator's control", so the leaf label is the operator's to choose: a synthesised name
would be well-formed and still NXDOMAIN. An MME that resolves a fabricated FQDN and fails
is worse off than one that finds no `pgwFqdn` and falls back to its own APN-based PGW
selection. The member is omitted and the reason logged.

An env var rather than a cargo feature, for the reason `eps_iwk.rs` records: CI builds
default features, so a feature-gated path is left uncompiled and rots.

## Criterion 8 — the docs

`docs/features.html` already marked GTPv2-C (S5/S8/N26) as **prototype**, "no wire
listener" — so `index.html`'s "full 4G/EPC interworking" contradicted the project's own
feature matrix, not just the code. Both `index.html:7` and `:39` now claim what is true: a
full 4G/EPC **network-function set** (MME, HSS, SGW, PCRF — which does exist), with
5GS↔EPS interworking named as **partial**, saying which parts work and that there is no
N26 and therefore no inter-system session continuity, and linking the matrix.

## Revert-verify

Five behavioural reverts, each confirmed applied by grep before the run and restored
after, each failing its own NAMED assertion:

| revert | test that failed |
|---|---|
| `iwk_n26_posture()` → `N26Supported` | `registration_accept_carries_iwk_n26_only_for_an_s1_mode_ue` — "IWK N26 SET, meaning 'interworking WITHOUT N26 interface supported'" |
| `req.s1_mode = false && …` | `the_live_parser_captures_ue_s1_mode_capability` |
| `guti_is_mapped_from_eps` → `false && …` | `a_mapped_eps_guti_is_recognised_as_mapped_and_reverse_maps_to_the_4g_guti` |
| `Ht::FivegsToEps => return None` | `an_inter_system_handover_is_declined_with_ho_target_not_allowed` — "FivegsToEps must be refused, not forwarded to a gNB" |
| drop the `body["pgwFqdn"]` assignment | `the_uecm_registration_carries_pgw_fqdn_only_for_an_interworking_session` |

All are **value/condition flips**, not deletions, because a revert that fails to *compile*
proves nothing about the assertion (#48's match-arm lesson).

Criterion 7's test asserts the **decision**, not the transmission: driving
`handle_handover_required` needs an SCTP-connected gNB the unit harness does not have —
`context.rs` says so in as many words. `inter_system_handover_refusal` is split out for
that, the same decision/transmission split used for #70, #91, #48 and #69. It also pins
`HoTargetNotAllowed as i64 == 8` against the spec table, so renaming the enum cannot
silently change the wire value.

## Ceilings, stated rather than implied

- **No N26 leg.** No GTPv2-C toward an MME, no Forward Relocation, no Context Request, no
  inter-system session continuity. That is #62, and every claim shipped here is worded so
  it stays true when #62 lands.
- **The EPS NAS message container is captured, not interpreted.** An ATTACH/TAU REQUEST
  inside it is an EPS NAS message; decoding and acting on it is the N26 leg.
- **`pgwFqdn` is registered, and nothing consumes it here.** It is the bootstrap an
  MME/HSS uses; this core has no MME-facing S5/S8 listener to be found *on* (`features.html`
  already says "no bound GTP-C socket").
- **`mapped_eps_guti` is recorded and has no reader yet.** Deliberate and load-bearing: it
  is the value a Context Request would carry, and recording it is what makes the mapped
  identity survive instead of being flattened into `old_guti`. Named here because
  "production writer, no production reader" is the shape #325/#335/#341 warn about — the
  difference is that the alternative was *losing* the identity, not storing it twice.
- **The EPS→5GS path still asks for a SUCI** and re-authenticates rather than retrieving
  context from the old MME. That is the honest degradation with no N26; it is not session
  continuity.
- amfd's registration parser remains hand-rolled and does not go through
  `nextgcore-nas`'s `RegistrationRequest` decoder. `claims_s1_mode` bridges the two so the
  S1-mode bit has one implementation; the rest of the parser is unchanged.

## Verification

- Workspace **6550 tests, 0 failures** (6538 + 12). `cargo clippy --workspace` 0 errors,
  `cargo fmt --all -- --check` clean.
- Wire constants read out of the vendored specs, not from memory: `24501-j62.txt` (IE
  layouts, IEIs, §5.5.1.2.2/§5.5.1.2.4/§5.5.1.3.4), `23003-k00.txt` (§2.10.2, §19.4.2.8),
  `TS29503_Nudm_UECM.yaml` (`pgwFqdn`), `TS29502_Nsmf_PDUSession.yaml`
  (`EpsInterworkingIndication`).

## Files

- `src/libs/nextgcore-nas/src/interworking.rs` — new: GUTI mapping, the network feature
  support IE, `Iwk26`, `claims_s1_mode`.
- `src/libs/nextgcore-nas/src/fiveg/message.rs` — `RegistrationAccept.network_feature_support`
  plus encode/decode.
- `src/libs/nextgcore-nas/tests/message_roundtrip.rs` — the IE inside a full IE walk, and
  its bytes and IEI order.
- `src/bins/nextgcore-amfd/src/gmm_build.rs` — emits the IE for an S1-mode UE;
  `iwk_n26_posture`.
- `src/bins/nextgcore-amfd/src/ngap_path.rs` — 5GMM capability and EPS NAS container arms,
  Additional GUTI decode, mapped-GUTI branch, `inter_system_handover_refusal`.
- `src/bins/nextgcore-amfd/src/context.rs` — `AmfUe.mapped_eps_guti`.
- `src/bins/nextgcore-smfd/src/udm.rs` — `EpsInterworkingInd`, `pgwFqdn`.
- `src/bins/nextgcore-smfd/src/main.rs` — parses the indication on SM context create.
- `docs/index.html` — the claim matches the delivered path and `features.html`.
