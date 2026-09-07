# nextgcore #70 (AMF mobility): seed and advance the {NH, NCC} forward-security chain

Verified against `main` @ `6e02d63`. The issue's cites are from `76ea248`; **all eight were
re-verified and all eight still hold**, at new line numbers.

`Refs #70`, **not Closes**. Ships gaps 1, 2 and 3 — the forward-security break and the missing
KAMF′ derivation. Gaps 4 and 5 (mobility control-plane completion) remain open; see "Scope" below.
The open count deliberately does not move.

## Why this ships alone

CONVENTIONS requires one PR per issue covering all its parts, with one stated exception: *a
safety-critical defect inside an umbrella may ship alone, labelled `Refs #N`, with the PR stating
why it did not wait.* This qualifies, and the enumeration was done before starting rather than
discovered late:

* gaps 1–3 are a **key forward-security break** with no new spec machinery required — `nh_gnb`
  (Annex A.10) already exists and KgNB is already derived and stored;
* gap 4 (N2 control plane) is wiring: `build_ue_context_release_command_asn1` and
  `call_smf_update_sm_context` both already exist;
* gap 5 (Xn → SMF) needs a **`PathSwitchRequestAcknowledgeTransfer` encoder that does not exist
  anywhere in the tree** — a new APER type plus SMF wiring, which wants its own review.

Holding a forward-security break behind that encoder is the failure mode the exception exists to
prevent.

## The defect

Two sites, one chain, three ways of getting it wrong.

`AmfUe::nh` is zero-initialised (`context.rs`) and `kgnb` — derived and stored at AS-security-context
establishment — was **never copied into it**. The only NH derivation chained `nh` from *itself*:
`nh_gnb(kamf, nh)` with `nh` still all-zeros.

* **N2 (`HandoverRequired`)** copied `{nhcc, nh}` into the HandoverRequest `SecurityContext`
  verbatim — no increment, no derivation. A UE that had performed no prior Xn handover shipped
  **32 zero bytes with NCC = 0**.
* **Xn (`PathSwitchRequest`)** did increment NCC and chain the NH, but from that zero seed.

Either way the target gNB derives an AS root key the source gNB — and anyone who logged KgNB — can
reproduce. That is exactly the property the NH chain exists to provide (TS 33.501 §6.9.2.3.3).

## The fix

**Seed once, advance everywhere, through one helper.**

`AmfUe::init_next_hop_chain()` is called immediately after `kgnb` is stored: `NH = KDF(KAMF, KgNB)`
with `NCC = 1`, per Annex A.10 — KgNB itself is the NCC = 0 pair.

`AmfUe::advance_next_hop() -> (u8, [u8; 32])` chains `NH = KDF(KAMF, NH)` and increments
`NCC = (NCC + 1) mod 8`, returning the pair **in the order the NGAP `SecurityContext` fields are
written** so a caller cannot transpose them. Both mobility paths call it, which is what stops them
diverging again — they had diverged in the worst way, one advancing and one not.

The advance-then-send ordering follows the issue's own criterion (*"NCC = previous + 1 (mod 8) for a
UE that has performed no prior handover"*) and matches what the Xn path already did, so the Xn wire
behaviour changes only in the seed.

### A defect the issue does not mention

`save_memento`/`restore_memento` persisted **`nh` but not `nhcc`** — `nhcc` was not even a field on
`AmfUeMemento`. `nh` and `nhcc` are one value: the NCC names the position of that NH in the chain.
Restoring the key while leaving the counter advanced makes the AMF convey a pair that does not
describe itself, and the target derives a key the UE cannot match. Found by reading the memento
while making the pair coherent; fixed by carrying `nhcc` with it.

### Gap 3: KAMF′ (FC 0x72)

`nextgcore_kdf_kamf_prime(kamf, direction, nas_count)` added to `nextgcore-crypt`, with the `S`
construction spelled out in the doc comment so a reviewer holding Annex A.13 can check it by eye:

```text
S = FC(0x72) || P0(direction) || L0(0x0001) || P1(NAS COUNT, 4 octets BE) || L1(0x0004)
```

`KAMF_PRIME_DIRECTION_UPLINK` (0x00) binds to the uplink NAS COUNT as at idle-mode mobility;
`KAMF_PRIME_DIRECTION_DOWNLINK` (0x01) binds to the downlink COUNT as at connected-mode handover.
The COUNT is big-endian, matching the other 5G derivations — note the **EPS-era helpers in the same
file deliberately use native byte order** to stay bit-compatible with the C original, which is a
live trap for anyone copying a neighbour.

It is **not yet called**: gaps 4 and 5 are where mobility re-keying is invoked. Shipping the
primitive with the security fix keeps that follow-up from having to touch the crypto library.

## Verification

Eight new tests. Workspace **5743 passed / 0 failed** (was 5735), `cargo test --workspace` exit 0,
checked for `^error` rather than only a `test result:` line. `cargo fmt --all --check` clean;
`cargo clippy --workspace` (the CI gate) exit 0.

**Revert-verified, one at a time — and the first pass found two of my own tests wanting:**

| revert | test that fails |
|---|---|
| seed the chain from zeros again | `next_hop_chain_is_seeded_from_kgnb_never_from_zero` |
| stop incrementing NCC | `first_handover_conveys_a_non_zero_nh_and_an_incremented_ncc` |
| drop `nhcc` from the memento | `memento_restores_the_nh_and_ncc_together` |
| N2 copies the stored pair | `both_mobility_paths_route_through_the_shared_next_hop_helper` |
| drop the KAMF′ direction parameter | `kamf_prime_uses_every_input` |
| native byte order for the KAMF′ COUNT | `kamf_prime_matches_its_golden_vectors` |

The last two rows are the interesting ones, because on the **first** revert pass neither failed:

* **The N2 wiring was uncovered.** The derivation is unit-tested, but nothing drove the emission
  site — amfd has no harness for `handle_handover_required` — so reverting N2 to copy the stored
  pair compiled and passed everything. Fixed with a source guard that positively asserts the two
  mobility sites and the single seed site, plus a negative on the defective expression. It lives in
  `context.rs` and reads `ngap_path.rs` **deliberately**: a guard grepping the file it lives in
  matches its own needle, including inside the comment explaining it — a trap this repo has already
  been bitten by.
* **My endianness test proved nothing.** It asserted only that two different COUNTs give different
  outputs, which is true under either byte order — a negative assertion satisfied by the very defect
  it was meant to catch. Replaced with golden vectors generated from the implementation and pasted,
  not typed.

**Not verified:**

* **No 3GPP test vector exists for FC 0x72 KAMF′**, in this tree or available to this session. The
  golden vectors pin *our* construction, so any change to the FC, parameter order, a length or the
  byte order fails the test — but agreement with 3GPP rests on the doc-commented `S` layout being
  read against Annex A.13 by a reviewer. **Interop against a real peer AMF is the outstanding
  validation, and this is the single highest-value review item in the change.**
* No real gNB, UE or handover was exercised. The chain is asserted at the `AmfUe` level; the emission
  sites are covered by a source guard, which proves the call is present, not that the encoded NGAP
  `SecurityContext` is correct on the wire.
* Docker E2E remains skipped by CI.
* GitNexus impact analysis, mandated by this repo's CLAUDE.md, was **not run** — no GitNexus MCP
  server was connected. Caller analysis was grep-based: every `.nh`/`.nhcc`/`.kgnb` use in amfd
  (12 sites, 2 of them the memento) and both `nextgcore_kdf_nh_gnb` callers.

## Scope: gaps 4 and 5 remain open, with the plan recorded

Stated up front rather than discovered late, so the next session does not re-derive it.

**Gap 4 — N2 handover control plane.** `HandoverNotify` mutates only in-memory serving state. It
must additionally (a) tell the SMF the target DL tunnel via `Nsmf_PDUSession_UpdateSMContext` —
`call_smf_update_sm_context` exists at `sbi_path.rs:986` — and (b) send a `UEContextReleaseCommand`
to the **source** gNB and drop its RAN-UE context;
`build_ue_context_release_command_asn1` exists at `ngap_asn1.rs:837`. The blocker is not machinery
but bookkeeping: the source association and RAN-UE-NGAP-ID are **overwritten** on the Xn path
(`state.ran_ue_ngap_id = req.ran_ue_ngap_id; state.association_id = association_id;`), so the source
identity must be captured before the switch or the release cannot be addressed. Cross-gNB relocation
(target RAN-UE-NGAP-ID allocation, T304, `HandoverRequestAcknowledge`→`HandoverCommand` stitching) is
marked "future work" at `ngap_path.rs:4522` and is the larger part.

**Gap 5 — Xn path switch → SMF.** `handle_path_switch_request` echoes the inbound
`PathSwitchRequestTransfer` back as the acknowledge transfer (`p.transfer.clone()`), and never calls
the SMF. The SMF's `PATH_SWITCH_REQ` branch returns only
`{upCnxState: "ACTIVATED", n2SmInfoType: "PATH_SWITCH_REQ_ACK"}` with no `n2SmInfo` binary part
(`smfd/main.rs:2607-2609`), and is unreachable because the AMF never invokes it — so both halves are
broken and neither can be tested against the other today. **`PathSwitchRequestAcknowledgeTransfer`
does not exist anywhere in the tree**, so this needs a new APER encoder first; that is the reason
gap 5 is not in this PR. Note the SMF *does* already perform a PFCP DL-FAR modify from the decoded
endpoint just above (`main.rs:2558`), so the user-plane DL is partially updated — which is why the
missing acknowledge transfer has not shown up as an outage.

## Definition of done

- [x] N2 `HandoverRequest` carries an NH derived from KgNB (never all-zero) with NCC incremented
- [x] N2 and Xn share one NCC-increment/NH-derive helper; a test drives both for equal inputs
- [x] `nextgcore-crypt` exposes FC 0x72 KAMF′ derivation with vectors (ours, not 3GPP's — see above)
- [x] `nh` and `nhcc` survive a memento round trip as a pair (not in the issue; found while fixing)
- [ ] `handle_path_switch_request` calls the SMF and uses the SMF-supplied acknowledge transfer — **#70 gap 5**
- [ ] SMF `PATH_SWITCH_REQ` response includes a non-empty `n2SmInfo` transfer — **#70 gap 5**
- [ ] `HandoverNotify` updates the SMF's DL tunnel and releases the source gNB — **#70 gap 4**
- [x] Full workspace lint and test suites pass
