# fix(amfd,smfd,ngap): complete the N2/Xn mobility control plane

Closes #70. Three of its seven criteria were already met by prior work; this delivers the
other four.

## Criteria re-verified against `2e1d985` (#70 was written against `76ea248`)

| # | criterion | state |
|---|---|---|
| 1 | HandoverRequest SecurityContext carries an NH derived from KgNB (never zero) with NCC incremented; a test asserts it for a UE with no prior handover | **met** — `context.rs:2769` seeds from `kgnb`; tests `next_hop_chain_is_seeded_from_kgnb_never_from_zero`, `first_handover_conveys_a_non_zero_nh_and_an_incremented_ncc` |
| 2 | N2 and Xn share one NCC-increment/NH-derive helper; a test drives both | **met** — `AmfUe::advance_next_hop`, test `n2_and_xn_derive_identically_for_equal_inputs` |
| 3 | `nextgcore-crypt` exposes FC 0x72 KAMF′ derivation with a test | **met** — `kdf.rs:35` `FC_FOR_KAMF_PRIME_DERIVATION`, `:335` `nextgcore_kdf_kamf_prime`, test `kamf_prime_uses_every_input` |
| **4** | **Xn path switch calls the SMF and uses the SMF-supplied acknowledge transfer, not the inbound one** | **NOT met** |
| **5** | **SMF `PATH_SWITCH_REQ` response carries a non-empty `n2SmInfo` acknowledge transfer** | **NOT met** |
| **6** | **HandoverNotify forwards the target DL tunnel to the SMF and releases the source gNB** | **NOT met** |
| 7 | full workspace lint and tests pass | this PR |

So the dominant defect #70 names — the all-zero NH with NCC=0 — was already fixed. What
remained is that **neither mobility path completes the control-plane relocation**, which is
gaps 4 and 5 of the issue's own list.

## The `PathSwitchRequestAcknowledgeTransfer` did not exist

`nextgcore-ngap::transfer` had `PathSwitchRequestTransfer` (decode-only, what the gNB sends)
and no acknowledge counterpart. That is *why* the AMF echoed: there was nothing else to send,
the AMF never asked the SMF, and the SMF answered with `n2SmInfoType` and no part.

Added per TS 38.413 §9.3.4.9, with all four members optional as the ASN.1 has them. Every
member type (`UpTransportLayerInformation`, `SecurityIndication`, `SecurityResult`,
`QosFlowWithCauseItem`) already existed.

**Why the echo is not a cosmetic problem.** §9.3.4.8 and §9.3.4.9 are different messages in
opposite directions: the request carries the *target's DL* tunnel, the acknowledge carries the
*core's UL* tunnel. Echoing one for the other tells the target gNB to send uplink traffic to
itself.

## Decisions

**The empty acknowledge is a real answer, not a fallback.** Every member of §9.3.4.9 is
OPTIONAL, and an Xn path switch does not move the uplink path — only the DL side moves to the
target. So when the SMF has no recorded UPF uplink endpoint the acknowledge is sent with the
UL tunnel *absent*, which conformantly means "no change". The alternative — inventing a
tunnel — would point the target at something no UPF serves.

**A session the SMF does not acknowledge is left OUT of the switched list.** Not echoed, and
not acknowledged with a fabricated transfer. A gNB that finds a session missing from the
switched list releases it, which is the honest outcome when the core cannot confirm the
switch.

**`upf_ul_endpoints` is a new map, not a widening of `pfcp_sessions`.** That map is keyed and
consumed as "which N4 session serves this context" and every reader wants exactly the SEID.
The uplink endpoint is recorded at establishment because that is the only moment the UPF has
just told us what it is.

**HandoverNotify tells the SMF, not HandoverRequestAcknowledge.** TS 23.502 §4.9.1.3.3 puts
the DL switch at step 12, *after* the UE has arrived. Switching at acknowledge time would
blackhole downlink traffic for the duration of the handover, while the source is still
serving. So the target's transfer is recorded at acknowledge time
(`handover_target_transfers`) and consumed at notify time.

**The source release does NOT go through `release_ue`.** That helper removes `ue_auth_state`,
and the UE has not gone away — it has *moved*. Dropping its context would deregister a UE the
target is now serving. Only the source gNB's copy is released, with cause
`successful-handover`.

**The source identity is captured before the relocation overwrites it.** `association_id` and
`ran_ue_ngap_id` both become the target's, and they are exactly what the release must be
addressed to.

**A failed release does not fail the procedure.** The UE has arrived and the core path is
switched; returning an error would leave the handover half-reported. The leak is logged.

## Verification

Whole workspace **6515 passed / 0 failed** (main: 6508). Clippy warnings **74, unchanged from
main**. `cargo fmt --check` clean. 16 consecutive runs of the three changed crates clean.

### Reverts, all of which bite

| revert | failing test |
|---|---|
| capture the source *after* the relocation (i.e. lose it) | `handover_notify_releases_the_source_ran_context` |
| echo the inbound transfer when the SMF does not answer | `the_switched_list_never_echoes_the_inbound_request_transfer` |
| break the acknowledge transfer's preamble/member order | the `transfer.rs` round-trip tests |

### The echo revert did NOT bite at first, and fixing that changed the code

The first version of the echo revert compiled and **passed**, because the switched list was
built inline in `handle_path_switch_request`, assembled into an acknowledge and immediately
sent — and this harness has no live gNB association, so the send fails and the list is never
observable. The property was implemented and untested.

`switched_list_from_smf` was extracted for exactly that reason, and it is stated in its doc
comment. With the list construction reachable, the revert fails. This is the second time in
this batch that "the revert did not bite" turned out to mean "the property is not covered"
rather than "the property holds".

### Two observables were split because one of them is not testable here

`HandoverCompletion` reports `source_context` (which source the handler *decided* to release)
separately from `source_release_sent` (whether the datagram left). The decision is made from
state the relocation immediately overwrites, so it is the part worth pinning and the part that
was missing; the send needs a live SCTP association and only an E2E can drive it. Collapsing
them into one field would have made the decision untestable — which is what the first draft
did, and its test failed for the wrong reason.

Reporting through a return value rather than a log line follows the crate's existing
convention (`handle_uplink_ran_status_transfer` returns its relay target) and exists because a
handler that logged without sending would pass a log assertion.

## Ceilings

- **nextgsim#39 is still required for an end-to-end handover.** #70's cross-repo note is
  about the gNB side: its inter-gNB N2/Xn path is dead code with no target-side PDU/DRB
  admission and no FC=0x70 KgNB* derivation. Nothing here changes that, and the key
  mismatch it describes remains invisible until both ends move together.
- **No E2E.** Every assertion is in-process. The AMF harness has no live SCTP association, so
  the acknowledge and release *sends* are exercised only as far as the transport call.
- **`HANDOVER_REQ_ACK` is not relayed to the SMF.** TS 29.502 §5.2.2.3.2.2 also has the AMF
  forward the target's transfer at HandoverRequestAcknowledge time with `hoState`; this
  records it and relays at `HANDOVER_COMPLETE` only. smfd already handles both types
  (`main.rs:4201`, `:4213`), so the earlier leg is a wiring addition, not new protocol.
- **The acknowledge re-states the uplink endpoint rather than reallocating.** Correct for
  Xn, where the UL path does not move; a switch that *did* need a new UPF endpoint would need
  the SMF to allocate one, which is a different procedure.
- **`qos_flow_to_release_list` is modelled and encoded but never populated** — the SMF has no
  path-switch-time flow-release decision to express yet.
- **`handover_target_transfers` is in-memory and not persisted**, so an AMF restart mid-
  handover loses the recorded target tunnel. The same is already true of
  `handover_target_assoc` beside it.

## References

- TS 38.413 §8.4.2, §8.4.3 (source release), §8.4.4, §9.3.1.87, §9.3.4.8, **§9.3.4.9**
- TS 29.502 §5.2.2.3.3 (the acknowledge transfer as an N2 SM part)
- TS 23.502 §4.9.1.3.3 step 12 (DL switch after the UE arrives)
- TS 33.501 §6.9.2.3.3, Annex A.10, Annex A.13 — criteria 1-3, already met
- #70; nextgsim#39 (the coupled gNB half)
