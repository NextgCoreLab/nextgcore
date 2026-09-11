# fix(mmed,s1ap,sgwcd): S1 Status Transfer, data forwarding, and Handover Cancel release

Closes #48. Both of its workstreams — (a) `mmed` + `nextgcore-s1ap` and (b) `sgwcd`'s S11
CIDFT — in one PR, per the whole-issue convention. #48 calls them "independently testable",
which they are, but it does not mark either separable, and the forwarding path does not
exist unless both land: the MME's request and the SGW's response are two halves of one
F-TEID exchange.

## Claim-vs-site-vs-still-true

Re-located against `741f0e9`. Every claim held, and two IE numbers the issue does not
mention turned out to be wrong.

| # | #48's claim | site now | still true? |
|---|---|---|---|
| 1 | no eNB/MME Status Transfer decode; proc 24 is a dead enum entry | `parser.rs` had no arm for `ENB_STATUS_TRANSFER`; `sm.rs:746` | **yes** |
| 2 | a mid-handover STATUS TRANSFER is answered with Error Indication | `s1ap_handler.rs` `S1apMessage::Unknown` arm | **yes** |
| 3 | `HandoverRequired` has no Direct Forwarding Path Availability field | `types.rs:430` | **yes** |
| 4 | `ErabAdmittedItem` DOES decode the DL/UL forwarding TEIDs | `types.rs:1135` | **yes** — decoded and then discarded |
| 5 | `handle_handover_request_acknowledge` stores only `gtp_teid` | it stored exactly those two fields | **yes** |
| 6 | `HandoverCommand` always built with an empty forwarding list | `erab_subject_to_forwarding_list: Vec::new()` | **yes** |
| 7 | `handle_handover_cancel` never releases the target | it cleared `target_ue_id` and removed the context, no release | **yes** |
| 8 | no handover-preparation supervision timer | nothing on `EnbUe` held a deadline | **yes** |
| 9 | the dispatcher passes `&[]` into the CIDFT handlers | `gtp_path.rs` `dispatch_indirect_tunnel_request` | **yes** |
| 10 | the CIDFT handler ignores the body and allocates nothing | `s11_handler.rs` | **yes** |
| 11 | `bearer_add` never adds forwarding tunnel types | `context.rs:902` adds only S5/S8 and S1-U | **yes** |
| 12 | forwarding F-TEIDs are emitted only for tunnels that never exist | `s11_build.rs:381` | **yes** |

### Three wire-format constants #48 does not mention, all wrong, all inert

Found while making the CIDFT path reachable. Values read from the vendored spec
(`6g_docs/specs/29274-j60.txt`), not from memory:

| constant | said | TS 29.274 §8.22 says | what the wrong value means |
|---|---|---|---|
| `mmed` `S1U_ENB_GTP_U_DL_FORWARDING` | 4 | **19** (`eNodeB/gNodeB GTP-U for DL data forwarding`) | 4 is "S5/S8 SGW GTP-U interface" |
| `sgwcd` `SGW_GTP_U_DL_DATA_FORWARDING` | 22 | **23** (Table 7.2.19-2 NOTE 3) | 22 is "SGSN GTP-U for data forwarding" |
| `sgwcd` `SGW_GTP_U_UL_DATA_FORWARDING` | 23 | **28** (Table 7.2.19-2 NOTE 4) | 23 is the DL value, so both directions went out identical |

Plus one instance number: `sgwcd` emitted its UL forwarding F-TEID at **instance 1**, which
Table 7.2.19-2 assigns to "S12 SGW F-TEID for DL data forwarding". A conformant MME would
have read the UL endpoint as a second DL one on an interface the deployment does not have.
It is now instance **4**.

This is the same latency that hid `smfd`'s `S_NSSAI = 250` (#321): a hand-maintained wire
table is wrong, and nothing notices because the emitting branch has no caller. Both crates
now carry `f_teid_interface_types_match_ts29274_clause_8_22`, asserting the numbers as
literals against the clause — a 30-row wire table cannot be kept correct by review.

`mmed` also had no UL forwarding constant at all, so the UL half of a forwarding pair was
inexpressible.

## What it does

### Status Transfer (criteria 1, 2)

`nextgcore-s1ap` gains `EnbStatusTransfer` (proc 24) and `MmeStatusTransfer` (proc 25) —
types, parser, builders — and `mmed` relays the container from the source to the target
under the **target's** UE ids.

The container is carried as the **raw APER open-type value** and re-emitted verbatim, never
decoded. §8.4.6's whole purpose is that the PDCP SN/HFN counts arrive UNCHANGED; putting a
`Bearers-SubjectToStatusTransfer` codec between the two eNBs would make every modelling gap
a silently corrupted PDCP count. `encode_enb_status_transfer_container` therefore pushes a
`ProtocolIeField` directly rather than going through `push_ie`, because re-running the bytes
through an `AperEncoder` that pads differently from the peer that produced them is exactly
the corruption to avoid. Byte-preservation becomes a property of the type, not of a test.

### Direct vs. indirect forwarding (criteria 3, 4, 5)

`HandoverRequired` decodes `Direct-Forwarding-Path-Availability` (IE **79**, read from
`36413-j20.txt:34389`; a value guessed from neighbouring handover IEs would be wrong, since
79 sits between the 60s and `id-UEIdentityIndexValue`). Modelled as
`Option<DirectForwardingPathAvailability>` rather than a `bool`: the ASN.1 has exactly one
root value, so PRESENCE carries the whole meaning, and a `bool` invites a caller to write
`false` where the wire has no IE at all. **Absent selects indirect forwarding**, which is
the reading that matters.

`handle_handover_request_acknowledge` now records the admitted `dl_gtp_teid`/`ul_gtp_teid`
and their addresses on the bearer, and builds the Handover Command's E-RABs Subject to
Forwarding List from them.

### The deferral, which is not an optimisation

For the indirect case the Handover Command **cannot** be built when the ack arrives: the
endpoints the source must forward to are the SGW's, and the SGW allocates them in the CIDFT
Response. So `mmed` sends the S11 CIDFT, returns nothing, and sends the command from
`s11_handler`'s response path. That is the only order in which the command can carry real
endpoints; sending it immediately with an empty list is what the code used to do.

The ack's own contribution is parked on the target context as `PendingHandoverCommand` and
**taken** (not cloned) when the response lands, because TS 29.274 §7.6 makes a GTP-C
response retransmittable and a second Handover Command would have the source hand the UE
over twice.

Failure handling is stated rather than implied: when the SGW refuses, or the request cannot
be sent, the handover **completes without forwarding** and the loss is logged. A UE that
loses its buffered downlink data is better off on the target than stranded between cells —
but falling through with the TARGET's endpoints instead would tell the source to forward
over a path it just said it does not have, which sends the data into a black hole rather
than dropping it.

### Handover Cancel and preparation supervision (criterion 6)

`handle_handover_cancel` sends a UE Context Release Command with cause
`handover-cancelled` to the prepared target before dropping the MME's record of it —
otherwise the target keeps its radio, S1-U endpoint and UE context with nothing left that
could ever ask for them back, since the ids that addressed it are gone.

The supervision timer rides `MmeApp::run`'s existing 100 ms tick, the same way
`nas_timer::expire_nas_timers` does — no extra task, no channel, and it cannot silently stop
firing. 10 s, a local choice (TS 36.413 names TS1RELOCprep/TS1RELOCoverall for the *source*
eNB and leaves the MME's own supervision to implementation), deliberately longer than the
source's own timer so the source's failure handling runs first and this fires only when the
source went away too — which is the case that used to leak the context forever. Cause
`tS1relocoverall-expiry` (value 8) rather than `handover-cancelled`, so the target can tell
a timeout from a cancel.

`expire_handover_preparations` **returns** its release commands instead of sending them, so
the DECISION (which target, and freeing the context) is separable from the TRANSMISSION
(which needs the process-global S1AP queue and a live SCTP association). This follows the
convention recorded for #70: when a handler's observable effect is an outbound message the
harness cannot deliver, return what was decided and let the test assert that.

### sgwcd (criterion 7)

The dispatcher passes the **decoded** `Gtp2Message`, not `&[]` — and not re-encoded bytes
either, since the message is already decoded at the dispatch site and the library has
`Gtp2BearerContextIe::decode` / `.fteid(instance)`. The handler parses the Bearer Contexts,
allocates a DL and a UL forwarding tunnel per bearer with real TEIDs, PDR and FAR ids, and
records the target eNB's endpoints as the tunnels' remote ends.

F-TEIDs are matched on **instance AND interface type**, both. An F-TEID whose instance says
"UL" and whose interface type says "DL" is contradictory, and believing the instance alone
would install a forwarding rule in the wrong direction. NOTE 1/NOTE 2 permit the SGW to send
several instances when it cannot decide, so first match wins.

The PFCP rules use `ACCESS` for **both** the PDI source and the FAR destination — unlike
every other rule `sxa_build` builds. Indirect forwarding is an eNB-to-eNB relay through the
SGW-U, so both ends are radio; getting that wrong would send forwarded user data out of SGi.

And the S11 answer is now **gated** on the SGW-U's response through a new
`S11Continuation::IndirectForwarding`, for the reason #54 gated Create Session: TS 29.274
§7.2.2 makes `Request accepted` mean the request was FULFILLED, and this response carries
F-TEIDs the source eNB is about to send user data to.

## Revert-verify

Six behavioural claims, each revert confirmed applied by `grep`/assertion before the test
ran, each failing on its own named assertion:

| revert | test that fails |
|---|---|
| status-transfer arm answers an Error Indication (the pre-#48 behaviour) | `enb_status_transfer_is_relayed_to_the_target_unchanged` — "the relay goes to the TARGET eNB", `left: 1 right: 6` |
| admitted DL forwarding TEID dropped again | `direct_forwarding_populates_the_handover_command_forwarding_list` |
| forwarding list hard-coded to `Vec::new()` | same test, on the list length |
| cancel no longer sends the target release | `handover_cancel_releases_the_prepared_target` |
| supervision deadline never armed | `handover_preparation_supervision_releases_a_target_that_never_completes` |
| sgwcd allocates no forwarding tunnels | `cidft_request_allocates_forwarding_tunnels_and_the_response_carries_them` |

The first attempt at the status-transfer revert **deleted** the dispatch arm, which made the
match non-exhaustive and produced a compile error. A compile error is not a revert-verify: it
proves nothing about the test. Redone as a behavioural revert that reproduces the shipped
Error Indication.

Worth naming what the pre-existing sgwcd test shows: `test_indirect_tunnel_responses`
asserted only that a Cause IE was present, so it passed against the empty accept for as long
as the defect existed. The new test asserts per-bearer DL/UL F-TEIDs at the right instances
with the right interface types.

## Verification

- Workspace **6520 → 6530** tests, 0 failures (+2 `nextgcore-s1ap`, +5 `mmed`, +3 `sgwcd`).
- `cargo clippy --workspace` 0 errors; `nextgcore-s1ap`, `nextgcore-mmed`, `nextgcore-sgwcd`
  and `nextgcore-asn1c` all at **0 warnings** — two pre-existing ones in files this change
  already touches went with it (`unused import: Gtp2FTeidIe`, and a hex-grouping lint on
  `0x0102_03`). `cargo fmt` clean.

## Ceilings, stated rather than implied

- **The MME does not inspect the PDCP SN/HFN counts**, by design: it relays the container.
  A deployment that needs the MME to reason about per-E-RAB PDCP state would need the
  `Bearers-SubjectToStatusTransfer` codec this deliberately avoids.
- **`send_create_indirect_data_forwarding_tunnel_request` had no caller before this**, and
  `CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE` had no dispatch arm. Both now do. The
  DELETE direction is still not driven by the handover paths — an indirect forwarding tunnel
  is torn down only when the session goes, so a completed handover leaves the forwarding
  rules installed until then. TS 23.401 §5.5.1.2.2 step 15 has the MME delete them on a
  timer after the handover completes; that timer does not exist here.
- **No `Data Forwarding Not Possible` handling.** It is an *extension* IE
  (`id-Data-Forwarding-Not-Possible = 143`) on `E-RABToBeSetupItemHOReq`, not a top-level IE
  of Handover Required, and this tree has no protocol-extension container plumbing for S1AP
  E-RAB items. A target that cannot forward a particular E-RAB signals it there, and the MME
  would omit that E-RAB from the forwarding list; today it is not read.
- **Only the intra-LTE, single-MME case is driven.** `TargetId::TargetRncId`/`Cgi` still
  fail preparation with `unknown-targetID`, and there is no S10 Forward Relocation leg, so
  the "source MME to a different SGW" variants of Table 7.2.18-2 (instances 1, 2, 3, 5, 6)
  are neither emitted nor read.
- **IPv6 forwarding endpoints are not supported**: `parse_wire_f_teid`'s IPv4-only read and
  `outer_header_creation`'s `remote_ip.ipv4?` both bail, because the SGW-U datapath in this
  build is IPv4. Returning `None` is honest where a zero address would not be.
