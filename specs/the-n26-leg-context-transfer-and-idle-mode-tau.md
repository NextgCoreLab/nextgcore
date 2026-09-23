# The N26 leg: GTPv2-C Context Request/Response and idle-mode TAU-with-N26

**Issue:** nextgcore #347 (an `architecture` + `epc` split out of #62 phases 2-3)
**Verified against:** nextgcore `main` @ `0dc01e4`
**Spec basis:** TS 29.274 §7.3.5 (Context Request), §7.3.6 (Context Response), §7.3.7
(Context Acknowledge), §8.38 (MM Context), §8.39 + Table 7.3.6-2 (PDN Connection),
Table 7.3.6-3 (Bearer Context), Table 8.1-1 (IE types), Table 8.38-1 (Security Mode
values); TS 23.502 §4.11.1.3.2 (5GS→EPS idle-mode mobility with N26); TS 23.401
§5.3.3.1 (TAU with Serving GW change), §4.3.19 (CN node resolution); TS 23.003
§2.10.2.1.2/.1.3; TS 24.301 §5.5.3.2.2 case z, §9.9.3.54 (UE status), Table 8.2.29.1;
TS 24.501 §9.11.3.56 (UE status), §9.11.3.5 (5GS network feature support);
TS 33.501 §8.6.1, Annex A.14.1 (K_ASME' from K_AMF).

---

## 1. Claim-vs-site-vs-still-true

Every site #347 names was re-located at `0dc01e4` before any code was written. The
enumeration **did** shrink the issue, and in one place it grew it.

| #347 claims | site on `0dc01e4` | verdict |
|---|---|---|
| `Gtp2MessageType` stops at the S11/S5 set; none of 128-136 defined | `libs/nextgcore-gtp/src/v2/header.rs:24-78` — highest variant is `ModifyAccessBearersResponse = 212`, and the 104→160 gap confirms 128-136 absent | **real** |
| amfd declares no GTP dependency | `bins/nextgcore-amfd/Cargo.toml` — no `nextgcore-gtp` line | **real** |
| the only N26 artefacts are smfd's two F-TEID interface-type constants, which nothing references | `smfd/src/gtp_build.rs:489,517` | **real** |
| MM Context is "a family of variants keyed on security-context type, each with its own layout" | TS 29.274 Table 8.1-1 (`29274-j60.txt:24528-24546`): IE types **103, 104, 105, 106, 107, 108** are six *distinct IE types*, not one type with a discriminator | **real, and the cost is lower than feared** — see §3 |
| `Gtp2IeType` has no `MmContext`/`PdnConnection` | **VOID.** `ie.rs:47-48` already declares `MmContext = 107` and `PdnConnection = 109`, with `TryFrom` arms at `:120-121` | **void** |
| mmed/amfd greps return only 5GS-internal matches | confirmed: `UE_CONTEXT_TRANSFER = 35` (NGAP) and Namf UEContextTransfer only | **real** |
| `AmfUe.mapped_eps_guti` has no reader | `context.rs:2663` (decl), written at `ngap_path.rs:2368`; `grep` for reads finds only the write and one test | **real** |
| `iwk_n26_posture()` is a constant returning `WithoutN26Supported` | `gmm_build.rs:604-606` | **real** |
| `ngap_path::inter_system_handover_refusal` declines every non-intra-5GS `HandoverRequired` | `ngap_path.rs:9230-9246`, called at `:6909` | **real** — and deliberately **left alone**, see §8 |
| #116 left the EPS NAS message container parsed and uninterpreted | `ngap_path.rs:2378-2388` logs its presence and says decoding it "IS the N26 leg (#62)" | **real** |

### Blockers and adjacent issues, state checked

`gh issue view N --json state` for every issue #347 or its parent names:
**#52 CLOSED, #62 CLOSED, #74 CLOSED, #78 CLOSED, #79 CLOSED, #116 CLOSED,
#117 CLOSED, #223 CLOSED, #321 CLOSED, #352 CLOSED, #380 CLOSED, #386 CLOSED.**
No open blocker. Nothing #347 depends on is waiting.

### Two facts that changed the sizing, neither of them in the issue

**#52 built the receive-loop pattern this needs.** `smfd/src/gtp_path.rs:1204,1209`
dispatch into `gtp_handler::dispatch_s5s8_{response,request}` from
`S5S8Server::handle_datagram`, driven by the loop `S5S8Server::open` spawns from
`main.rs:744`. mmed's equivalent is `gtp_path.rs:598` (`handle_datagram`) →
`s11_handler::dispatch_{triggered,initial}`. So "how does a GTPv2-C datagram reach a
handler" is a solved problem in this tree, twice, and the N26 endpoint is modelled on
the second rather than invented.

**The discriminator for "this TAU came from 5GS" is NOT the GUTI type.** #347 and #62
both imply the MME learns it from a mapped GUTI. TS 24.301 §5.5.3.2.2 **case z**
(`24301-k00.txt:17068-17074`) says the opposite, verbatim:

> The UE shall include a GUTI, mapped from 5G-GUTI [...] in the Old GUTI IE [...]
> In addition, the UE shall include Old GUTI type IE with GUTI set to **"Native
> GUTI"**, and the UE shall include a **UE status IE with a 5GMM registration status
> set to "UE is in 5GMM-REGISTERED state"**.

So a 5GS→EPS TAU arrives with `Old GUTI type = Native`, exactly like an intra-EPS
TAU — the GUTI type is **useless** as the discriminator, and an implementation that
keyed on "mapped GUTI" would never fire. The load-bearing IE is **UE status**
(IEI `0x6D`, TLV, TS 24.301 Table 8.2.29.1 at `24301-k00.txt:36942`), whose octet 3
**bit 2** is `N1 mode reg` (TS 24.501 Table 9.11.3.56.1,
`24501-k00_5_Main-Body_s09_s10.txt:11556-11560`). That IE was **not parsed** by
`emm_handler::handle_tau_request` — its default TLV arm walked past it.

This is the single most important finding in the issue, and it is the inverse of the
polarity trap in #116: there, the obvious reading of a bit was backwards; here, the
obvious *choice of field* is wrong.

---

## 2. Disposition of the eight acceptance criteria

The issue spans two daemons and three named procedures. Enumerated, **six of the
eight criteria are in scope for this PR and two are separable**; the separable pair
is filed as **#408** and this PR closes #347, per the convention that a criterion
whose remainder is filed and numbered may be split.

| # | criterion | disposition |
|---|---|---|
| 1 | `Gtp2MessageType` carries 128-136, numbers asserted as literals | **done** — §3 |
| 2 | amfd + mmed encode/decode Context Request/Response **and Forward Relocation Request/Response**, incl. MM Context and PDN Connection, round-trip + literal field assertions | **Context Request/Response/Acknowledge done in full** (§3, §4). **Forward Relocation Request/Response split to #408** — see §2.1 |
| 3 | amfd binds a GTPv2-C N26 endpoint, mmed handles S10, both behind an off-by-default **runtime** switch | **done** — §5 |
| 4 | idle-mode TAU-with-N26 completes: TAU → Context Request → Context Response → Context Acknowledge → Modify Bearer → TAU Accept | **done** — §6 |
| 5 | `AmfUe.mapped_eps_guti` gains a reader; the AMF resolves its context from the 4G-GUTI an MME sends | **done** — §4.3 |
| 6 | `iwk_n26_posture()` reflects the switch | **done** — §7 |
| 7 | `docs/index.html` + `docs/features.html` updated together | **done** — §9 |
| 8 | standalone 5GC and standalone EPC unchanged with the switch off; lint and tests green | **done** — §10 |

### 2.1 Why Forward Relocation splits, and why the split is at this seam

Criterion 4 names **idle-mode TAU**, which per TS 23.502 §4.11.1.3.2 and TS 23.401
§5.3.3.1 uses **Context Request/Response/Acknowledge** — messages 130/131/132.
Forward Relocation Request/Response (133/134) belong to **connected-mode handover**
(TS 29.274 §7.3.1, and #62's own phase 3 ordering: *"idle-mode first [...] then EPS
fallback, then connected-mode handover"*).

The split is at that seam and not an arbitrary line, for a reason that is a *ceiling*
rather than a preference: **Forward Relocation Request carries data-forwarding
tunnel endpoints this core cannot supply for an inter-system move.** Table 7.3.1-3
(`29274-j60.txt:18810`) makes `SGW S1/S4/S12 IP Address and TEID for user plane`
mandatory, and a connected-mode 5GS→EPS handover additionally needs indirect
forwarding tunnels established toward the target — which is exactly the gap #398
recorded for `/relocate` and which this PR does **not** close for the user plane
(§8). Shipping messages 133/134 as encoders with no procedure would produce precisely
this tree's commonest defect: correct wire format, zero production senders.

Message types 133-136 **are** added to `Gtp2MessageType` (criterion 1 asks for all
of them and a type enum is not a procedure), and `#408` owns the procedure.

---

## 3. The library: message types and the two composite IEs

### 3.1 Message types, each pinned to a quoted line

TS 29.274 Table 6.1-1, the `MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN,
MME to AMF, AMF to MME (S3/S10/S16/N26)` block. Every number is read off its own
row, not inferred from a neighbour — #401 found three of four IE ids inferred that
way were wrong.

| type | message | vendored line |
|---|---|---|
| 128 | Identification Request | `29274-j60.txt:2410` |
| 129 | Identification Response | `29274-j60.txt:2413` |
| 130 | **Context Request** | `29274-j60.txt:2416` |
| 131 | **Context Response** | `29274-j60.txt:2418` |
| 132 | **Context Acknowledge** | `29274-j60.txt:2420` |
| 133 | Forward Relocation Request | `29274-j60.txt:2422` |
| 134 | Forward Relocation Response | `29274-j60.txt:2425` |
| 135 | Forward Relocation Complete Notification | `29274-j60.txt:2428` |
| 136 | Forward Relocation Complete Acknowledge | `29274-j60.txt:2431` |

`gtp2_n26_message_types_match_ts29274_table_6_1_1` asserts all nine as literals
against the quoted lines, per the #321/#340 guard.

### 3.2 IE types — already present, and that is worth stating

`Gtp2IeType::MmContext = 107` and `PdnConnection = 109` **already existed**
(`ie.rs:47-48`), contradicting #347's §1. Confirmed against Table 8.1-1:

| IE | id | vendored line |
|---|---|---|
| IMSI | 1 | `29274-j60.txt:24419` |
| Cause | 2 | `29274-j60.txt:24423` |
| EBI | 73 | `29274-j60.txt:24452` |
| Bearer QoS | 80 | `29274-j60.txt:24467` |
| F-TEID | 87 | `29274-j60.txt:24490` |
| Bearer Context | 93 | `29274-j60.txt:24506` |
| **MM Context (EPS Security Context, Quadruplets and Quintuplets)** | **107** | `29274-j60.txt:24535` |
| **PDN Connection** | **109** | `29274-j60.txt:24547` |
| Complete Request Message | 116 | `29274-j60.txt:24568` |
| GUTI | 117 | `29274-j60.txt:24571` |
| APN | 71 | `29274-j60.txt:24444` |
| AMBR | 72 | `29274-j60.txt:24448` |

A new `gtp2_n26_ie_types_match_ts29274_table_8_1_1` pins 107, 109, 116 and 117 —
the four this leg newly depends on.

### 3.3 MM Context: one variant, deliberately

Table 8.1-1 makes 103-108 **six separate IE types**, so "a family keyed on a
discriminator" overstates the cost: an implementation that only ever sends and
receives one security-context type only needs one layout. This leg implements
**107 — EPS Security Context and Quadruplets** (Figure 8.38-5,
`29274-j60.txt:28371`), because that is the only one the N26 interface uses in
either direction:

- old AMF → new MME: §8.38 (`29274-j60.txt:28198-28202`) — *"The current EPS Security
  Context may be transmitted by the old AMF to the new MME [...] The field 'Number of
  Quadruplets' and 'Number of Quintuplets' shall be set to the value '0'."*
- old MME → new AMF: `29274-j60.txt:28190-28193` — *"Authentication Quintuplets shall
  not be transmitted to the new MME/AMF [...] The field 'Number of Quintuplets' shall
  be set to the value '0'."*

So on N26 **both** vector counts are zero by spec, in both directions. The other five
variants (GSM/UMTS keys, triplets) exist for S3/S16 toward a GSM/UMTS SGSN, which
this core has no interface to. Types 103-106 and 108 are **not** added to
`Gtp2IeType`: an enum variant whose encoder cannot be reached is the dead code this
tree keeps growing.

Octet layout implemented, from Figure 8.38-5 read field by field:

| octet | field | line |
|---|---|---|
| 5 | `Security Mode`(3) \| `NHI`(1) \| `DRXI`(1) \| `KSI_ASME`(3) | `29274-j60.txt:28260` |
| 6 | `Number of Quintuplets`(3) \| `Number of Quadruplet`(3) \| `UAMBRI`(1) \| `OSCI`(1) | `29274-j60.txt:28262` |
| 7 | `SAMBRI`(1) \| `Used NAS integrity protection algorithm`(3) \| `Used NAS Cipher`(4) | `29274-j60.txt:28264` |
| 8-10 | `NAS Downlink Count` (24 bits) | `29274-j60.txt:28266` |
| 11-13 | `NAS Uplink Count` (24 bits) | `29274-j60.txt:28268` |
| 14-45 | `K_ASME` (32 octets) | `29274-j60.txt:28270` |
| then | `Length of UE Network Capability` + contents, `Length of MS Network Capability` + contents, `Length of MEI` + contents, access-restriction octet | `29274-j60.txt:28294-28309` |

`Security Mode = 4` for "EPS Security Context and Quadruplets"
(Table 8.38-1, `29274-j60.txt:28671-28672`), asserted as a literal.

**Every one of those positions is asserted at an exact byte offset** by
`mm_context_encodes_ts29274_figure_8_38_5_field_positions` — the K_ASME at `[9..41]`
of the contents field, the counts at `[3..6]` and `[6..9]`, and the bit-packing of
octets 5-7 each on their own. An encode/decode round-trip alone would pass with the
counts transposed.

### 3.4 PDN Connection: a grouped IE, per Table 7.3.6-2

§8.39's own table is **empty** (`29274-j60.txt:28819` — the row is blank, with a NOTE
saying the per-message clauses carry the detail), so the layout comes from
**Table 7.3.6-2** (`29274-j60.txt:20508`), which is what TS 29.502's
`EpsPdnCnxContainer` names too (`29502-k00.txt:24142-24149`: *"encoding the
UeEpsPdnConnection IE specified in Table 7.3.1-2 or Table 7.3.6-2"*).

Members implemented, mandatory ones first:

| member | P | IE type | ins | line |
|---|---|---|---|---|
| APN | M | APN (71) | 0 | `29274-j60.txt:20522` |
| Linked EPS Bearer ID | M | EBI (73) | 0 | `29274-j60.txt:20548` |
| PGW S5/S8 IP Address for Control Plane | M | F-TEID (87) | 0 | `29274-j60.txt:20552` |
| Bearer Contexts | M | Bearer Context (93) | 0 | `29274-j60.txt:20567` |
| APN-AMBR | M | AMBR (72) | 0 | `29274-j60.txt:20573` |
| IPv4 Address | C | IP Address (74) | 0 | `29274-j60.txt:20539` |

and the nested Bearer Context per **Table 7.3.6-3** (`29274-j60.txt:20872`):
EBI (73/0) M, `SGW S1/S4/S12/S11 F-TEID` (87/0) C, `PGW S5/S8 user-plane F-TEID`
(87/1) C, `Bearer Level QoS` (80/0) M.

`Gtp2BearerContextIe` already models a nested-IE bag with instance-keyed accessors,
so `Gtp2PdnConnectionIe` is built the same way rather than as a rival design — one
notion of "a grouped GTPv2 IE", which is the #335/#340 lesson.

**The N26 reserved-TEID rule is honoured and tested.** Table 7.3.6-3
(`29274-j60.txt:20906-20915`) requires that over N26 the SGW user-plane F-TEID carry
*"any reserved TEID (e.g. all 0's, or all 1's)"* with *"IPv4 address set to
0.0.0.0"*. `Gtp2PdnConnectionIe::n26_reserved_sgw_fteid()` is the only way the AMF
constructs it, and `n26_sgw_fteid_is_the_reserved_value_ts29274_table_7_3_6_3_requires`
asserts TEID `0` and address `0.0.0.0` at their byte offsets. Encoding a real SGW
endpoint here would point an MME's user plane at an address the 5GC never allocated.

---

## 4. The two peers

### 4.1 mmed: the new MME, sending Context Request

`mmed/src/n26_path.rs` (new) binds the S10/N26 socket and owns the peer table;
`mmed/src/n26_build.rs` (new) builds and parses. Both modelled on `gtp_path.rs` /
`s11_build.rs` — same `Gtp2XactMgr`, same `OnceLock` server, same synchronous
blocking socket with a read timeout, because the NAS path that originates a Context
Request is synchronous. A second transport design here would be a second answer to
"how long may a GTPv2-C message take".

Context Request IEs, per Table 7.3.5-1 (`29274-j60.txt:19672`):

| IE | P | why | line |
|---|---|---|---|
| GUTI (117/0) | C — *"the new MME/AMF shall include this IE over S10/N26 interface if the IMSI is not present"* | the 4G-GUTI from the TAU's Old GUTI IE | `29274-j60.txt:19685-19688` |
| Complete TAU request message (116/0) | C — *"shall include this IE if available, and the old MME/AMF may use this IE for integrity check"* | the verbatim TAU REQUEST octets, type **1** = "Complete TAU Request Message" (Table 8.46-1, `29274-j60.txt:29078`) | `29274-j60.txt:19759-19762` |
| S3/S16/S10/N26 F-TEID (87/0) | C | interface type **12** (`S10_N26_MME_GTP_C`), the constant `smfd/src/gtp_build.rs:489` defined and nothing used | `29274-j60.txt:19765` |
| RAT Type (82/0) | C | `6` = EUTRAN | `29274-j60.txt:19794` |
| Indication (77/0) | CO — MSV flag *"when set to 1, indicates that the new system has successfully authenticated the UE, or [...] has validated the integrity protection of the TAU request message"* | set only when the MME actually verified it | `29274-j60.txt:19804-19812` |

**The MME sends this only when the UE said it came from 5GS.** The trigger is the
UE status IE's `N1 mode reg` bit, newly parsed (§1). Without it, per TS 24.301
§5.5.3.2.2 case z, nothing distinguishes this TAU from an intra-EPS one.

When N26 is off, or no AMF peer is configured, the MME answers
`TRACKING AREA UPDATE REJECT` with **EMM cause #9 "UE identity cannot be derived by
the network"** — which is not a choice but a requirement: TS 24.301
(`24301-k00.txt:18854-18858`) says *"if the UE initiated the tracking area updating
procedure due to inter-system change from N1 mode to S1 mode, and the MME does not
support N26 interface, the MME shall send a TRACKING AREA UPDATE REJECT message with
EMM cause value #9"*. Today the code reaches `EmmCause::ImplicitlyDetached` (#10) via
the no-security-context branch, which tells the UE something else.

### 4.2 amfd: the old AMF, answering Context Response

`amfd/src/n26_path.rs` + `amfd/src/n26_build.rs` (new), and `nextgcore-gtp` added to
`amfd/Cargo.toml` — the dependency #347 correctly reports absent.

amfd's socket is **tokio** (`UdpSocket` from `tokio::net`), not a blocking thread,
because every amfd handler is `async` and the Context Response path has to call the
SMF over N11 (§4.4). That is a deliberate divergence from mmed's synchronous server
and it matches smfd's `S5S8Server`, which is the async one of the two existing
GTPv2-C endpoints — so it is still one of the two established patterns, chosen by
the surrounding code's colour rather than invented.

Context Response IEs, per Table 7.3.6-1 (`29274-j60.txt:19949`):

| IE | P | line |
|---|---|---|
| Cause (2/0) | **M** | `29274-j60.txt:19957` |
| IMSI (1/0) | C — *"shall be included in the message except [...] UICCless"* | `29274-j60.txt:19959` |
| MME/SGSN/AMF UE MM Context (107/0) | C — *"shall be included if the Cause IE has the value 'Request Accepted'"* | `29274-j60.txt:19975-19977` |
| MME/SGSN/AMF UE EPS PDN Connections (109/0) | C — *"shall be included if [...] there is at least a PDU session for this UE on the sending AMF"* | `29274-j60.txt:19980-19989` |

### 4.3 `mapped_eps_guti` gains its reader — criterion 5

`AmfContext::amf_ue_find_by_mapped_eps_guti(&EpsGuti)` (new) is the reader. It
resolves **two** ways, because §2.10.2.1.3 and the storage #116 chose are different
things:

1. against `AmfUe.mapped_eps_guti` directly, for a UE that arrived *from* EPS and
   whose 4G identity #116 preserved; and
2. by mapping each UE's **native** `current_guti` forward through
   `five_g_guti_to_eps_guti` and comparing — which is literally what §2.10.2.1.3
   asks for (`23003-k00.txt:2545-2551`: *"the AMF needs to map the GUTI (sent by the
   MME) to create the 5G-GUTI and compare it with the stored 5G-GUTI"*).

Path 2 is the one that matters for 5GS→EPS, and path 1 alone would have found
nothing: a UE that registered natively on 5GS and then moved to EPS has
`mapped_eps_guti == None`. Both paths are tested, and
`a_natively_registered_ue_is_found_by_the_guti_an_mme_maps_from_its_5g_guti` is the
positive assertion that the SUPI comes back.

The lookup is `eps_guti_to_5g_guti`-free on purpose: comparing in the EPS space via
the forward map, rather than reverse-mapping the incoming GUTI, keeps one direction
of the bijection in use and cannot disagree with what the UE computed.

### 4.4 Where the PDN connections come from: the SMF, not invented

TS 23.502 §4.11.1.3.2 step 5a/5c (`23502-k20.txt:22016-22091`) has the AMF retrieve
the mapped EPS bearer contexts **from the SMF+PGW-C**, and Table 7.3.6-3 NOTE 5
(`29274-j60.txt:20980-20983`) is explicit that the AMF *"shall transparently transfer
the MME/SGSN/AMF UE EPS PDN Connections IE received from the SMF"*.

So `n26_path` calls the SMF's `GET /nsmf-pdusession/v1/sm-contexts/{ref}/retrieve`
per session with an EBI — the endpoint #78/#117 built and which **had no AMF
caller**, verified by `grep -rn "sm_context_retrieve\|SmContextRetrieve" amfd/src`
returning nothing at `0dc01e4`. `sbi_path::call_smf_retrieve_sm_context` (new) is
that caller, modelled on `call_smf_release_sm_context` (`sbi_path.rs:1377`).

The SMF returns `ueEpsPdnConnection` as a base64 `EpsPdnCnxContainer`
(`29502-k00.txt:24142`). **It is decoded and re-encoded rather than forwarded
verbatim, and that is a stated deviation from NOTE 5's "transparently".** The reason
is honesty about what this tree's SMF actually produces: `build_ue_eps_pdn_connection`
(`smfd/src/main.rs:5705`) emits #78's *positional ad-hoc layout* — a length-prefixed
APN, a PDN-type octet, four address octets, a QCI octet, optionally an EBI — **not** a
Table 7.3.6-2 grouped IE. Forwarding those bytes as a PDN Connection IE would put a
non-conformant blob on the N26 wire under IE type 109. So `n26_build` parses that
known layout and builds a real Table 7.3.6-2 grouped IE from it. The ceiling is
stated at the site.

Where the SMF supplied no EBI (interworking off, or assignment failed), the session
is **excluded** from the Context Response and named in a log, because §4.11.1.3.2
step 5a says *"The AMF does not retrieve the context for a PDU Session that cannot be
transferred to EPS due to no EBI allocated"*. A UE with no transferable session gets
Cause "Request Rejected", per §7.3.6 (`29274-j60.txt:19935-19937`: reject *"if the UE
is registered to the source AMF without any PDU session"*).

### 4.5 The mapped security context

MM Context's `K_ASME` is **derived, not copied**: TS 33.501 §8.6.1
(`33501-k20.txt:11743-11746`) requires *"The K_ASME' key, taken as the K_ASME, shall
be derived from the K_AMF using the 5G NAS Uplink COUNT value derived from the TAU
Request message [...] in idle mode mobility [...] as described in Annex A.14"*, and
Annex A.14.1 (`33501-k20.txt:17168-17178`) gives `FC = 0x73`, `P0 = NAS Uplink COUNT`,
`L0 = 0x0004`, `KEY = K_AMF`.

`nextgcore_kdf_kasme_prime` is new in `nextgcore-crypt`, alongside
`nextgcore_kdf_kamf_prime` (FC `0x72`) which was already there. It reuses
`nextgcore_kdf_common` so there is one TS 33.220 B.2.0 construction in the tree.
`kasme_prime_matches_ts33501_annex_a_14_1` asserts `FC = 0x73`, that the COUNT is
load-bearing, and that the output differs from `kamf_prime`'s — the last because a
copy-pasted FC is exactly the defect that would round-trip clean.

Also per §8.6.1: the eKSI value field is the ngKSI's and the type field marks a
**mapped** context; the EPS NAS COUNTs are set to the 5G ones. Both are done and
asserted.

---

## 5. The runtime switch — criterion 3

A runtime switch, not a cargo feature, for the reason `smfd/src/eps_iwk.rs:19-29`
records and this PR does not re-litigate: CI builds default features, so a
feature-gated path is left **uncompiled** and rots. Consequently criterion 8
("standalone builds unchanged with the switch off") is a thing a test asserts in one
`cargo test` run rather than a claim about a build CI never performs.

- **amfd**: `AMF_N26_INTERWORKING=1` plus an `amf.n26` config block for the bind
  address and the MME peer. `amfd/src/n26_path.rs::enabled()`.
- **mmed**: `MME_N26_INTERWORKING=1` plus `mme.n26`. `mmed/src/n26_path.rs::enabled()`.

Both default **off**, and with the switch off neither daemon binds a socket, neither
sends anything, and `iwk_n26_posture()` returns `WithoutN26Supported` exactly as
today. `with_the_switch_off_the_amf_advertises_no_n26_and_binds_nothing` and
`with_the_switch_off_an_inter_system_tau_is_rejected_with_emm_cause_9` assert both
ends of that.

Each daemon's `set_for_test` takes the crate's existing process-state lock
(`amfd::test_support::CONTEXT_GUARD`, `mmed::gtp_path::S11_TEST_LOCK`) rather than
declaring a new one — #276's lesson that a second lock over one variable *hangs* the
suite rather than flaking it.

---

## 6. The procedure — criterion 4

TS 23.502 §4.11.1.3.2 over TS 23.401 §5.3.3.1, end to end:

| step | who | what | site |
|---|---|---|---|
| 1-3 | eNB → MME | TAU REQUEST with Old GUTI (mapped, typed *Native*) and **UE status** `N1 mode reg = 1` | `nas_dispatch::emm_tau_request` |
| 4 | MME → AMF | **Context Request** (130): GUTI, Complete TAU Request, F-TEID iface 12, RAT type, Indication/MSV | `n26_path::send_context_request` |
| 5a/5c | AMF → SMF | `SmContextRetrieve` per EBI-bearing session | `sbi_path::call_smf_retrieve_sm_context` |
| 6 | AMF → MME | **Context Response** (131): Cause, IMSI, MM Context (K_ASME'), PDN Connections | `n26_path::handle_context_request` |
| 7 | MME → AMF | **Context Acknowledge** (132) | `n26_path::send_context_acknowledge` |
| 8-11 | MME → SGW | **Modify Bearer Request** with the transferred bearers | `gtp_path::send_modify_bearer_request` |
| 16-18 | MME → UE | **TAU ACCEPT** | `nas_path::nas_eps_send_tau_accept` |

**Production reachability, proven not asserted.** Every link in that chain is a
production call site, and the two that matter most are the ones this tree keeps
getting wrong:

- the AMF's Context Request handler is reached from `N26Server::handle_datagram`,
  which is spawned by `N26Server::open`, called from `amfd/src/main.rs` at startup
  when the switch is on — the same shape as `smfd/src/gtp_path.rs:744`;
- the MME's `send_context_request` is reached from `emm_tau_request`
  (`nas_dispatch.rs:821`), which `nas_dispatch` reaches from
  `emm_type::TAU_REQUEST => emm_tau_request` at `:321` — a live S1AP NAS dispatch,
  not a test-only function.

`grep -n "send_context_request\|handle_context_request\|send_context_acknowledge"`
over each crate shows a non-`#[cfg(test)]` caller for all three.

Step 7's **Context Acknowledge** is sent with Cause "Request Accepted" and is what
licences the old AMF to start its guard timer (§4.11.1.3.2 step 6: *"The AMF may
start an implementation specific (guard) timer for the UE context"*). It is not
skipped: §7.3.7 makes it a distinct message, and an old AMF that never receives it
per TS 23.401 §5.3.3.1 step 5 keeps buffered data it should discard.

### Positive assertions, not "no error"

`an_idle_mode_tau_with_n26_transfers_the_ue_context_to_the_mme` drives the whole
chain in-process and asserts, **from the MME's store afterwards**:

- the UE's **IMSI** matches what the AMF held (not "the response parsed");
- the **K_ASME** equals `kdf_kasme_prime(kamf, ul_count)` computed independently in
  the test — so a stubbed or zeroed key fails;
- the transferred **EBI** is present on an `MmeBearer`;
- the **PGW S5/S8 control-plane TEID** is readable from the session;
- the **APN** matches the DNN.

A negative assertion ("no error was returned") is satisfied by every path that never
arrives, which is what makes it useless here.

### Revert-verification

Each behavioural claim was made to fail, the named test watched to fail, and
restored:

| change made | test that failed |
|---|---|
| `Security Mode` 4 → 3 in the MM Context encoder | `mm_context_encodes_ts29274_figure_8_38_5_field_positions` |
| `NAS Downlink Count` and `NAS Uplink Count` transposed | same |
| Context Request type 130 → 131 | `gtp2_n26_message_types_match_ts29274_table_6_1_1` |
| `kdf_kasme_prime` FC `0x73` → `0x72` | `kasme_prime_matches_ts33501_annex_a_14_1` |
| UE status `N1 mode reg` mask `0x02` → `0x01` | `a_tau_from_5gs_is_recognised_by_the_ue_status_n1_mode_bit` (see below — this one initially found NOTHING) |
| N26 SGW F-TEID given a real address instead of 0.0.0.0 | `n26_sgw_fteid_is_the_reserved_value_ts29274_table_7_3_6_3_requires` |
| `amf_ue_find_by_mapped_eps_guti` path-2 forward mapping removed | `a_natively_registered_ue_is_found_by_the_guti_an_mme_maps_from_its_5g_guti` |
| `iwk_n26_posture`'s two arms swapped (the natural-English reading) | `iwk_n26_posture_follows_the_runtime_switch` |
| `amf_ue_find_by_mapped_eps_guti`'s forward-mapping arm disabled | `a_natively_registered_ue_is_found_by_the_guti_an_mme_maps_from_its_5g_guti` |

### One revert-verification failed, and it found a real gap

The UE status bit flip (`0x02` → `0x01`) initially **passed the whole mmed suite**. That
is the finding, not a footnote: the discriminator the entire procedure hangs on had no
test, so the most consequential single constant in this change was unpinned — exactly the
condition that lets a "correct but unreachable" path ship, because with the wrong mask the
N26 branch simply never fires and every test still passes.

`a_tau_from_5gs_is_recognised_by_the_ue_status_n1_mode_bit` was written in response. It now
fails on the flip, and it additionally covers the *other* way to get this wrong — keying on
a mapped Old GUTI type — by asserting that a **native** Old GUTI type with the 5GMM bit set
still routes over N26, and that a **mapped** type without the UE status IE does not.

Both flips were then re-run against the new test and both fail, which is what makes the
row in the table above true rather than aspirational.

---

## 7. `iwk_n26_posture()` — criterion 6, and the polarity

The bit is **inverted from the obvious reading** and #116 modelled it as an enum
precisely so a call site cannot misread it. TS 24.501 Table 9.11.3.5.1 names it
*"Interworking without N26 interface indicator"*:

| bit | means | so |
|---|---|---|
| `0` | interworking without N26 **not** supported | the AMF **HAS** N26 → `Iwk26::N26Supported` |
| `1` | interworking without N26 supported | the AMF has **no** N26 → `Iwk26::WithoutN26Supported` |

`iwk_n26_posture()` becomes:

```rust
if crate::n26_path::enabled() {
    Iwk26::N26Supported        // bit CLEAR
} else {
    Iwk26::WithoutN26Supported // bit SET
}
```

Note the direction: the switch being **on** yields `N26Supported`, which encodes
**0**. Writing `if enabled() { WithoutN26Supported }` reads more naturally in English
and is exactly backwards, which is the trap.

Criterion 6 also says *"never merely because the code exists"*, and
`enabled()` — not `cfg!` and not a constant — is what satisfies that: with the code
compiled in and the switch off, the bit is still SET. The existing
`iwk_n26_posture_says_this_amf_has_no_n26_leg` (`gmm_build.rs:2058`) is replaced by
`iwk_n26_posture_follows_the_runtime_switch`, which asserts **both** states and both
encoded bit values.

---

## 8. Ceilings, stated at the site

**Connected-mode handover is not lifted, and #398's ceiling is only half-lifted.**
#398 recorded that `/relocate` *"records the transferred `sessionContextList` but
cannot move N3 tunnels (endpoints arrive over N26; this AMF has none)"*. After this
PR the AMF **does** have an N26 leg, so the premise changes — but the ceiling does
not fully lift, for a reason that is structural rather than incidental:

- `/relocate` is the **EPS→5GS** direction, where the AMF is the *target* and needs
  the MME's control-plane address and TEID per PDU session. Those arrive in a
  **Forward Relocation Request** (133), which is #408.
- This PR implements **5GS→EPS** idle-mode, where the AMF is the *source*. It
  supplies endpoints rather than consuming them.

So the honest statement, recorded in `namf_server.rs` at
`record_transferred_sessions`: the N26 *transport and codec* now exist, the
*idle-mode* context transfer works in the 5GS→EPS direction, and `/relocate` still
cannot move N3 tunnels until #408 lands the Forward Relocation consumer. The log
message is updated to name #408 rather than claiming the gap closed.

**`inter_system_handover_refusal` is deliberately unchanged.** #62 criterion 6 (done)
and #347 both gesture at replacing it with routing. It still declines every
non-intra-5GS `HandoverRequired` with `ho-target-not-allowed`, because a
`HandoverRequired` is *connected-mode* handover — the thing this PR does not
implement. Replacing the refusal with routing before #408 would forward a preparation
the AMF cannot complete, which is strictly worse than the current honest refusal
(and is the exact defect #116's spec describes fixing). The log now names #408.

**Two decoders for one message, in mmed.** `n26_path` uses the library decoder for
transaction correlation and `n26_build` walks the IEs for content — the same cost
`s11_handler.rs:248-252` already records for S11 and explicitly says #51 did not ask
to remove. Not introduced here; matched rather than compounded.

**No 3GPP test vector for K_ASME'.** As with `kdf_kamf_prime`
(`kdf.rs:325-333`), none is published and none is in this tree. The tests pin the
Annex A.14.1 construction — FC, the COUNT's load-bearing role, distinctness from
`0x72` — and the `S` layout is spelled out in the doc comment so a reviewer holding
the annex can check it by eye. Interop against a real MME remains the outstanding
validation.

---

## 9. Docs — criterion 7

Both files, together, and only as far as the truth goes. #116 set them to
"interworking partial, no N26"; this moves them to N26 **idle-mode** interworking,
off by default:

- `docs/index.html`: the `<meta description>` and the hero paragraph stop saying
  *"there is no N26 interface and therefore no inter-system session continuity"* and
  say instead that the N26 interface exists behind an off-by-default runtime switch,
  carrying idle-mode context transfer, with connected-mode handover outstanding
  (#408).
- `docs/features.html`: the GTPv2-C row (`:70`) moves off `prototype` — it said *"no
  wire listener"*, which #52 already falsified for S5/S8 and this falsifies for N26 —
  and a new N26 row states idle-mode implemented / handover not.

Neither file is upgraded to a flat "implemented": that would be the docs defect #116
existed to fix, in the other direction.

---

## 10. Verification — criterion 8

- `cargo fmt --all -- --check` clean.
- `cargo clippy --workspace` clean (warnings are errors).
- `cargo test --workspace`: **6833 → 6870** passed on `0dc01e4`; **6882** after rebasing onto
  `ed1f2ad` (sibling PRs #402/#404/#407 landed 12 more). 0 failed either way; this change
  adds **37**.
- `nextgcore-gtp`, `nextgcore-crypt`, `nextgcore-amfd`, `nextgcore-mmed` suites looped
  **10×**, `head -1 /proc/loadavg` noted each pass.
- CI dispatched on `feat/347-wt` because this touches the EPC seam, and the
  `EPC bring-up` / `Docker` stages are gated `schedule || workflow_dispatch` and skip
  on a PR.

Standalone posture, asserted rather than claimed: with both switches off, no socket is
bound, no IE is emitted, `iwk_n26_posture()` is unchanged, and the TAU path behaves as
it did at `0dc01e4`.
