# The N26 connected-mode leg: GTPv2-C Forward Relocation, and lifting `/relocate`'s N3 ceiling

**Issue:** nextgcore #408 (an `architecture` + `enhancement` + `epc` split out of #347)
**Verified against:** nextgcore `main` @ `fd99448`
**Spec basis:** TS 29.274 §7.3.1 (Forward Relocation Request, type 133), §7.3.2 (Response,
134), §7.3.3 (Complete Notification, 135), §7.3.4 (Complete Acknowledge, 136),
Table 7.3.1-1, Table 7.3.1-2 (PDN Connections within Forward Relocation Request),
Table 7.3.1-3 (Bearer Context within it), Table 7.3.2-1, Table 7.3.2-2 (Bearer Context for
data forwarding), Table 8.1-1 (IE types), Table 6.1-1 (message types), §8.12 (Indication
flags); TS 23.502 §4.11.1.2.1 (5GS→EPS handover using N26), §4.11.1.2.2.2/.3 (EPS→5GS
handover, preparation and execution); TS 33.501 §8.3.2 (handover 5GS→EPS over N26), §8.6.1
(mapping a 5G security context to an EPS one), Annex A.14.1 (FC `0x73`), **Annex A.14.2**
(FC `0x74`); TS 29.518 §5.2.2.2.5.1 (`/relocate`); TS 38.413 §9.2.3.2 (HANDOVER COMMAND),
§9.3.1.22 (HandoverType), §9.3.3.26 (NAS Security Parameters from NG-RAN); TS 24.501
§9.11.2.7 (N1 mode to S1 mode NAS transparent container).

---

## 1. Claim-vs-site-vs-still-true

Every site #408 names was re-located at `fd99448` before any code was written. The
enumeration confirmed most of the issue and **falsified one premise outright** (row 6),
which is what moved criterion 5 out of this PR.

| # | #408 claim | site on `fd99448` | verdict |
|---|---|---|---|
| 1 | `Gtp2MessageType::ForwardRelocationRequest = 133` … `= 136` are defined and **nothing dispatches on them** | `header.rs:75-78` (decl), `:144-147` (`TryFrom`), asserted at `:416-447`. `grep -rn "ForwardRelocation" bins/` at base returns **only** amfd's `n26_path.rs:265` log string | **real** |
| 2 | amfd's N26 receive loop says *"Forward Relocation (types 133-136) is #404"* | `amfd/src/n26_path.rs:262-266` — and the issue number in the log is **#404, not #408** | **real, and the log cites the wrong issue** — fixed here |
| 3 | mmed's loop *"logs that the message matches no outstanding transaction"* | `mmed/src/n26_path.rs:395-399` | **real** |
| 4 | `record_transferred_sessions` records a `sessionContextList` and cannot re-establish the user plane; its `log::warn!` names #408 | `namf_server.rs:4377-4431`, the warn at `:4421-4428` | **real** |
| 5 | `ngap_path.rs:9230` returns `ho-target-not-allowed` for `FivegsToEps` and `EpsTo5gs` | **line number drifted**: the function is `inter_system_handover_refusal` at **`ngap_path.rs:9760-9776`**, called at **`:7377`**, asserted at `:10865-10875` | **real, at a moved line** |
| 6 | criterion 5: *"`/relocate` … replaced by an `Nsmf_PDUSession_UpdateSMContext` per SMF carrying the endpoints the Forward Relocation Request supplied"* | **the premise is FALSE.** See §2.2 — TS 29.518 §5.2.2.2.5.1 (`29518-k00.txt:2953-2958`) has the **consumer** carry the MME address and TEID *"in the request"*, i.e. in `UeContextRelocateData`, and the `forwardRelocationRequest` part is the **source MME's** message. But TS 23.502 §4.11.1.2.2.2 step 4 (`23502-k20.txt:21384-21391`) puts the EPS→5GS endpoint consumption in **`Nsmf_PDUSession_CreateSMContext`**, not Update — and smfd's create handler has **no `ueEpsPdnConnection` consumer at all** (`grep` over `handle_sm_context_create`, `main.rs:2941-3400`, returns nothing) | **VOID as written** — split, see §2.2 |
| 7 | Table 7.3.1-3 makes `SGW S1/S4/S12 IP Address and TEID for user plane` **mandatory** (`:18810`) | confirmed — the row is at `29274-j60.txt:18827-18829`, `M`, F-TEID, instance 0, and the N26 reserved-value rule is at `:18833-18843` | **real** |
| 8 | `Gtp2PdnConnectionIe::n26_reserved_sgw_fteid` already encodes the reserved value | `ie.rs:1653` | **real** |
| 9 | `nextgcore_kdf_kasme_prime` exists; A.14.2's FC `0x74` counterpart does not | `kdf.rs:409`, and `kdf.rs:397-399` says in as many words that A.14.2 *"is deliberately absent: connected-mode 5GS→EPS handover is #408"* | **real** |

### Blockers and adjacent issues, state checked

`gh issue view N --json state` for every issue #408 or its parent names:
**#62 CLOSED, #74 CLOSED, #75 CLOSED, #78 CLOSED, #116 CLOSED, #117 CLOSED, #185 CLOSED,
#223 CLOSED, #347 CLOSED, #398 CLOSED, #401 CLOSED, #404 CLOSED.** No open blocker.

### Four facts that changed the sizing, none of them in the issue

**(a) The 5GS→EPS direction has a peer problem the idle-mode direction does not.**
`grep -rn "mme_n26\|amf.n26.client\|MME_ADDR" bins/nextgcore-amfd/src/` returns **nothing**.
amfd's `n26_open` (`lib.rs:951-977`) takes a *bind* address from `AMF_N26_ADDR` and no peer
list at all — because #347 made the AMF purely **reactive** on N26 (it answers a Context
Request at the source address the datagram came from). A Forward Relocation Request is
**AMF-initiated**, so it needs an MME address the AMF has nowhere to get. That is a config
surface this PR adds, and it is why criterion 4's conditional has three conjuncts rather
than one (§6).

**(b) `DirectForwardingPathAvailability` is decoded by nobody.** The IE id constant exists
(`ngap/ie.rs:1468`: `IE_ID_DIRECT_FORWARDING_PATH_AVAILABILITY: u16 = 22`, confirmed against
`38413-j30.txt:59477`) and `DirectForwardingPathAvailability` is a full `AperEncode`/
`AperDecode` type (`asn1c/ngap/ies.rs:679-705`) — but `parse_handover_required`
(`parser.rs:1647-1681`) has **no arm for it**, so it falls into `handle_unknown_ie` and
`HandoverRequired` (`types.rs:566-581`) has no field for it. TS 23.502 §4.11.1.2.1 step 1
(`23502-k20.txt:20953-20958`) makes that IE the **source NG-RAN's own statement** about
whether direct forwarding is possible, and step 3 (`:21063-21065`) has the AMF set the GTPv2-C
Direct Forwarding Flag from it. So the single input the forwarding decision needs was being
discarded. **This is the most consequential finding in the issue** and §5 is built on it.

Note the asymmetry with mmed, which gets this right already: `s1ap_handler.rs:1111`
(`let direct_forwarding_available = msg.direct_forwarding_path_availability.is_some();`) with
#48's comment recording that ABSENT means no direct path. One core, two nodes, and only the
EPS one kept the IE.

**(c) `HandoverCommandTransfer` has no encoder in this tree.**
`grep -rn "HandoverCommandTransfer\|dLForwardingUP" libs/` returns **nothing**. TS 38.413
§9.2.3.2 (`38413-j30.txt:13196-13206`) makes each `PDU Session Resource Handover Item` carry
a `Handover Command Transfer` OCTET STRING, whose ASN.1 (`38413-j30.txt:48917-48930`) is
`SEQUENCE { dLForwardingUP-TNLInformation OPTIONAL, qosFlowToBeForwardedList OPTIONAL,
dataForwardingResponseDRBList OPTIONAL, ... }`. The AMF's existing intra-5GS
`HandoverCommand` (`ngap_path.rs:7622-7637`) sidesteps this by **relaying the target gNB's
own admitted-list transfer verbatim** — which works intra-5GS and cannot work inter-system,
because in 5GS→EPS the "target" is an MME that produces no NGAP transfer at all. §5 states
this as the ceiling it is rather than fabricating a container.

**(d) `PDU Session Resource Handover List` is OPTIONAL in HANDOVER COMMAND.**
`38413-j30.txt:38763`: `{ ID id-PDUSessionResourceHandoverList ... PRESENCE optional }`,
and the tabular form at `:13188` gives range `0..1` with criticality `ignore`. The tree's
`build_handover_command` (`builder.rs:658`) encodes it unconditionally, which is legal but
means an empty list is representable. That is what makes §5's "no forwarding" answer
**expressible in a conformant HANDOVER COMMAND** rather than requiring a refusal — and it is
the difference between criterion 6 being satisfiable and not.

---

## 2. Disposition of the eight acceptance criteria

Enumerated before any code was written. **Seven of the eight are in scope for this PR and
one is separable**; the separable one is criterion 5, filed as **#415**, per the convention that a criterion whose remainder is filed and numbered may be
split. This PR **closes #408**.

| # | criterion | disposition |
|---|---|---|
| 1 | encode/decode **Forward Relocation Request/Response** (133/134) incl. Table 7.3.1-2 PDN Connections and Table 7.3.1-3 Bearer Contexts, with **literal field assertions** | **done** — §3, §4 |
| 2 | **Complete Notification/Acknowledge** (135/136) complete the procedure so the source learns the move succeeded and can release | **done** — §4.4 |
| 3 | FC **`0x74`** (Annex A.14.2), bound to the **downlink** NAS COUNT, asserted to differ from `0x73` for identical inputs | **done** — §7 |
| 4 | `inter_system_handover_refusal` stops declining `FivegsToEps` **only when a Forward Relocation can actually be driven**, and still declines when it cannot | **done** — §6, and the conditional has **three** conjuncts, not one |
| 5 | `/relocate` re-establishes N3 tunnels: the ceiling comment and `log::warn!` go, replaced by an `Nsmf_PDUSession_UpdateSMContext` per SMF | **SPLIT to #415.** Its premise is void as written and the real work is in **smfd**, not amfd — see §2.2. The ceiling comment is **rewritten** with the corrected mechanism and **#415** rather than left naming #408 |
| 6 | the data-forwarding decision is **recorded** — tunnels established, or the site states which bearers lose data and why | **done, and it is a DECISION** — §5 |
| 7 | behind the same `AMF_N26_INTERWORKING` / `MME_N26_INTERWORKING` switches; standalone 5GC and EPC unchanged with the switches off | **done** — §8 |
| 8 | a test drives a connected-mode inter-system handover and asserts the transferred bearer contexts and tunnel endpoints are **readable from the target's store** — positive assertions | **done** — §9 |

### 2.1 Why criterion 5 splits, and why the split is at this seam

Criterion 5 asks for *"an `Nsmf_PDUSession_UpdateSMContext` per SMF carrying the endpoints
the Forward Relocation Request supplied"*. Three facts, each pinned, make that the wrong
call in the wrong daemon:

1. **The clause names a different operation.** TS 23.502 §4.11.1.2.2.2 **step 4**
   (`23502-k20.txt:21384-21391`) is explicit: *"The initial AMF invokes the
   **Nsmf_PDUSession_CreateSMContext** service operation (UE EPS PDN Connection, initial AMF
   ID, data Forwarding information, Target ID) on the SMF identified by the SMF+PGW-C address
   and indicates HO Preparation Indication"*. `UpdateSMContext` appears in this direction only
   at **execution** step 7 (`:21747-21752`), carrying a *"Handover Complete Indication"* — and
   that is a **completion signal, not an endpoint delivery**. So the criterion names the
   operation that carries no endpoints and omits the one that does.

2. **The endpoints do not arrive where the criterion says.** §5.2.2.2.5.1
   (`29518-k00.txt:2953-2958`) has *"the NF Service Consumer shall carry per PDU session the
   S-NSSAI for serving PLMN, the MME Control Plane Address and the TEID **in the request**"* —
   that is, as JSON members of `UeContextRelocateData`, put there by the *initial* AMF which
   already decoded the Forward Relocation Request. The `forwardRelocationRequest` binary part
   (`TS29518_Namf_Communication.yaml:3727-3728`) is the raw message for the target's reference.
   And `UeContextRelocateData`'s schema (`yaml:3717-3746`) has **no member for the MME address
   or TEID at all** — they ride inside `ueContext`. So "the endpoints the Forward Relocation
   Request supplied" describes the *initial* AMF's job, and `/relocate`'s producer is the
   **target** AMF in a re-allocation case that only arises when the initial AMF reselects.

3. **The SMF cannot consume them.** `handle_sm_context_create`
   (`smfd/src/main.rs:2941`, body grepped through `:3400`) reads no `ueEpsPdnConnection`,
   no `epsBearerContext`, and no HO Preparation Indication. smfd **produces** that container
   (`build_ue_eps_pdn_connection`, `main.rs:5706`) and has never consumed one. So even a
   perfectly-built call from amfd would be answered by an SMF that ignores the endpoints,
   which is this tree's commonest defect wearing a different hat: not "correct but
   unreachable" but **"reachable but inert"**.

Filing the remainder is therefore not a scope dodge — the criterion as written would produce
a call no SMF acts on. **#415** owns: smfd consuming `ueEpsPdnConnection` +
`hoPreparationIndication` on `CreateSMContext`, allocating a CN tunnel per §4.11.1.2.2.2
step 6, and answering the `EPS Bearer Setup List` of step 7; then amfd driving it. That is
an smfd-shaped piece of work, and this PR is an amfd+mmed one.

**What this PR does do at that site:** `record_transferred_sessions`'s ceiling comment and
its `log::warn!` are **rewritten**, not left. They currently say the gap closes when #408
lands the Forward Relocation consumer — which after this PR is false, because the consumer
now exists and the gap is still open for the reason above. Leaving the text would be a
ceiling that lies about its own cause. The new text names `CreateSMContext` (not Update), the
SMF-side gap, and **#415**.

---

## 3. The library: Forward Relocation, pinned line by line

### 3.1 Message types, each read off its own row

TS 29.274 Table 6.1-1, the `MME to MME, … MME to AMF, AMF to MME (S3/S10/S16/N26)` block.
All four were already present and asserted by #347's
`gtp2_n26_message_types_match_ts29274_table_6_1_1`; re-verified rather than re-added, because
#401 found three of four IE ids inferred from adjacent rows were wrong.

| type | message | vendored line |
|---|---|---|
| 133 | Forward Relocation Request | `29274-j60.txt:2422` |
| 134 | Forward Relocation Response | `29274-j60.txt:2425` |
| 135 | Forward Relocation Complete Notification | `29274-j60.txt:2428` |
| 136 | Forward Relocation Complete Acknowledge | `29274-j60.txt:2431` |

### 3.2 IE types this leg newly depends on

Every one read off its own Table 8.1-1 row (`29274-j60.txt:24400-24620`), not from a
neighbour:

| IE | id | vendored line | used for |
|---|---|---|---|
| Cause | 2 | `:24422` | Response / Complete Acknowledge (M) |
| Indication | 77 | `:24460` | Request (C), the **DFI** flag |
| F-TEID | 87 | `:24487` | Sender's F-TEID (M), bearer forwarding endpoints |
| Bearer Context | 93 | `:24505` | Table 7.3.1-3 and Table 7.3.2-2 |
| MM Context | 107 | `:24538` | Request (**M**) |
| PDN Connection | 109 | `:24546` | Request (C) |
| F-Container | 118 | `:24569` | Source/Target-to-Target/Source transparent container |
| F-Cause | 119 | `:24572` | S1-AP Cause |
| PLMN ID | 120 | `:24575` | Selected PLMN ID |
| Target Identification | 121 | `:24578` | Request (C) |

All ten already existed in `Gtp2IeType` (`ie.rs:16-77`), so **no enum variant is added** — and
that is worth stating, because #347's §1 recorded the opposite mistake in the other direction.
`gtp2_forward_relocation_ie_types_match_ts29274_table_8_1_1` pins the six this PR newly reads
(77, 118, 119, 120, 121, and 107's re-use as mandatory rather than conditional).

### 3.3 Table 7.3.1-1: what a Forward Relocation Request carries

The presence column is read off each row. The three that are **M** are the load-bearing
difference from a Context Response, where the MM Context is merely conditional:

| IE | P | line | note |
|---|---|---|---|
| IMSI | C | `:17786` | *"except if the UE is emergency or RLOS attached and the UE is UICCless"* |
| **Sender's F-TEID for Control Plane** | **M** | `:17797` | the AMF's own N26 F-TEID, interface type 40 |
| MME/SGSN/AMF UE EPS PDN Connections | C | `:17801` | PDN Connection (109), instance 0 |
| SGW S11/S4 F-TEID for Control Plane | C | `:17839` | instance **1** |
| **MME/SGSN/AMF UE MM Context** | **M** | `:17871` | MM Context (107) — *mandatory here*, unlike §7.3.6 |
| Indication Flags | C | `:17874` | *"shall be included if any … flags are set to 1"* |
| E-UTRAN Transparent Container | C | `:17995` | F-Container (118) instance 0, the Source-to-Target container |
| Target Identification | C | `:18029` | Target Identification (121) |
| S1-AP Cause | C | `:18051` | F-Cause (119) instance 0 |
| Selected PLMN ID | C | `:18082` | PLMN ID (120) |
| Recovery | C | `:18090` | restart counter |

**The SGW control-plane F-TEID at instance 1 is sent as the reserved value, and §4.11.1.2.1
step 3 requires exactly that**: *"The SGW address and TEID for both the control-plane or EPS
bearers in the message are such that target MME **selects a new SGW**"* (`23502-k20.txt:21058-21060`).
So the reserved value is not a gap this core papers over — it is the instruction, and it is
the same reserved-F-TEID discipline #347 already established for the user-plane one. The
existing `Gtp2PdnConnectionIe::n26_reserved_sgw_fteid()` is reused rather than a second
all-zero constructor being written.

### 3.4 Table 7.3.1-2 and Table 7.3.1-3: the nested layout

Table 7.3.1-2 (`:18484`) and Table 7.3.6-2 (#347's) **differ**, and the difference is checked
rather than assumed. The members this PR emits, mandatory first:

| member | P | IE / ins | line |
|---|---|---|---|
| APN | M | APN (71) / 0 | `:18498` |
| Linked EPS Bearer ID | M | EBI (73) / 0 | `:18523` |
| PGW S5/S8 IP Address for Control Plane or PMIP | M | F-TEID (87) / 0 | `:18526` |
| Bearer Contexts | C | Bearer Context (93) / 0 | `:18541` |
| Aggregate Maximum Bit Rate | M | AMBR (72) / 0 | `:18546` |
| IPv4 Address | C | IP Address (74) / 0 | `:18516` |

— which is **the same member set** Table 7.3.6-2 gives, so `Gtp2PdnConnectionIe` is reused
unchanged and no rival type is introduced. That was checked, not presumed: Table 7.3.1-2 adds
`APN Restriction`, `Selection Mode`, `PDN Type` and a dozen `CO` members that Table 7.3.6-2
also has, and its `Bearer Contexts` row is `C` where 7.3.6-2's is `M` — neither difference
touches what this AMF can supply.

Table 7.3.1-3's Bearer Context (`:18809`):

| member | P | IE / ins | line |
|---|---|---|---|
| EPS Bearer ID | M | EBI (73) / 0 | `:18823` |
| **SGW S1/S4/S12 IP Address and TEID for user plane** | **M** | F-TEID (87) / 0 | `:18827` |
| PGW S5/S8 F-TEID for user plane | C | F-TEID (87) / **1** | `:18849` |
| Bearer Level QoS | M | Bearer QoS (80) / 0 | `:18868` |

and `:18833-18843` is the reserved-value rule, verbatim: over N26 *"the SMF (on behalf of the
source AMF) shall set the IP address and TEID to the following values: - any reserved TEID
(e.g. all 0's, or all 1's); - IPv4 address set to 0.0.0.0"*. Identical wording to Table
7.3.6-3's, which is why one constructor serves both.

### 3.5 Table 7.3.2-2: the Bearer Context that carries forwarding, and what it proves

This is the table criterion 6 turns on, and it earns its own subsection because reading it
settles the decision. §7.3.2's own prose at `:19396-19397` says: *"Bearer Context IE in this
message is specified in Table 7.3.2-2, **the source system shall use this IE for data
forwarding in handover**"*. Its members:

| member | P | IE / ins | line | applies to 5GS→EPS? |
|---|---|---|---|---|
| EPS Bearer ID | C | EBI (73) / 0 | `:19413` | **yes** — *"if the message is used for … 5GS to EPS handover or EPS to 5GS handover"* |
| eNodeB/gNodeB F-TEID for DL data forwarding | C | F-TEID (87) / 0 | `:19430` | **only EPS→5GS** — *"included during a 4G to 5G handover in the message sent from the target AMF"* |
| eNodeB F-TEID for UL data forwarding | O | F-TEID (87) / 1 | `:19450` | no — *"during the intra-EUTRAN HO"* |
| **SGW/UPF F-TEID for DL data forwarding** | CO | F-TEID (87) / **2** | `:19461` | **yes** — *"when using indirect data forwarding during an EPS to 5GS handover **or a 5GS to EPS handover**"* |
| RNC / SGSN F-TEID | C | F-TEID (87) / 3, 4 | `:19470`, `:19476` | no — SGSN only |
| SGW F-TEID for UL data forwarding | O | F-TEID (87) / 5 | `:19482` | no — *"during the intra-EUTRAN HO"* |

So for a **5GS→EPS** handover the target MME may return exactly **two** things this AMF can
act on: the EBI, and an **instance-2 SGW/UPF F-TEID for DL data forwarding** present only
when *indirect* forwarding applies. Instance 0 — the eNB's own DL forwarding endpoint, which
is what *direct* forwarding would need — is by its own condition *"included during a 4G to 5G
handover"*, i.e. the **other** direction. That asymmetry is the whole of §5.

---

## 4. The procedure

### 4.1 amfd, source side: driving a Forward Relocation Request

`amfd/src/n26_build.rs` (new) is pure — context in, messages out, no socket, no globals —
split from `n26_path` exactly as mmed's `n26_build` is split from its `n26_path`, so every
wire assertion is a value comparison rather than a transport test. `n26_path` gains the
sending and receiving halves.

The chain, against TS 23.502 §4.11.1.2.1:

| step | who | what | site |
|---|---|---|---|
| 1 | gNB → AMF | `HandoverRequired`, `HandoverType = fivegs-to-eps`, **Direct Forwarding Path Availability** | `ngap_path::handle_handover_required` |
| 2a-2c | AMF → SMF | per-session EPS PDN connection retrieval | `n26_path::retrieve_pdn_connections` (#347's, reused) |
| 3 | AMF → MME | **Forward Relocation Request (133)** | `n26_path::send_forward_relocation_request` |
| 6 | MME → AMF | **Forward Relocation Response (134)** with the Target-to-Source container | `n26_path::handle_forward_relocation_response` |
| 10a-11 | AMF → gNB | `HandoverCommand`, forwarding decision recorded | §5 |
| — | MME → AMF | **Forward Relocation Complete Notification (135)** | `n26_path::handle_forward_relocation_complete_notification` |
| — | AMF → MME | **Forward Relocation Complete Acknowledge (136)** | same site |

**Production reachability, proven not asserted.** `grep -n` over amfd for each new function
shows a non-`#[cfg(test)]` caller:
- `send_forward_relocation_request` ← `ngap_path::handle_handover_required`, which the NGAP
  receive loop reaches from `HANDOVER_PREPARATION`;
- `handle_forward_relocation_response` and `handle_forward_relocation_complete_notification`
  ← `N26Server::handle_datagram`, the loop `N26Server::open` spawns and `n26_open` installs
  from `lib.rs`'s `run` at startup.

That is stated here because "correct but unreachable" is this tree's commonest defect — nine
instances in one session, including a dead MBS manager whose driving enum variants had zero
senders.

### 4.2 The MM Context is different from #347's, in two ways that matter

§7.3.1's MM Context is **mandatory** where §7.3.6's is conditional, and the *contents* differ
because TS 33.501 §8.3.2 step 2 (`33501-k20.txt:11335-11340`) requires:

> the source AMF shall derive a K'_(ASME) using the K_(AMF) key and the **current downlink 5G
> NAS COUNT** of the current 5G security context as described in clause 8.6.1 and then
> **increments its stored downlink 5G NAS COUNT value by one**.

and step 2's continuation (`:11372-11375`): *"The source AMF subsequently derives NH two times
… The {NH, NCC=2} pair is provided to the target MME as a part of UE security context in the
Forward Relocation Request message."*

So versus #347's idle-mode MM Context: **FC `0x74` not `0x73`**, bound to the **downlink**
COUNT not the uplink one, and **`NHI = 1`** with an NH/NCC pair rather than `NHI = 0`.
`Gtp2MmContextIe` already has the `nhi` field (`ie.rs:1439`) and its encoder already honours
it (`:1483`), but **`NH` and `NCC` themselves are not encoded** — Figure 8.38-5 puts them at
octets `p..(p+31)` and `(p+32)` (`29274-j60.txt:28278-28281` in the figure rows), *after* the
DRX parameter and *before* the AMBR octets, and #347's encoder jumps straight from `K_ASME`
to the three length-prefixed capability fields.

**That is the one library change this PR makes**, and it is stated as a ceiling rather than
silently worked around: see §10.

### 4.3 The COUNT, at which moment, in which direction

This is the row the prompt flags as a trap, and the nextgsim #203 defect it names — a `KgNB`
derived from the wrong NAS COUNT, because `protect_uplink` incremented the count before the
derive, so the UE used the *next* message's COUNT. The three facts, each from its own line:

1. **Which COUNT:** downlink. Annex A.14.2 (`33501-k20.txt:17150-17154`): `FC = 0x74`,
   `P0 = NAS Downlink COUNT value`, `L0 = 0x00 0x04`, `KEY = K_AMF`. §8.6.1
   (`:11743-11747`) makes the choice explicit — *"the 5G NAS Uplink COUNT value derived from
   the TAU Request message or Attach Request message **in idle mode mobility** or the 5G NAS
   **Downlink COUNT value in handovers**"*.

2. **At which moment:** the **current** downlink COUNT, *before* the increment. §8.3.2 step 2
   is ordered: *"derive a K'_(ASME) using … the current downlink 5G NAS COUNT … **and then**
   increments its stored downlink 5G NAS COUNT value by one"*. Deriving after the increment
   is precisely the #203 defect, and it is invisible to every test that does not fix the
   COUNT independently.

3. **Why the increment happens at all:** step 7 (`:11409-11412`) has the AMF send *"the 8 LSB
   of the downlink NAS COUNT value used in K_(ASME)' derivation in step 2"* to the UE, and
   step 8 has the UE *"ensure that the estimated downlink NAS COUNT value is **greater than**
   the stored downlink NAS COUNT value"*. So the COUNT must be consumed — a second handover
   reusing it would derive the same `K_ASME'` twice, and the UE would reject the second.

The derive site therefore reads `dl_count`, derives, and **then** writes `dl_count + 1` back —
in that order, under the pool write lock, with the pre-increment value returned so the
HANDOVER COMMAND's container carries the COUNT that was actually used rather than a re-read.
`the_handover_kasme_is_bound_to_the_downlink_count_before_the_increment` asserts all three:
the key equals `kdf_kasme_prime_handover(kamf, dl_count_before)`, the stored count advanced by
exactly one, and the key does **not** equal the same function of `dl_count_before + 1`.

### 4.4 Complete Notification and Acknowledge (criterion 2)

Table 7.3.3-1 (`:19500`) gives the Notification **no mandatory IE at all** — only a
conditional `Indication Flags` and a `Private Extension`. Table 7.3.4-1 (`:19554`) gives the
Acknowledge a **mandatory Cause** and an optional Recovery.

That shape is why this half is small and why it is nonetheless not a formality: §7.3.3
(`:19493-19495`) says the Notification *"shall be sent to the source MME/SGSN/AMF to indicate
the handover has been successfully finished"*, and §4.11.1.2.1 step 12d
(`23502-k20.txt:21167-21169`) has the source AMF answer and **start a timer to supervise when
resources in NG-RAN shall be released** — step 21 (`:21279-21281`) is where the UE Context
Release Command actually goes out. So an AMF that never answers 136 is an AMF whose source
gNB holds radio resources for a UE that has left.

Both directions are implemented:
- as the **source** (5GS→EPS): the AMF *receives* 135 and answers 136 with
  `Request accepted`, then releases the source NG-RAN context — reusing the same
  `build_ue_context_release_command_asn1` + `cause successful-handover` path
  `handle_handover_notify` already uses (`ngap_path.rs:7950-7960`), rather than a second
  spelling of "release the source".
- as the **target** (EPS→5GS): `send_forward_relocation_complete_notification` exists and is
  driven from `handle_handover_notify` when the UE arrived from EPS — §4.11.1.2.2.3 step 5
  (`23502-k20.txt:21738-21741`): *"the target AMF knows that the UE has arrived to the target
  side and informs the MME by sending a Forward Relocation Complete Notification message"*.

### 4.5 mmed, target side

mmed's `n26_build` gains the parse/build counterparts and `n26_path` the dispatch. The target
MME's job on receiving 133 is TS 23.401 §5.5.1.2.2 step 4-5: install the context, then drive
an S1AP `HandoverRequest` toward the target eNB. `install_transferred_context` (#347's,
`n26_path.rs:599`) already does the install and is **reused unchanged** — the same write-back
discipline, the same `&mut` under the pool write lock rather than the discarded-clone bug
`mme_ue_find_by_id` invites.

What is new on the mmed side is the **response**: building 134 with the Target-to-Source
container and a Table 7.3.2-2 Bearer Context per admitted bearer, and the
`ForwardRelocationCompleteNotification` when the UE arrives. The forwarding endpoint mmed
puts at instance 2 is the SGW's, which it gets from the CIDFT response #48 already plumbs
(`s11_handler`'s deferred-command path) — so the MME's half of indirect forwarding is real
where the AMF's is not, and §5 says so.

---

## 5. The data-forwarding decision — criterion 6

**This is a decision, recorded, and it is the #185 posture: the AMF states which bearers lose
data and why, at the site, and it does so with the spec's own signal rather than a fabricated
success.**

### 5.1 What was decided

For **5GS→EPS connected-mode handover this AMF does not establish forwarding tunnels**, and
the HANDOVER COMMAND carries an **empty `PDU Session Resource Handover List`** with the reason
logged per PDU session and per EBI. Indirect forwarding is **not** claimed, direct forwarding
is **not** claimed, and the GTPv2-C `Indication` IE's **DFI flag is left clear** — which is
not a default but a statement, for the reason in §5.3.

For **EPS→5GS**, where mmed is the source and the AMF the target, the MME's existing #48
indirect-forwarding machinery is honoured: mmed reads the AMF's instance-2 SGW/UPF F-TEID
from the Forward Relocation Response and routes forwarding through it. That direction is not
ceilinged, because the endpoint arrives rather than having to be produced.

### 5.2 Why — three facts, each pinned, and none of them a preference

**(a) Direct forwarding needs a container this tree cannot build.** §4.11.1.2.1 step 11
(`23502-k20.txt:21151-21155`): *"If direct data forwarding is applied, Data forwarding tunnel
info includes E-UTRAN tunnel info for data forwarding per EPS bearer. NG-RAN initiate data
forwarding to the target E-UTRAN based on the Data Forwarding Tunnel Info"*. On the NGAP wire
that "tunnel info" is `HandoverCommandTransfer.dLForwardingUP-TNLInformation`
(`38413-j30.txt:48919`), inside each `PDU Session Resource Handover Item`
(`38413-j30.txt:13196-13206`). **This tree has no `HandoverCommandTransfer` encoder** (§1,
fact c) — the intra-5GS path relays the target gNB's own transfer verbatim
(`ngap_path.rs:7627-7634`), and inter-system there is no target gNB to have produced one.
Writing that encoder is real work in `nextgcore-ngap` and it would still not close the gap,
because of (b).

**(b) Indirect forwarding needs an SMF operation the SMF does not implement.**
§4.11.1.2.1 step 10a (`23502-k20.txt:21099-21101`): *"If data forwarding applies, the AMF
sends the **Nsmf_PDUSession_UpdateSMContext Request (data forwarding information)** to the
SMF+PGW-C"*, and 10b (`:21103-21110`) has the SMF *"select an intermediate PGW-U+UPF for data
forwarding"* and return, in 10c (`:21116-21118`), a *"Data Forwarding tunnel Info"*. Those
endpoints are **allocated by the UPF**, relayed by the SMF, and there is no other source for
them. smfd's `handle_sm_context_update` (`main.rs:4131-4562`) implements the `hoState`
machine `PREPARING → PREPARED → COMPLETED` and **no data-forwarding branch**:
`grep -rn "indirect_data_forwarding\s*=\|data_forwarding_not_possible\s*=" bins/nextgcore-smfd/src/`
returns **nothing** — the two fields exist on `SmfSess` (`context.rs:960-961`) and are
initialised once to `false` (`main.rs:2684`) with **zero further writers**. So the AMF has
nowhere to ask, and an `UpdateSMContext` carrying data-forwarding information would be
answered by the `hoState` arm, which ignores it.

**(c) Even if (a) and (b) were closed, the endpoint the MME returns would be absent.**
Table 7.3.2-2's `SGW/UPF F-TEID for DL data forwarding` at instance 2 is `CO` — *"shall be
included when using indirect data forwarding during an EPS to 5GS handover or a 5GS to EPS
handover"* (`:19461-19468`) — conditioned on indirect forwarding *applying*, which is what the
AMF signals with DFI and step 3's Direct Forwarding Flag. So the chain is: AMF must claim
forwarding → MME establishes it → MME returns the endpoint → AMF relays it to the gNB. This
AMF cannot complete the last link (a) and cannot begin the first honestly (b). **Claiming
forwarding it cannot relay would be strictly worse than declining it**: the MME would
establish indirect tunnels through a Serving GW, hold them until its timer expired
(§4.11.1.2.1 step 16 / 21), and the source gNB would forward to an endpoint it was never
told — so the data would be lost *and* both nodes would have leaked tunnel state.

### 5.3 What is stated, and where

Three sites, each naming the consequence rather than the omission:

1. **`n26_build::forward_relocation_indication`** — DFI is clear, and the doc says why with
   the clause: `29274-j60.txt:25930-25933` defines DFI as *"direct data forwarding applies
   between the source RAN and the target RAN … during an inter-system handover between 5GS and
   EPS"*. Setting it would tell the MME the source gNB has a path to the target eNB **and**
   that this AMF will relay the endpoints — and (a) says it cannot. Table 7.3.1-1's Indication
   row (`:17874`) is *"shall be included if any one of the applicable flags is set to 1"*, so
   with DFI clear and no other applicable flag the **IE is omitted entirely** rather than sent
   with a zero DFI — the same distinction #347 drew for MSV, and for the same reason: a
   present-but-zero Indication claims every applicable flag was evaluated.

   **Even when the gNB says direct forwarding IS available**, DFI stays clear — and that is
   the sharpest part of the decision. The IE is now parsed (§1 fact b) precisely so the
   refusal can be *specific*: the log names the gNB's own `direct-path-available` and says the
   AMF is declining to use it because it cannot encode the `HandoverCommandTransfer` the
   source gNB would need. Discarding the IE, as the base did, would have made that
   distinction unsayable.

2. **`ngap_path`'s HANDOVER COMMAND site** — logs, per PDU session and per EBI, that the
   bearer is handed over **without forwarding**, so *"downlink data in flight at the source
   gNB for these bearers is DISCARDED, not forwarded"*, and names which of (a)/(b) applies.
   The list is empty rather than absent-by-accident, and `38413-j30.txt:38763` makes it
   `PRESENCE optional` so an empty list is conformant (§1 fact d). The UE still gets its
   bearers: §4.11.1.2.1 step 11 has the UE correlate QoS flows with EPS Bearer IDs from the
   command, and that correlation does not depend on forwarding.

3. **`namf_server::record_transferred_sessions`** — rewritten per §2.2.

`a_5gs_to_eps_handover_command_declines_forwarding_and_says_which_bearers_lose_data` asserts
the decision positively: the list is empty, the Indication IE is absent from the Forward
Relocation Request, and the refusal is reported **even when the gNB advertised a direct
path** — the last being the assertion that fails if someone later wires DFI to the parsed IE
without also writing the transfer encoder.

### 5.4 Why not simply refuse the handover instead

Because the UE is better served by a handover that completes with a data gap than by a
refusal. §4.11.1.2.1 is a *connected-mode* procedure triggered by radio conditions, load, or
IMS voice fallback (step 1, `:20925-20931`) — a UE whose radio is failing and whose handover
is refused loses the session entirely, where one handed over without forwarding loses only
the packets in flight and resumes on the target eNB. TS 23.401 §5.5.1.2.2's own "no
forwarding" path exists for exactly this. That is the #185 posture applied in the direction it
points: answer with what is true, at the honest ceiling, rather than fail closed **or** claim
success. Criterion 4's conditional (§6) is what keeps the *other* case — the one where the
AMF cannot drive the procedure at all — an honest refusal.

---

## 6. `inter_system_handover_refusal` — criterion 4, and the three conjuncts

The criterion is *"no longer declines `FivegsToEps` when the N26 leg is enabled **AND** a
Forward Relocation procedure can actually be driven — and still declines when it cannot"*.
Getting that conditional right is the trap, because "the leg is enabled" is the easy half and
is not sufficient.

`inter_system_handover_refusal` (`ngap_path.rs:9760`) keeps its shape — a pure
decision function, split from transmission so the decision is assertable without an
SCTP-connected gNB (`context.rs` records that amfd has no harness driving
`handle_handover_required`). It gains a parameter for **whether a Forward Relocation can be
driven**, computed by a new `n26_path::forward_relocation_drivable()`:

```text
forward_relocation_drivable() =
      n26_path::enabled()          // the runtime switch (§8)
  &&  n26_path::server().is_some() // a BOUND socket, not just a set switch
  &&  !mme_n26_peers().is_empty()  // somewhere to send it
```

All three are load-bearing and none is redundant:

- **`enabled()`** is the switch, and alone it is exactly the insufficient reading: `n26_open`
  (`n26_path.rs:760-781`) forces the switch back **off** when no bind address is configured,
  but a *bind failure* returns `Err` and `lib.rs:971-977` logs and continues — so a process
  can have the switch set and no socket.
- **`server().is_some()`** covers that: no socket means no source address for the AMF's
  mandatory `Sender's F-TEID` (Table 7.3.1-1, `:17797`, **M**), so the request could not be
  built even if it had somewhere to go.
- **`!mme_n26_peers().is_empty()`** is the conjunct #347 never needed and this PR adds, for
  the reason in §1 fact (a): the AMF was purely reactive on N26 and has **no MME peer
  configuration at all**. Without a peer there is no destination, and routing the preparation
  would produce the exact defect #347 refused to introduce — forwarding a preparation the AMF
  cannot complete, which is strictly worse than an honest refusal.

`EpsTo5gs` **keeps refusing unconditionally**, and that is not an oversight. A
`HandoverRequired` with `HandoverType = eps-to-5gs` arriving at this AMF from a **gNB** is
malformed: §9.3.1.22 (`38413-j30.txt:19660-19662`) makes the type *"which kind of handover was
triggered in the source"*, and an EPS→5GS handover is triggered in the **E-UTRAN** and reaches
this AMF as a Forward Relocation Request over N26 (§4.11.1.2.2.2 step 3), never as an NGAP
`HandoverRequired`. So there is no condition under which routing it is right, and
`ho-target-not-allowed` remains the accurate answer.

The peer list is `amf.n26.client.mme` in config plus an `AMF_N26_MME_ADDR` environment
override, mirroring mmed's `mme.n26.client.amf` (`mmed/src/config.rs:327`) so the two ends of
one interface are configured the same way rather than two ways.

`inter_system_handover_refusal_routes_only_when_a_forward_relocation_can_be_driven` asserts
the full truth table — all eight combinations of the three conjuncts for `FivegsToEps`,
`EpsTo5gs` refused in all eight, and `Intra5gs` never refused — so a conjunct silently
dropped to `true` fails here.

---

## 7. `K_ASME'` for handover — criterion 3, FC `0x74`

`nextgcore_kdf_kasme_prime_handover` (new, `nextgcore-crypt`) sits beside
`nextgcore_kdf_kasme_prime` (FC `0x73`) and `nextgcore_kdf_kamf_prime` (FC `0x72`), reusing
`nextgcore_kdf_common` so there is one TS 33.220 B.2.0 construction in the tree.

Annex A.14.2 (`33501-k20.txt:17144-17156`), read on its own rather than inferred from A.14.1:

```text
FC  = 0x74
P0  = NAS Downlink COUNT value
L0  = length of NAS Downlink COUNT value (i.e. 0x00 0x04)
KEY = K_AMF
```

so `S = FC(0x74) || P0(downlink NAS COUNT, 4 octets BE) || L0(0x0004)`.

**The `0x73` form is structurally identical** — same key, same 4-octet COUNT, same `L0` — and
differs **only in the FC octet**. So a copy-paste yields a well-formed 32-byte key that no
MME can reproduce, and no round trip detects it. The criterion's own requirement, *"asserted
to differ from the FC `0x73` idle-mode form for identical inputs"*, is exactly this hazard,
and `kasme_prime_handover_matches_ts33501_annex_a_14_2` asserts it head-on plus:

- **golden vectors computed independently** of this implementation. An outside HMAC-SHA256 was
  fed `S = 0x74 || COUNT(4, big-endian) || 0x0004` with `KEY = [0x55; 32]`, straight from
  A.14.2's parameter list, and the digests pasted in. That independence is the point: it
  catches a wrong FC, a wrong `L0`, a reversed parameter order, or `to_ne_bytes()` instead of
  `to_be_bytes()` — where a self-snapshot would bless all four. (The tree has both kinds:
  `kamf_prime_matches_its_golden_vectors` pastes its own output and says so.)
- `COUNT = 0xFFFF_FFFF`, because a 4-octet COUNT truncated to the MM Context's 3 would still
  differ from `COUNT = 1` and pass every negative assertion.
- distinctness from **both** `0x73` and `0x72` for identical inputs.

The doc comment spells out the `S` layout so a reviewer holding the annex can check it by eye.
**No published 3GPP test vector exists** for A.14.2, the same ceiling `kdf.rs:401-408` already
records for A.14.1; interop against a real MME remains the outstanding validation, and that
is stated at the site rather than implied.

`kdf.rs:397-399`'s comment — *"Annex A.14.2 (FC 0x74 …) is the handover counterpart and is
deliberately absent: connected-mode 5GS→EPS handover is #408, and a KDF with no caller is the
dead code this tree keeps growing"* — is replaced by a pointer to the new function, because
that sentence becomes false the moment this lands. And the new function **has a caller**:
`n26_build::build_handover_mm_context`, reached from `send_forward_relocation_request`.

---

## 8. The runtime switches — criterion 7

No new switch. Both halves sit behind #347's `AMF_N26_INTERWORKING` /
`MME_N26_INTERWORKING`, read through `n26_path::enabled()` — not `cfg!`, for the reason
`smfd/src/eps_iwk.rs:19-29` records and this PR does not re-litigate: CI builds default
features, so a feature-gated path is left **uncompiled** and rots. A runtime switch is
compiled always and exercised in *both* states by one `cargo test` run.

With the switches off, asserted rather than claimed:
- no Forward Relocation Request is built or sent — `send_forward_relocation_request` returns
  an `Err` naming the switch, the same shape as #347's `send_context_request`;
- `inter_system_handover_refusal` **still refuses** `FivegsToEps`, because
  `forward_relocation_drivable()`'s first conjunct is `enabled()` (§6);
- `iwk_n26_posture()` is unchanged;
- no socket is bound and standalone 5GC / standalone EPC behave as at `fd99448`.

`with_the_switches_off_no_forward_relocation_is_driven_and_the_refusal_stands` asserts all
four, and it is what makes criterion 7 a test rather than a claim about a build CI never
performs.

Each `set_for_test` takes the crate's **existing** process-state lock —
`amfd::test_support::CONTEXT_GUARD`, `mmed::gtp_path::S11_TEST_LOCK` — and this PR declares
**no new lock**, in either crate, and none inside a `mod tests`. #276's lesson is that a
second lock over one variable *hangs* the suite rather than flaking it, and the globals here
(`N26_ENABLED`, `N26_SERVER`, the MME peer list, the UE/session/bearer pools) are the ones
those guards already cover.

---

## 9. Positive assertions, not "no error" — criterion 8

`a_connected_mode_inter_system_handover_transfers_the_bearer_contexts_to_the_mme` drives the
whole chain in-process across **both** daemons and asserts, **from the MME's own pools
afterwards**:

1. the **IMSI** the AMF held;
2. the **K_ASME'**, against an independently computed
   `kdf_kasme_prime_handover(kamf, dl_count_before_increment)` — so a zeroed key, a copied
   `K_AMF`, an FC `0x73` key, and a key derived from the *post*-increment COUNT each fail;
3. the **`NCC = 2`** and the **NH** the MME must put in its S1 HANDOVER REQUEST
   (§8.3.2 step 4, `33501-k20.txt:11361-11366`) — this is the assertion #347's idle-mode test
   could not make, because idle mode has no AS keys;
4. the **EBI** on a real `MmeBearer`;
5. the **PGW-C S5/S8 control-plane TEID** and address on a real `MmeSess`;
6. the **APN** and the converted **APN-AMBR**;
7. that the bearer is on `sess.bearer_list`, not merely in the pool.

The Forward Relocation Request is built by amfd's **real** `build_forward_relocation_request`
from a real `AmfUe`, **encoded and decoded over the wire** (so a framing bug fails there), and
installed through mmed's **production** `install_transferred_context` — not a test
reimplementation of it. That is the strict-peer pattern lmfd, pcfd and udmd already use, and
it is what catches the two sides drifting; a request hand-written in mmed's crate would agree
with mmed's parser by construction.

A negative assertion ("no error was returned") is satisfied by every path that never arrives,
which is what makes it useless here and what let a dead MBS manager and a caller-less
`udm_nrf_register` ship.

**Literal field assertions, not only round trips** (criterion 1). Round-tripping is blind to
transposition, to an off-by-four on a nested offset, and to a swapped instance number, so:
- `forward_relocation_request_carries_its_table_7_3_1_1_ies` asserts the message type as the
  literal `133`, the MM Context present at instance 0 (**mandatory** here, `:17871`), the
  Sender's F-TEID at instance 0 with interface type `40`, the SGW control F-TEID at instance
  **1** and reserved, and the Indication IE **absent** (§5.3);
- `forward_relocation_bearer_context_matches_ts29274_table_7_3_1_3` asserts the reserved SGW
  user-plane F-TEID at instance **0** and the PGW one at instance **1** — transposing them is
  invisible to a round trip and would point an MME's user plane at the wrong endpoint;
- `forward_relocation_response_bearer_context_matches_ts29274_table_7_3_2_2` asserts the
  forwarding endpoint at instance **2**, which §3.5 shows is the only one that applies to
  5GS→EPS;
- `handover_mm_context_encodes_nh_and_ncc_at_figure_8_38_5_positions` asserts the NH at its
  exact contents offset and `NCC` in the low 3 bits of the octet after it, with `NHI = 1` in
  octet 5 bit 5.

### Revert-verification

Each behavioural claim was made to fail, the **named** test watched to fail, and restored:

| change made | test that failed |
|---|---|
| `kdf_kasme_prime_handover` FC `0x74` → `0x73` | `kasme_prime_handover_matches_ts33501_annex_a_14_2` |
| that FC → `0x75` (A.15.1's, the adjacent row) | same |
| `to_be_bytes()` → `to_ne_bytes()` in the new KDF | same (the golden vectors) |
| derive from `dl_count + 1` instead of `dl_count` | `the_handover_kasme_is_bound_to_the_downlink_count_before_the_increment` |
| derive from `ul_count` instead of `dl_count` | same |
| send `NH_1` instead of `NH_2` with `NCC = 2` | same |
| `ncc` field sent as `0`, ignoring the constant | same |
| `MM_CONTEXT_NCC_AT_HANDOVER` 2 → 1 | `handover_mm_context_encodes_nh_and_ncc_at_figure_8_38_5_positions` |
| `NCC` written shifted (`2 << 3`) | same |
| `NHI` forced `true` while NH still gated | same |
| Forward Relocation Request type `133` → `130` | `forward_relocation_request_carries_its_table_7_3_1_1_ies` |
| MM Context omitted from the request (legal in §7.3.6, **M** in §7.3.1) | same |
| `FR_INSTANCE_SGW_CONTROL_FTEID` 1 → 0 | same |
| `forward_relocation_indication` made to set DFI | same |
| SGW and PGW user-plane F-TEID instances transposed (0↔1) | `forward_relocation_bearer_context_matches_ts29274_table_7_3_1_3` |
| `FR_INSTANCE_FORWARDING_FTEID` 2 → 0 | `forward_relocation_fteid_instances_match_their_tables` **and** `forward_relocation_response_bearer_context_matches_ts29274_table_7_3_2_2` (see below) |
| `CAUSE_RELOCATION_FAILURE` 81 → 75 | `forward_relocation_response_carries_its_table_7_3_2_1_ies` |
| DFI read from bit 6 (`HI`) instead of bit 5 | `direct_forwarding_indication_is_read_from_ts29274_8_12_bit_5` |
| the `!mme_n26_peers().is_empty()` conjunct forced `true` | `inter_system_handover_refusal_routes_only_when_a_forward_relocation_can_be_driven` |
| the `server().is_some()` conjunct forced `true` | same |
| `EpsTo5gs` made to route when the leg is drivable | same |
| `forwarding_sessions` made non-empty | `a_5gs_to_eps_handover_command_declines_forwarding_and_says_which_bearers_lose_data` |
| `bearers_without_forwarding` emptied | same |
| `nas_count_lsb` taken from the post-increment count | same |
| `DirectForwardingPathAvailability` arm removed from `parse_handover_required` | `handover_required_keeps_the_direct_forwarding_path_availability_ie` |
| `take_forward_relocation_source` made to answer `Some` for every UE | `the_complete_notification_fires_only_for_a_ue_that_arrived_over_n26` |

### Four findings from the revert sweep and the reachability audit

**(1) The truth table was too narrow.** Forcing `socket_bound` to `true` initially **passed
the whole amfd suite**. The reason is the finding, not a footnote: the first draft's table
exercised `enabled()` and the peer list but seeded a bound server in every case, so the
conjunct that distinguishes "switch set, bind failed" — the one real production path where
`enabled()` is `true` and there is no socket (`lib.rs`'s `n26_open` error branch logs and
continues) — had no case at all. The test now enumerates all eight combinations rather than the
four that were convenient, and both forced-`true` flips fail against it. Same shape as #347's
UE-status-bit finding: the conjunct the whole refusal hangs on was unpinned, and with it wrong
the AMF would route a preparation into a socket that does not exist.

**(2) A position test that round-tripped through its own constant.** Flipping
`FR_INSTANCE_FORWARDING_FTEID` from 2 to 0 initially left
`forward_relocation_response_bearer_context_matches_ts29274_table_7_3_2_2` **green** — it wrote
the endpoint at `FR_INSTANCE_FORWARDING_FTEID` and read it back from the same constant, so it
agreed with whatever value that constant held. Only the literal-pinning test caught it. The
test now writes the **literal `2`** and plants a **decoy at instance 0** (the eNB/gNB endpoint
Table 7.3.2-2 conditions on a 4G-to-5G handover), so a wrong constant fails on both sides. The
general lesson, and it applies to every instance-keyed IE in this tree: a test that uses the
constant under test on both sides of a round trip pins nothing about that constant.

**(3) A builder with only a test caller — caught by grepping, not by a failing test.**
`build_forward_relocation_complete_notification` existed in **both** crates with no production
caller at all: the "correct but unreachable" defect this tree keeps growing, and criterion 2
(*"Complete Notification/Acknowledge complete the procedure, so the source node learns the move
succeeded and can release"*) was therefore **not** satisfied by having the encoder. Two different
fixes, because the two crates are in different positions:

- **mmed** IS the target of a 5GS→EPS move, so the builder is now driven from
  `s1ap_handler::handle_handover_notify` via `n26_path::notify_forward_relocation_complete`. That
  needed new state (`ForwardRelocationSource`, keyed by `mme_ue_id`) because S1AP's HandoverNotify
  carries **nothing** saying where the UE came from — so without a record the MME would notify an
  AMF on every intra-LTE handover. Fired **before** the source-context release, because an N26
  arrival has no local source eNB context and the `enb_ue_find_by_id` below takes an early exit
  that would skip the notification.
- **amfd** is the **source** in the only direction #408 implements: it receives 135 and answers
  136. It is the target only in EPS→5GS, which needs #415's `CreateSMContext` consumer. So its
  builder was **deleted** and replaced by a comment recording why a builder there would be
  unreachable. Deleting beat keeping: an encoder no caller can reach is the defect, not the
  mitigation.

The guard test then needed its own fix. Asserting on `notify_forward_relocation_complete` could
not distinguish "not an N26 arrival" from "no bound socket" — both answer `false`, so dropping the
gate entirely still passed. The decision is now split out as `take_forward_relocation_source` and
the test asserts on that, which is the same decision/transmission split
`inter_system_handover_refusal` uses. **General lesson:** when a function's failure paths
collapse to one return value, a test on that value pins none of them.

**(4) A public accessor with zero callers, same audit.** The same grep found
`n26_path::forward_relocation_outcome(ue)` — added on the theory that `ngap_path` would consult it
when building the HandoverCommand — with **no callers at all**. The outcome arrives
asynchronously on the N26 receive loop, so that is where the decision is computed
(`handle_forward_relocation_response` calls `inter_system_handover_command` directly). A public
accessor nothing reads is the unreachable-encoder defect one layer up, so it was **removed**
rather than kept for a caller that may never arrive, along with the test helper that existed only
to feed it. `clippy --all-targets` on both crates now reports no unused item in any file this PR
touches.

**One thing the revert sweep caught in the code rather than the tests.**
`CAUSE_RELOCATION_FAILURE` was first written as **75**, inferred from §7.3.2's prose position
rather than read from Table 8.4-1. Checking the table found 75 is *"Syntactic error in the TFT
operation"* and `Relocation failure` is **81** (`29274-j60.txt:25480`). That is #401's defect
exactly — three of four IE ids inferred from adjacent rows were wrong — and it survived the
first `cargo test` because nothing yet asserted the value against the table. The constant is
now pinned in both crates with the line quoted.

---

## 10. Ceilings, stated at the site

**Data forwarding is not established for 5GS→EPS.** §5, in full, with the three pinned facts
and the two named consequences. Not restated here beyond the pointer, because the site carries
it.

**`/relocate` still cannot move N3 tunnels, and the reason has changed.** §2.2. The ceiling
comment and `log::warn!` at `record_transferred_sessions` are **rewritten** rather than
removed: the Forward Relocation consumer this PR adds was the cause they named, and it now
exists, so leaving the text would be a ceiling lying about itself. The new text names
`CreateSMContext` (per §4.11.1.2.2.2 step 4, not Update), the absent smfd-side consumer, and
**#415**.

**NH and NCC are newly encoded in `Gtp2MmContextIe`, and the fields between them and
`K_ASME` are still absent.** Figure 8.38-5 orders the optional tail
`Authentication Quadruplets → Quintuplets → DRX parameter → NH → NCC → AMBR octets → the
three length-prefixed capability fields`. This PR emits `NH`/`NCC` immediately after
`K_ASME`, which is correct **only because** all four preceding gates are zero — both vector
counts (§8.38 requires 0 on N26 in both directions, `:28190-28202`), `DRXI = 0` (§8.38 forbids
sending the 5G DRX parameter to an MME, `:27727-27733`), and `UAMBRI`/`SAMBRI` = 0. That
invariant is asserted by `handover_mm_context_encodes_nh_and_ncc_at_figure_8_38_5_positions`
rather than left as a comment, because a future change setting `SAMBRI = 1` would silently
shift the NH by eight octets and the decoder would read a key out of AMBR bytes. The decoder
reads `NH`/`NCC` only when `NHI = 1`, which is the figure's own gate.

**The Target-to-Source container is relayed, not interpreted.** TS 38.413 §9.3.1.21's
inter-system form is *"encoded according to the definition of the Target eNB to Source eNB
Transparent Container IE as specified in TS 36.413"* (`38413-j30.txt:5952-5955`) — an
E-UTRAN structure the AMF has no business decoding. It crosses from the Forward Relocation
Response's F-Container (118/0) into the HANDOVER COMMAND byte-for-byte, the same discipline
`handle_uplink_ran_status_transfer` already applies.

**The NAS Security Parameters from NG-RAN IE is not sent.** §9.2.3.2 makes it
`C-iftoEPSUTRA` (`38413-j30.txt:13181-13184`) and §9.3.3.26 (`:29892-29910`) says it *"Refers
to the N1 mode to S1 mode NAS transparent container IE"*, whose value part is **one octet** —
TS 24.501 §9.11.2.7 (`24501-k00_5_Main-Body_s09_s10.txt:776-793`): a type-3 IE of 2 octets
whose octet 2 is a `Sequence number`. TS 33.501 §8.3.2 step 7 (`:11409-11412`) says what goes
in it: *"the 8 LSB of the downlink NAS COUNT value used in K_(ASME)' derivation in step 2"*.
**The value is computed and logged**, and it is not put on the wire because
`build_handover_command` (`builder.rs:639-674`) has no arm for IE 39
(`id-NASSecurityParametersFromNGRAN`, `38413-j30.txt:59511`) and adding one is an
`nextgcore-ngap` change with its own encode/decode tests. The consequence is named at the
site: the UE cannot estimate the downlink COUNT from the HANDOVER COMMAND and so cannot
derive the same `K_ASME'`, which means the handover's **NAS security will not interoperate
with a real UE** even though the MME side is correct. That is the honest ceiling, stated
where a reader will look, rather than a container encoded with a plausible octet.

**Two decoders for one message, in mmed.** `n26_path` uses the library decoder for
transaction correlation and `n26_build` walks the IEs for content — the cost
`s11_handler.rs:248-252` already records for S11 and says #51 did not ask to remove. Matched
rather than compounded.

---

## 10a. Docs, because two claims became false

#408 lists no docs criterion, but #347 set `docs/index.html` and `docs/features.html` to say
*"connected-mode inter-system handover is not implemented"* and *"Connected-mode inter-system
handover (GTPv2-C Forward Relocation) is still absent, so a UE in a call cannot be handed
over"*. Both are false after this PR, and leaving them would be the docs defect #116 existed to
fix — in the other direction.

Neither file is upgraded to a flat "implemented", which would be the same defect a third way.
Both now say what is true and what is not:

- **`docs/features.html`**: the existing N26 row loses its "Connected-mode handover not
  implemented" tail, and a **new row** marks connected-mode handover `partial`, naming the
  runtime switch, the A.14.2 key, the empty forwarding list, and the un-encoded NAS Security
  Parameters IE. mmed's own row gains "connected-mode Forward Relocation as the target".
- **`docs/index.html`**: the `<meta description>` and the hero paragraph both say a connected UE
  *can* be handed over, and both state the two ceilings — no forwarding tunnels, so in-flight
  downlink data is discarded; and the NAS Security Parameters IE is not encoded, so NAS security
  does not interoperate with a real UE.

---

## 10b. A pre-existing test flake, found by CI and fixed here

The dispatched run on the final commit **failed** in `Test`:
`twelve_establish_release_cycles_keep_getting_an_ebi_and_twelve_without_release_do_not`
answered **404 where 200 was expected** (*"cycle 2 of eleven must fit"*). The test is in
`namf_server.rs` and this PR touches nothing near the EBI path.

**Established as a flake, not a regression**, by re-dispatching the **byte-identical commit** —
which passed. Three earlier CI runs of the branch also passed, and the amfd suite passed 8/8
locally plus 3× at each of `--test-threads=1,2,4,8,16`.

**The cause is a convention violation the audit surfaced.** A 404 means
`find_ue_by_context_id` no longer resolved the UE, i.e. something removed it from the live
store mid-test. **Seven** tests in that module read and write the process-global AMF context and
the live store **without taking `crate::test_support::CONTEXT_GUARD`**, while **50** siblings in
the same module do — including `release_ue_context_releases_the_context` and
`cancel_relocate_ue_context_releases_the_relocated_context`, both of which call
`amf_ue_unpublish`. A guarded test holding the guard does not exclude an unguarded one, so a
release could evict the EBI test's UE between its cycles.

All seven now take the **existing** guard. Never a new lock: #276 showed a second lock over the
same variables *hangs* the suite rather than merely flaking it. `assign_ebi_request`, the helper
they share, carries the full rationale so the next test added there inherits it.

**Honesty about the fix, recorded at the site rather than only here:** the race was **not
reproduced locally** — 25 runs at `--test-threads=16` with the guard removed all passed, so the
window is narrower than that hammering reaches and this is not a *verified* fix for the observed
failure. What it definitely is: closing the only mechanism by which a sibling can evict the UE
mid-test, and bringing seven tests in line with the convention the other fifty follow. Claiming
more than that would be the kind of overstatement this tree's ceilings exist to avoid.

---

## 11. Verification

- `cargo fmt --all -- --check` clean.
- `cargo clippy --workspace` clean (warnings are errors); **no `#[allow]` added**.
- `cargo test --workspace`: **6902 → 6922** passed, 0 failed. This change adds **20**.
- `nextgcore-crypt`, `nextgcore-gtp`, `nextgcore-ngap`, `nextgcore-amfd`, `nextgcore-mmed`
  suites looped **10×** with `head -1 /proc/loadavg` noted each pass, because five of the new
  tests touch process-global context and a pass that only ever ran once proves nothing about
  ordering.
- CI dispatched on `feat/408-v5-wt` and read via `--log`, not the tick: this touches the EPC
  seam and `Docker Build` / `Docker E2E` / `EPC bring-up` are gated
  `schedule || workflow_dispatch`, so they **skip on a PR**. As of `fd99448` there are zero
  live `continue-on-error` directives in `ci.yml` (PR #414 removed the last three), so a
  heavy-job failure genuinely fails the job and no tolerance was reintroduced to get green.

Standalone posture, asserted rather than claimed: with both switches off no socket is bound,
no Forward Relocation is built, `inter_system_handover_refusal` refuses exactly as at
`fd99448`, and `iwk_n26_posture()` is unchanged.
