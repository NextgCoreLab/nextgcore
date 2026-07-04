# PDU Sessions and the PFCP Session Model

A PDU session is the end-to-end user-plane pipe between a UE and a data network: an IP address for the UE, a GTP-U tunnel across N3, and a set of forwarding/QoS rules programmed into the UPF over N4/PFCP. This chapter traces how NextGCore actually builds one — from the NAS *PDU Session Establishment Request* that arrives at the SMF, through the PCF policy call, the PFCP session toward the UPF, the N2 resource-setup container handed back to the gNB, and finally the GTP-U packets that the UPF forwards. Every step below names the file and function/struct that implements it, and where the implementation takes a shortcut relative to the 3GPP procedure, that shortcut is called out rather than glossed over.

> **Honesty note:** The PDU-session and PFCP behavior described here is validated by this project's own unit tests plus a matched-simulator docker E2E (84/84 green as of 2026-07-02), **not** by third-party conformance certification. The peer on the other side is the in-tree `nextgsim` gNB/UE, not a commercial RAN or a certified test set. Concrete simplifications (a hand-rolled NAS accept encoder, a bespoke PFCP TLV codec, a userspace UPF fast path, an unwired UDM fetch) are listed under [Simplifications and known gaps](#simplifications-and-known-gaps). TS numbers below are quoted only where they appear in this repo's source comments, phrased "per code comments".

## Components involved

| Function | Daemon / crate | Role in the PDU session |
|---|---|---|
| SMF | [`nextgcore-smfd`](../configuration/smf.md) | Owns the session: parses N1, calls PCF, drives N4/PFCP, builds the N1 accept + N2 setup transfer. |
| UPF | [`nextgcore-upfd`](../configuration/upf.md) | The PFCP node: installs PDR/FAR/QER/URR, terminates N3 GTP-U, forwards packets via a TUN device. |
| AMF | [`nextgcore-amfd`](../configuration/amf.md) | Relays N1 (NAS) to the UE and the opaque N2 transfer to the gNB; not covered in depth here. |
| PCF | [`nextgcore-pcfd`](../configuration/pcf.md) | Authorizes Session-AMBR / 5QI via Npcf_SMPolicyControl (optional — a config-default is used when absent). |
| NSACF | [`nextgcore-nsacfd`](../configuration/nsacf.md) | Optional per-slice PDU-session admission (fail-open when not deployed). |
| PFCP model | `src/libs/nextgcore-pfcp` | Header/SEID model, IE-type registry, typed message structs. |
| NGAP transfers | `src/libs/nextgcore-ngap` | Real-APER PDU Session Resource *transfer* codec used for the N2 container. |

## The two state machines (and how much they actually drive)

The SMF ships two ported finite-state machines:

- **GSM (5G Session Management)** — `src/bins/nextgcore-smfd/src/gsm_sm.rs`, struct `GsmFsm`, states `Initial → Wait5gcSmPolicyAssociation → WaitPfcpEstablishment → Operational → WaitPfcpDeletion → …` (`GsmState`).
- **PFCP node FSM** — `src/bins/nextgcore-smfd/src/pfcp_sm.rs`, struct `PfcpFsm`, states `Initial → WillAssociate → Associated`.

Be aware of a real structural fact: these FSMs are largely **state-tracking scaffolding**, not the engine that builds messages. Their handlers (`GsmFsm::dispatch`, `PfcpFsm::dispatch`) mostly log, flip a state, and return `Handled`/`Ignored`; the header comments describe them as a "Port of src/smf/gsm-sm.c / pfcp-sm.c". The real establishment logic lives in one imperative async function, `handle_sm_context_create` in `src/bins/nextgcore-smfd/src/main.rs`, which constructs a fresh `GsmFsm`, calls `fsm.init()`, and drives it with several `fsm.dispatch(...)` calls — the initial `ESTABLISHMENT_REQUEST` gsm_message dispatch (~line 2006), the PCF policy response via `fsm_dispatch_policy_response(&mut fsm, …)` (which itself calls `fsm.dispatch`, ~lines 2052/2059), and an `n4_message` dispatch after PFCP establishment (~line 2212) — interleaved with explicit `fsm.transition_to(...)` calls (`WaitPfcpEstablishment`/`Exception`) for logging while it does the actual work inline. When you read the flow below, treat the FSM state names as a narration of `handle_sm_context_create`, not as an independent dispatcher.

## PDU session establishment, step by step

The trigger is an SBI `POST` to `Nsmf_PDUSession` CreateSMContext from the AMF. The whole flow is `handle_sm_context_create` (`main.rs`).

```
UE ──NAS PDU Session Est. Req──▶ AMF ──Nsmf CreateSMContext──▶ SMF
                                                                │
                          (1) validate  (2) parse N1  (3) alloc UE IP
                          (4) NSAC admit (5) PCF policy
                                                                │
                                        (6) PFCP Session Est. ──▶ UPF
                                        ◀── UP F-SEID + UPF N3 F-TEID ──
                                                                │
                    (7) build N1 Accept   (8) build N2 setup transfer (APER)
                                                                │
SMF ──201 multipart {SmContext, n1SmMsg, n2SmInfo}──▶ AMF ──▶ gNB + UE
```

1. **Parse and validate `SmContextCreateData`.** `handle_sm_context_create` deserializes the JSON body and calls `validate_sm_context_create_data`; genuinely-missing mandatory IEs are rejected with the matching `ProblemDetails` cause. It then reads `pduSessionId` (1..15), `dnn`, `sNssai.sst`/`sd`, and (leniently) `supi`, `anType`, `smContextStatusUri`. Per code comments, this maps to TS 29.502 Table 6.1.6.2.2-1. **Lenience worth knowing:** the current matched-sim AMF omits `supi`/`anType`, so those are warned-and-defaulted (`"imsi-unknown"`, `3GPP_ACCESS`) rather than rejected.

2. **Decode the N1 container.** The N1 `PDU Session Establishment Request` arrives either as a multipart `application/vnd.3gpp.5gnas` part (resolved from its `RefToBinaryData` contentId) or as a base64 string — `resolve_binary_ref` accepts both. It is parsed by `policy::parse_establishment_request`, yielding PTI, requested PDU-session type, and requested SSC mode. **This SMF serves IPv4 only:** `selected_type` collapses IPv4/IPv4v6 to IPv4; IPv6-only/Ethernet/Unstructured are rejected with 5GSM cause #50 ("PDU session type IPv4 only allowed", per code comments).

3. **Allocate the UE IP.** `context.ipv4_pool.allocate()` draws from `Ipv4Pool` (`src/bins/nextgcore-smfd/src/session_extensions.rs`), a bitmap allocator over a `/16`. `Ipv4Pool::default_pool()` is `10.45.0.0/16` and reserves `.0.0` (network) and `.0.1` (gateway); exhaustion returns 5GSM cause #26 insufficient resources. This is the UE's IPv4 for the life of the session; a `release_ip` closure rolls it back on any later failure.

4. **Slice admission (optional).** `policy::resolve_nsacf_endpoint()` + `policy::nsac_pdu_session_admit(...)` ask the NSACF whether a new PDU session is admissible for this S-NSSAI (per code comments, TS 29.536 §5.3). This is **fail-open**: no NSACF configured, or an unreachable one, proceeds anyway; only an explicit `Rejected` (quota exhausted) fails the session with 5GSM cause #67.

5. **SM policy (PCF, or config-default).** `policy::resolve_pcf_endpoint()` decides the source:
   - **PCF present:** `policy::sm_policy_create(...)` performs Npcf_SMPolicyControl_Create (per code comments, TS 29.512 §4.2.2) and returns a `PolicyDecision` (default 5QI, Session-AMBR UL/DL, PCC rules). A PCF *rejection* fails the session (cause #29-family); a PCF that is configured-but-**unreachable** is a hard `504` failure with cause #38 — no silent fallback.
   - **No PCF:** `PolicyDecision::config_default_for_dnn(&dnn)` applies a documented default (DNN-derived 5QI, AMBR 100/100 Mbps). An "xr" DNN yields a delay-critical GBR XR 5QI so the XR QER path below is still exercised.

   The decision is then post-processed: `decision.ensure_xr_for_dnn(&dnn)` (Rel-18 XR 5QI upgrade for an XR DNN) and, for a `redcapIndication` UE, a Session-AMBR cap (default 150/50 Mbps DL/UL, env-overridable) applied once so it flows to the N1 accept, the PFCP QER, and the stored binding.

   > **Not wired:** there is **no** UDM `Nudm_SDM` subscription-data fetch on this path. The GSM FSM has a placeholder `nudm-sdm` branch, but `handle_sm_context_create` and `policy.rs` never call UDM — session type, DNN and S-NSSAI come from `SmContextCreateData` + the N1 container, and QoS comes from PCF or the config default. (SMF↔UDM N10 exists as an interface line but is not on the establishment path.)

6. **PFCP Session Establishment toward the UPF.** `pfcp_session_establish` (`main.rs`) builds and sends the N4 request. See [The PFCP session, as built](#the-pfcp-session-as-built) for the exact PDR/FAR/QER layout. On success it returns the UPF's `UP F-SEID`, the UPF N3 GTP-U TEID, and the UPF N3 address, and stores the `upf_seid` in `SmfContext.pfcp_sessions` keyed by `smContextRef`.

7. **Build the N1 `PDU Session Establishment Accept`.** `policy::build_establishment_accept` (`src/bins/nextgcore-smfd/src/policy.rs`) hand-encodes the 5GSM message byte-by-byte: octet-5 SSC|type, the authorized QoS-rules LV-E, the Session-AMBR, the IPv4 PDU address, the S-NSSAI IE (`0x22`), conditional QoS-flow descriptions (`0x79`), and the DNN. Its doc comment stresses the layout is byte-identical to the legacy encoding and golden-tested. When the UE asked for IPv4v6 but only the IPv4 leg is granted, 5GSM cause #50 is attached (per code comments, TS 24.501 §8.3.2.2).

8. **Build the N2 `PDUSessionResourceSetupRequestTransfer`.** `build_setup_request_transfer` (`main.rs`) — this is **real APER**, encoded through `nextgcore_ngap::transfer::PduSessionResourceSetupRequestTransfer::encode()`, carrying the UPF N3 F-TEID (`UpTransportLayerInformation::GtpTunnel`) and a `QosFlowSetupRequestItem` (QFI, `NonDynamic5qi`, ARP). The code comment is explicit about *why* it is real APER: "the gNB's strict APER decoder rejects the legacy hand-rolled byte layout (smfd#2)." This is a place where an earlier bespoke-bytes shortcut was deliberately replaced with a spec codec — the N2 setup, modify, path-switch, and setup-response transfers all go through `nextgcore-ngap`.

9. **Respond.** `sbi_response_with_n1_n2` (`main.rs`) returns `201` as `multipart/related`: a JSON `SmContextCreatedData` root (`smContextRef`, `pduSessionId`, `upCnxState: "ACTIVATING"`, `n2SmInfoType: "PDU_RES_SETUP_REQ"`) plus two binary parts — `n1SmMsg` (`application/vnd.3gpp.5gnas`) and `n2SmInfo` (`application/vnd.3gpp.ngap`) — referenced by `RefToBinaryData` (per code comments, TS 29.502 §6.1.2.2.2/§6.1.2.4). **Shortcut:** the N1/N2 are kept *inline* in the CreateSMContext response; the separate `Namf_Communication` N1N2MessageTransfer is noted in-code as out of scope (smfd-03).

### Completing the tunnel: SM Context Update

The gNB accepts the resource and reports its own downlink GTP-U endpoint. The AMF forwards this as an `Nsmf_PDUSession` update, handled by `handle_sm_context_update` (`main.rs`), which dispatches on `n2SmInfoType`:

- `PDU_RES_SETUP_RSP` → `decode_setup_response_dl_endpoint` (real-APER `PDUSessionResourceSetupResponseTransfer`) extracts the gNB DL TEID + address + QFI.
- `PATH_SWITCH_REQ` → `decode_path_switch_dl_endpoint` (real-APER `PathSwitchRequestTransfer`) for an Xn handover.

Either way the SMF then calls `pfcp_session_modify` (`main.rs`), which sends a PFCP **Session Modification** that flips the downlink FAR from BUFF to FORW and installs an `OuterHeaderCreation` (GTP-U/UDP/IPv4, description `0x0100`) pointing at the gNB TEID, with the SNDEM flag to emit End Markers on any old tunnel. Only after this does downlink traffic actually flow to the UE.

## The PFCP session, as built

### Request construction (SMF side)

`pfcp_session_establish` builds the message with the SMF's bespoke TLV builder `n4_build::PfcpMessageBuilder` (not the library's typed structs). It first checks `client.is_associated()` — no session signalling without an association (per code comments, TS 29.244 6.2.6.2) — then assembles:

| IE | Value | Notes |
|---|---|---|
| Node ID (IPv4) | SMF IP | `add_node_id_ipv4` |
| F-SEID | `smf_n4_seid = (sess_idx \| 0x1000)` | SMF's own SEID |
| APN/DNN, S-NSSAI | from the request | |
| **Create QER 1** | Session-AMBR as MBR UL/DL, gates open, QFI | enforces authorized AMBR |
| **Create QER 2** (conditional) | XR GBR UL/DL | only when the authorized 5QI is XR (82–85); GBR is the wire-stable XR signal since a 6-bit QFI cannot carry an 82–85 5QI |
| **Create PDR 1** (uplink) | source interface **Access(0)**, F-TEID `teid=0` (UPF allocates), outer-header-removal GTP-U/UDP/IPv4, FAR 1, QER, QFI | |
| **Create FAR 1** (uplink) | apply-action **FORW(0x02)**, dest interface **N6/SGi(2)** | |
| **Create PDR 2** (downlink) | source interface **Core(1)**, UE IP as destination, FAR 2 | |
| **Create FAR 2** (downlink) | apply-action **BUFF(0x04)**, dest interface **Access(0)** | buffered until the gNB TEID arrives (step above) |

It sends `SESSION_ESTABLISHMENT_REQUEST` with **SEID=0** for a new session (per code comments, TS 29.244 7.2.2.4.2) through the transaction engine (T1/N1 retransmission). A missing/rejected `Cause` is a hard failure — there is deliberately no fabricated-TEID fallback, since that would create a data-plane black hole.

**Response parsing is hand-rolled here:** rather than decode with the library, `pfcp_session_establish` walks the response TLVs itself, pulling the `UP F-SEID` (IE type 57) and the `Created PDR` (IE 8) → `F-TEID` (IE 21). The code even documents a subtle gotcha: the F-TEID V4 flag is Bit1 (`0x01`), the **opposite** of F-SEID's V4 flag (Bit2), per code comments TS 29.244 §8.2.3 vs §8.2.37. A missing UP F-SEID or a missing Created-PDR F-TEID aborts the session.

### The object model (UPF side)

The UPF stores everything in a per-session `SessionContext` (`src/bins/nextgcore-upfd/src/n4_handler.rs`), which is just four `HashMap`s plus a BAR:

```
SessionContext { upf_n4_seid, smf_n4_seid,
                 pdrs: HashMap<u16, Pdr>,
                 fars: HashMap<u32, Far>,
                 urrs: HashMap<u32, Urr>,
                 qers: HashMap<u32, Qer>,
                 bar:  Option<Bar> }
```

- **`Pdr`** (`context.rs`) — `pdr_id`, `precedence`, `source_interface`, optional `ue_ip`/`f_teid`/`sdf_filter`, `far_id`, `qer_id`, `urr_ids`, `outer_header_removal`. `Pdr::pdr_match` compares source interface, UE IP, and TEID; SDF filters compile via `nextgcore-ipfw` but full per-packet SDF matching happens in the data plane.
- **`Far`** (`context.rs`) — `apply_action` bitmask (DROP `0x01`, FORW `0x02`, BUFF `0x04`, NOCP `0x08`, DUPL `0x10`), `destination_interface`, optional `OuterHeaderCreation`, forwarding/duplicating params, `bar_id`. Helpers `should_forward`/`should_drop`.
- **`Qer`** (`n4_handler.rs`) — `qer_id`, `GateStatus{ul_gate,dl_gate}` (0=open), `Mbr`, `Gbr`, `qfi`, `rqi`, `ppi`.
- **`Urr`** (`n4_handler.rs`) — measurement method/reporting-trigger flag structs, volume/time thresholds and quotas; accounting lives in `UrrAccounting`.

`handle_session_establishment_request` (`n4_handler.rs`) inserts the incoming PDRs/FARs/URRs/QERs/BAR into those maps (each guarded by `MAX_NUM_OF_*` caps → `NoResourcesAvailable`). `handle_session_modification_request` applies create/update/remove for each rule class. `handle_session_deletion_request` snapshots each URR into a final `UsageReport` before teardown.

The shared **`nextgcore-pfcp`** library underpins the wire format: `header.rs` models the `PfcpHeader` (the S-bit `seid_presence`, the 8-byte no-SEID vs 16-byte with-SEID layouts, and `has_seid()` per message type); `ie.rs` is the `IeType` registry (`CreatePdr=1`, `CreateFar=3`, `CreateUrr=6`, `CreateQer=7`, `CreatedPdr=8`, …); `message.rs` and `types.rs` carry typed structs (`AssociationSetupRequest/Response` with a Recovery Time Stamp, `SessionEstablishmentRequest`/`Response` that validate a present `UP F-SEID` on accept, `CreatePdr`/`CreateFar`/`CreateQer`). In practice the daemons build and parse the concrete bytes through their own per-daemon `n4_build` module, so the library's typed message structs and the daemons' TLV codecs coexist.

## PFCP association, heartbeats, and failure handling

Session signalling requires a live association, and **the SMF is the initiator**:

- `associate()` (`src/bins/nextgcore-smfd/src/pfcp_path.rs`) sends `ASSOCIATION_SETUP_REQUEST`; on an accepted cause it sets `associated = true` and records the peer's Recovery Time Stamp.
- The UPF answers in `handle_association_setup_request` (`src/bins/nextgcore-upfd/src/pfcp_path.rs`): Node ID and Recovery Time Stamp are mandatory (per code comments, TS 29.244 7.4.4.1) — a missing one yields a rejected response naming the offending IE — otherwise it replies `ASSOCIATION_SETUP_RESPONSE` via `build_association_setup_response`.

Heartbeats keep the association alive and detect restarts. Both sides build/handle `HEARTBEAT_REQUEST`/`HEARTBEAT_RESPONSE` (`build_heartbeat_response` carries the sender's Recovery Time Stamp; heartbeat messages use SEID=0). On the SMF, a lapsed no-heartbeat timer tears down the association and returns the `PfcpFsm` to `WillAssociate` (i.e., UPF reselection, `PfcpFsm::handle_associated` on `N4NoHeartbeat`). On the UPF, a per-N3-peer `path_table` compares the Recovery Time Stamp on each heartbeat/echo to spot a restarted peer whose tunnels are now stale (per code comments, TS 29.281 §7.2.2 / TS 23.007).

Teardown mirrors setup: `handle_sm_context_release` (`main.rs`) calls `pfcp_session_delete`, which sends `SESSION_DELETION_REQUEST` (no body IEs, per code comments TS 29.244 7.5.6) keyed on the stored `upf_seid`; the UPF returns the final usage reports and drops the `SessionContext`.

## The UPF data plane (GTP-U ⇄ TUN)

The forwarder is a **userspace** fast path in `src/bins/nextgcore-upfd/src/data_plane.rs`. `DataPlane::run` opens the N3 GTP-U UDP socket (default `127.0.0.4:2152`, `--gtpu-addr`) and a TUN device, then spawns two tokio tasks feeding a `select!` loop:

- a GTP-U receive task (`recv_from`) → `handle_uplink_packet`;
- a TUN read task (`libc::read` on the raw fd) → `handle_downlink_packet`.

The TUN device is **its own inline `TunDevice`** (`data_plane.rs`), which opens `/dev/net/tun` directly via `libc` and is Linux-only (the macOS `create` is a stub returning an error). Default interface `ogstun`, IP `10.45.0.1/16` (`--tun-ip`/`--tun-prefix`) — the gateway that the E2E ping targets. Note the workspace ships a `nextgcore-tun` library, but **the UPF does not use it** (a grep for `nextgcore_tun` in `nextgcore-upfd/src` is empty).

**Uplink — `handle_uplink_packet` (gNB → UPF → data network):**
1. `parse_gtpu_header`; branch on message type — reply to `ECHO_REQUEST`, raise an Error-Indication Report to the SMF on `ERROR_INDICATION`, update the path table on `ECHO_RESPONSE`, ignore `END_MARKER`; only `GPDU` continues.
2. Locate the session by uplink TEID (`find_by_ul_teid`), falling back to the inner source IP (`find_by_ue_ip`). A GPDU for an unknown non-zero TEID triggers a GTP-U Error Indication back to the sender (per code comments, TS 29.281 §7.3.1); TEID=0 is dropped silently.
3. **Anti-spoofing:** the inner source IP must equal the session's allocated UE IP, else drop and count (per code comments, TS 23.501 §5.6.1).
4. `match_pdr_with_packet(SRC_INTF_ACCESS, …)` → check the QER gate (`check_qer_gate`, a token bucket built from the MBR) and pull any DSCP → apply the FAR (`Forward`/`Drop`/`Buffer`) → record URR bytes. No PDR match ⇒ drop (per code comments, TS 23.501 §5.8.2).
5. MTU guard, optional inner-packet DSCP marking (checksum recomputed), then `libc::write` the decapsulated IP packet to the TUN.

**Downlink — `handle_downlink_packet` (data network → UPF → gNB):**
1. Find the session by destination UE IP (`find_by_ue_ip`).
2. `match_pdr_with_packet(SRC_INTF_CORE, …)` → QER gate + DSCP + QFI → apply the FAR:
   - `Forward` → resolve `(dl_teid, gnb_addr)` from the FAR's `OuterHeaderCreation` (or the session default);
   - `Buffer` → queue the packet, and on the first buffered packet with NOCP set, emit a **Downlink Data Report** to the SMF (per code comments, TS 29.244 5.2.3);
   - `Drop` → drop.
3. DSCP is applied to the **outer** transport header via a GTP-U socket `IP_TOS` option, never the inner UE packet (per code comments, TS 23.501 §5.7.4 — the inner packet is carried byte-for-byte on N3).
4. `encapsulate_dl_gpdu` prepends the GTP-U header, carrying the QFI in a PDU Session Container extension header (per code comments, TS 38.415 / TS 29.281), and `send_to` the gNB.

When the SMF's modification flips the DL FAR to FORW, `main.rs`'s `handle_pfcp_session_event` calls `update_session_from_pfcp` (record gNB TEID/addr) and then `flush_buffered_dl`, draining any packets buffered during establishment. Per-session and aggregate packet/byte counters are maintained throughout (the same counters surfaced in [Observability](../observability.md)).

## Simplifications and known gaps

Grounded in the code, not aspirational:

- **The GSM/PFCP FSMs are scaffolding.** `gsm_sm.rs`/`pfcp_sm.rs` mostly log and track state; the establishment logic is imperative in `handle_sm_context_create`, which advances the FSM with explicit `transition_to` calls. Do not expect the dispatcher to be authoritative.
- **No UDM subscription fetch.** Establishment never calls `Nudm_SDM`; QoS is PCF-or-config-default and session parameters come from `SmContextCreateData`/N1. The `nudm-sdm` FSM branch is unused.
- **Bespoke NAS 5GSM encoder.** `policy::build_establishment_accept` hand-writes bytes (golden-tested, byte-identical to the legacy layout) rather than using a general NAS codec.
- **Bespoke PFCP TLV codec with a hand-rolled response parser.** PFCP messages are built/parsed via each daemon's `n4_build`; `pfcp_session_establish` walks response TLVs manually, in parallel with the typed structs in `nextgcore-pfcp`.
- **N1/N2 carried inline in CreateSMContext.** The separate `Namf_Communication` N1N2MessageTransfer is explicitly out of scope (smfd-03).
- **IPv4 only.** IPv6/Ethernet/Unstructured sessions are rejected (cause #50); the IP pool is a single `/16` bitmap with no per-DNN/per-slice pools.
- **Userspace UPF forwarder, Linux-only TUN.** No eBPF/kernel offload; `data_plane.rs` uses `unsafe libc::read`/`write`; the macOS TUN path is a stub. The `nextgcore-tun` library is unused by the UPF.
- **Optional NFs fail open.** A missing/unreachable NSACF (and a missing PCF) do not block the basic data path by design.
- **What is genuinely spec-faithful:** the N2 resource transfers use the real-APER `nextgcore-ngap` codec (a deliberate fix so a strict-APER gNB decoder accepts them), the PFCP F-TEID/F-SEID flag handling and SEID=0-on-new-session semantics follow TS 29.244, and the GTP-U path implements Echo, Error Indication, End Marker, QFI extension headers, uplink anti-spoofing, and DL buffering with Downlink Data Reports.

## How it is validated

**Unit / property tests.** State-machine transitions (`gsm_sm.rs`, `pfcp_sm.rs` `#[cfg(test)]`), the NAS accept builder (`gsm_build.rs::test_build_pdu_session_establishment_accept`), the multipart N1/N2 response and APER transfer round-trip (`main.rs` tests such as `sm_context_created_response_is_multipart_with_binary_refs` and the `PduSessionResourceSetupRequestTransfer` decode test), the IPv4 pool (`session_extensions.rs`), and `property_tests.rs` in both `nextgcore-smfd` and `nextgcore-upfd`.

**Matched-simulator docker E2E.** The single entrypoint `docker/rust/e2e.sh` chains `preflight.sh → build.sh → e2e-test.sh`. `e2e-test.sh` brings up the full stack (5GC NFs + `nextgsim-gnb` + `nextgsim-ue`) and asserts, against real container logs, the whole establishment and — crucially — the data plane:

- UPF: `GTP-U path opened`, `Configured TUN device …10.45.0.1`, `Added data plane session`, `Updated data plane session …DL_TEID`;
- gNB: `GTP-U socket bound`, `created GTP-U session`;
- UE: `Sending PDU Session Establishment Request`, `PDU Session Establishment Accept`, `PDU session 1 is now ACTIVE (IPv4: Some…)`, `Creating TUN interface`;
- **User-plane proof:** `docker exec nextgsim-ue ping -c 3 10.45.0.1` — an ICMP round-trip *through the UE's GTP-U tunnel* to the UPF gateway.

The full baseline suite was **84/84 green on 2026-07-02** with 0% loss on the UE→UPF GTP-U path. Overlays extend the same suite: `--overlay kernel-sctp` (native N2 SCTP), `--overlay oauth2` (SBI token enforcement), `--overlay features` (Rel-17/18 harness). When an assertion fails, `e2e.sh` saves every container's `docker logs` under `docker/rust/artifacts/` before teardown; see [Observability & Troubleshooting](../observability.md) for the recipe and the log-grep pitfalls.
