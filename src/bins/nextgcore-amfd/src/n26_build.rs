//! N26 GTPv2-C **Forward Relocation** building and parsing for the AMF (#408).
//!
//! The AMF is the **source** node in 5GS→EPS connected-mode handover (TS 23.502
//! §4.11.1.2.1): a gNB sends it a `HandoverRequired` with `HandoverType = fivegs-to-eps`,
//! and the AMF hands the UE's context to a target MME with a **Forward Relocation Request**
//! (TS 29.274 §7.3.1, type 133).
//!
//! ```text
//! gNB --HandoverRequired(fivegs-to-eps)--> AMF
//!                                          AMF --Forward Relocation Request (133)--> MME
//!                                          AMF <--Forward Relocation Response (134)-- MME
//! gNB <--HandoverCommand------------------- AMF
//!                                          AMF <--Fwd Reloc Complete Notification (135)- MME
//!                                          AMF --Fwd Reloc Complete Acknowledge (136)--> MME
//! ```
//!
//! Split from [`crate::n26_path`] the same way mmed's `n26_build` is split from its
//! `n26_path`: this module is **pure** — context in, messages out, messages in, data out, no
//! socket and no globals — so every wire assertion in its tests is a value comparison rather
//! than a transport test.
//!
//! # How this differs from #347's Context Response, in three ways that matter
//!
//! #347 built the **idle-mode** 5GS→EPS transfer (Context Request/Response/Acknowledge,
//! 130/131/132). This is the connected-mode counterpart, and the differences are not cosmetic:
//!
//! 1. **The MM Context is mandatory, not conditional.** Table 7.3.1-1 (`29274-j60.txt:17871`)
//!    marks `MME/SGSN/AMF UE MM Context` **M**, where §7.3.6's Table 7.3.6-1 makes it
//!    conditional on the Cause being "Request Accepted". A Forward Relocation Request with no
//!    MM Context is malformed rather than merely unhelpful.
//! 2. **`K_ASME'` comes from FC `0x74` and the DOWNLINK COUNT.** TS 33.501 Annex A.14.2, not
//!    A.14.1 — see [`build_handover_mm_context`].
//! 3. **`{NH, NCC=2}` is carried.** TS 33.501 §8.3.2 step 2 requires the AS-level key pair the
//!    target eNB needs, which an idle-mode move has no target eNB for.

use bytes::{BufMut, Bytes, BytesMut};
use nextgcore_gtp::v2::{
    Gtp2BearerContextIe, Gtp2CauseIe, Gtp2FTeidIe, Gtp2Header, Gtp2Ie, Gtp2IeType,
    Gtp2IndicationIe, Gtp2Message, Gtp2MessageType, Gtp2MmContextIe, Gtp2PdnConnectionIe,
    MM_CONTEXT_NCC_AT_HANDOVER,
};

/// GTPv2-C cause `Request accepted` (TS 29.274 Table 8.4-1).
pub const CAUSE_REQUEST_ACCEPTED: u8 = 16;

/// GTPv2-C cause `Relocation failure` (TS 29.274 Table 8.4-1).
///
/// §7.3.2 (`29274-j60.txt:19133-19136`) names it as the Forward Relocation Response's
/// message-specific cause: *"The relocation has not been accepted by the target
/// MME/SGSN/AMF if the Cause IE value differs from 'Request accepted'. [...] Message
/// specific cause values are: - 'Relocation failure'."*
///
/// **81**, read off its own Table 8.4-1 row (`29274-j60.txt:25480`). The first draft of this
/// constant said 75 -- which is *"Syntactic error in the TFT operation"* -- and the revert-check
/// against the table caught it. #401's lesson: read the row, never count to it.
pub const CAUSE_RELOCATION_FAILURE: u8 = 81;

/// Instance of the `SGW S11/S4 IP Address and TEID for Control Plane` IE in a Forward
/// Relocation Request (Table 7.3.1-1, `29274-j60.txt:17839`).
///
/// **1**, not 0 — instance 0 is the Sender's own F-TEID. Transposing the two would have the
/// target MME address its Forward Relocation Response to what it thinks is an SGW.
pub const FR_INSTANCE_SGW_CONTROL_FTEID: u8 = 1;

/// Instance of the `SGW/UPF F-TEID for DL data forwarding` IE inside a Forward Relocation
/// Response's Bearer Context (Table 7.3.2-2, `29274-j60.txt:19461`).
///
/// **2**. Table 7.3.2-2 puts six different F-TEIDs at six instances in one Bearer Context,
/// and only this one applies to indirect forwarding during an inter-system handover: instance
/// 0 is the eNB/gNB DL endpoint (*"included during a 4G to 5G handover"*, i.e. the **other**
/// direction), 1 and 5 are *"during the intra-EUTRAN HO"*, and 3 and 4 are an SGSN's. Reading
/// the wrong instance yields a well-formed F-TEID pointing at an endpoint for a different
/// procedure.
pub const FR_INSTANCE_FORWARDING_FTEID: u8 = 2;

/// What the AMF learns from a **Forward Relocation Response** (TS 29.274 §7.3.2).
#[derive(Debug, Clone, Default)]
pub struct ForwardRelocationResponseData {
    /// Cause (mandatory, `29274-j60.txt:19145`).
    pub cause: u8,
    /// The target MME's own control-plane F-TEID (conditional, `:19147`).
    ///
    /// *"If the Cause IE contains the value 'Request accepted' the target MME/SGSN/AMF
    /// shall [include this]"* — and it is what the Forward Relocation Complete
    /// Acknowledge must be addressed to, so a response without it leaves the procedure
    /// unable to complete even though it said yes.
    pub mme_fteid: Option<Gtp2FTeidIe>,
    /// The **Target-to-Source** transparent container (conditional, `:19258`).
    ///
    /// F-Container (118) at instance 0. Relayed to the source gNB **byte for byte**: TS
    /// 38.413 §9.3.1.21 (`38413-j30.txt:5952-5955`) says that for inter-system handover to
    /// LTE this *"shall be encoded according to the definition of the Target eNB to Source
    /// eNB Transparent Container IE as specified in TS 36.413"*, which is an E-UTRAN
    /// structure the AMF has no business decoding.
    pub target_to_source_container: Option<Vec<u8>>,
    /// Per-bearer results from the `List of Set-up Bearers` (Bearer Context at instance 0,
    /// `:19167`), each a Table 7.3.2-2 entry.
    pub set_up_bearers: Vec<ForwardRelocationBearerResult>,
}

impl ForwardRelocationResponseData {
    /// Did the target MME accept the relocation?
    ///
    /// §7.3.2 (`29274-j60.txt:19133-19135`): *"The relocation has not been accepted by the
    /// target MME/SGSN/AMF if the Cause IE value differs from 'Request accepted'."* So this
    /// is an equality test and not `cause != CAUSE_RELOCATION_FAILURE`: the clause enumerates
    /// one message-specific failure cause but permits any of Table 8.4-1's.
    pub fn accepted(&self) -> bool {
        self.cause == CAUSE_REQUEST_ACCEPTED
    }
}

/// One bearer the target MME admitted, with whatever forwarding endpoint it offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRelocationBearerResult {
    /// EPS Bearer ID (Table 7.3.2-2, `29274-j60.txt:19413`).
    pub ebi: u8,
    /// The `SGW/UPF F-TEID for DL data forwarding` at instance
    /// [`FR_INSTANCE_FORWARDING_FTEID`], present only when the MME established indirect
    /// forwarding.
    ///
    /// `None` is the normal case for this AMF, because it never asks for forwarding — see
    /// [`forward_relocation_indication`].
    pub forwarding_fteid: Option<Gtp2FTeidIe>,
}

/// Build a **Forward Relocation Request** (TS 29.274 §7.3.1, message type 133).
///
/// Sent *"from the source AMF to the target MME over the N26 interface as part of the [...]
/// 5GS to EPS handover procedures"* (`29274-j60.txt:17701-17703`).
///
/// # IEs, each against its Table 7.3.1-1 row
///
/// | IE | P | why this one | line |
/// |---|---|---|---|
/// | IMSI (1/0) | C | *"shall be included in the message, except if the UE is emergency or RLOS attached and the UE is UICCless"* | `:17786` |
/// | Sender's F-TEID for Control Plane (87/0) | **M** | the AMF's own N26 endpoint, interface type 40 | `:17797` |
/// | MME/SGSN/AMF UE MM Context (107/0) | **M** | the mapped EPS security context with `{NH, NCC=2}` | `:17871` |
/// | MME/SGSN/AMF UE EPS PDN Connections (109/0) | C | one per transferable PDU session | `:17801` |
/// | SGW S11/S4 F-TEID for Control Plane (87/**1**) | C | the **reserved** value; see below | `:17839` |
/// | E-UTRAN Transparent Container (118/0) | C | the gNB's Source-to-Target container | `:17995` |
/// | Target Identification (121/0) | C | the target eNB the gNB named | `:18029` |
/// | Selected PLMN ID (120/0) | C | *"The old MME/SGSN/AMF shall [include this]"* | `:18082` |
/// | Indication Flags (77/0) | C | **omitted**; see [`forward_relocation_indication`] | `:17874` |
///
/// # The SGW control-plane F-TEID is reserved, and that is the instruction
///
/// TS 23.502 §4.11.1.2.1 step 3 (`23502-k20.txt:21058-21060`) is explicit: *"The SGW address
/// and TEID for both the control-plane or EPS bearers in the message are such that target MME
/// **selects a new SGW**."* So the all-zero value is not a gap this core papers over — it is
/// how the AMF tells the MME to pick its own Serving GW, and the alternative (a real address)
/// would point the MME at a node the 5GC never allocated. The same
/// [`Gtp2PdnConnectionIe::n26_reserved_sgw_fteid`] constructor #347 established for the
/// user-plane F-TEID is reused rather than a second all-zero builder being written.
///
/// # TEID 0 in the header
///
/// The source AMF does not yet know the target MME's N26 TEID; learning it is what the
/// response's Sender's F-TEID is for. TS 29.274 §5.5.1 makes a request to an unknown peer
/// context carry TEID 0, which is also how every Create Session Request starts.
#[allow(clippy::too_many_arguments)]
pub fn build_forward_relocation_request(
    sequence_number: u32,
    imsi_digits: Option<&str>,
    local_fteid: &Gtp2FTeidIe,
    mm_context: &Gtp2MmContextIe,
    pdn_connections: &[Gtp2PdnConnectionIe],
    source_to_target_container: &[u8],
    target_identification: &[u8],
    selected_plmn_id: &[u8],
) -> Gtp2Message {
    let header = Gtp2Header::new(
        Gtp2MessageType::ForwardRelocationRequest as u8,
        0,
        sequence_number,
    );
    let mut msg = Gtp2Message::new(header);

    // IMSI (C). The SUPI is an `imsi-<digits>` string, so the digits go on the wire in TBCD.
    if let Some(digits) = imsi_digits {
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &crate::n26_path::string_to_bcd(digits),
        ));
    }

    // Sender's F-TEID for Control Plane (M), instance 0.
    msg.add_ie(local_fteid.to_ie(0));

    // MM Context (M), instance 0. MANDATORY here, unlike §7.3.6's conditional one.
    msg.add_ie(mm_context.to_ie(0));

    // PDN Connections (C), all at instance 0: §8.39 requires repeated IEs to share one
    // instance value, so they must NOT be numbered 0,1,2.
    for pdn in pdn_connections {
        msg.add_ie(pdn.to_ie(0));
    }

    // SGW S11/S4 F-TEID for Control Plane (C) at instance 1 -- the reserved value, so the
    // target MME selects a new SGW (§4.11.1.2.1 step 3).
    msg.add_ie(Gtp2PdnConnectionIe::n26_reserved_sgw_fteid().to_ie(FR_INSTANCE_SGW_CONTROL_FTEID));

    // E-UTRAN Transparent Container (C) at instance 0: the gNB's Source-to-Target container,
    // relayed verbatim. The AMF does not decode it (§9.3.1.29 is an NG-RAN structure).
    if !source_to_target_container.is_empty() {
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::FContainer as u8,
            0,
            source_to_target_container,
        ));
    }

    // Target Identification (C) at instance 0.
    if !target_identification.is_empty() {
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::TargetIdentification as u8,
            0,
            target_identification,
        ));
    }

    // Selected PLMN ID (C) at instance 0.
    if !selected_plmn_id.is_empty() {
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::PlmnId as u8,
            0,
            selected_plmn_id,
        ));
    }

    // The Indication IE is OMITTED. `forward_relocation_indication` documents why, and it is
    // the data-forwarding decision (#408 criterion 6) expressed on the wire.
    if let Some(indication) = forward_relocation_indication() {
        let mut value = BytesMut::new();
        indication.encode(&mut value, 0);
        let mut bytes = value.freeze();
        if let Ok(ie) = Gtp2Ie::decode(&mut bytes) {
            msg.add_ie(ie);
        }
    }

    msg
}

/// The Forward Relocation Request's `Indication` IE — **`None`, deliberately**.
///
/// # This is the data-forwarding decision (#408 criterion 6)
///
/// The flag at stake is **DFI**. TS 29.274 §8.12 (`29274-j60.txt:25930-25933`): *"Bit 5 – DFI
/// (Direct Forwarding Indication): If this bit is set to 1, it shall indicate that direct data
/// forwarding applies between the source RAN and the target RAN during an S1 based handover
/// procedure or **during an inter-system handover between 5GS and EPS**."*
///
/// Setting it would assert two things this AMF cannot deliver:
///
/// 1. that the source gNB has a usable path to the target eNB — which the AMF now *does* know,
///    because #408 taught `parse_handover_required` to keep the Direct Forwarding Path
///    Availability IE; and
/// 2. that **this AMF will relay the forwarding endpoints to the gNB** — which it cannot,
///    because the endpoints travel in a `HandoverCommandTransfer`
///    (`dLForwardingUP-TNLInformation`, `38413-j30.txt:48917-48930`) and this tree has no
///    encoder for that structure. The intra-5GS path relays the *target gNB's own* transfer
///    verbatim, and inter-system there is no target gNB to have produced one.
///
/// So DFI stays clear **even when the gNB advertised a direct path**, and that is the sharp
/// end of the decision rather than a default: the IE is now parsed precisely so the refusal
/// can be *specific* about what it is declining. `crate::ngap_path` logs the gNB's own
/// `direct-path-available` alongside the reason it is not being used.
///
/// Indirect forwarding is not claimed either. §4.11.1.2.1 step 10a-10c
/// (`23502-k20.txt:21099-21118`) routes it through an `Nsmf_PDUSession_UpdateSMContext` whose
/// *"Data Forwarding tunnel Info"* the **UPF** allocates, and smfd's update handler implements
/// the `hoState` machine with no data-forwarding branch at all — `SmfSess`'s
/// `indirect_data_forwarding` and `data_forwarding_not_possible` have zero writers past their
/// initialisation. There is nowhere to ask.
///
/// # Why the IE is omitted rather than sent with DFI clear
///
/// Table 7.3.1-1's Indication row (`29274-j60.txt:17874`) is *"shall be included if any one of
/// the applicable flags [is] set to 1"*. With DFI clear and no other applicable flag, a
/// present-but-zero Indication would claim the AMF evaluated every applicable flag and none
/// applied — a different and stronger statement than having nothing to say. #347 drew the same
/// distinction for MSV in the Context Request.
///
/// # Consequence, stated
///
/// Downlink data in flight at the source gNB for the transferred bearers is **discarded, not
/// forwarded**. That is the #185 posture: the node answers with what is true rather than
/// establishing tunnels it cannot complete — which would be strictly worse, because the MME
/// would hold indirect tunnels through a Serving GW until its own timer expired
/// (§4.11.1.2.1 steps 16 and 21) while the gNB forwarded to an endpoint it was never told.
pub fn forward_relocation_indication() -> Option<Gtp2IndicationIe> {
    None
}

/// Build the MM Context for a **Forward Relocation Request** (TS 33.501 §8.6.1 + §8.3.2).
///
/// # `K_ASME'` is FC `0x74` over the DOWNLINK COUNT — not #347's FC `0x73`
///
/// §8.6.1 (`33501-k20.txt:11743-11747`) splits on the procedure: the key is derived *"using
/// the 5G NAS Uplink COUNT value derived from the TAU Request message or Attach Request
/// message in idle mode mobility or the 5G NAS **Downlink COUNT value in handovers**"*, per
/// Annex A.14.2's FC `0x74`.
///
/// `dl_count` must be the value the AMF holds **before** advancing it. §8.3.2 step 2
/// (`33501-k20.txt:11335-11340`) fixes the order: *"derive a K'_(ASME) using the K_(AMF) key
/// and the **current** downlink 5G NAS COUNT [...] and **then increments** its stored downlink
/// 5G NAS COUNT value by one"*. The caller owns the increment because the caller owns the pool
/// write lock; [`crate::n26_path::send_forward_relocation_request`] does both in that order and
/// returns the pre-increment value, which is what the UE is later told.
///
/// # `{NH, NCC=2}`
///
/// §8.3.2 step 2 (`:11370-11375`): *"The source AMF subsequently derives NH **two times** as
/// specified in clause A.4 of TS 33.401. The {NH, NCC=2} pair is provided to the target MME as
/// a part of UE security context in the Forward Relocation Request message."* So:
///
/// - the initial `K_eNB` comes from `K_ASME'` and an uplink NAS COUNT of `2^32 - 1`
///   (`:11378-11381`, and NOTE 3 explains the value is *"not in the normal NAS COUNT range"*
///   deliberately, *"to avoid any possibility that the value may be used to derive the same
///   K_eNB again"*) — `nextgcore_kdf_kenb`;
/// - `NH_1 = KDF(K_ASME', K_eNB)` and `NH_2 = KDF(K_ASME', NH_1)` — `nextgcore_kdf_nh_enb`,
///   twice, which is what makes `NCC = 2` the right counter rather than a number.
///
/// Getting the iteration count wrong is invisible to every codec test and makes the UE and the
/// target eNB compute different `K_eNB`, so `NHI` is set and the pair encoded only here.
///
/// # What is carried across unchanged
///
/// Per §8.6.1: the eKSI's value field is the ngKSI's with the type field marking a **mapped**
/// context (the MME sets TSC = 1 on receipt, which #347's `apply_mm_context` already does);
/// the EPS NAS COUNTs are the 5G ones; and the EPS NAS algorithms are the ones the AMF
/// signalled the UE, whose identifier *numbering* is the same in both systems — see
/// [`crate::n26_path::MAX_NAS_ALGORITHM_ID`].
pub fn build_handover_mm_context(ue: &crate::context::AmfUe, dl_count: u32) -> Gtp2MmContextIe {
    // Annex A.14.2: the HANDOVER form, bound to the downlink COUNT the caller holds.
    let kasme = nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime_handover(&ue.kamf, dl_count);

    // TS 33.501 §8.3.2 step 2 over TS 33.401 Annex A.3 then A.4, twice.
    //
    // The uplink NAS COUNT parameter is 2^32 - 1 and NOT the UE's real uplink count: NOTE 3
    // (`33501-k20.txt:11384-11389`) says the AMF and the UE *"only use[] the 2^32-1 as the
    // value of the uplink NAS COUNT for the purpose of deriving K_eNB and do not actually set
    // the uplink NAS COUNT to 2^32-1"*. Using the real count here would make the UE -- which
    // uses the constant -- derive a different K_eNB.
    let kenb = nextgcore_crypt::kdf::nextgcore_kdf_kenb(&kasme, u32::MAX);
    let nh1 = nextgcore_crypt::kdf::nextgcore_kdf_nh_enb(&kasme, &kenb);
    let nh2 = nextgcore_crypt::kdf::nextgcore_kdf_nh_enb(&kasme, &nh1);

    Gtp2MmContextIe {
        // The eKSI's value field is the ngKSI's (§8.6.1). `amf_ksi` is what this AMF assigned,
        // not `ue_ksi` -- the latter is what the UE last CLAIMED and may name a context the
        // AMF has since replaced.
        ksi_asme: ue.nas.amf_ksi & 0x07,
        // NHI SET, unlike #347's idle-mode context: a connected-mode move HAS a target eNB and
        // §8.3.2 step 4 has the MME put this pair in its S1 HANDOVER REQUEST.
        nhi: true,
        nh: Some(nh2),
        ncc: MM_CONTEXT_NCC_AT_HANDOVER,
        used_nas_integrity_algorithm: ue.selected_int_algorithm & 0x07,
        used_nas_cipher: ue.selected_enc_algorithm & crate::n26_path::MAX_NAS_ALGORITHM_ID,
        // Masked to the 24 bits Figure 8.38-5's three-octet fields hold. The DOWNLINK count is
        // the PRE-increment one, so it matches the key derived above -- writing the advanced
        // value here would hand the MME a COUNT that does not correspond to the K_ASME' beside
        // it, and the UE would reject the first EPS NAS message.
        nas_downlink_count: dl_count & 0x00FF_FFFF,
        nas_uplink_count: ue.ul_count & 0x00FF_FFFF,
        kasme,
        // The UE network capability in TS 24.301 §9.9.3.34 order: EEA bitmap then EIA bitmap.
        // Only those two octets, for the reason #347's `build_mm_context` records: §9.9.3.34's
        // later octets describe UTRAN/GERAN capabilities a 5GS-only UE never presented, and
        // emitting zeroes would tell the MME the UE supports NONE of them rather than saying
        // nothing.
        ue_network_capability: vec![ue.ue_network_capability.eea, ue.ue_network_capability.eia],
        // A GSM/GPRS capability (TS 24.008 §10.5.5.12) a 5GS UE does not present to an AMF.
        ms_network_capability: Vec::new(),
        mei: ue
            .pei
            .as_deref()
            .and_then(|p| {
                p.strip_prefix("imeisv-")
                    .or_else(|| p.strip_prefix("imei-"))
            })
            .map(crate::n26_path::string_to_bcd)
            .unwrap_or_default(),
        // Every bit of this octet means "not allowed" when set, so zero is both the permissive
        // and the truthful value for an AMF holding no subscribed RAT restrictions.
        access_restriction: 0,
    }
}

/// Parse a **Forward Relocation Response** (TS 29.274 §7.3.2, message type 134).
///
/// Strict about the one mandatory IE and tolerant of the conditional ones: a response with no
/// Cause is *unparseable*, not a rejection, and treating a missing Cause as acceptance would
/// continue a handover on the strength of a malformed datagram.
pub fn parse_forward_relocation_response(
    msg: &Gtp2Message,
) -> Result<ForwardRelocationResponseData, String> {
    let cause_ie = msg.get_ie(Gtp2IeType::Cause as u8, 0).ok_or_else(|| {
        "Forward Relocation Response has no Cause IE, which Table 7.3.2-1 makes mandatory \
         (29274-j60.txt:19145)"
            .to_string()
    })?;
    let cause = Gtp2CauseIe::decode(&cause_ie.value)
        .map_err(|e| format!("Forward Relocation Response Cause unparsable: {e}"))?
        .cause;

    // Instance 0 is the target MME's own control-plane F-TEID, the same instance the AMF used
    // for its own in the request (Table 7.3.2-1, `:19147`).
    let mme_fteid = msg
        .get_ie(Gtp2IeType::FTeid as u8, 0)
        .and_then(|ie| Gtp2FTeidIe::decode(&ie.value).ok());

    // F-Container instance 0 is the E-UTRAN Transparent Container, i.e. the Target-to-Source
    // one in this direction (`:19258`). Instance 1 would be UTRAN's and instance 2 a BSS
    // container -- neither reachable from this core.
    let target_to_source_container = msg
        .get_ie(Gtp2IeType::FContainer as u8, 0)
        .map(|ie| ie.value.to_vec());

    // `List of Set-up Bearers` is Bearer Context at instance 0 (`:19167`). Instance 1 is
    // `List of Set-up RABs` and 2 `List of Set-up PFCs`, both UTRAN/GERAN, and 3 is the SCEF
    // list -- reading the wrong instance would report RABs as EPS bearers.
    let mut set_up_bearers = Vec::new();
    for ie in msg.get_ies(Gtp2IeType::BearerContext as u8) {
        if ie.instance != 0 {
            continue;
        }
        let Ok(bearer) = Gtp2BearerContextIe::decode(&ie.value) else {
            log::warn!(
                "N26 Forward Relocation Response carries a Bearer Context this AMF cannot \
                 decode; that bearer is not recorded as set up"
            );
            continue;
        };
        let Ok(ebi) = bearer.ebi() else {
            // Table 7.3.2-2 makes the EBI conditional but *"shall be included if the message
            // is used for [...] 5GS to EPS handover"* (`:19413-19417`), so its absence in this
            // direction means the AMF cannot tell which bearer the entry describes.
            log::warn!(
                "N26 Forward Relocation Response Bearer Context has no EPS Bearer ID, which \
                 Table 7.3.2-2 requires for a 5GS-to-EPS handover; the entry names no bearer \
                 and is skipped rather than attached to an arbitrary one"
            );
            continue;
        };
        set_up_bearers.push(ForwardRelocationBearerResult {
            ebi,
            forwarding_fteid: bearer.fteid(FR_INSTANCE_FORWARDING_FTEID).ok().flatten(),
        });
    }

    Ok(ForwardRelocationResponseData {
        cause,
        mme_fteid,
        target_to_source_container,
        set_up_bearers,
    })
}

/// Build a **Forward Relocation Complete Acknowledge** (TS 29.274 §7.3.4, type 136).
///
/// Table 7.3.4-1 (`29274-j60.txt:19554`) makes the **Cause** mandatory and everything else
/// optional, so this is a short message — and not a formality. §7.3.3 (`:19493-19495`) has the
/// Notification tell the source *"the handover has been successfully finished"*, and
/// TS 23.502 §4.11.1.2.1 step 12d (`23502-k20.txt:21167-21169`) has the source AMF answer and
/// **start a timer to supervise when resources in NG-RAN shall be released** — step 21
/// (`:21279-21281`) is where the UE Context Release Command goes out. An AMF that never
/// answers is an AMF whose source gNB holds radio resources for a UE that has left.
///
/// Addressed to the TEID the MME supplied in its Forward Relocation Response, which is what
/// makes it land on the right UE context at the peer rather than on none.
pub fn build_forward_relocation_complete_acknowledge(
    sequence_number: u32,
    mme_teid: u32,
    cause: u8,
) -> Gtp2Message {
    let header = Gtp2Header::new(
        Gtp2MessageType::ForwardRelocationCompleteAcknowledge as u8,
        mme_teid,
        sequence_number,
    );
    let mut msg = Gtp2Message::new(header);
    msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));
    msg
}

// A **Forward Relocation Complete Notification** (type 135) builder is deliberately ABSENT from
// this module, and the absence is the point.
//
// §7.3.3 (`29274-j60.txt:19493-19495`) has the notification sent *"to the source MME/SGSN/AMF"*
// -- so it is the TARGET's message. This AMF is the **source** in the only direction #408
// implements (5GS to EPS): it RECEIVES 135 and answers 136, which
// `build_forward_relocation_complete_acknowledge` above does.
//
// The AMF is the target only in EPS to 5GS, and reaching that point needs the preparation of
// TS 23.502 §4.11.1.2.2.2 steps 4-7 -- an `Nsmf_PDUSession_CreateSMContext` carrying the UE EPS
// PDN Connection, which smfd does not consume (#415). So a builder here would have NO production
// caller, and an encoder no caller can reach is the "correct but unreachable" defect this tree
// keeps growing. mmed has the builder because mmed IS the target of a 5GS-to-EPS move and
// `s1ap_handler::handle_handover_notify` drives it through
// `n26_path::notify_forward_relocation_complete`.

/// Encode a `Target Identification` IE body for a target eNB (TS 29.274 §8.51).
///
/// | octet | field | line |
/// |---|---|---|
/// | 5 | Target Type | `29274-j60.txt:29283` |
/// | 6.. | Target ID, per the type | same |
///
/// Target Type **1** is `eNodeB ID` (Table 8.51-1). The body is the MCC/MNC in TBCD followed
/// by the eNB's own identity, which for an inter-system handover is what the source gNB named
/// in its NGAP `TargetID` — relayed rather than invented, because a Target Identification the
/// AMF made up would route the preparation to an eNB the gNB did not choose.
pub fn encode_target_identification(target_type: u8, plmn_bcd: &[u8], enb_id: &[u8]) -> Bytes {
    let mut value = BytesMut::with_capacity(1 + plmn_bcd.len() + enb_id.len());
    value.put_u8(target_type);
    value.put_slice(plmn_bcd);
    value.put_slice(enb_id);
    value.freeze()
}

/// `Target Type` = `eNodeB ID` (TS 29.274 Table 8.51-1).
pub const TARGET_TYPE_ENODEB: u8 = 1;

/// Encode amfd's nibble-packed PLMN as the three TBCD octets every GTPv2-C PLMN field uses.
///
/// TS 29.274 §8.51 and §8.47 share the TS 24.008 §10.5.1.13 layout: `MCC2|MCC1`,
/// `MNC3|MCC3`, `MNC2|MNC1`, with `0xF` in the MNC3 nibble for a two-digit MNC. amfd already
/// stores `mnc3 == 0x0f` for that case, so no filler logic is needed here — and the encoding
/// is deliberately written the same way `gmm_build::encode_tai_list` writes it rather than a
/// second nibble order being invented.
pub fn encode_plmn_bcd(plmn: &crate::context::PlmnId) -> [u8; 3] {
    [
        (plmn.mcc2 << 4) | plmn.mcc1,
        (plmn.mnc3 << 4) | plmn.mcc3,
        (plmn.mnc2 << 4) | plmn.mnc1,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AmfUe;
    use nextgcore_gtp::v2::{Gtp2AmbrIe, Gtp2ApnIe, Gtp2BearerQosIe, Gtp2EbiIe};

    /// The two instance numbers Table 7.3.1-1 and Table 7.3.2-2 assign, as literals.
    ///
    /// Both tables put SEVERAL F-TEIDs in one message or one grouped IE, distinguished only by
    /// instance — so an off-by-one here is a well-formed message describing a different
    /// endpoint. #401's lesson applied to instances rather than IE ids.
    #[test]
    fn forward_relocation_fteid_instances_match_their_tables() {
        assert_eq!(
            FR_INSTANCE_SGW_CONTROL_FTEID, 1,
            "the SGW S11/S4 control-plane F-TEID is instance 1 (Table 7.3.1-1, \
             29274-j60.txt:17839); instance 0 is the SENDER's own, so transposing them would \
             have the MME answer to what it thinks is an SGW"
        );
        assert_eq!(
            FR_INSTANCE_FORWARDING_FTEID, 2,
            "the SGW/UPF F-TEID for DL data forwarding is instance 2 (Table 7.3.2-2, \
             29274-j60.txt:19461) -- instance 0 is the eNB/gNB endpoint, which that table \
             conditions on a 4G-to-5G handover, i.e. the OTHER direction"
        );
        assert_eq!(
            CAUSE_RELOCATION_FAILURE, 81,
            "'Relocation failure' is cause 81, read off its OWN Table 8.4-1 row \
             (29274-j60.txt:25480), and is §7.3.2's message-specific cause \
             (:19133-19137). It is NOT 75 -- that row is 'Syntactic error in the TFT \
             operation' (:25490 region), which is the mistake an implementer makes by \
             counting rows rather than reading them (#401's lesson)"
        );
        assert_eq!(
            TARGET_TYPE_ENODEB, 1,
            "Target Type 1 is eNodeB ID (Table 8.51-1)"
        );
    }

    /// A Forward Relocation Request carries exactly its Table 7.3.1-1 IEs, at the right
    /// instances, with the right message type — and **no Indication IE**.
    #[test]
    fn forward_relocation_request_carries_its_table_7_3_1_1_ies() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut ue = AmfUe::new(0x408_0001, 1);
        ue.supi = Some("imsi-001010000000408".to_string());
        ue.kamf = [0x48; 32];
        ue.dl_count = 0x0408;
        ue.ul_count = 0x0409;
        ue.nas.amf_ksi = 3;

        let mm = build_handover_mm_context(&ue, ue.dl_count);
        let local = Gtp2FTeidIe::new_ipv4(crate::n26_path::N26_AMF_GTP_C, 0x0408, [10, 4, 0, 8]);

        let mut pdn = Gtp2PdnConnectionIe::new();
        pdn.add_ie(Gtp2ApnIe::from_string("internet").to_ie(0));
        pdn.add_ie(Gtp2EbiIe::new(5).to_ie(0));
        pdn.add_ie(Gtp2PdnConnectionIe::n26_reserved_sgw_fteid().to_ie(0));
        pdn.add_ie(Gtp2AmbrIe::new(0, 0).to_ie(0));
        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_ebi(5);
        bearer.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));
        pdn.add_ie(bearer.to_ie(0));

        let msg = build_forward_relocation_request(
            0x408,
            Some("001010000000408"),
            &local,
            &mm,
            std::slice::from_ref(&pdn),
            &[0xAA, 0xBB],
            &encode_target_identification(TARGET_TYPE_ENODEB, &[0x00, 0xF1, 0x10], &[0, 0, 0, 1]),
            &[0x00, 0xF1, 0x10],
        );

        // The message type, as a LITERAL against the table row.
        assert_eq!(
            msg.header.message_type, 133,
            "Forward Relocation Request is message type 133 (29274-j60.txt:2422)"
        );
        assert_eq!(
            msg.header.teid,
            Some(0),
            "the source AMF does not yet know the target MME's N26 TEID, so the request \
             carries 0 (TS 29.274 §5.5.1)"
        );
        assert_eq!(msg.header.sequence_number, 0x408);

        // IMSI (C): the SUPI's digits in TBCD.
        let imsi = msg.get_ie(Gtp2IeType::Imsi as u8, 0).expect("IMSI IE");
        assert_eq!(
            imsi.value.as_ref(),
            crate::n26_path::string_to_bcd("001010000000408").as_slice()
        );

        // Sender's F-TEID (M) at instance 0, interface type 40.
        let sender = Gtp2FTeidIe::decode(
            &msg.get_ie(Gtp2IeType::FTeid as u8, 0)
                .expect("Sender's F-TEID is MANDATORY (29274-j60.txt:17797)")
                .value,
        )
        .expect("decodes");
        assert_eq!(sender.interface_type, crate::n26_path::N26_AMF_GTP_C);
        assert_eq!(sender.teid, 0x0408);
        assert_eq!(sender.ipv4_addr, Some([10, 4, 0, 8]));

        // SGW control-plane F-TEID (C) at instance 1, RESERVED -- so the MME selects a new
        // SGW (TS 23.502 §4.11.1.2.1 step 3, 23502-k20.txt:21058-21060).
        let sgw = Gtp2FTeidIe::decode(
            &msg.get_ie(Gtp2IeType::FTeid as u8, FR_INSTANCE_SGW_CONTROL_FTEID)
                .expect("the SGW control F-TEID must be at instance 1, not 0")
                .value,
        )
        .expect("decodes");
        assert_eq!(
            sgw.teid, 0,
            "the SGW control-plane TEID is RESERVED: §4.11.1.2.1 step 3 requires values 'such \
             that target MME selects a new SGW', and a real endpoint would point the MME at a \
             node the 5GC never allocated"
        );
        assert_eq!(sgw.ipv4_addr, Some([0, 0, 0, 0]));

        // MM Context (M) at instance 0 -- MANDATORY here, unlike §7.3.6's conditional one.
        let carried = Gtp2MmContextIe::decode(
            &msg.get_ie(Gtp2IeType::MmContext as u8, 0)
                .expect(
                    "the MM Context is MANDATORY in a Forward Relocation Request (Table \
                     7.3.1-1, 29274-j60.txt:17871), unlike the CONDITIONAL one in a Context \
                     Response",
                )
                .value,
        )
        .expect("the MM Context this AMF built must decode");
        assert_eq!(carried, mm, "and it must survive the wire unchanged");
        assert!(
            carried.nhi,
            "NHI must be SET for a handover: TS 33.501 §8.3.2 step 2 requires the {{NH, \
             NCC=2}} pair, which an idle-mode move has no target eNB for"
        );
        assert_eq!(carried.ncc, 2);
        assert!(carried.nh.is_some());

        // PDN Connections (C) at instance 0.
        let pdns = msg.get_ies(Gtp2IeType::PdnConnection as u8);
        assert_eq!(pdns.len(), 1);
        assert!(pdns.iter().all(|ie| ie.instance == 0));

        // Source-to-Target container as F-Container instance 0, VERBATIM.
        let container = msg
            .get_ie(Gtp2IeType::FContainer as u8, 0)
            .expect("F-Container IE");
        assert_eq!(
            container.value.as_ref(),
            &[0xAA, 0xBB],
            "the gNB's Source-to-Target container must travel byte-for-byte: it is an NG-RAN \
             structure the AMF has no business re-encoding"
        );

        // Target Identification and Selected PLMN ID.
        let target = msg
            .get_ie(Gtp2IeType::TargetIdentification as u8, 0)
            .expect("Target Identification IE");
        assert_eq!(
            target.value[0], TARGET_TYPE_ENODEB,
            "Target Type must be 1 (eNodeB ID): the target of a 5GS-to-EPS handover is an eNB"
        );
        assert_eq!(
            msg.get_ie(Gtp2IeType::PlmnId as u8, 0)
                .expect("Selected PLMN ID IE")
                .value
                .as_ref(),
            &[0x00, 0xF1, 0x10]
        );

        // THE forwarding assertion: no Indication IE at all.
        assert!(
            msg.get_ie(Gtp2IeType::Indication as u8, 0).is_none(),
            "the Indication IE must be OMITTED, not sent with DFI clear. Table 7.3.1-1 \
             includes it only 'if any one of the applicable flags [is] set to 1' \
             (29274-j60.txt:17874), and a present-but-zero Indication claims every applicable \
             flag was evaluated and none applied -- a stronger statement than this AMF can \
             make. Setting DFI would assert this AMF will relay forwarding endpoints it has \
             no HandoverCommandTransfer encoder to carry."
        );
        assert!(
            forward_relocation_indication().is_none(),
            "and the decision is at ONE site, so it cannot be set here and cleared there"
        );
    }

    /// The nested Bearer Context of a Forward Relocation Request's PDN Connection, at its
    /// Table 7.3.1-3 instances.
    ///
    /// The SGW user-plane F-TEID is at instance **0** and the PGW one at **1**. Transposing
    /// them round-trips perfectly and points the MME's user plane at the wrong endpoint — so
    /// the instances, not the values, are what this asserts.
    #[test]
    fn forward_relocation_bearer_context_matches_ts29274_table_7_3_1_3() {
        let pgw = Gtp2FTeidIe::new_ipv4(5, 0x0408_1111, [10, 4, 8, 1]);
        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_ebi(6);
        bearer.set_fteid(0, &Gtp2PdnConnectionIe::n26_reserved_sgw_fteid());
        bearer.set_fteid(1, &pgw);
        bearer.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));

        let decoded = Gtp2BearerContextIe::decode(&bearer.to_ie(0).value).expect("decodes");
        assert_eq!(
            decoded.ebi().unwrap(),
            6,
            "EPS Bearer ID is M (29274-j60.txt:18823)"
        );

        // Instance 0: the SGW S1/S4/S12 user-plane F-TEID, MANDATORY and RESERVED over N26.
        let sgw = decoded
            .fteid(0)
            .expect("decodes")
            .expect("the SGW user-plane F-TEID is MANDATORY (29274-j60.txt:18827)");
        assert_eq!(
            sgw.teid, 0,
            "over N26 Table 7.3.1-3 requires 'any reserved TEID (e.g. all 0's, or all 1's)' \
             and 'IPv4 address set to 0.0.0.0' (29274-j60.txt:18833-18843) -- there is no SGW \
             in the 5GC and the user plane is anchored at a UPF the MME cannot address"
        );
        assert_eq!(sgw.ipv4_addr, Some([0, 0, 0, 0]));

        // Instance 1: the PGW S5/S8 user-plane F-TEID, a REAL endpoint.
        let carried_pgw = decoded
            .fteid(1)
            .expect("decodes")
            .expect("the PGW user-plane F-TEID is at instance 1 (29274-j60.txt:18849)");
        assert_eq!(
            carried_pgw.teid, 0x0408_1111,
            "instance 1 carries the PGW's REAL user-plane endpoint. If this read 0 the two \
             instances are transposed, which a round trip cannot see and which would point \
             the MME's user plane at 0.0.0.0"
        );
        assert_eq!(carried_pgw.ipv4_addr, Some([10, 4, 8, 1]));
        assert_eq!(decoded.bearer_qos().unwrap().unwrap().qci, 9);
    }

    /// A Forward Relocation Response's Bearer Context puts the forwarding endpoint at
    /// instance **2**, and this AMF reads it from there.
    ///
    /// Table 7.3.2-2 puts six F-TEIDs at six instances in one Bearer Context and only
    /// instance 2 applies to indirect forwarding during an inter-system handover. Reading
    /// instance 0 instead would pick up the eNB/gNB DL endpoint, whose own condition is *"during
    /// a 4G to 5G handover"* — the other direction — so it would be a plausible F-TEID for the
    /// wrong procedure.
    #[test]
    fn forward_relocation_response_bearer_context_matches_ts29274_table_7_3_2_2() {
        // The MME's answer: two bearers, one with an indirect-forwarding endpoint and one
        // without, so the parser is exercised in both states.
        //
        // The instance is the LITERAL `2` on the write side, deliberately NOT
        // `FR_INSTANCE_FORWARDING_FTEID`. Writing and reading through one constant makes the
        // test round-trip through whatever value that constant holds, so a wrong constant
        // passes -- which is exactly what the revert-check found: flipping the constant to 0
        // left this test green and only the literal-pinning test caught it. With the literal
        // here, a wrong constant now fails on BOTH sides.
        let fwd = Gtp2FTeidIe::new_ipv4(1, 0x0408_2222, [10, 4, 8, 2]);
        let mut with_forwarding = Gtp2BearerContextIe::new();
        with_forwarding.set_ebi(5);
        with_forwarding.set_fteid(2, &fwd);
        // A DECOY at instance 0 -- the eNB/gNB DL forwarding endpoint, which Table 7.3.2-2
        // conditions on "a 4G to 5G handover", i.e. the OTHER direction. A parser reading
        // instance 0 would pick this up and report it as the forwarding endpoint, so its
        // presence is what makes the assertion below discriminate rather than merely succeed.
        with_forwarding.set_fteid(0, &Gtp2FTeidIe::new_ipv4(1, 0xDEAD_0000, [10, 9, 9, 9]));
        let mut without = Gtp2BearerContextIe::new();
        without.set_ebi(6);

        let mut msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::ForwardRelocationResponse as u8,
            0x0408_AAAA,
            9,
        ));
        msg.add_ie(Gtp2CauseIe::new(CAUSE_REQUEST_ACCEPTED).to_ie(0));
        msg.add_ie(Gtp2FTeidIe::new_ipv4(12, 0x0408_BBBB, [10, 4, 8, 9]).to_ie(0));
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::FContainer as u8,
            0,
            &[0xCC, 0xDD],
        ));
        msg.add_ie(with_forwarding.to_ie(0));
        msg.add_ie(without.to_ie(0));
        // Instance 1 is `List of Set-up RABs` (UTRAN). Added so the parser is proven to IGNORE
        // it: counting it would report a RAB as an EPS bearer.
        let mut rab = Gtp2BearerContextIe::new();
        rab.set_ebi(7);
        msg.add_ie(rab.to_ie(1));

        // Over the wire, so framing is exercised.
        let encoded = msg.encode();
        let mut bytes = bytes::Bytes::from(encoded.to_vec());
        let on_the_wire = Gtp2Message::decode(&mut bytes).expect("decodes");
        assert_eq!(
            on_the_wire.header.message_type, 134,
            "Forward Relocation Response is message type 134 (29274-j60.txt:2425)"
        );

        let data = parse_forward_relocation_response(&on_the_wire).expect("parses");
        assert!(data.accepted(), "cause 16 is 'Request accepted'");

        // The MME's F-TEID, which the Complete Acknowledge has to be addressed to.
        let mme = data
            .mme_fteid
            .as_ref()
            .expect("the target MME's F-TEID (Table 7.3.2-1, 29274-j60.txt:19147)");
        assert_eq!(mme.teid, 0x0408_BBBB);

        // The Target-to-Source container, verbatim.
        assert_eq!(
            data.target_to_source_container.as_deref(),
            Some(&[0xCC, 0xDD][..]),
            "the Target-to-Source container must be relayed byte-for-byte: TS 38.413 \
             §9.3.1.21 says it is a TS 36.413 Target-eNB-to-Source-eNB container \
             (38413-j30.txt:5952-5955), an E-UTRAN structure the AMF must not decode"
        );

        // Exactly the two instance-0 bearers, in order, and NOT the instance-1 RAB.
        assert_eq!(
            data.set_up_bearers.len(),
            2,
            "only the instance-0 'List of Set-up Bearers' entries are EPS bearers \
             (29274-j60.txt:19167); instance 1 is the UTRAN RAB list and must not be counted"
        );
        assert_eq!(data.set_up_bearers[0].ebi, 5);
        assert_eq!(
            data.set_up_bearers[0]
                .forwarding_fteid
                .as_ref()
                .expect("the forwarding F-TEID must be read from instance 2")
                .teid,
            0x0408_2222,
            "the SGW/UPF F-TEID for DL data forwarding is at instance 2 (Table 7.3.2-2, \
             29274-j60.txt:19461). Instance 0 is the eNB/gNB DL endpoint, conditioned on 'a \
             4G to 5G handover' -- so reading 0 would pick up the other direction's endpoint."
        );
        assert_eq!(data.set_up_bearers[1].ebi, 6);
        assert_eq!(
            data.set_up_bearers[1].forwarding_fteid, None,
            "a bearer the MME admitted without forwarding must read as None, not as a \
             zero-valued endpoint the AMF might then relay"
        );
    }

    /// A Forward Relocation Response with no Cause is unparseable, NOT an acceptance.
    #[test]
    fn a_forward_relocation_response_without_a_cause_is_rejected() {
        let msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::ForwardRelocationResponse as u8,
            1,
            1,
        ));
        let err = parse_forward_relocation_response(&msg).expect_err("no Cause must not parse");
        assert!(
            err.contains("Cause"),
            "the error must name the missing mandatory IE, got {err:?}"
        );

        // And a refusal is a refusal: any cause other than 16 is not acceptance.
        let mut refused = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::ForwardRelocationResponse as u8,
            1,
            1,
        ));
        refused.add_ie(Gtp2CauseIe::new(CAUSE_RELOCATION_FAILURE).to_ie(0));
        let data = parse_forward_relocation_response(&refused).expect("parses");
        assert!(
            !data.accepted(),
            "§7.3.2 (29274-j60.txt:19133-19135): the relocation is not accepted if the Cause \
             'differs from Request accepted' -- so this is an equality test on 16 and not an \
             inequality test against the one message-specific failure cause"
        );
    }

    /// Complete Notification (135) and Acknowledge (136), addressed to the peer's TEID.
    #[test]
    fn forward_relocation_complete_messages_carry_their_types_and_teids() {
        let ack =
            build_forward_relocation_complete_acknowledge(4, 0x0408_CCCC, CAUSE_REQUEST_ACCEPTED);
        assert_eq!(
            ack.header.message_type, 136,
            "Forward Relocation Complete Acknowledge is type 136 (29274-j60.txt:2431)"
        );
        assert_eq!(
            ack.header.teid,
            Some(0x0408_CCCC),
            "the acknowledge must carry the TEID the MME supplied in its Forward Relocation \
             Response, or it lands on no UE context at the peer and the MME never learns the \
             source released"
        );
        let cause = Gtp2CauseIe::decode(
            &ack.get_ie(Gtp2IeType::Cause as u8, 0)
                .expect("Cause is M")
                .value,
        )
        .expect("decodes");
        assert_eq!(
            cause.cause, CAUSE_REQUEST_ACCEPTED,
            "Cause is the ONLY mandatory IE of Table 7.3.4-1 (29274-j60.txt:19554)"
        );

        // No Complete NOTIFICATION builder is asserted here, because this module has none: this
        // AMF is the SOURCE in the direction #408 implements, so it receives 135 and answers
        // 136. The note above `encode_target_identification` records why a builder here would
        // have no production caller; mmed's
        // `forward_relocation_response_carries_its_table_7_3_2_1_ies` covers the one that IS
        // driven.
        //
        // The type number is still pinned, because `handle_datagram` dispatches on it.
        assert_eq!(
            Gtp2MessageType::ForwardRelocationCompleteNotification as u8,
            135,
            "Forward Relocation Complete Notification is type 135 (29274-j60.txt:2428), and \
             this AMF must recognise it on receipt even though it never builds one"
        );
    }

    /// **#408 criterion 3, at the procedure level**: the handover MM Context's key is bound to
    /// the DOWNLINK COUNT the AMF held BEFORE the increment.
    ///
    /// This is the assertion that catches the nextgsim-#203 shape of defect — a key derived
    /// from the *next* message's COUNT because the increment happened first. TS 33.501 §8.3.2
    /// step 2 orders it *"using the **current** downlink 5G NAS COUNT [...] and **then**
    /// increments"*, and an off-by-one desynchronises every EPS NAS message after the handover
    /// with a MAC failure pointing nowhere near here.
    #[test]
    fn the_handover_kasme_is_bound_to_the_downlink_count_before_the_increment() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        const KAMF: [u8; 32] = [0x74; 32];
        const DL_BEFORE: u32 = 0x0408_00AA;

        let mut ue = AmfUe::new(0x408_0002, 2);
        ue.kamf = KAMF;
        ue.dl_count = DL_BEFORE;
        ue.ul_count = 0x0408_00BB;
        ue.nas.amf_ksi = 5;

        let mm = build_handover_mm_context(&ue, DL_BEFORE);

        // Computed independently from the FC and the COUNT, so a stubbed or copied key fails.
        assert_eq!(
            mm.kasme,
            nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime_handover(&KAMF, DL_BEFORE),
            "K_ASME' must be KDF(K_AMF, FC 0x74, DOWNLINK NAS COUNT) per TS 33.501 Annex A.14.2"
        );

        // NOT the post-increment COUNT. This is the #203 defect made explicit.
        assert_ne!(
            mm.kasme,
            nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime_handover(&KAMF, DL_BEFORE + 1),
            "the key must come from the COUNT held BEFORE the increment: §8.3.2 step 2 says \
             'using the current downlink 5G NAS COUNT [...] and then increments'. Deriving \
             after the increment gives the UE -- which is told the count that WAS used -- a \
             different key, and every EPS NAS message fails its MAC."
        );

        // NOT the idle-mode form. Criterion 3 verbatim.
        assert_ne!(
            mm.kasme,
            nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime(&KAMF, DL_BEFORE),
            "and it must differ from Annex A.14.1's FC 0x73 idle-mode form for the same \
             inputs: the two differ only in the FC octet"
        );
        // NOT bound to the uplink count, which is A.14.1's parameter.
        assert_ne!(
            mm.kasme,
            nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime_handover(&KAMF, ue.ul_count),
            "the DOWNLINK count is the parameter (A.14.2 P0); the uplink one is A.14.1's"
        );

        // The COUNT the MM Context reports must be the one the key was derived from, masked
        // to the field's 24 bits -- a context naming a different COUNT than its own key is
        // unusable even if both values are individually right.
        assert_eq!(
            mm.nas_downlink_count,
            DL_BEFORE & 0x00FF_FFFF,
            "the MM Context's NAS Downlink Count must be the PRE-increment value, matching \
             the K_ASME' beside it"
        );

        // {NH, NCC=2}: derived twice from K_ASME' over an initial K_eNB keyed with 2^32-1.
        let kenb = nextgcore_crypt::kdf::nextgcore_kdf_kenb(&mm.kasme, u32::MAX);
        let nh1 = nextgcore_crypt::kdf::nextgcore_kdf_nh_enb(&mm.kasme, &kenb);
        let expected_nh = nextgcore_crypt::kdf::nextgcore_kdf_nh_enb(&mm.kasme, &nh1);
        assert_eq!(
            mm.nh,
            Some(expected_nh),
            "TS 33.501 §8.3.2 step 2 (33501-k20.txt:11370-11375): the AMF derives NH TWICE \
             and sends the second. Sending NH_1 with NCC=2 would make the target eNB chain \
             from the wrong hop and every AS key would differ."
        );
        assert_ne!(
            mm.nh,
            Some(nh1),
            "specifically NOT the FIRST NH: that pairs with NCC=1, and the counter says 2"
        );
        assert_eq!(mm.ncc, 2);
        assert!(
            mm.nhi,
            "and NHI must be set or the MME never reads the pair"
        );
    }

    /// The PLMN nibble order, against TS 24.008 §10.5.1.13.
    ///
    /// Written out as a literal because the failure mode is a swapped nibble, which is
    /// invisible to "the length is 3": both orders are three octets. A two-digit MNC's `0xF`
    /// filler lands in the MNC3 nibble of octet 2.
    #[test]
    fn plmn_bcd_matches_ts24008_10_5_1_13_nibble_order() {
        // MCC 001, MNC 01 (two-digit, so mnc3 = 0xF).
        let plmn = crate::context::PlmnId {
            mcc1: 0,
            mcc2: 0,
            mcc3: 1,
            mnc1: 0,
            mnc2: 1,
            mnc3: 0x0F,
        };
        assert_eq!(
            encode_plmn_bcd(&plmn),
            [0x00, 0xF1, 0x10],
            "octet 1 is MCC2|MCC1, octet 2 is MNC3|MCC3 (0xF filler for a two-digit MNC), \
             octet 3 is MNC2|MNC1. A big-endian reading would give [0x00, 0x1F, 0x01]."
        );

        // MCC 310, MNC 260 (three-digit).
        let three = crate::context::PlmnId {
            mcc1: 3,
            mcc2: 1,
            mcc3: 0,
            mnc1: 2,
            mnc2: 6,
            mnc3: 0,
        };
        assert_eq!(
            encode_plmn_bcd(&three),
            [0x13, 0x00, 0x62],
            "a three-digit MNC puts its third digit in the high nibble of octet 2 rather than \
             the 0xF filler"
        );

        // And the Target Identification body starts with the type, then the PLMN.
        let target = encode_target_identification(TARGET_TYPE_ENODEB, &[0x00, 0xF1, 0x10], &[1, 2]);
        assert_eq!(target[0], TARGET_TYPE_ENODEB, "octet 5 is the Target Type");
        assert_eq!(&target[1..4], &[0x00, 0xF1, 0x10], "then the PLMN in TBCD");
        assert_eq!(&target[4..], &[1, 2], "then the eNB identity the gNB named");
    }
}
