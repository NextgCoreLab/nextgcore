//! N26 (and S10) GTPv2-C message building and parsing for the MME (#347).
//!
//! The MME is the **new** node in the 5GS→EPS idle-mode mobility procedure
//! (TS 23.502 §4.11.1.3.2 over TS 23.401 §5.3.3.1): it receives a TRACKING AREA UPDATE
//! REQUEST from a UE that has just left NG-RAN, asks the old AMF for the UE's context
//! with a **Context Request**, and acknowledges the **Context Response** it gets back.
//!
//! Split from [`crate::n26_path`] the same way `s11_build` is split from `gtp_path`:
//! this module is pure — it turns context into messages and messages into data, with no
//! socket and no globals — so every wire assertion in its tests is a value comparison
//! rather than a transport test.
//!
//! # Interface types
//!
//! `S10_N26_MME_GTP_C = 12` is the F-TEID interface type the MME puts in its own
//! `S3/S16/S10/N26 Address and TEID for Control Plane` IE, and `N26_AMF_GTP_C = 40` is
//! what it expects from the AMF. Both constants were defined in
//! `bins/nextgcore-smfd/src/gtp_build.rs:489,517` and, until this issue, **nothing in
//! the workspace referenced either** — they were the whole of the tree's N26 support.
//! They are re-declared here rather than imported because smfd is a separate binary
//! crate with no library target, so there is nothing to import from; the values are
//! pinned against TS 29.274 Table 8.22-1 by
//! `n26_fteid_interface_types_match_ts29274_table_8_22_1`.

use crate::context::{EpsGuti, MmeUe};
use bytes::{BufMut, Bytes, BytesMut};
use nextgcore_gtp::v2::{
    Gtp2CauseIe, Gtp2FTeidIe, Gtp2Header, Gtp2Ie, Gtp2IeType, Gtp2IndicationIe, Gtp2Message,
    Gtp2MessageType, Gtp2MmContextIe, Gtp2PdnConnectionIe, Gtp2RatTypeIe,
};

/// F-TEID interface type `S10/N26 MME GTP-C`.
///
/// TS 29.274 Table 8.22-1. Mirrors `smfd/src/gtp_build.rs:489`'s `S10_N26_MME_GTP_C`.
pub const S10_N26_MME_GTP_C: u8 = 12;

/// F-TEID interface type `N26 AMF GTP-C`.
///
/// TS 29.274 Table 8.22-1. Mirrors `smfd/src/gtp_build.rs:517`'s `N26_AMF_GTP_C`.
pub const N26_AMF_GTP_C: u8 = 40;

/// RAT Type `EUTRAN` (TS 29.274 §8.17, Table 8.17-1).
///
/// The Context Request's RAT Type IE *"indicates the Radio Access Technology which is
/// used in the **new** system"* (`29274-j60.txt:19794-19796`) — so it is E-UTRAN, the
/// system the UE has moved **to**, not NR.
pub const RAT_TYPE_EUTRAN: u8 = 6;

/// `Complete Request Message Type` = "Complete TAU Request Message".
///
/// TS 29.274 Table 8.46-1 (`29274-j60.txt:29078`): Complete Attach Request is 0,
/// Complete **TAU** Request is **1**. Sending 0 here would tell the old AMF to
/// integrity-check the octets as an ATTACH REQUEST.
pub const COMPLETE_REQUEST_TAU: u8 = 1;

/// GTPv2-C cause `Request accepted` (TS 29.274 Table 8.4-1).
pub const CAUSE_REQUEST_ACCEPTED: u8 = 16;

/// GTPv2-C cause `IMSI/IMEI not known` (TS 29.274 Table 8.4-1).
///
/// One of the four message-specific causes §7.3.6 names for a Context Response
/// (`29274-j60.txt:19878`).
pub const CAUSE_IMSI_IMEI_NOT_KNOWN: u8 = 92;

/// GTPv2-C cause `Request rejected` (TS 29.274 Table 8.4-1).
pub const CAUSE_REQUEST_REJECTED: u8 = 94;

/// Build a **Context Request** (TS 29.274 §7.3.5, message type 130).
///
/// Sent by the new MME to the old AMF over N26 *"as a part of an 5GS to EPS Idle mode
/// Mobility using N26 interface procedure, to get the MM and EPS bearer Contexts for the
/// UE"* (`29274-j60.txt:19615-19617`).
///
/// # IEs, each against its Table 7.3.5-1 row
///
/// | IE | P | why this one | line |
/// |---|---|---|---|
/// | GUTI (117/0) | C | *"The new MME/AMF shall include this IE over S10/N26 interface if the IMSI is not present"* | `:19685` |
/// | Complete TAU request message (116/0) | C | *"shall include this IE if available, and the old MME/AMF may use this IE for integrity check"* | `:19759` |
/// | S3/S16/S10/N26 F-TEID (87/0) | C | *"the address and the TEID for control plane message which is chosen by the new MME/SGSN/AMF"* | `:19765` |
/// | RAT Type (82/0) | C | *"the Radio Access Technology which is used in the new system"* | `:19794` |
/// | Indication (77/0) | CO | MSV, *"when set to 1, indicates that the new system has [...] validated the integrity protection of the TAU request message"* | `:19804` |
///
/// # Why the GUTI and not the IMSI
///
/// Table 7.3.5-1 makes IMSI conditional on the UE *"having been successfully
/// authenticated"* (`:19681`) and the GUTI conditional on *"the IMSI [not being]
/// present"*. At this point in the procedure the MME has done neither — TS 23.401
/// §5.3.3.1 step 4 has the Context Request *precede* authentication, and step 6 says
/// authentication is only mandatory *"if the integrity check of TAU Request message
/// failed"*. So the GUTI is the identity the MME actually has, and it is the one the old
/// AMF is required to reverse-map (TS 23.003 §2.10.2.1.3).
///
/// # `msv`
///
/// Set only when the caller actually verified the TAU REQUEST's integrity. TS 23.401
/// §5.3.3.1 step 4 defines it as *"UE Validated indicates that the new MME has validated
/// the integrity protection of the TAU message"*, and §7.3.6 lets the old node reject
/// with "User authentication failed" when it cannot validate. Asserting MSV on an
/// unverified message would ask the AMF to skip a check the MME also did not make.
pub fn build_context_request(
    sequence_number: u32,
    guti: &EpsGuti,
    complete_tau_request: &[u8],
    local_fteid: &Gtp2FTeidIe,
    ue_validated: bool,
) -> Gtp2Message {
    // TEID 0: the MME does not yet know the AMF's N26 TEID -- learning it is what the
    // Context Response's F-TEID is for. TS 29.274 §5.5.1 makes a request to an unknown
    // peer context carry TEID 0, which is also how every Create Session Request starts.
    let header = Gtp2Header::new(Gtp2MessageType::ContextRequest as u8, 0, sequence_number);
    let mut msg = Gtp2Message::new(header);

    msg.add_ie(encode_guti_ie(guti, 0));

    if !complete_tau_request.is_empty() {
        msg.add_ie(encode_complete_request_message(
            COMPLETE_REQUEST_TAU,
            complete_tau_request,
            0,
        ));
    }

    msg.add_ie(local_fteid.to_ie(0));
    msg.add_ie(rat_type_ie(RAT_TYPE_EUTRAN, 0));

    // Table 7.3.5-1: the Indication IE *"shall be included if any one of the applicable
    // flags is set to 1"* (`:19801`) -- so an unvalidated UE means the IE is OMITTED,
    // not sent with MSV clear. A present-but-zero Indication says "I evaluated every
    // applicable flag and none applies", which is a different claim.
    if ue_validated {
        let indication = Gtp2IndicationIe {
            msv: true,
            ..Default::default()
        };
        let mut value = BytesMut::new();
        indication.encode(&mut value, 0);
        let mut bytes = value.freeze();
        if let Ok(ie) = Gtp2Ie::decode(&mut bytes) {
            msg.add_ie(ie);
        }
    }

    msg
}

/// Build a **Context Acknowledge** (TS 29.274 §7.3.7, message type 132).
///
/// TS 23.401 §5.3.3.1 step 5 ends with *"The buffered data in the old MME is discarded
/// after receipt of Context Acknowledgement"*, and §4.11.1.3.2 step 6 has the old AMF
/// start a guard timer over its UE context. So this is not a formality: an old AMF that
/// never receives it holds state it should have released, and the UE has two cores
/// believing they serve it.
///
/// Addressed to the TEID the AMF supplied in its Context Response, which is what makes
/// it land on the right UE context at the peer rather than on none.
pub fn build_context_acknowledge(sequence_number: u32, amf_teid: u32, cause: u8) -> Gtp2Message {
    let header = Gtp2Header::new(
        Gtp2MessageType::ContextAcknowledge as u8,
        amf_teid,
        sequence_number,
    );
    let mut msg = Gtp2Message::new(header);
    msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));
    msg
}

/// The GUTI IE (TS 29.274 §8.47, Figure 8.47-1, `29274-j60.txt:29092`).
///
/// | octet | field |
/// |---|---|
/// | 5 | MCC digit 2 \| MCC digit 1 |
/// | 6 | MNC digit 3 \| MCC digit 3 |
/// | 7 | MNC digit 2 \| MNC digit 1 |
/// | 8-9 | MME Group ID |
/// | 10 | MME Code |
/// | 11.. | M-TMSI |
///
/// The PLMN encoding is delegated to [`nextgcore_nas::common::types::PlmnId::encode`]
/// rather than re-nibbled here: it is the same MCC/MNC layout TS 24.008 §10.5.1.13
/// defines and this tree already has one implementation of, and a second would be free
/// to disagree about the two-digit-MNC `1111` filler that §8.47 calls out
/// (`29274-j60.txt:29115-29116`).
pub fn encode_guti_ie(guti: &EpsGuti, instance: u8) -> Gtp2Ie {
    let mut value = BytesMut::new();
    value.put_slice(&crate::s11_build::encode_plmn_bcd(&guti.plmn_id));
    value.put_u16(guti.mme_gid);
    value.put_u8(guti.mme_code);
    value.put_u32(guti.m_tmsi);
    Gtp2Ie::new(Gtp2IeType::Guti as u8, instance, value.freeze())
}

/// Parse a GUTI IE back into an [`EpsGuti`].
///
/// Returns `None` for anything shorter than the fixed 10 octets Figure 8.47-1 requires
/// (3 PLMN + 2 MME Group ID + 1 MME Code + 4 M-TMSI), because a short GUTI would
/// otherwise resolve to a UE context by accident.
pub fn parse_guti_ie(value: &Bytes) -> Option<EpsGuti> {
    if value.len() < 10 {
        return None;
    }
    let plmn_id = crate::s11_build::decode_plmn_bcd(&value[0..3])?;
    Some(EpsGuti {
        plmn_id,
        mme_gid: u16::from_be_bytes([value[3], value[4]]),
        mme_code: value[5],
        m_tmsi: u32::from_be_bytes([value[6], value[7], value[8], value[9]]),
    })
}

/// The Complete Request Message IE (TS 29.274 §8.46, Figure 8.46-1,
/// `29274-j60.txt:29053`): a one-octet type followed by the verbatim NAS message.
pub fn encode_complete_request_message(
    message_type: u8,
    nas_message: &[u8],
    instance: u8,
) -> Gtp2Ie {
    let mut value = BytesMut::with_capacity(1 + nas_message.len());
    value.put_u8(message_type);
    value.put_slice(nas_message);
    Gtp2Ie::new(
        Gtp2IeType::CompleteRequestMessage as u8,
        instance,
        value.freeze(),
    )
}

/// Split a Complete Request Message IE into its type octet and the NAS message.
pub fn parse_complete_request_message(value: &Bytes) -> Option<(u8, Bytes)> {
    if value.is_empty() {
        return None;
    }
    Some((value[0], value.slice(1..)))
}

/// A RAT Type IE at the given instance.
fn rat_type_ie(rat_type: u8, instance: u8) -> Gtp2Ie {
    let mut value = BytesMut::new();
    Gtp2RatTypeIe::new(rat_type).encode(&mut value, instance);
    let mut bytes = value.freeze();
    Gtp2Ie::decode(&mut bytes).expect("a just-encoded RAT Type IE decodes")
}

/// What a MME learns from a Context Response (TS 29.274 §7.3.6).
#[derive(Debug, Clone, Default)]
pub struct ContextResponseData {
    /// Cause (mandatory, `29274-j60.txt:19957`).
    pub cause: u8,
    /// IMSI, BCD-decoded (conditional, `:19959`).
    pub imsi_bcd: Option<String>,
    /// The UE's MM context, i.e. its mapped EPS security context (`:19975`).
    pub mm_context: Option<Gtp2MmContextIe>,
    /// The UE's EPS PDN connections, one per transferable PDU session (`:19980`).
    ///
    /// Repeated IEs all at instance 0 per §8.39, so this is a `Vec` rather than an
    /// instance-keyed map.
    pub pdn_connections: Vec<Gtp2PdnConnectionIe>,
    /// The AMF's N26 control-plane F-TEID, which the Context Acknowledge is addressed to.
    pub amf_fteid: Option<Gtp2FTeidIe>,
}

impl ContextResponseData {
    /// Did the old AMF accept?
    pub fn accepted(&self) -> bool {
        self.cause == CAUSE_REQUEST_ACCEPTED
    }
}

/// Parse a Context Response.
///
/// Tolerant of absent conditional IEs and strict about the one mandatory one: a response
/// with no Cause is not a rejection, it is unparseable, and treating a missing Cause as
/// acceptance would transfer a context on the strength of a malformed datagram.
pub fn parse_context_response(msg: &Gtp2Message) -> Result<ContextResponseData, String> {
    let cause_ie = msg
        .get_ie(Gtp2IeType::Cause as u8, 0)
        .ok_or_else(|| "Context Response has no Cause IE, which is mandatory".to_string())?;
    let cause = Gtp2CauseIe::decode(&cause_ie.value)
        .map_err(|e| format!("Context Response Cause unparsable: {e}"))?
        .cause;

    let imsi_bcd = msg
        .get_ie(Gtp2IeType::Imsi as u8, 0)
        .map(|ie| bcd_to_string(&ie.value));

    let mm_context = match msg.get_ie(Gtp2IeType::MmContext as u8, 0) {
        Some(ie) => match Gtp2MmContextIe::decode(&ie.value) {
            Ok(ctx) => Some(ctx),
            Err(e) => {
                // Named rather than swallowed: a Context Response whose MM Context this
                // MME cannot read is a UE it cannot serve securely, and the reason
                // (typically a Security Mode this build does not implement) is the
                // operator-actionable part.
                log::warn!(
                    "N26 Context Response carries an MM Context this MME cannot decode \
                     ({e}); the UE has no transferable security context"
                );
                None
            }
        },
        None => None,
    };

    let mut pdn_connections = Vec::new();
    for ie in msg.get_ies(Gtp2IeType::PdnConnection as u8) {
        match Gtp2PdnConnectionIe::decode(&ie.value) {
            Ok(pdn) => pdn_connections.push(pdn),
            Err(e) => log::warn!("N26 Context Response PDN Connection unparsable: {e}"),
        }
    }

    // Instance 0 is the AMF's own S3/S16/S10/N26 control-plane F-TEID, the same
    // instance the MME used for its own in the request (Table 7.3.6-1).
    let amf_fteid = msg
        .get_ie(Gtp2IeType::FTeid as u8, 0)
        .and_then(|ie| Gtp2FTeidIe::decode(&ie.value).ok());

    Ok(ContextResponseData {
        cause,
        imsi_bcd,
        mm_context,
        pdn_connections,
        amf_fteid,
    })
}

/// Decode a TBCD-encoded identity (TS 29.274 §8.3) to digits.
///
/// Low nibble first, and `0xF` terminates — the same convention
/// [`nextgcore_dbi::types::nextgcore_bcd_to_buffer`] encodes with, read in the opposite
/// direction. Written here rather than reused because that function is an encoder with
/// no inverse in the tree, and its crate is not in mmed's dependency graph for this
/// purpose.
fn bcd_to_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        for nibble in [byte & 0x0F, byte >> 4] {
            if nibble == 0x0F {
                return out;
            }
            out.push(char::from_digit(nibble as u32, 16).unwrap_or('0'));
        }
    }
    out
}

/// Encode a BCD digit string for an IMSI/MEI IE (TS 29.274 §8.3).
pub fn string_to_bcd(digits: &str) -> Vec<u8> {
    let chars: Vec<char> = digits.chars().collect();
    let mut out = Vec::with_capacity(chars.len().div_ceil(2));
    for pair in chars.chunks(2) {
        let low = pair[0].to_digit(16).unwrap_or(0) as u8;
        let high = pair.get(1).and_then(|c| c.to_digit(16)).unwrap_or(0x0F) as u8;
        out.push((high << 4) | low);
    }
    out
}

/// The bearers and PDN connections a Context Response asks this MME to install.
///
/// Returned rather than applied, so the caller owns the write-back. That matters here
/// specifically: `MmeContext::sess_find_by_id` and `bearer_find_by_id` return **clones**,
/// and #223 found the same shape in smfd's `sess_add_by_apn` — `create_session` mutated a
/// detached copy, so the wire response was right while the SMF kept no record. A pure
/// function that hands back values cannot make that mistake, and its caller has to be
/// explicit about the write.
#[derive(Debug, Clone)]
pub struct TransferredPdnConnection {
    /// The APN, from the mandatory APN IE.
    pub apn: String,
    /// The default bearer's EBI, from the mandatory Linked EPS Bearer ID.
    pub linked_ebi: u8,
    /// The PGW-C's S5/S8 control-plane TEID.
    pub pgw_s5c_teid: u32,
    /// The PGW-C's S5/S8 control-plane address.
    pub pgw_s5c_ipv4: Option<[u8; 4]>,
    /// The UE's IPv4 address, when the PDN connection has one.
    pub ue_ipv4: Option<[u8; 4]>,
    /// APN-AMBR uplink, bits per second.
    pub ambr_uplink: u64,
    /// APN-AMBR downlink, bits per second.
    pub ambr_downlink: u64,
    /// Every bearer of this PDN connection, with its QoS.
    pub bearers: Vec<TransferredBearer>,
}

/// One transferred EPS bearer context (TS 29.274 Table 7.3.6-3).
#[derive(Debug, Clone)]
pub struct TransferredBearer {
    /// EPS Bearer ID (mandatory).
    pub ebi: u8,
    /// QCI, from the mandatory Bearer Level QoS.
    pub qci: u8,
    /// The PGW's S5/S8 user-plane TEID (instance 1), when present.
    pub pgw_s5u_teid: Option<u32>,
    /// The PGW's S5/S8 user-plane address (instance 1), when present.
    pub pgw_s5u_ipv4: Option<[u8; 4]>,
}

/// Turn a decoded PDN Connection IE into the values a session and its bearers need.
///
/// Errors name the missing mandatory member rather than defaulting it: a PDN connection
/// with no Linked EPS Bearer ID has no default bearer, and installing it with EBI 0
/// (which TS 24.301 §9.3.2 reserves) would create a session the UE can never address.
pub fn transferred_pdn_connection(
    pdn: &Gtp2PdnConnectionIe,
) -> Result<TransferredPdnConnection, String> {
    let apn = pdn
        .apn()
        .map_err(|e| format!("PDN Connection APN: {e}"))?
        .to_string();
    let linked_ebi = pdn
        .linked_ebi()
        .map_err(|e| format!("PDN Connection Linked EPS Bearer ID: {e}"))?;
    let pgw = pdn
        .pgw_s5s8_control_fteid()
        .map_err(|e| format!("PDN Connection PGW S5/S8 control F-TEID: {e}"))?;
    let ambr = pdn
        .apn_ambr()
        .map_err(|e| format!("PDN Connection APN-AMBR: {e}"))?;

    let mut bearers = Vec::new();
    for bearer in pdn
        .bearer_contexts()
        .map_err(|e| format!("PDN Connection Bearer Contexts: {e}"))?
    {
        let ebi = bearer
            .ebi()
            .map_err(|e| format!("Bearer Context EPS Bearer ID: {e}"))?;
        let qos = bearer
            .bearer_qos()
            .map_err(|e| format!("Bearer Context Bearer QoS: {e}"))?
            .ok_or_else(|| format!("Bearer Context for EBI {ebi} has no Bearer Level QoS"))?;
        // Instance 1 is the PGW S5/S8 user-plane F-TEID (Table 7.3.6-3, `:20920`).
        // Instance 0 is the SGW one, which over N26 is the reserved all-zero value, so
        // it is deliberately NOT read: a zero TEID is what the spec requires there and
        // recording it as a real endpoint would be worse than ignoring it.
        let pgw_u = bearer.fteid(1).ok().flatten();
        bearers.push(TransferredBearer {
            ebi,
            qci: qos.qci,
            pgw_s5u_teid: pgw_u.as_ref().map(|f| f.teid),
            pgw_s5u_ipv4: pgw_u.as_ref().and_then(|f| f.ipv4_addr),
        });
    }

    if bearers.is_empty() {
        return Err(format!(
            "PDN Connection for APN '{apn}' carries no Bearer Context, which Table \
             7.3.6-2 makes mandatory"
        ));
    }

    // TS 29.274 §8.7: the AMBR IE is in kbps; MmeSess::ambr is bits per second, the
    // unit `s11_build` already uses when it puts the session's AMBR back on the wire.
    // Converting here rather than at the two call sites keeps one place that knows.
    Ok(TransferredPdnConnection {
        apn,
        linked_ebi,
        pgw_s5c_teid: pgw.teid,
        pgw_s5c_ipv4: pgw.ipv4_addr,
        ue_ipv4: pdn.ipv4_address(),
        ambr_uplink: u64::from(ambr.uplink) * 1000,
        ambr_downlink: u64::from(ambr.downlink) * 1000,
        bearers,
    })
}

/// Apply a decoded MM Context to a UE's EPS security context (TS 33.501 §8.6.1).
///
/// Takes `&mut MmeUe` so the caller must already hold the pool write lock — the write-back
/// hazard again. Every field comes from the MM Context; nothing is invented, and nothing
/// the AMF did not send is left at a previous value that a later NAS message would use.
pub fn apply_mm_context(mme_ue: &mut MmeUe, ctx: &Gtp2MmContextIe) {
    mme_ue.kasme.copy_from_slice(&ctx.kasme);
    // TS 33.501 §8.6.1 (`33501-k20.txt:11748-11751`): *"The eKSI for the newly derived
    // K_ASME key shall be defined such as the value field is taken from the ngKSI and
    // the type field is set to indicate a mapped security context."*
    //
    // TSC = 1 is "mapped security context" (TS 24.301 §9.9.3.21). Setting it to 0 would
    // claim the UE holds a NATIVE EPS context derived from an EPS AKA run that never
    // happened, and the UE — which knows it is mapped — would then disagree with the MME
    // about which context to use, failing every subsequent integrity check.
    mme_ue.nas_eps.mme_ksi.ksi = ctx.ksi_asme;
    mme_ue.nas_eps.mme_ksi.tsc = 1;
    mme_ue.nas_eps.ue_ksi.ksi = ctx.ksi_asme;
    mme_ue.nas_eps.ue_ksi.tsc = 1;
    // §8.6.1: *"The EPS uplink and downlink NAS COUNT values in the mapped context shall
    // be set to the uplink and downlink NAS COUNT values of the current 5G security
    // context respectively."* -- i.e. carried across, not reset to zero.
    mme_ue.dl_count = ctx.nas_downlink_count;
    mme_ue.ul_count = ctx.nas_uplink_count;
    // §8.6.1: *"The selected EPS NAS algorithms shall be set to the EPS algorithms
    // signalled to the UE by the AMF"*, which is what the MM Context's Used NAS
    // Cipher / Used NAS integrity protection algorithm carry.
    mme_ue.selected_enc_algorithm = ctx.used_nas_cipher;
    mme_ue.selected_int_algorithm = ctx.used_nas_integrity_algorithm;
    // The UE network capability the AMF forwarded (Figure 8.38-5's length-prefixed
    // `UE Network Capability`, TS 24.301 §9.9.3.34 contents).
    //
    // Parsed by `emm_handler::parse_ue_network_capability` rather than re-masked here, so
    // there is ONE reading of §9.9.3.34's octets in this crate — the #335/#340 lesson.
    // The field-by-field copy is because `emm_handler` and `context` declare two distinct
    // `UeNetworkCapability` types (the former is the parser's output, the latter is what
    // `MmeUe` stores), and adding a third conversion impl for one call site would be more
    // surface than the four assignments it saves. `length` is the *contents* length, which
    // is what the IE's own length octet carries.
    if !ctx.ue_network_capability.is_empty() {
        let parsed = crate::emm_handler::parse_ue_network_capability(&ctx.ue_network_capability);
        mme_ue.ue_network_capability.eea = parsed.eea;
        mme_ue.ue_network_capability.eia = parsed.eia;
        mme_ue.ue_network_capability.uea = parsed.uea;
        mme_ue.ue_network_capability.uia = parsed.uia;
        mme_ue.ue_network_capability.length =
            ctx.ue_network_capability.len().min(u8::MAX as usize) as u8;
    }
    // The transferred context IS established security: the UE is already
    // integrity-protecting with these keys (TS 24.301 §5.5.3.2.2 case z has it protect
    // the TAU REQUEST with the 5G context, and case zd with the mapped EPS one), so a
    // MME that left this false would re-authenticate a UE that needs no
    // re-authentication and reject the TAU as implicitly detached.
    mme_ue.security_context_available = true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PlmnId;

    fn plmn() -> PlmnId {
        PlmnId::new("001", "01")
    }

    fn test_guti() -> EpsGuti {
        EpsGuti {
            plmn_id: plmn(),
            mme_gid: 0xAB9B,
            mme_code: 0x6A,
            m_tmsi: 0x1234_5678,
        }
    }

    /// The two F-TEID interface types, against Table 8.22-1 and against smfd's
    /// constants, which are the values #62 left in the tree with no reader.
    #[test]
    fn n26_fteid_interface_types_match_ts29274_table_8_22_1() {
        assert_eq!(
            S10_N26_MME_GTP_C, 12,
            "the MME's own N26 control-plane interface type is 12, matching \
             smfd/src/gtp_build.rs:489's S10_N26_MME_GTP_C"
        );
        assert_eq!(
            N26_AMF_GTP_C, 40,
            "the AMF's is 40, matching smfd/src/gtp_build.rs:517's N26_AMF_GTP_C"
        );
        assert_ne!(
            S10_N26_MME_GTP_C, N26_AMF_GTP_C,
            "the two ends of N26 must not share an interface type, or a peer cannot tell \
             an MME F-TEID from an AMF one"
        );
    }

    /// The Complete Request Message type must be TAU (1), not Attach (0).
    #[test]
    fn complete_request_message_type_is_tau_not_attach() {
        assert_eq!(
            COMPLETE_REQUEST_TAU, 1,
            "TS 29.274 Table 8.46-1 (29274-j60.txt:29078): Complete Attach Request is 0, \
             Complete TAU Request is 1 -- sending 0 would have the old AMF \
             integrity-check the octets as an ATTACH REQUEST"
        );
    }

    /// The GUTI IE, at its Figure 8.47-1 byte positions.
    #[test]
    fn guti_ie_encodes_ts29274_figure_8_47_1_field_positions() {
        let ie = encode_guti_ie(&test_guti(), 0);
        assert_eq!(ie.ie_type, 117, "GUTI is IE type 117");
        assert_eq!(
            ie.value.len(),
            10,
            "3 PLMN + 2 MME Group ID + 1 MME Code + 4 M-TMSI (Figure 8.47-1)"
        );
        // Octets 8-9 of the figure = contents[3..5]: MME Group ID, big-endian.
        assert_eq!(
            &ie.value[3..5],
            &[0xAB, 0x9B],
            "MME Group ID occupies figure octets 8-9 = contents offset 3"
        );
        // Octet 10 = contents[5]: MME Code.
        assert_eq!(
            ie.value[5], 0x6A,
            "MME Code is figure octet 10 = contents offset 5"
        );
        // Octets 11.. = contents[6..10]: M-TMSI, big-endian.
        assert_eq!(
            &ie.value[6..10],
            &[0x12, 0x34, 0x56, 0x78],
            "M-TMSI occupies figure octets 11 onward = contents offset 6"
        );

        // And the inverse recovers the GUTI exactly, because the old AMF has to resolve
        // its UE context from these bytes (TS 23.003 §2.10.2.1.3).
        assert_eq!(parse_guti_ie(&ie.value), Some(test_guti()));
    }

    /// A short GUTI is refused rather than resolved.
    #[test]
    fn a_truncated_guti_ie_does_not_parse() {
        for len in 0..10usize {
            let short = Bytes::from(vec![0xAAu8; len]);
            assert!(
                parse_guti_ie(&short).is_none(),
                "a {len}-octet GUTI must not resolve: it would match a UE context by \
                 accident on the bytes that happen to be there"
            );
        }
    }

    /// The Context Request carries exactly the Table 7.3.5-1 IEs the MME can supply,
    /// with the right message type and interface type.
    #[test]
    fn context_request_carries_its_table_7_3_5_1_ies() {
        let tau = [0x07u8, 0x48, 0x0B, 0xF6];
        let local = Gtp2FTeidIe::new_ipv4(S10_N26_MME_GTP_C, 0xDEAD_BEEF, [10, 0, 0, 5]);
        let msg = build_context_request(0x42, &test_guti(), &tau, &local, true);

        assert_eq!(
            msg.header.message_type, 130,
            "Context Request is message type 130 (29274-j60.txt:2416)"
        );
        assert_eq!(msg.header.sequence_number, 0x42);
        assert_eq!(
            msg.header.teid,
            Some(0),
            "the new MME does not yet know the AMF's TEID, so the request carries 0"
        );

        // GUTI, and it must be the one an AMF can reverse-map.
        let guti_ie = msg.get_ie(Gtp2IeType::Guti as u8, 0).expect("GUTI IE");
        assert_eq!(parse_guti_ie(&guti_ie.value), Some(test_guti()));

        // Complete TAU Request: the type octet then the VERBATIM NAS message. Verbatim
        // matters -- the old AMF integrity-checks these octets, so a single byte of
        // re-encoding fails the check and the UE is rejected.
        let crm = msg
            .get_ie(Gtp2IeType::CompleteRequestMessage as u8, 0)
            .expect("Complete Request Message IE");
        let (kind, nas) = parse_complete_request_message(&crm.value).expect("parses");
        assert_eq!(kind, COMPLETE_REQUEST_TAU);
        assert_eq!(
            nas.as_ref(),
            &tau,
            "the TAU REQUEST must travel byte-for-byte: the old AMF integrity-checks it"
        );

        // The MME's own F-TEID, with interface type 12.
        let fteid = Gtp2FTeidIe::decode(
            &msg.get_ie(Gtp2IeType::FTeid as u8, 0)
                .expect("F-TEID IE")
                .value,
        )
        .expect("decodes");
        assert_eq!(fteid.interface_type, S10_N26_MME_GTP_C);
        assert_eq!(fteid.teid, 0xDEAD_BEEF);
        assert_eq!(fteid.ipv4_addr, Some([10, 0, 0, 5]));

        // RAT Type is the NEW system's, i.e. E-UTRAN.
        let rat = msg
            .get_ie(Gtp2IeType::RatType as u8, 0)
            .expect("RAT Type IE");
        assert_eq!(
            rat.value[0], RAT_TYPE_EUTRAN,
            "Table 7.3.5-1: RAT Type is 'the Radio Access Technology which is used in \
             the NEW system' (29274-j60.txt:19794), so E-UTRAN and not NR"
        );

        // Indication with MSV, because this call said the TAU was validated.
        let ind = Gtp2IndicationIe::decode(
            &msg.get_ie(Gtp2IeType::Indication as u8, 0)
                .expect("Indication IE")
                .value,
        )
        .expect("decodes");
        assert!(
            ind.msv,
            "MSV set means 'the new system has validated the integrity protection of \
             the TAU request message' (29274-j60.txt:19806)"
        );
    }

    /// An unvalidated UE means the Indication IE is OMITTED, not sent with MSV clear.
    #[test]
    fn an_unvalidated_tau_omits_the_indication_ie_entirely() {
        let msg = build_context_request(
            1,
            &test_guti(),
            &[0x07],
            &Gtp2FTeidIe::new_ipv4(S10_N26_MME_GTP_C, 1, [10, 0, 0, 5]),
            false,
        );
        assert!(
            msg.get_ie(Gtp2IeType::Indication as u8, 0).is_none(),
            "Table 7.3.5-1 includes the Indication IE only 'if any one of the applicable \
             flags is set to 1' (29274-j60.txt:19801). A present-but-zero Indication \
             claims every applicable flag was evaluated and none applied, which is a \
             different statement from not having validated the UE."
        );
        // And the validated form DOES carry it, so the assertion above is about the
        // flag rather than about the IE never being built.
        assert!(build_context_request(
            1,
            &test_guti(),
            &[0x07],
            &Gtp2FTeidIe::new_ipv4(S10_N26_MME_GTP_C, 1, [10, 0, 0, 5]),
            true,
        )
        .get_ie(Gtp2IeType::Indication as u8, 0)
        .is_some());
    }

    /// Context Acknowledge is addressed to the AMF's TEID, not to zero.
    #[test]
    fn context_acknowledge_is_addressed_to_the_amf_teid() {
        let msg = build_context_acknowledge(7, 0x00AF_0001, CAUSE_REQUEST_ACCEPTED);
        assert_eq!(msg.header.message_type, 132);
        assert_eq!(
            msg.header.teid,
            Some(0x00AF_0001),
            "the acknowledge must carry the TEID the AMF supplied in its Context \
             Response, or it lands on no UE context at the peer and the AMF never \
             releases its buffered state (TS 23.401 §5.3.3.1 step 5)"
        );
        assert_eq!(msg.header.sequence_number, 7);
        let cause = Gtp2CauseIe::decode(&msg.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
            .expect("decodes");
        assert_eq!(cause.cause, CAUSE_REQUEST_ACCEPTED);
    }

    /// BCD round-trips, including the odd-length case the `0xF` filler covers.
    #[test]
    fn bcd_round_trips_including_the_odd_length_filler() {
        for imsi in ["001010000000001", "00101000000000", "1"] {
            let encoded = string_to_bcd(imsi);
            assert_eq!(
                bcd_to_string(&encoded),
                imsi,
                "TS 29.274 §8.3 TBCD: low nibble first, 0xF terminates"
            );
        }
        // An odd-length identity's last high nibble is the 0xF filler.
        assert_eq!(string_to_bcd("123").last().copied(), Some(0xF3));
    }

    /// A Context Response with no Cause is unparseable, NOT an acceptance.
    #[test]
    fn a_context_response_without_a_cause_is_rejected() {
        let msg = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::ContextResponse as u8,
            1,
            1,
        ));
        let err = parse_context_response(&msg).expect_err("no Cause must not parse");
        assert!(
            err.contains("Cause"),
            "the error must name the missing mandatory IE, got {err:?}"
        );
    }

    /// `apply_mm_context` marks the context MAPPED, not native.
    ///
    /// TSC = 0 would claim the UE holds a native EPS context from an EPS AKA run that
    /// never happened. The UE knows it is mapped (TS 24.301 §5.5.3.2.2 case z), so the
    /// two would disagree about which context to use and every subsequent integrity
    /// check would fail — with a symptom (MAC failure) that points nowhere near here.
    #[test]
    fn apply_mm_context_installs_a_mapped_security_context() {
        let mut ue = MmeUe::default();
        let mut kasme = [0u8; 32];
        for (i, b) in kasme.iter_mut().enumerate() {
            *b = 0x10 + i as u8;
        }
        let ctx = Gtp2MmContextIe {
            ksi_asme: 3,
            used_nas_cipher: 2,
            used_nas_integrity_algorithm: 1,
            nas_downlink_count: 0x0001_0203 & 0x00FF_FFFF,
            nas_uplink_count: 0x0004_0506 & 0x00FF_FFFF,
            kasme,
            ..Default::default()
        };
        apply_mm_context(&mut ue, &ctx);

        assert_eq!(ue.kasme, kasme, "K_ASME comes from the MM Context verbatim");
        assert_eq!(ue.nas_eps.mme_ksi.ksi, 3, "the eKSI value is the ngKSI's");
        assert_eq!(
            ue.nas_eps.mme_ksi.tsc, 1,
            "TSC = 1 marks a MAPPED security context (TS 33.501 §8.6.1); 0 would claim a \
             native EPS context from an AKA run that never happened"
        );
        assert_eq!(ue.nas_eps.ue_ksi.tsc, 1, "and the UE side agrees");
        assert_eq!(
            ue.dl_count,
            0x0001_0203 & 0x00FF_FFFF,
            "the 5G downlink NAS COUNT is CARRIED ACROSS, not reset (TS 33.501 §8.6.1)"
        );
        assert_eq!(ue.ul_count, 0x0004_0506 & 0x00FF_FFFF);
        assert_eq!(ue.selected_enc_algorithm, 2);
        assert_eq!(ue.selected_int_algorithm, 1);
        assert!(
            ue.security_context_available,
            "a transferred context IS established security: leaving this false makes the \
             TAU path reject the UE as implicitly detached (nas_dispatch.rs)"
        );
    }
}
