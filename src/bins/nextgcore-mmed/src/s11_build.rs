//! MME S11 GTP-C Message Building
//!
//! Port of src/mme/mme-s11-build.c - GTPv2-C message building functions for S11 interface

use crate::context::{MmeBearer, MmeSess, MmeUe, SgwUe};

// ============================================================================
// GTP-C Message Types
// ============================================================================

/// GTP-C message types
pub mod message_type {
    pub const ECHO_REQUEST: u8 = 1;
    pub const ECHO_RESPONSE: u8 = 2;
    pub const CREATE_SESSION_REQUEST: u8 = 32;
    pub const CREATE_SESSION_RESPONSE: u8 = 33;
    pub const MODIFY_BEARER_REQUEST: u8 = 34;
    pub const MODIFY_BEARER_RESPONSE: u8 = 35;
    pub const DELETE_SESSION_REQUEST: u8 = 36;
    pub const DELETE_SESSION_RESPONSE: u8 = 37;
    pub const CREATE_BEARER_REQUEST: u8 = 95;
    pub const CREATE_BEARER_RESPONSE: u8 = 96;
    pub const UPDATE_BEARER_REQUEST: u8 = 97;
    pub const UPDATE_BEARER_RESPONSE: u8 = 98;
    pub const DELETE_BEARER_REQUEST: u8 = 99;
    pub const DELETE_BEARER_RESPONSE: u8 = 100;
    pub const CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST: u8 = 166;
    pub const CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE: u8 = 167;
    pub const DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST: u8 = 168;
    pub const DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE: u8 = 169;
    pub const RELEASE_ACCESS_BEARERS_REQUEST: u8 = 170;
    pub const RELEASE_ACCESS_BEARERS_RESPONSE: u8 = 171;
    pub const DOWNLINK_DATA_NOTIFICATION: u8 = 176;
    pub const DOWNLINK_DATA_NOTIFICATION_ACK: u8 = 177;
    /// TS 29.274 §7.2.11.3 (#956).
    pub const DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION: u8 = 70;
    pub const DELETE_BEARER_COMMAND: u8 = 66;
    pub const BEARER_RESOURCE_COMMAND: u8 = 68;
    pub const BEARER_RESOURCE_FAILURE_INDICATION: u8 = 69;
    pub const CHANGE_NOTIFICATION_REQUEST: u8 = 38;
    pub const CHANGE_NOTIFICATION_RESPONSE: u8 = 39;
    pub const MODIFY_BEARER_COMMAND: u8 = 64;
    pub const MODIFY_BEARER_FAILURE_INDICATION: u8 = 65;
    pub const DELETE_BEARER_FAILURE_INDICATION: u8 = 67;
}

// ============================================================================
// GTP-C IE Types
// ============================================================================

/// GTP-C IE types
pub mod ie_type {
    pub const IMSI: u8 = 1;
    pub const CAUSE: u8 = 2;
    pub const RECOVERY: u8 = 3;
    pub const APN: u8 = 71;
    pub const AMBR: u8 = 72;
    pub const EBI: u8 = 73;
    pub const MEI: u8 = 75;
    pub const MSISDN: u8 = 76;
    pub const INDICATION: u8 = 77;
    pub const IP_ADDRESS: u8 = 74;
    pub const PCO: u8 = 78;
    pub const CHANGE_REPORTING_ACTION: u8 = 131;
    pub const PAA: u8 = 79;
    pub const BEARER_QOS: u8 = 80;
    pub const FLOW_QOS: u8 = 81;
    pub const RAT_TYPE: u8 = 82;
    pub const SERVING_NETWORK: u8 = 83;
    pub const BEARER_TFT: u8 = 84;
    pub const TAD: u8 = 85;
    pub const ULI: u8 = 86;
    pub const F_TEID: u8 = 87;
    pub const BEARER_CONTEXT: u8 = 93;
    pub const CHARGING_ID: u8 = 94;
    pub const CHARGING_CHARACTERISTICS: u8 = 95;
    pub const PDN_TYPE: u8 = 99;
    pub const PTI: u8 = 100;
    pub const UE_TIME_ZONE: u8 = 114;
    pub const APN_RESTRICTION: u8 = 127;
    pub const SELECTION_MODE: u8 = 128;
    pub const EPCO: u8 = 197;
}

// ============================================================================
// GTP Cause Values
// ============================================================================

/// GTP-C Cause values: the shared TS 29.274 Table 8.4-1 enum (#1037), so this
/// node and its peers name every cause from one table.
pub use nextgcore_gtp::v2::Gtp2Cause as GtpCause;

/// RAT Type values (TS 29.274 §8.17).
pub mod rat_type {
    /// E-UTRAN — the only access this MME serves.
    pub const EUTRAN: u8 = 6;
}

// ============================================================================
// Action Types
// ============================================================================

/// Create session action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpCreateAction {
    AttachRequest,
    UplinkNasTransport,
    PathSwitchRequest,
    TrackingAreaUpdate,
}

/// Delete session action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpDeleteAction {
    NoAction,
    SendAuthenticationRequest,
    SendDetachAccept,
    SendDeactivateBearerContextRequest,
    SendReleaseWithUeContextRemove,
    SendReleaseWithS1RemoveAndUnlink,
    HandlePdnConnectivityRequest,
    InPathSwitchRequest,
    /// The UE left for 5GS over N26 (#584, TS 23.502 §4.11.1.2.2.3 step 13 /
    /// TS 23.401 §5.5.1.2.2 step 19): the Serving GW releases its own state
    /// only, because the SMF+PGW-C keeps the PDN connection as a PDU session.
    /// So Operation Indication is NOT set.
    InEpsTo5gsHandover,
}

/// Modify bearer action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpModifyAction {
    NoAction,
    InPathSwitchRequest,
    InErabModification,
}

/// Release access bearers action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpReleaseAction {
    S1ContextRemove,
    S1ContextRemoveByResetAll,
    S1ContextRemoveByLoConnRefused,
}

// ============================================================================
// Data Structures
// ============================================================================

/// Bearer QoS data
#[derive(Debug, Clone, Default)]
pub struct Gtp2BearerQos {
    pub qci: u8,
    pub priority_level: u8,
    pub pre_emption_capability: u8,
    pub pre_emption_vulnerability: u8,
    pub ul_mbr: u64,
    pub dl_mbr: u64,
    pub ul_gbr: u64,
    pub dl_gbr: u64,
}

/// Indication flags
#[derive(Debug, Clone, Default)]
pub struct Gtp2Indication {
    pub dual_address_bearer_flag: bool,
    pub handover_indication: bool,
    pub operation_indication: bool,
    pub scope_indication: bool,
    pub change_reporting_support_indication: bool,
}

// ============================================================================
// Build Error
// ============================================================================

/// S11 build error
#[derive(Debug, Clone)]
pub enum S11BuildError {
    InvalidSession,
    InvalidUe,
    InvalidBearer,
    MissingRequiredField(String),
    BuildFailed(String),
}

impl std::fmt::Display for S11BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSession => write!(f, "Invalid session"),
            Self::InvalidUe => write!(f, "Invalid UE"),
            Self::InvalidBearer => write!(f, "Invalid bearer"),
            Self::MissingRequiredField(field) => write!(f, "Missing required field: {field}"),
            Self::BuildFailed(msg) => write!(f, "Build failed: {msg}"),
        }
    }
}

impl std::error::Error for S11BuildError {}

pub type S11BuildResult<T> = Result<T, S11BuildError>;

// ============================================================================
// Message builders (TS 29.274), on the shared nextgcore-gtp v2 codec
// ============================================================================
//
// #51 deleted the hand-rolled `GtpBuffer` these were written against. It duplicated
// the round-trip-tested library codec and mis-encoded protocol semantics on its own:
// the sequence number was a literal 0 in every initial message, the Indication IE put
// the OI flag in the wrong content octet, and there was no mandatory-IE validation at
// all — so the messages it built would have been rejected by sgwcd's own conformant
// parser, if any of them had ever been transmitted.
//
// Every builder now returns a `Gtp2Message` and takes the sequence number the
// transaction layer allocated, so the transport owns correlation rather than each
// builder guessing at it.

use bytes::BytesMut;
use nextgcore_gtp::v2::{
    Gtp2AmbrIe, Gtp2ApnIe, Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2CauseIe, Gtp2FTeidIe,
    Gtp2Header, Gtp2Ie, Gtp2IeType, Gtp2IndicationIe, Gtp2Message, Gtp2PaaIe, Gtp2PdnTypeIe,
    Gtp2RatTypeIe, Gtp2SelectionModeIe,
};

/// F-TEID interface types (TS 29.274 §8.22 Table 8.22-1).
pub mod f_teid_interface {
    /// S1-U eNodeB GTP-U
    pub const S1U_ENB_GTP_U: u8 = 0;
    /// S1-U SGW GTP-U interface (TS 29.274 §8.22 value 1): the SGW's uplink endpoint
    /// in a Create Session Response's Bearer Context created (Table 7.2.2-2).
    pub const S1U_SGW_GTP_U: u8 = 1;
    /// S5/S8 PGW GTP-U interface (TS 29.274 §8.22 value 5).
    pub const S5_S8_PGW_GTP_U: u8 = 5;
    /// eNodeB/gNodeB GTP-U interface for DL data forwarding.
    ///
    /// #48: this constant said **4**, which TS 29.274 §8.22 defines as "S5/S8 SGW
    /// GTP-U interface". The only user was `build_create_indirect_data_forwarding_tunnel_request`,
    /// which itself had no caller, so the wrong value was inert -- exactly the shape
    /// of the S_NSSAI=250 defect #321 found in `smfd`'s hand-copied IE table. Making
    /// the CIDFT path reachable makes it live, so it is read from the spec here:
    /// `6g_docs/specs/29274-j60.txt:27219` lists "19: eNodeB/gNodeB GTP-U interface
    /// for DL data forwarding".
    pub const ENB_GTP_U_DL_DATA_FORWARDING: u8 = 19;
    /// eNodeB GTP-U interface for UL data forwarding (TS 29.274 §8.22, value 20).
    ///
    /// Absent before #48, so the UL half of a forwarding pair could not be expressed
    /// at all.
    pub const ENB_GTP_U_UL_DATA_FORWARDING: u8 = 20;
    /// SGW/UPF GTP-U interface for DL data forwarding (TS 29.274 §8.22, value 23;
    /// Table 7.2.19-2 NOTE 3 mandates it for the SGW's DL forwarding F-TEID).
    pub const SGW_GTP_U_DL_DATA_FORWARDING: u8 = 23;
    /// SGW GTP-U interface for UL data forwarding (TS 29.274 §8.22, value 28;
    /// Table 7.2.19-2 NOTE 4).
    pub const SGW_GTP_U_UL_DATA_FORWARDING: u8 = 28;
    /// S11 MME GTP-C
    pub const S11_MME_GTP_C: u8 = 10;
}

/// A message with a TEID-bearing header.
fn new_message(message_type: u8, teid: u32, sequence_number: u32) -> Gtp2Message {
    Gtp2Message::new(Gtp2Header::new(message_type, teid, sequence_number))
}

/// Encode one library IE type into a `Gtp2Ie` at the given instance.
///
/// The library's IE types encode themselves into a buffer including their own TLV
/// header, so the round trip back through `Gtp2Ie::decode` is how a typed value
/// becomes something `Gtp2Message::add_ie` accepts. Same idiom sgwcd uses.
fn typed_ie<F>(encode: F) -> S11BuildResult<Gtp2Ie>
where
    F: FnOnce(&mut BytesMut),
{
    let mut buf = BytesMut::new();
    encode(&mut buf);
    let mut frozen = buf.freeze();
    Gtp2Ie::decode(&mut frozen).map_err(|e| S11BuildError::BuildFailed(e.to_string()))
}

/// The MME's own S11 control-plane F-TEID (TS 29.274 Table 7.2.1-1, M).
///
/// Absent from every Create Session Request this daemon built before #51, which
/// sgwcd's parser `require()`s — so the SGW-C would have answered
/// "Mandatory IE missing" to every one of them.
///
/// The local address is a PARAMETER rather than read from `mme_self()`: a builder that
/// reaches for a process global cannot be exercised without one, and the sender
/// already holds the context that knows it.
fn sender_fteid(mme_ue: &MmeUe, local: std::net::SocketAddr) -> S11BuildResult<Gtp2FTeidIe> {
    match local.ip() {
        std::net::IpAddr::V4(v4) => Ok(Gtp2FTeidIe::new_ipv4(
            f_teid_interface::S11_MME_GTP_C,
            mme_ue.mme_s11_teid,
            v4.octets(),
        )),
        std::net::IpAddr::V6(v6) => Ok(Gtp2FTeidIe::new_ipv6(
            f_teid_interface::S11_MME_GTP_C,
            mme_ue.mme_s11_teid,
            v6.octets(),
        )),
    }
}

/// The Bearer QoS IE for a bearer's subscribed QoS (TS 29.274 §8.15).
pub(crate) fn bearer_qos(bearer: &MmeBearer) -> Gtp2BearerQosIe {
    let mut qos = Gtp2BearerQosIe::new(
        bearer.qos.qci,
        bearer.qos.mbr.uplink,
        bearer.qos.mbr.downlink,
        bearer.qos.gbr.uplink,
        bearer.qos.gbr.downlink,
    );
    qos.pl = bearer.qos.arp.priority_level;
    // The context stores the GTP spelling (TS 29.274 §8.15: PCI/PVI 1 =
    // disabled), and the library IE's `pci`/`pvi` are those raw bits (`true`
    // sets 0x40 / 0x01), so they are copied as they are (#1186 review: `== 0`
    // inverted them, opposite to what S1AP now says).
    qos.pci = bearer.qos.arp.pre_emption_capability != 0;
    qos.pvi = bearer.qos.arp.pre_emption_vulnerability != 0;
    qos
}

/// An F-TEID carrying whichever address families `ip` has (#948, TS 29.274
/// §8.22: IPv4, IPv6 or both), or `None` without an address.
fn fteid_of(interface_type: u8, teid: u32, ip: &crate::context::IpAddr) -> Option<Gtp2FTeidIe> {
    match (ip.ipv4, ip.ipv6) {
        (Some(v4), Some(v6)) => Some(Gtp2FTeidIe::new_dual(interface_type, teid, v4, v6)),
        (Some(v4), None) => Some(Gtp2FTeidIe::new_ipv4(interface_type, teid, v4)),
        (None, Some(v6)) => Some(Gtp2FTeidIe::new_ipv6(interface_type, teid, v6)),
        (None, None) => None,
    }
}

/// The eNB's S1-U F-TEID for a bearer, or `None` when none has been saved yet.
fn enb_s1u_fteid(bearer: &MmeBearer, interface_type: u8) -> Option<Gtp2FTeidIe> {
    fteid_of(interface_type, bearer.enb_s1u_teid, &bearer.enb_s1u_ip)
}

/// An F-TEID from an explicit TEID and context address, for the data-forwarding
/// endpoints (which are NOT the bearer's serving S1-U endpoint).
fn forwarding_fteid(
    interface_type: u8,
    teid: u32,
    ip: &crate::context::IpAddr,
) -> Option<Gtp2FTeidIe> {
    if teid == 0 {
        return None;
    }
    fteid_of(interface_type, teid, ip)
}

/// Build Create Session Request (TS 29.274 §7.2.1)
pub fn build_create_session_request(
    sess: &MmeSess,
    mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    _create_action: GtpCreateAction,
    sequence_number: u32,
    bearers: &[&MmeBearer],
    local_s11_addr: std::net::SocketAddr,
) -> S11BuildResult<Gtp2Message> {
    log::debug!("Build Create Session Request for APN={}", sess.apn);
    let mut msg = new_message(
        message_type::CREATE_SESSION_REQUEST,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );

    // IMSI (M)
    if mme_ue.imsi_len > 0 {
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &mme_ue.imsi[..mme_ue.imsi_len],
        ));
    }

    // MSISDN (C)
    if mme_ue.msisdn_len > 0 {
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Msisdn as u8,
            0,
            &mme_ue.msisdn[..mme_ue.msisdn_len],
        ));
    }

    // MEI (C)
    if mme_ue.imeisv_len > 0 {
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Mei as u8,
            0,
            &mme_ue.imeisv[..mme_ue.imeisv_len],
        ));
    }

    // RAT Type (M) — from the UE context, not a literal (#51 criterion 5)
    msg.add_ie(typed_ie(|buf| {
        Gtp2RatTypeIe::new(mme_ue.rat_type).encode(buf, 0)
    })?);

    // Sender F-TEID for Control Plane (M)
    msg.add_ie(sender_fteid(mme_ue, local_s11_addr)?.to_ie(0));

    // APN (M)
    msg.add_ie(typed_ie(|buf| {
        Gtp2ApnIe::from_string(&sess.apn).encode(buf, 0)
    })?);

    // Serving Network (C, TS 29.274 §8.18) and ULI (C, §8.21).
    //
    // Added by #52, not #51: #51's criteria named only the Sender F-TEID and the Bearer
    // Contexts, and these two were listed in that issue's PROSE. Building the anchor
    // (smfd's PGW-C role) is what showed they are load-bearing — a conformant PGW
    // answers `ConditionalIeMissing` for an E-UTRAN session without them, so the
    // MME→SGW-C→PGW chain cannot complete while they are absent, however conformant the
    // first hop looks on its own.
    msg.add_ie(Gtp2Ie::from_slice(
        Gtp2IeType::ServingNetwork as u8,
        0,
        &encode_plmn_bcd(&mme_ue.tai.plmn_id),
    ));
    msg.add_ie(uli_ie(mme_ue)?);

    // Indication (C, §8.12): Change Reporting Support Indication. TS 23.401 §5.9.2:
    // the MME says in the Create Session Request whether it supports location
    // change reporting, and since #593 it does (Change Notification Request).
    let indication = Gtp2IndicationIe {
        crsi: true,
        ..Default::default()
    };
    msg.add_ie(typed_ie(|buf| indication.encode(buf, 0))?);

    // Selection Mode (C)
    msg.add_ie(typed_ie(|buf| Gtp2SelectionModeIe::new(0).encode(buf, 0))?);

    // PDN Type (C). GTPv2's code points are not ESM's: TS 29.274 §8.34 has Non-IP
    // = 4 and Ethernet = 5, where TS 24.301 §9.9.4.10 has 5 and 6.
    let gtp_pdn_type = gtp_pdn_type(sess.ue_request_pdn_type);
    msg.add_ie(typed_ie(|buf| {
        Gtp2PdnTypeIe::new(gtp_pdn_type).encode(buf, 0)
    })?);

    // PAA (C, TS 29.274 Table 7.2.1-1, §8.14): present for an E-UTRAN initial
    // attach. No static address is held, so this requests DYNAMIC allocation:
    // the address octets are zero and the PGW allocates (TS 23.401 §5.3.2.1
    // step 12). Without it a conformant PGW rejects with cause 109 (#479).
    msg.add_ie(create_session_paa(gtp_pdn_type).to_ie(0));

    // APN-AMBR (C)
    msg.add_ie(typed_ie(|buf| {
        // TS 29.274 §8.7 states APN-AMBR in kbps as two u32s.
        Gtp2AmbrIe::new(
            (sess.ambr.uplink / 1000) as u32,
            (sess.ambr.downlink / 1000) as u32,
        )
        .encode(buf, 0)
    })?);

    // Bearer Contexts to be created (M), each with EBI (M) and Bearer QoS (M)
    let mut created = 0;
    for bearer in bearers {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(bearer.ebi);
        bc.set_bearer_qos(&bearer_qos(bearer));
        msg.add_bearer_context(0, &bc);
        created += 1;
    }
    if created == 0 {
        // TS 29.274 Table 7.2.1-1 makes this mandatory, and sgwcd's parser
        // `require()`s it: building the message without one produces a request the
        // peer must reject, which is worse than refusing to build it.
        return Err(S11BuildError::MissingRequiredField(
            "Create Session Request requires at least one bearer context".to_string(),
        ));
    }

    Ok(msg)
}

/// The GTPv2 PDN Type (TS 29.274 §8.34 / Table 8.14-1) for an ESM PDN type
/// (TS 24.301 §9.9.4.10). The IP values coincide; Non-IP and Ethernet do not.
pub fn gtp_pdn_type(pdn_type: crate::esm_build::PdnType) -> u8 {
    use crate::esm_build::PdnType;
    match pdn_type {
        PdnType::Ipv4 => 1,
        PdnType::Ipv6 => 2,
        PdnType::Ipv4v6 => 3,
        PdnType::NonIp => 4,
        PdnType::Ethernet => 5,
    }
}

/// A PAA asking the PGW for dynamic allocation: the PDN type with every address
/// octet zero, and no address at all for Non-IP / Ethernet (§8.14).
fn create_session_paa(gtp_pdn_type: u8) -> Gtp2PaaIe {
    match gtp_pdn_type {
        1 => Gtp2PaaIe::ipv4([0; 4]),
        2 => Gtp2PaaIe::ipv6(64, [0; 16]),
        3 => Gtp2PaaIe::ipv4v6([0; 4], 64, [0; 16]),
        other => Gtp2PaaIe {
            pdn_type: other,
            ipv4_addr: None,
            ipv6_prefix_len: None,
            ipv6_addr: None,
        },
    }
}

/// Build Modify Bearer Request (TS 29.274 §7.2.7).
///
/// `to_remove` are the EBIs sent as "Bearer Contexts to be removed" (instance 1,
/// EBI only). Table 7.2.7-1 makes them mandatory "on the S4 and S11 interfaces for
/// the TAU/RAU/Handover ... procedures where any of the bearers existing before
/// the ... Handover procedure will be deactivated as consequence of the ...
/// Handover procedure"; NOTE 3 says the MME then removes them by a separate
/// procedure (#730 review M1).
///
/// The User Location Information IE is not encoded: a stated ceiling of #730.
pub fn build_modify_bearer_request(
    mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    bearers: &[&MmeBearer],
    to_remove: &[u8],
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    log::debug!("Build Modify Bearer Request with {} bearers", bearers.len());
    let mut msg = new_message(
        message_type::MODIFY_BEARER_REQUEST,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );

    // Bearer Contexts to be modified, each carrying the eNB's S1-U F-TEID — which
    // is the whole point of the message (Table 7.2.7-1). The previous caller passed
    // an empty slice, so the SGW was asked to modify nothing.
    let mut modified = 0;
    for bearer in bearers {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(bearer.ebi);
        match enb_s1u_fteid(bearer, f_teid_interface::S1U_ENB_GTP_U) {
            Some(ft) => bc.set_fteid(0, &ft),
            None => {
                // No eNB S1-U endpoint saved yet means Initial Context Setup has not
                // completed for this bearer. Sending the context without it would ask
                // the SGW to switch the downlink tunnel to nowhere.
                log::warn!(
                    "Modify Bearer Request: EBI {} has no eNB S1-U F-TEID saved; omitting it",
                    bearer.ebi
                );
                continue;
            }
        }
        msg.add_bearer_context(0, &bc);
        modified += 1;
    }
    if modified == 0 {
        return Err(S11BuildError::MissingRequiredField(
            "Modify Bearer Request requires at least one bearer context with an eNB S1-U F-TEID"
                .to_string(),
        ));
    }
    for ebi in to_remove {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(*ebi);
        msg.add_bearer_context(1, &bc);
    }

    // RAT Type (C)
    msg.add_ie(typed_ie(|buf| {
        Gtp2RatTypeIe::new(mme_ue.rat_type).encode(buf, 0)
    })?);

    Ok(msg)
}

/// Build Delete Session Request (TS 29.274 §7.2.9)
pub fn build_delete_session_request(
    _sess: &MmeSess,
    _mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    linked_bearer_ebi: u8,
    _action: GtpDeleteAction,
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    log::debug!("Build Delete Session Request for LBI={linked_bearer_ebi}");
    let mut msg = new_message(
        message_type::DELETE_SESSION_REQUEST,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );

    // Linked EPS Bearer ID (M, Table 7.2.9.1-1): the DEFAULT bearer of the PDN
    // connection being torn down. The caller used to pass a literal 5, which tears
    // down the wrong PDN for any UE with more than one.
    msg.add_ie(Gtp2Ie::from_slice(
        Gtp2IeType::Ebi as u8,
        0,
        &[linked_bearer_ebi],
    ));

    // Indication (C, §8.12): Operation Indication. Hand-encoded as
    // `[0x00, 0x08, 0x00]` before #51, which puts the bit in the SECOND content
    // octet and therefore left OI unset; the library IE puts it where §8.12 does.
    //
    // #584: an EPS→5GS handover is the exception. TS 23.401 §5.5.1.2.2 step 19
    // has the source MME release the source Serving GW "with the Operation
    // Indication flag not set, that indicates to the S-GW that the S-GW shall
    // not initiate a delete procedure towards the PDN GW" -- the PDN connection
    // now lives on as a PDU session at the SMF+PGW-C.
    let mut indication = Gtp2IndicationIe::default();
    indication.oi = _action != GtpDeleteAction::InEpsTo5gsHandover;
    msg.add_ie(typed_ie(|buf| indication.encode(buf, 0))?);

    Ok(msg)
}

/// Build a Delete Bearer Command (TS 29.274 §7.2.17.1) for the dedicated
/// bearers `ebis` of one PDN connection, which the eNB released (#584, TS
/// 23.401 §5.4.4.2 step 2).
///
/// Table 7.2.17.1-1: Bearer Contexts (M, one per bearer, each the EBI), User
/// Location Information (C: the MME includes it when it has it).
pub fn build_delete_bearer_command(
    mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    ebis: &[u8],
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    if ebis.is_empty() {
        return Err(S11BuildError::MissingRequiredField(
            "Delete Bearer Command requires at least one Bearer Context (Table 7.2.17.1-1)"
                .to_string(),
        ));
    }
    let mut msg = new_message(
        message_type::DELETE_BEARER_COMMAND,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );
    for ebi in ebis {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(*ebi);
        msg.add_bearer_context(0, &bc);
    }
    msg.add_ie(uli_ie(mme_ue)?);
    Ok(msg)
}

/// Build a Change Notification Request (TS 29.274 §7.3.14, Table 7.3.14-1) for
/// the PDN connection `sess`, whose default bearer is `lbi` (#593, TS 23.401
/// §5.9.2): it tells the PDN GW, via the Serving GW, where the UE now is.
///
/// - IMSI (C): included when the UE has one;
/// - RAT Type (M): the UE's;
/// - ULI (C): the TAI and ECGI just stored;
/// - Linked EPS Bearer ID (C, "shall include on S4/S11") and PGW S5/S8 GTP-C IP
///   Address (C, same): together they name the PDN connection at the SGW.
pub fn build_change_notification_request(
    mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    sess: &MmeSess,
    lbi: u8,
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    let mut msg = new_message(
        message_type::CHANGE_NOTIFICATION_REQUEST,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );
    if mme_ue.imsi_len > 0 {
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &mme_ue.imsi[..mme_ue.imsi_len],
        ));
    }
    msg.add_ie(typed_ie(|buf| {
        Gtp2RatTypeIe::new(mme_ue.rat_type).encode(buf, 0)
    })?);
    msg.add_ie(uli_ie(mme_ue)?);
    msg.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 0, &[lbi & 0x0F]));
    if let Some(v4) = sess.pgw_s5c_ip.ipv4 {
        msg.add_ie(Gtp2Ie::from_slice(ie_type::IP_ADDRESS, 0, &v4));
    } else if let Some(v6) = sess.pgw_s5c_ip.ipv6 {
        msg.add_ie(Gtp2Ie::from_slice(ie_type::IP_ADDRESS, 0, &v6));
    }
    Ok(msg)
}

/// Build Create Bearer Response (TS 29.274 §7.2.4)
pub fn build_create_bearer_response(
    bearer: &MmeBearer,
    mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    cause_value: GtpCause,
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    log::debug!("Build Create Bearer Response for EBI={}", bearer.ebi);
    let mut msg = new_message(
        message_type::CREATE_BEARER_RESPONSE,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );
    msg.add_ie(typed_ie(|buf| {
        Gtp2CauseIe::new(cause_value as u8).encode(buf, 0)
    })?);

    let mut bc = Gtp2BearerContextIe::new();
    bc.set_ebi(bearer.ebi);
    bc.set_cause(&Gtp2CauseIe::new(cause_value as u8));
    if cause_value as u8 == GtpCause::RequestAccepted as u8 {
        if let Some(ft) = enb_s1u_fteid(bearer, f_teid_interface::S1U_ENB_GTP_U) {
            bc.set_fteid(0, &ft);
        }
    }
    msg.add_bearer_context(0, &bc);

    // ULI (C): where the UE is. Encoded by the library rather than by hand — the
    // previous version built the TAI/ECGI BCD nibbles inline in the builder.
    msg.add_ie(uli_ie(mme_ue)?);

    Ok(msg)
}

/// User Location Information carrying TAI and ECGI (TS 29.274 §8.21).
fn uli_ie(mme_ue: &MmeUe) -> S11BuildResult<Gtp2Ie> {
    let mut value = Vec::with_capacity(1 + 5 + 7);
    // Flags: TAI (bit 3) | ECGI (bit 4)
    value.push(0x08 | 0x10);
    value.extend_from_slice(&encode_plmn_bcd(&mme_ue.tai.plmn_id));
    value.extend_from_slice(&mme_ue.tai.tac.to_be_bytes());
    value.extend_from_slice(&encode_plmn_bcd(&mme_ue.e_cgi.plmn_id));
    value.extend_from_slice(&mme_ue.e_cgi.cell_id.to_be_bytes());
    Ok(Gtp2Ie::from_slice(Gtp2IeType::Uli as u8, 0, &value))
}

/// PLMN ID in the 3-octet BCD form GTP-C uses (TS 29.274 §8.21.1).
///
/// `pub(crate)` for #347: the GUTI IE (§8.47, Figure 8.47-1, `29274-j60.txt:29099-29103`)
/// opens with the **same** three octets in the same nibble order, so the N26 builder uses
/// this rather than re-nibbling them. A second copy would be free to disagree about the
/// two-digit-MNC `1111` filler §8.47 calls out (`29274-j60.txt:29115-29116`), which is
/// invisible to any test using a three-digit MNC.
pub(crate) fn encode_plmn_bcd(plmn: &crate::context::PlmnId) -> [u8; 3] {
    [
        (plmn.mcc2 << 4) | plmn.mcc1,
        (plmn.mnc3 << 4) | plmn.mcc3,
        (plmn.mnc2 << 4) | plmn.mnc1,
    ]
}

/// The inverse of [`encode_plmn_bcd`] (#347).
///
/// The N26 leg **parses** a GUTI as well as building one: TS 23.003 §2.10.2.1.3 has the old
/// AMF reverse-map the GUTI an MME sends, so `n26_build::parse_guti_ie` has to recover the
/// PLMN to resolve a UE context. Written directly beside its inverse so the two nibble
/// layouts are one edit apart and cannot drift — `plmn_bcd_round_trips_including_the_two_digit_mnc`
/// holds them together.
pub(crate) fn decode_plmn_bcd(octets: &[u8]) -> Option<crate::context::PlmnId> {
    if octets.len() < 3 {
        return None;
    }
    Some(crate::context::PlmnId {
        mcc1: octets[0] & 0x0F,
        mcc2: octets[0] >> 4,
        mcc3: octets[1] & 0x0F,
        mnc1: octets[2] & 0x0F,
        mnc2: octets[2] >> 4,
        mnc3: octets[1] >> 4,
    })
}

/// Build Update Bearer Response (TS 29.274 §7.2.16)
pub fn build_update_bearer_response(
    bearer: &MmeBearer,
    _mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    cause_value: GtpCause,
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    log::debug!("Build Update Bearer Response for EBI={}", bearer.ebi);
    let mut msg = new_message(
        message_type::UPDATE_BEARER_RESPONSE,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );
    msg.add_ie(typed_ie(|buf| {
        Gtp2CauseIe::new(cause_value as u8).encode(buf, 0)
    })?);
    let mut bc = Gtp2BearerContextIe::new();
    bc.set_ebi(bearer.ebi);
    bc.set_cause(&Gtp2CauseIe::new(cause_value as u8));
    msg.add_bearer_context(0, &bc);
    Ok(msg)
}

/// Build Delete Bearer Response (TS 29.274 §7.2.10)
pub fn build_delete_bearer_response(
    bearer: &MmeBearer,
    _mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    cause_value: GtpCause,
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    log::debug!("Build Delete Bearer Response for EBI={}", bearer.ebi);
    let mut msg = new_message(
        message_type::DELETE_BEARER_RESPONSE,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );
    msg.add_ie(typed_ie(|buf| {
        Gtp2CauseIe::new(cause_value as u8).encode(buf, 0)
    })?);
    let mut bc = Gtp2BearerContextIe::new();
    bc.set_ebi(bearer.ebi);
    bc.set_cause(&Gtp2CauseIe::new(cause_value as u8));
    msg.add_bearer_context(0, &bc);
    Ok(msg)
}

/// Build a Delete Bearer Response (TS 29.274 §7.2.10.2) accepting the deletion
/// of `ebis` -- one Bearer Context per EBI, each with its own Cause -- for the
/// Delete Bearer Request at `sequence_number` (#584).
pub fn build_delete_bearer_response_for_ebis(
    sgw_s11_teid: u32,
    ebis: &[u8],
    cause_value: GtpCause,
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    let mut msg = new_message(
        message_type::DELETE_BEARER_RESPONSE,
        sgw_s11_teid,
        sequence_number,
    );
    msg.add_ie(typed_ie(|buf| {
        Gtp2CauseIe::new(cause_value as u8).encode(buf, 0)
    })?);
    for ebi in ebis {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(*ebi);
        bc.set_cause(&Gtp2CauseIe::new(cause_value as u8));
        msg.add_bearer_context(0, &bc);
    }
    Ok(msg)
}

/// Create Bearer Response refusing every bearer of the request (#641 stop-gap,
/// TS 29.274 §7.2.4, Table 7.2.4-1): the message Cause, and one Bearer Context
/// per bearer of the request (Bearer Contexts are mandatory and "all the bearer
/// contexts included in the corresponding Create Bearer Request shall be
/// included"), each with its EBI and the same Cause.
pub fn build_create_bearer_refusal(
    sgw_s11_teid: u32,
    ebis: &[u8],
    cause_value: GtpCause,
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    let mut msg = new_message(
        message_type::CREATE_BEARER_RESPONSE,
        sgw_s11_teid,
        sequence_number,
    );
    msg.add_ie(typed_ie(|buf| {
        Gtp2CauseIe::new(cause_value as u8).encode(buf, 0)
    })?);
    for ebi in ebis {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(*ebi);
        bc.set_cause(&Gtp2CauseIe::new(cause_value as u8));
        msg.add_bearer_context(0, &bc);
    }
    Ok(msg)
}

/// Delete Bearer Response for a request that named a PDN connection by its
/// Linked EPS Bearer ID (TS 29.274 Table 7.2.10.2-1: the LBI is included "if
/// the request contained" it, and Bearer Contexts only for EBIs it named) (#688).
pub fn build_delete_bearer_response_for_lbi(
    sgw_s11_teid: u32,
    lbi: u8,
    cause_value: GtpCause,
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    let mut msg = new_message(
        message_type::DELETE_BEARER_RESPONSE,
        sgw_s11_teid,
        sequence_number,
    );
    msg.add_ie(typed_ie(|buf| {
        Gtp2CauseIe::new(cause_value as u8).encode(buf, 0)
    })?);
    msg.add_ie(nextgcore_gtp::v2::Gtp2EbiIe::new(lbi).to_ie(0));
    Ok(msg)
}

/// Build Release Access Bearers Request (TS 29.274 §7.2.21)
pub fn build_release_access_bearers_request(teid: u32, sequence_number: u32) -> Gtp2Message {
    new_message(
        message_type::RELEASE_ACCESS_BEARERS_REQUEST,
        teid,
        sequence_number,
    )
}

/// Build a Downlink Data Notification Failure Indication (TS 29.274 §7.2.11.3,
/// #956): the UE did not answer the paging a Downlink Data Notification started.
/// Cause (M); Originating Node and IMSI are conditional on ISR and restoration,
/// neither of which this MME runs, so they are absent.
pub fn build_downlink_data_notification_failure_indication(
    sgw_s11_teid: u32,
    sequence_number: u32,
    cause: GtpCause,
) -> S11BuildResult<Gtp2Message> {
    let mut msg = new_message(
        message_type::DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION,
        sgw_s11_teid,
        sequence_number,
    );
    msg.add_ie(typed_ie(|buf| {
        Gtp2CauseIe::new(cause as u8).encode(buf, 0)
    })?);
    Ok(msg)
}

/// Build Downlink Data Notification Acknowledge (TS 29.274 §7.2.11)
pub fn build_downlink_data_notification_ack(
    teid: u32,
    sequence_number: u32,
    cause: GtpCause,
) -> S11BuildResult<Gtp2Message> {
    let mut msg = new_message(
        message_type::DOWNLINK_DATA_NOTIFICATION_ACK,
        teid,
        sequence_number,
    );
    msg.add_ie(typed_ie(|buf| {
        Gtp2CauseIe::new(cause as u8).encode(buf, 0)
    })?);
    Ok(msg)
}

/// Build Create Indirect Data Forwarding Tunnel Request (TS 29.274 §7.2.18)
pub fn build_create_indirect_data_forwarding_tunnel_request(
    _mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    bearers: &[&MmeBearer],
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    log::debug!(
        "Build Create Indirect Data Forwarding Tunnel Request with {} bearers",
        bearers.len()
    );
    let mut msg = new_message(
        message_type::CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );
    // #48: this used to send the bearer's SERVING S1-U endpoint
    // (`bearer.enb_s1u_teid`, the SOURCE eNB's) under the wrong interface type, which
    // asked the SGW to forward downlink data to the eNB the UE is leaving. TS 29.274
    // Table 7.2.18-2 wants the TARGET eNodeB's DL data-forwarding F-TEID at instance
    // 0 and its UL one at instance 4 -- the endpoints the target admits in the
    // Handover Request Acknowledge, which `handle_handover_request_acknowledge` now
    // records on `enb_dl_*` / `enb_ul_*`.
    for bearer in bearers {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(bearer.ebi);
        if let Some(ft) = forwarding_fteid(
            f_teid_interface::ENB_GTP_U_DL_DATA_FORWARDING,
            bearer.enb_dl_teid,
            &bearer.enb_dl_ip,
        ) {
            bc.set_fteid(0, &ft);
        }
        if let Some(ft) = forwarding_fteid(
            f_teid_interface::ENB_GTP_U_UL_DATA_FORWARDING,
            bearer.enb_ul_teid,
            &bearer.enb_ul_ip,
        ) {
            bc.set_fteid(4, &ft);
        }
        msg.add_bearer_context(0, &bc);
    }
    Ok(msg)
}

/// Build Bearer Resource Command (TS 29.274 §7.2.5)
#[allow(clippy::too_many_arguments)]
pub fn build_bearer_resource_command(
    _bearer: &MmeBearer,
    _mme_ue: &MmeUe,
    sgw_ue: &SgwUe,
    linked_bearer_ebi: u8,
    pti: u8,
    tad: &[u8],
    qos: Option<&Gtp2BearerQos>,
    sequence_number: u32,
) -> S11BuildResult<Gtp2Message> {
    log::debug!("Build Bearer Resource Command, linked EBI={linked_bearer_ebi}");
    let mut msg = new_message(
        message_type::BEARER_RESOURCE_COMMAND,
        sgw_ue.sgw_s11_teid,
        sequence_number,
    );

    // Linked EPS Bearer ID (M)
    msg.add_ie(Gtp2Ie::from_slice(
        Gtp2IeType::Ebi as u8,
        0,
        &[linked_bearer_ebi],
    ));
    // Procedure Transaction Id (M)
    msg.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Pti as u8, 0, &[pti]));
    // Traffic Aggregate Description (C)
    if !tad.is_empty() {
        msg.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Tad as u8, 0, tad));
    }
    // Flow QoS (C, TS 29.274 §8.16): QCI then the four bit rates, 21 octets. It
    // is the Bearer QoS layout WITHOUT the leading ARP octet, so the library's
    // Bearer QoS is encoded and its first octet dropped (#1186 review: it was
    // sent whole, so the PGW read the ARP octet as the QCI).
    if let Some(q) = qos {
        let flow = Gtp2BearerQosIe::new(q.qci, q.ul_mbr, q.dl_mbr, q.ul_gbr, q.dl_gbr);
        let encoded = typed_ie(|buf| flow.encode(buf, 0))?;
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::FlowQos as u8,
            0,
            &encoded.value[1..],
        ));
    }

    Ok(msg)
}

// ============================================================================
// Tests
// ============================================================================

/// Encode APN to DNS wire format (label-length prefix per TS 23.003)
fn encode_apn_dns(apn: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for label in apn.split('.') {
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result
}

#[cfg(test)]
mod tests {

    /// #1186 review, TS 29.274 §8.15: the Bearer QoS ARP octet carries the
    /// context's GTP PCI/PVI as they are (1 = disabled): PCI 1 / PVI 0 sets bit 7
    /// (0x40) and clears bit 1, and the reverse.
    #[test]
    fn bearer_qos_arp_bits_are_the_gtp_coding() {
        for (pci, pvi, arp_bits) in [(1u8, 0u8, 0x40u8), (0, 1, 0x01)] {
            let mut bearer = crate::context::MmeBearer::default();
            bearer.qos.qci = 9;
            bearer.qos.arp.priority_level = 8;
            bearer.qos.arp.pre_emption_capability = pci;
            bearer.qos.arp.pre_emption_vulnerability = pvi;
            let ie = super::typed_ie(|buf| super::bearer_qos(&bearer).encode(buf, 0)).unwrap();
            assert_eq!(ie.value[0] & 0x41, arp_bits, "PCI {pci} PVI {pvi}");
            assert_eq!((ie.value[0] >> 2) & 0x0f, 8, "priority level");
        }
    }

    /// #1186 review, TS 29.274 §8.16: the Bearer Resource Command's Flow QoS is
    /// QCI then the four rates (21 octets), with no ARP octet.
    #[test]
    fn flow_qos_has_no_arp_octet() {
        let qos = super::Gtp2BearerQos {
            qci: 3,
            priority_level: 8,
            ul_mbr: 64,
            dl_mbr: 128,
            ..Default::default()
        };
        let msg = super::build_bearer_resource_command(
            &crate::context::MmeBearer::default(),
            &crate::context::MmeUe::default(),
            &crate::context::SgwUe::default(),
            5,
            1,
            &[],
            Some(&qos),
            0x1186,
        )
        .unwrap();
        let flow = msg
            .get_ie(nextgcore_gtp::v2::Gtp2IeType::FlowQos as u8, 0)
            .expect("a Flow QoS");
        assert_eq!(flow.value.len(), 21, "QCI and four 5-octet rates");
        assert_eq!(flow.value[0], 3, "octet 5 is the QCI");
        assert_eq!(&flow.value[1..6], &[0, 0, 0, 0, 64], "UL MBR");
        assert_eq!(&flow.value[6..11], &[0, 0, 0, 0, 128], "DL MBR");
    }

    /// #48: the F-TEID interface types are wire values from TS 29.274 §8.22, read from
    /// `6g_docs/specs/29274-j60.txt`, and two of them were WRONG while their only user
    /// had no caller. A hand-maintained wire table cannot be kept correct by review, so
    /// the numbers are asserted as literals against the spec clause -- the same guard
    /// #321 added after `smfd` shipped S-NSSAI under IE 250.
    #[test]
    fn f_teid_interface_types_match_ts29274_clause_8_22() {
        use super::f_teid_interface as iface;
        assert_eq!(iface::S1U_ENB_GTP_U, 0, "0: S1-U eNodeB GTP-U interface");
        assert_eq!(iface::S11_MME_GTP_C, 10, "10: S11 MME GTP-C interface");
        assert_eq!(
            iface::ENB_GTP_U_DL_DATA_FORWARDING,
            19,
            "19: eNodeB/gNodeB GTP-U interface for DL data forwarding (was 4, which is \
             S5/S8 SGW GTP-U)"
        );
        assert_eq!(
            iface::ENB_GTP_U_UL_DATA_FORWARDING,
            20,
            "20: eNodeB GTP-U interface for UL data forwarding"
        );
        assert_eq!(
            iface::SGW_GTP_U_DL_DATA_FORWARDING,
            23,
            "23: SGW/UPF GTP-U interface for DL data forwarding (Table 7.2.19-2 NOTE 3)"
        );
        assert_eq!(
            iface::SGW_GTP_U_UL_DATA_FORWARDING,
            28,
            "28: SGW GTP-U interface for UL data forwarding (Table 7.2.19-2 NOTE 4)"
        );
    }
    use super::*;

    #[test]
    fn test_gtp_cause_from_u8() {
        assert_eq!(GtpCause::from_wire(16), GtpCause::RequestAccepted);
        assert_eq!(GtpCause::from_wire(64), GtpCause::ContextNotFound);
        assert_eq!(GtpCause::from_wire(0), GtpCause::UndefinedValue);
    }

    /// #51 criterion 6: every value this enum declares must round-trip, because a
    /// cause collapsed to `Reserved` is a rejection reason the operator cannot see.
    ///
    /// 78 is called out separately below; this covers the twelve the old mapping
    /// dropped as a set, so adding a variant without a mapping fails here.
    #[test]
    fn every_declared_gtp_cause_is_distinguishable() {
        for value in [
            16u8, 17, 18, 19, 64, 65, 66, 67, 68, 69, 70, 72, 73, 74, 75, 76, 77, 78, 94, 103,
        ] {
            let mapped = GtpCause::from_wire(value);
            assert_ne!(
                mapped,
                GtpCause::UndefinedValue,
                "GTP cause {value} collapses to Reserved, so a peer's rejection reason is lost"
            );
            assert_eq!(
                mapped as u8, value,
                "GTP cause {value} maps to a variant with a different value"
            );
        }
    }

    #[test]
    fn release_access_bearers_request_carries_the_allocated_sequence() {
        let msg = build_release_access_bearers_request(0x1234_5678, 0x0042);
        assert_eq!(
            msg.header.message_type,
            message_type::RELEASE_ACCESS_BEARERS_REQUEST
        );
        assert_eq!(msg.header.teid, Some(0x1234_5678));
        assert_eq!(
            msg.header.sequence_number, 0x0042,
            "the sequence number is the transaction layer's, not a literal 0"
        );
    }

    #[test]
    fn downlink_data_notification_ack_echoes_the_sequence_and_carries_a_cause() {
        let msg =
            build_downlink_data_notification_ack(0x1234_5678, 0x99, GtpCause::RequestAccepted)
                .expect("build");
        assert_eq!(
            msg.header.message_type,
            message_type::DOWNLINK_DATA_NOTIFICATION_ACK
        );
        assert_eq!(
            msg.header.sequence_number, 0x99,
            "a triggered message echoes the request's sequence number (TS 29.274 §7.6)"
        );
        let cause = msg
            .get_ie(Gtp2IeType::Cause as u8, 0)
            .expect("the Ack carries a Cause");
        assert_eq!(cause.value.first().copied(), Some(16));
    }

    /// #51 criterion 5, and the defect the hand-rolled encoder had: `[0x00, 0x08,
    /// 0x00]` put the OI bit in the SECOND content octet, so Operation Indication was
    /// never actually set on the wire.
    /// #593, TS 23.401 §5.9.2: the Create Session Request says the MME supports
    /// location change reporting (CRSI), or a PDN GW would never ask for it.
    #[test]
    fn a_create_session_request_announces_change_reporting_support() {
        let mme_ue = MmeUe {
            imsi_len: 1,
            ..Default::default()
        };
        let sgw_ue = SgwUe::default();
        let sess = MmeSess {
            apn: "internet".to_string(),
            ..Default::default()
        };
        let bearer = MmeBearer {
            ebi: 5,
            ..Default::default()
        };
        let msg = build_create_session_request(
            &sess,
            &mme_ue,
            &sgw_ue,
            GtpCreateAction::AttachRequest,
            1,
            &[&bearer],
            "127.0.0.1:2123".parse().unwrap(),
        )
        .expect("build");
        let indication = msg
            .get_ie(Gtp2IeType::Indication as u8, 0)
            .expect("the Indication IE must be present");
        assert!(Gtp2IndicationIe::decode(&indication.value).unwrap().crsi);
    }

    #[test]
    fn delete_session_request_sets_the_operation_indication_flag() {
        let sess = MmeSess::default();
        let mme_ue = MmeUe::default();
        let sgw_ue = SgwUe {
            sgw_s11_teid: 0xabcd,
            ..Default::default()
        };
        let msg = build_delete_session_request(
            &sess,
            &mme_ue,
            &sgw_ue,
            7,
            GtpDeleteAction::NoAction,
            0x11,
        )
        .expect("build");

        let ebi = msg
            .get_ie(Gtp2IeType::Ebi as u8, 0)
            .expect("Linked EPS Bearer ID is mandatory");
        assert_eq!(
            ebi.value.first().copied(),
            Some(7),
            "the LBI is the session's default bearer, not a literal 5"
        );

        let indication = msg
            .get_ie(Gtp2IeType::Indication as u8, 0)
            .expect("the Indication IE must be present");
        let decoded = Gtp2IndicationIe::decode(&indication.value).expect("decode");
        assert!(
            decoded.oi,
            "Operation Indication must be SET, which the hand-rolled octets never were"
        );
    }

    /// #479: GTPv2 and ESM disagree on Non-IP / Ethernet code points.
    #[test]
    fn gtp_pdn_type_maps_esm_values() {
        use crate::esm_build::PdnType;
        assert_eq!(gtp_pdn_type(PdnType::Ipv4), 1);
        assert_eq!(gtp_pdn_type(PdnType::Ipv6), 2);
        assert_eq!(gtp_pdn_type(PdnType::Ipv4v6), 3);
        assert_eq!(gtp_pdn_type(PdnType::NonIp), 4);
        assert_eq!(gtp_pdn_type(PdnType::Ethernet), 5);
    }

    /// #479: a dynamic-allocation PAA per TS 29.274 §8.14 — zero addresses,
    /// /64 for IPv6, none at all for Non-IP.
    #[test]
    fn create_session_paa_requests_dynamic_allocation() {
        let value = |p: Gtp2PaaIe| {
            let mut b = BytesMut::new();
            p.encode_value(&mut b);
            b.to_vec()
        };
        assert_eq!(value(create_session_paa(1)), [1, 0, 0, 0, 0]);
        let mut v6 = vec![2, 64];
        v6.extend([0u8; 16]);
        assert_eq!(value(create_session_paa(2)), v6);
        let mut v46 = vec![3, 64];
        v46.extend([0u8; 20]);
        assert_eq!(value(create_session_paa(3)), v46);
        assert_eq!(value(create_session_paa(4)), [4]);
    }
}
