//! GTP-C Message Handling

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
//!
//! Port of src/smf/s5c-handler.c - GTP-C message handling for SMF
//! Handles GTPv2-C (S5/S8) request and response processing

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::context::{SmfSess, SmfBearer, SmfUe, SmfContext, Qos, IpAddr as SmfIpAddr};
use crate::gtp_build::{
    Gtp2Cause, gtp2_message_type, gtp2_ie_type, gtp2_rat_type,
    BearerQos, FTeid, Paa, pdn_type,
};

// ============================================================================
// GTPv2-C Request Parsing Structures
// ============================================================================

/// Parsed Create Session Request
#[derive(Debug, Clone, Default)]
pub struct CreateSessionRequest {
    /// IMSI
    pub imsi: Vec<u8>,
    /// MSISDN
    pub msisdn: Option<Vec<u8>>,
    /// MEI (Mobile Equipment Identity)
    pub mei: Option<Vec<u8>>,
    /// Serving Network PLMN
    pub serving_network: Option<[u8; 3]>,
    /// RAT Type
    pub rat_type: u8,
    /// Sender F-TEID (SGW S5C)
    pub sender_f_teid: Option<FTeid>,
    /// APN
    pub apn: Option<String>,
    /// Selection Mode
    pub selection_mode: Option<u8>,
    /// PDN Type
    pub pdn_type: u8,
    /// PAA (PDN Address Allocation)
    pub paa: Option<Paa>,
    /// AMBR
    pub ambr: Option<(u32, u32)>, // (uplink, downlink) in kbps
    /// Bearer contexts to be created
    pub bearer_contexts: Vec<BearerContextToCreate>,
    /// PCO
    pub pco: Option<Vec<u8>>,
    /// APCO
    pub apco: Option<Vec<u8>>,
    /// ePCO
    pub epco: Option<Vec<u8>>,
    /// User Location Information
    pub uli: Option<Vec<u8>>,
    /// UE Time Zone
    pub ue_timezone: Option<Vec<u8>>,
    /// Charging Characteristics
    pub charging_characteristics: Option<Vec<u8>>,
}

/// Bearer context to be created
#[derive(Debug, Clone, Default)]
pub struct BearerContextToCreate {
    /// EPS Bearer ID
    pub ebi: u8,
    /// Bearer QoS
    pub bearer_qos: Option<BearerQos>,
    /// S5/S8 U SGW F-TEID
    pub s5u_sgw_f_teid: Option<FTeid>,
    /// S2b U ePDG F-TEID
    pub s2b_u_epdg_f_teid: Option<FTeid>,
}


/// Parsed Delete Session Request
#[derive(Debug, Clone, Default)]
pub struct DeleteSessionRequest {
    /// Linked EPS Bearer ID
    pub linked_ebi: Option<u8>,
    /// PCO
    pub pco: Option<Vec<u8>>,
    /// ePCO
    pub epco: Option<Vec<u8>>,
    /// Indication flags
    pub indication: Option<Vec<u8>>,
}

/// Parsed Modify Bearer Request
#[derive(Debug, Clone, Default)]
pub struct ModifyBearerRequest {
    /// Sender F-TEID (SGW S5C)
    pub sender_f_teid: Option<FTeid>,
    /// Bearer contexts to be modified
    pub bearer_contexts: Vec<BearerContextToModify>,
    /// Indication flags
    pub indication: Option<Vec<u8>>,
    /// User Location Information
    pub uli: Option<Vec<u8>>,
}

/// Bearer context to be modified
#[derive(Debug, Clone, Default)]
pub struct BearerContextToModify {
    /// EPS Bearer ID
    pub ebi: u8,
    /// S4 U SGSN F-TEID (SGW S5U)
    pub s4u_sgsn_f_teid: Option<FTeid>,
}

/// Parsed Create Bearer Response
#[derive(Debug, Clone, Default)]
pub struct CreateBearerResponse {
    /// Cause
    pub cause: Gtp2Cause,
    /// Bearer context
    pub bearer_context: Option<BearerContextCreated>,
}

/// Bearer context created
#[derive(Debug, Clone, Default)]
pub struct BearerContextCreated {
    /// EPS Bearer ID
    pub ebi: u8,
    /// Cause
    pub cause: Gtp2Cause,
    /// S5/S8 U PGW F-TEID
    pub s5u_pgw_f_teid: Option<FTeid>,
    /// S5/S8 U SGW F-TEID
    pub s5u_sgw_f_teid: Option<FTeid>,
    /// S2b U PGW F-TEID
    pub s2b_u_pgw_f_teid: Option<FTeid>,
    /// S2b U ePDG F-TEID
    pub s2b_u_epdg_f_teid: Option<FTeid>,
}

/// Parsed Update Bearer Response
#[derive(Debug, Clone, Default)]
pub struct UpdateBearerResponse {
    /// Cause
    pub cause: Gtp2Cause,
    /// Bearer context
    pub bearer_context: Option<BearerContextUpdated>,
}

/// Bearer context updated
#[derive(Debug, Clone, Default)]
pub struct BearerContextUpdated {
    /// EPS Bearer ID
    pub ebi: u8,
    /// Cause
    pub cause: Gtp2Cause,
}

/// Parsed Delete Bearer Response
#[derive(Debug, Clone, Default)]
pub struct DeleteBearerResponse {
    /// Cause
    pub cause: Gtp2Cause,
    /// Linked EPS Bearer ID (for default bearer)
    pub linked_ebi: Option<u8>,
    /// Bearer context (for dedicated bearer)
    pub bearer_context: Option<BearerContextDeleted>,
}

/// Bearer context deleted
#[derive(Debug, Clone, Default)]
pub struct BearerContextDeleted {
    /// EPS Bearer ID
    pub ebi: u8,
    /// Cause
    pub cause: Gtp2Cause,
}

/// Parsed Bearer Resource Command
#[derive(Debug, Clone, Default)]
pub struct BearerResourceCommand {
    /// Linked EPS Bearer ID
    pub linked_ebi: u8,
    /// EPS Bearer ID (optional, for dedicated bearer)
    pub ebi: Option<u8>,
    /// PTI (Procedure Transaction ID)
    pub pti: u8,
    /// TAD (Traffic Aggregate Description)
    pub tad: Option<Vec<u8>>,
    /// Flow QoS
    pub flow_qos: Option<FlowQos>,
}

/// Flow QoS parameters
#[derive(Debug, Clone, Default)]
pub struct FlowQos {
    /// QCI
    pub qci: u8,
    /// Maximum Bit Rate Uplink
    pub ul_mbr: u64,
    /// Maximum Bit Rate Downlink
    pub dl_mbr: u64,
    /// Guaranteed Bit Rate Uplink
    pub ul_gbr: u64,
    /// Guaranteed Bit Rate Downlink
    pub dl_gbr: u64,
}


// ============================================================================
// Handler Result Types
// ============================================================================

/// Result of handling a Create Session Request
#[derive(Debug)]
pub enum CreateSessionResult {
    /// Request accepted, proceed with PFCP session establishment
    Accepted,
    /// Request rejected with cause
    Rejected(Gtp2Cause),
}

/// Result of handling a Delete Session Request
#[derive(Debug)]
pub enum DeleteSessionResult {
    /// Request accepted, proceed with PFCP session deletion
    Accepted,
    /// Request rejected with cause
    Rejected(Gtp2Cause),
}

/// Result of handling a Modify Bearer Request
#[derive(Debug)]
pub enum ModifyBearerResult {
    /// No modification needed, send response immediately
    NoModification { sgw_relocation: bool },
    /// Modification needed, proceed with PFCP modification
    ModificationNeeded { 
        bearers_to_modify: Vec<u64>,
        end_marker: bool,
        sgw_relocation: bool,
    },
    /// Request rejected with cause
    Rejected(Gtp2Cause),
}

/// Result of handling a Create Bearer Response
#[derive(Debug)]
pub enum CreateBearerResponseResult {
    /// Response accepted, proceed with PFCP modification
    Accepted { bearer_id: u64 },
    /// Response rejected, remove bearer
    Rejected { bearer_id: u64 },
}

/// Result of handling an Update Bearer Response
#[derive(Debug)]
pub enum UpdateBearerResponseResult {
    /// Response accepted
    Accepted { 
        bearer_id: u64,
        tft_update: bool,
        qos_update: bool,
    },
    /// Response rejected
    Rejected { bearer_id: u64 },
}

/// Result of handling a Delete Bearer Response
#[derive(Debug)]
pub enum DeleteBearerResponseResult {
    /// Default bearer deleted, release entire session
    DefaultBearerDeleted,
    /// Dedicated bearer deleted
    DedicatedBearerDeleted { bearer_id: u64 },
    /// Response rejected
    Rejected,
}

/// Result of handling a Bearer Resource Command
#[derive(Debug)]
pub enum BearerResourceResult {
    /// TFT update needed
    TftUpdate { bearer_id: u64, pti: u8 },
    /// QoS update needed
    QosUpdate { bearer_id: u64, pti: u8 },
    /// TFT and QoS update needed
    TftAndQosUpdate { bearer_id: u64, pti: u8 },
    /// TFT delete (deactivate bearer)
    TftDelete { bearer_id: u64, pti: u8 },
    /// Request rejected with cause
    Rejected(Gtp2Cause),
}


// ============================================================================
// Echo Handlers
// ============================================================================

/// Handle Echo Request
/// Port of smf_s5c_handle_echo_request
pub fn handle_echo_request(recovery: u8) -> u8 {
    log::debug!("[PGW] Receiving Echo Request");
    // Return the recovery value to be used in Echo Response
    recovery
}

/// Handle Echo Response
/// Port of smf_s5c_handle_echo_response
pub fn handle_echo_response(_recovery: u8) {
    // Not implemented - just log
    log::debug!("[PGW] Receiving Echo Response");
}

// ============================================================================
// Create Session Request Handler
// ============================================================================

/// Handle Create Session Request
/// Port of smf_s5c_handle_create_session_request
pub fn handle_create_session_request(
    sess: &mut SmfSess,
    smf_ue: &mut SmfUe,
    req: &CreateSessionRequest,
    has_gx_peer: bool,
    has_s6b_peer: bool,
) -> CreateSessionResult {
    log::debug!("Create Session Request");

    // Validate mandatory IEs
    if req.imsi.is_empty() {
        log::error!("No IMSI");
        return CreateSessionResult::Rejected(Gtp2Cause::ConditionalIeMissing);
    }

    if req.sender_f_teid.is_none() {
        log::error!("No TEID");
        return CreateSessionResult::Rejected(Gtp2Cause::MandatoryIeMissing);
    }

    if req.bearer_contexts.is_empty() {
        log::error!("No Bearer");
        return CreateSessionResult::Rejected(Gtp2Cause::MandatoryIeMissing);
    }

    if req.bearer_contexts[0].bearer_qos.is_none() {
        log::error!("No EPS Bearer QoS");
        return CreateSessionResult::Rejected(Gtp2Cause::MandatoryIeMissing);
    }

    if req.paa.is_none() {
        log::error!("No PAA");
        return CreateSessionResult::Rejected(Gtp2Cause::ConditionalIeMissing);
    }

    if req.serving_network.is_none() {
        log::error!("No Serving Network");
        return CreateSessionResult::Rejected(Gtp2Cause::ConditionalIeMissing);
    }

    // Check Gx Diameter peer
    if !has_gx_peer {
        log::error!("No Gx Diameter Peer");
        return CreateSessionResult::Rejected(Gtp2Cause::RemotePeerNotResponding);
    }

    // RAT type specific validation
    match sess.gtp_rat_type {
        gtp2_rat_type::EUTRAN => {
            if req.bearer_contexts[0].s5u_sgw_f_teid.is_none() {
                log::error!("No S5/S8 SGW GTP-U TEID");
                return CreateSessionResult::Rejected(Gtp2Cause::MandatoryIeMissing);
            }
            if req.uli.is_none() {
                log::error!("No UE Location Information");
                return CreateSessionResult::Rejected(Gtp2Cause::MandatoryIeMissing);
            }
        }
        gtp2_rat_type::WLAN => {
            if !has_s6b_peer {
                log::error!("No S6b Diameter Peer");
                return CreateSessionResult::Rejected(Gtp2Cause::RemotePeerNotResponding);
            }
            if req.bearer_contexts[0].s2b_u_epdg_f_teid.is_none() {
                log::error!("No S2b ePDG GTP-U TEID");
                return CreateSessionResult::Rejected(Gtp2Cause::MandatoryIeMissing);
            }
        }
        _ => {
            log::error!("Unknown RAT Type [{}]", req.rat_type);
            return CreateSessionResult::Rejected(Gtp2Cause::MandatoryIeMissing);
        }
    }

    // Set MSISDN
    if let Some(ref msisdn) = req.msisdn {
        smf_ue.msisdn = msisdn.clone();
        smf_ue.msisdn_bcd = buffer_to_bcd(msisdn);
    }

    // Set Selection Mode
    if let Some(selection_mode) = req.selection_mode {
        // Store in session if needed
        let _ = selection_mode;
    }

    // Store UE session type from PAA
    if let Some(ref paa) = req.paa {
        sess.ue_session_type = paa.pdn_type;
    }

    // Set SGW S5C TEID and IP
    if let Some(ref f_teid) = req.sender_f_teid {
        sess.sgw_s5c_teid = f_teid.teid;
        if let Some(addr) = f_teid.ipv4_addr {
            sess.sgw_s5c_ip.ipv4 = Some(addr);
        }
        if let Some(addr) = f_teid.ipv6_addr {
            sess.sgw_s5c_ip.ipv6 = Some(addr);
        }
    }

    log::debug!("    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
        sess.sgw_s5c_teid, sess.smf_n4_teid);

    // Set AMBR
    if let Some((uplink, downlink)) = req.ambr {
        sess.session_ambr.uplink = (uplink as u64) * 1000;
        sess.session_ambr.downlink = (downlink as u64) * 1000;
    }

    // Set session QoS from first bearer
    if let Some(ref bearer_qos) = req.bearer_contexts[0].bearer_qos {
        sess.session_qos.index = bearer_qos.qci;
        sess.session_qos.arp_priority_level = bearer_qos.priority_level;
        sess.session_qos.arp_preempt_cap = bearer_qos.pre_emption_capability;
        sess.session_qos.arp_preempt_vuln = bearer_qos.pre_emption_vulnerability;
    }

    log::info!("UE IMSI[{}] APN[{}]",
        smf_ue.imsi_bcd,
        sess.session_name.as_deref().unwrap_or(""));

    CreateSessionResult::Accepted
}

/// Convert binary buffer to BCD string
fn buffer_to_bcd(buf: &[u8]) -> String {
    let mut result = String::new();
    for byte in buf {
        let low = byte & 0x0f;
        let high = (byte >> 4) & 0x0f;
        if low < 10 {
            result.push((b'0' + low) as char);
        }
        if high < 10 {
            result.push((b'0' + high) as char);
        }
    }
    result
}


// ============================================================================
// Delete Session Request Handler
// ============================================================================

/// Handle Delete Session Request
/// Port of smf_s5c_handle_delete_session_request
pub fn handle_delete_session_request(
    sess: &SmfSess,
    req: &DeleteSessionRequest,
    has_gx_peer: bool,
    has_s6b_peer: bool,
) -> DeleteSessionResult {
    log::debug!("Delete Session Request");

    // Check Gx Diameter peer
    if !has_gx_peer {
        log::error!("No Gx Diameter Peer");
        return DeleteSessionResult::Rejected(Gtp2Cause::RemotePeerNotResponding);
    }

    // Check S6b for WLAN
    if sess.gtp_rat_type == gtp2_rat_type::WLAN && !has_s6b_peer {
        log::error!("No S6b Diameter Peer");
        return DeleteSessionResult::Rejected(Gtp2Cause::RemotePeerNotResponding);
    }

    log::debug!("    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
        sess.sgw_s5c_teid, sess.smf_n4_teid);

    DeleteSessionResult::Accepted
}

// ============================================================================
// Modify Bearer Request Handler
// ============================================================================

/// Handle Modify Bearer Request
/// Port of smf_s5c_handle_modify_bearer_request
pub fn handle_modify_bearer_request(
    sess: &mut SmfSess,
    bearers: &mut [SmfBearer],
    req: &ModifyBearerRequest,
) -> ModifyBearerResult {
    log::debug!("Modify Bearer Request");

    // Update SGW S5C TEID if present
    let sgw_relocation = if let Some(ref f_teid) = req.sender_f_teid {
        sess.sgw_s5c_teid = f_teid.teid;
        if let Some(addr) = f_teid.ipv4_addr {
            sess.sgw_s5c_ip.ipv4 = Some(addr);
        }
        if let Some(addr) = f_teid.ipv6_addr {
            sess.sgw_s5c_ip.ipv6 = Some(addr);
        }
        log::debug!("    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
            sess.sgw_s5c_teid, sess.smf_n4_teid);
        true
    } else {
        false
    };

    // Check bearer contexts to modify
    let mut bearers_to_modify = Vec::new();
    let mut end_marker = false;

    for bc in &req.bearer_contexts {
        // Find bearer by EBI
        if let Some(bearer) = bearers.iter_mut().find(|b| b.ebi == bc.ebi) {
            if let Some(ref f_teid) = bc.s4u_sgsn_f_teid {
                // Check if SGW S5U IP changed (handover)
                let old_ip = bearer.sgw_s5u_ip.clone();
                let new_teid = f_teid.teid;
                
                bearer.sgw_s5u_teid = new_teid;
                if let Some(addr) = f_teid.ipv4_addr {
                    // Check if IP changed
                    if old_ip.ipv4.is_some() && old_ip.ipv4 != Some(addr) {
                        end_marker = true;
                    }
                    bearer.sgw_s5u_ip.ipv4 = Some(addr);
                }
                if let Some(addr) = f_teid.ipv6_addr {
                    if old_ip.ipv6.is_some() && old_ip.ipv6 != Some(addr) {
                        end_marker = true;
                    }
                    bearer.sgw_s5u_ip.ipv6 = Some(addr);
                }

                bearers_to_modify.push(bearer.id);

                log::debug!("    SGW_S5U_TEID[0x{:x}] PGW_S5U_TEID[0x{:x}]",
                    bearer.sgw_s5u_teid, bearer.pgw_s5u_teid);
            }
        } else {
            log::error!("No Bearer Context for EBI[{}]", bc.ebi);
        }
    }

    if bearers_to_modify.is_empty() {
        // No modification needed
        ModifyBearerResult::NoModification { sgw_relocation }
    } else {
        ModifyBearerResult::ModificationNeeded {
            bearers_to_modify,
            end_marker,
            sgw_relocation,
        }
    }
}


// ============================================================================
// Create Bearer Response Handler
// ============================================================================

/// Handle Create Bearer Response
/// Port of smf_s5c_handle_create_bearer_response
pub fn handle_create_bearer_response(
    sess: &SmfSess,
    bearer: &mut SmfBearer,
    rsp: &CreateBearerResponse,
) -> CreateBearerResponseResult {
    log::debug!("Create Bearer Response");

    // Check cause
    if rsp.cause != Gtp2Cause::RequestAccepted {
        log::error!("GTP Cause [Value:{:?}]", rsp.cause);
        return CreateBearerResponseResult::Rejected { bearer_id: bearer.id };
    }

    // Check bearer context
    let bc = match &rsp.bearer_context {
        Some(bc) => bc,
        None => {
            log::error!("No Bearer Context");
            return CreateBearerResponseResult::Rejected { bearer_id: bearer.id };
        }
    };

    // Check bearer cause
    if bc.cause != Gtp2Cause::RequestAccepted {
        log::error!("GTP Bearer Cause [Value:{:?}]", bc.cause);
        return CreateBearerResponseResult::Rejected { bearer_id: bearer.id };
    }

    // Get SGW S5U F-TEID
    let sgw_f_teid = match sess.gtp_rat_type {
        gtp2_rat_type::EUTRAN => bc.s5u_sgw_f_teid.as_ref(),
        gtp2_rat_type::WLAN => bc.s2b_u_epdg_f_teid.as_ref(),
        _ => bc.s5u_sgw_f_teid.as_ref(),
    };

    if let Some(f_teid) = sgw_f_teid {
        bearer.ebi = bc.ebi;
        bearer.sgw_s5u_teid = f_teid.teid;
        if let Some(addr) = f_teid.ipv4_addr {
            bearer.sgw_s5u_ip.ipv4 = Some(addr);
        }
        if let Some(addr) = f_teid.ipv6_addr {
            bearer.sgw_s5u_ip.ipv6 = Some(addr);
        }
    } else {
        log::error!("No SGW TEID");
        return CreateBearerResponseResult::Rejected { bearer_id: bearer.id };
    }

    log::debug!("Create Bearer Response : SGW[0x{:x}] --> SMF[0x{:x}]",
        sess.sgw_s5c_teid, sess.smf_n4_teid);

    CreateBearerResponseResult::Accepted { bearer_id: bearer.id }
}

// ============================================================================
// Update Bearer Response Handler
// ============================================================================

/// Handle Update Bearer Response
/// Port of smf_s5c_handle_update_bearer_response
pub fn handle_update_bearer_response(
    sess: &SmfSess,
    bearer_id: u64,
    rsp: &UpdateBearerResponse,
    tft_update: bool,
    qos_update: bool,
) -> UpdateBearerResponseResult {
    log::debug!("Update Bearer Response");

    // Check cause
    if rsp.cause != Gtp2Cause::RequestAccepted {
        log::error!("GTP Cause [Value:{:?}]", rsp.cause);
        return UpdateBearerResponseResult::Rejected { bearer_id };
    }

    // Check bearer context
    if let Some(ref bc) = rsp.bearer_context {
        if bc.cause != Gtp2Cause::RequestAccepted {
            log::error!("GTP Bearer Cause [Value:{:?}]", bc.cause);
            return UpdateBearerResponseResult::Rejected { bearer_id };
        }
    } else {
        log::error!("No Bearer Context");
        return UpdateBearerResponseResult::Rejected { bearer_id };
    }

    log::debug!("    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
        sess.sgw_s5c_teid, sess.smf_n4_teid);

    log::debug!("Update Bearer Response : SGW[0x{:x}] --> SMF[0x{:x}]",
        sess.sgw_s5c_teid, sess.smf_n4_teid);

    UpdateBearerResponseResult::Accepted {
        bearer_id,
        tft_update,
        qos_update,
    }
}

// ============================================================================
// Delete Bearer Response Handler
// ============================================================================

/// Handle Delete Bearer Response
/// Port of smf_s5c_handle_delete_bearer_response
pub fn handle_delete_bearer_response(
    sess: &SmfSess,
    bearer_id: u64,
    rsp: &DeleteBearerResponse,
) -> DeleteBearerResponseResult {
    log::debug!("Delete Bearer Response");

    // Check if this is for default bearer (linked EBI present)
    if rsp.linked_ebi.is_some() {
        // Default bearer deleted - release entire session
        if rsp.cause != Gtp2Cause::RequestAccepted {
            log::error!("GTP Cause [Value:{:?}]", rsp.cause);
        }
        return DeleteBearerResponseResult::DefaultBearerDeleted;
    }

    // Dedicated bearer
    if let Some(ref bc) = rsp.bearer_context {
        if rsp.cause != Gtp2Cause::RequestAccepted {
            log::error!("GTP Cause [Value:{:?}]", rsp.cause);
        }
        if bc.cause != Gtp2Cause::RequestAccepted {
            log::error!("GTP Bearer Cause [Value:{:?}]", bc.cause);
        }
    } else {
        log::error!("No Bearer Context");
    }

    log::debug!("    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
        sess.sgw_s5c_teid, sess.smf_n4_teid);

    log::debug!("Delete Bearer Response : SGW[0x{:x}] --> SMF[0x{:x}]",
        sess.sgw_s5c_teid, sess.smf_n4_teid);

    DeleteBearerResponseResult::DedicatedBearerDeleted { bearer_id }
}


// ============================================================================
// Bearer Resource Command Handler
// ============================================================================

/// TFT Operation codes
pub mod tft_code {
    pub const NO_TFT_OPERATION: u8 = 0;
    pub const CREATE_NEW_TFT: u8 = 1;
    pub const DELETE_EXISTING_TFT: u8 = 2;
    pub const ADD_PACKET_FILTERS_TO_EXISTING_TFT: u8 = 3;
    pub const REPLACE_PACKET_FILTERS_IN_EXISTING: u8 = 4;
    pub const DELETE_PACKET_FILTERS_FROM_EXISTING: u8 = 5;
}

/// Handle Bearer Resource Command
/// Port of smf_s5c_handle_bearer_resource_command
pub fn handle_bearer_resource_command(
    sess: &SmfSess,
    bearer: &mut SmfBearer,
    cmd: &BearerResourceCommand,
    has_packet_filters: bool,
) -> BearerResourceResult {
    log::debug!("Bearer Resource Command");

    // Validate mandatory IEs
    if cmd.tad.is_none() {
        log::error!("No Traffic aggregate description(TAD)");
        return BearerResourceResult::Rejected(Gtp2Cause::MandatoryIeMissing);
    }

    log::debug!("    SGW_S5C_TEID[0x{:x}] PGW_S5C_TEID[0x{:x}]",
        sess.sgw_s5c_teid, sess.smf_n4_teid);

    // Parse TAD to determine operation
    // For now, we'll use a simplified approach
    let tft_update = cmd.tad.is_some();
    let qos_update = cmd.flow_qos.is_some();

    // Update bearer QoS if flow QoS present
    if let Some(ref flow_qos) = cmd.flow_qos {
        bearer.qos.mbr_uplink = flow_qos.ul_mbr;
        bearer.qos.mbr_downlink = flow_qos.dl_mbr;
        bearer.qos.gbr_uplink = flow_qos.ul_gbr;
        bearer.qos.gbr_downlink = flow_qos.dl_gbr;
    }

    // Determine result based on operations
    if !tft_update && !qos_update {
        return BearerResourceResult::Rejected(Gtp2Cause::ServiceNotSupported);
    }

    // Check if this is a TFT delete operation
    // (would need to parse TAD to determine this properly)
    let is_tft_delete = !has_packet_filters && tft_update;

    if is_tft_delete {
        BearerResourceResult::TftDelete {
            bearer_id: bearer.id,
            pti: cmd.pti,
        }
    } else if tft_update && qos_update {
        BearerResourceResult::TftAndQosUpdate {
            bearer_id: bearer.id,
            pti: cmd.pti,
        }
    } else if tft_update {
        BearerResourceResult::TftUpdate {
            bearer_id: bearer.id,
            pti: cmd.pti,
        }
    } else {
        BearerResourceResult::QosUpdate {
            bearer_id: bearer.id,
            pti: cmd.pti,
        }
    }
}

// ============================================================================
// Indication Flags
// ============================================================================

/// Indication flags from GTPv2-C
#[derive(Debug, Clone, Default)]
pub struct IndicationFlags {
    /// Handover Indication
    pub handover_indication: bool,
    /// Direct Forwarding Indication
    pub direct_forwarding_indication: bool,
    /// Operation Indication
    pub operation_indication: bool,
    /// ISRAI (Idle mode Signalling Reduction Activation Indication)
    pub israi: bool,
    /// SGWCI (SGW Change Indication)
    pub sgwci: bool,
    /// SQCI (Subscribed QoS Change Indication)
    pub sqci: bool,
    /// UIMSI (Unauthenticated IMSI)
    pub uimsi: bool,
    /// CFSI (Change F-TEID support Indication)
    pub cfsi: bool,
}

impl IndicationFlags {
    /// Parse indication flags from bytes
    pub fn parse(data: &[u8]) -> Self {
        let mut flags = Self::default();
        
        if !data.is_empty() {
            flags.handover_indication = (data[0] & 0x01) != 0;
            flags.direct_forwarding_indication = (data[0] & 0x02) != 0;
            flags.operation_indication = (data[0] & 0x04) != 0;
            flags.israi = (data[0] & 0x08) != 0;
        }
        
        if data.len() > 1 {
            flags.sgwci = (data[1] & 0x01) != 0;
            flags.sqci = (data[1] & 0x02) != 0;
            flags.uimsi = (data[1] & 0x04) != 0;
            flags.cfsi = (data[1] & 0x08) != 0;
        }
        
        flags
    }
}


// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_to_bcd() {
        // Test IMSI: 001010123456789
        let imsi = vec![0x00, 0x10, 0x10, 0x21, 0x43, 0x65, 0x87, 0x09];
        let bcd = buffer_to_bcd(&imsi);
        assert!(!bcd.is_empty());
    }

    #[test]
    fn test_handle_echo_request() {
        let recovery = handle_echo_request(5);
        assert_eq!(recovery, 5);
    }

    #[test]
    fn test_create_session_request_missing_imsi() {
        let mut sess = SmfSess::default();
        let mut smf_ue = SmfUe::new(1);
        let req = CreateSessionRequest::default();

        let result = handle_create_session_request(
            &mut sess,
            &mut smf_ue,
            &req,
            true,
            true,
        );

        match result {
            CreateSessionResult::Rejected(cause) => {
                assert_eq!(cause, Gtp2Cause::ConditionalIeMissing);
            }
            _ => panic!("Expected rejection"),
        }
    }

    #[test]
    fn test_create_session_request_missing_teid() {
        let mut sess = SmfSess::default();
        let mut smf_ue = SmfUe::new(1);
        let req = CreateSessionRequest {
            imsi: vec![0x00, 0x10, 0x10],
            ..Default::default()
        };

        let result = handle_create_session_request(
            &mut sess,
            &mut smf_ue,
            &req,
            true,
            true,
        );

        match result {
            CreateSessionResult::Rejected(cause) => {
                assert_eq!(cause, Gtp2Cause::MandatoryIeMissing);
            }
            _ => panic!("Expected rejection"),
        }
    }

    #[test]
    fn test_create_session_request_no_gx_peer() {
        let mut sess = SmfSess::default();
        let mut smf_ue = SmfUe::new(1);
        let req = CreateSessionRequest {
            imsi: vec![0x00, 0x10, 0x10],
            sender_f_teid: Some(FTeid::new_ipv4(
                gtp2_f_teid_interface::S5_S8_SGW_GTP_C,
                0x12345678,
                Ipv4Addr::new(192, 168, 1, 1),
            )),
            bearer_contexts: vec![BearerContextToCreate {
                ebi: 5,
                bearer_qos: Some(BearerQos::new(9, 1)),
                s5u_sgw_f_teid: Some(FTeid::new_ipv4(
                    gtp2_f_teid_interface::S5_S8_SGW_GTP_U,
                    0x12345679,
                    Ipv4Addr::new(192, 168, 1, 2),
                )),
                ..Default::default()
            }],
            paa: Some(Paa::ipv4(Ipv4Addr::new(10, 0, 0, 1))),
            serving_network: Some([0x00, 0x01, 0x01]),
            ..Default::default()
        };

        let result = handle_create_session_request(
            &mut sess,
            &mut smf_ue,
            &req,
            false, // No Gx peer
            true,
        );

        match result {
            CreateSessionResult::Rejected(cause) => {
                assert_eq!(cause, Gtp2Cause::RemotePeerNotResponding);
            }
            _ => panic!("Expected rejection"),
        }
    }

    #[test]
    fn test_delete_session_request_no_gx_peer() {
        let sess = SmfSess::default();
        let req = DeleteSessionRequest::default();

        let result = handle_delete_session_request(&sess, &req, false, true);

        match result {
            DeleteSessionResult::Rejected(cause) => {
                assert_eq!(cause, Gtp2Cause::RemotePeerNotResponding);
            }
            _ => panic!("Expected rejection"),
        }
    }

    #[test]
    fn test_delete_session_request_accepted() {
        let sess = SmfSess::default();
        let req = DeleteSessionRequest::default();

        let result = handle_delete_session_request(&sess, &req, true, true);

        match result {
            DeleteSessionResult::Accepted => {}
            _ => panic!("Expected acceptance"),
        }
    }

    #[test]
    fn test_modify_bearer_request_no_modification() {
        let mut sess = SmfSess::default();
        let mut bearers: Vec<SmfBearer> = vec![];
        let req = ModifyBearerRequest::default();

        let result = handle_modify_bearer_request(&mut sess, &mut bearers, &req);

        match result {
            ModifyBearerResult::NoModification { sgw_relocation } => {
                assert!(!sgw_relocation);
            }
            _ => panic!("Expected no modification"),
        }
    }

    #[test]
    fn test_modify_bearer_request_sgw_relocation() {
        let mut sess = SmfSess::default();
        let mut bearers: Vec<SmfBearer> = vec![];
        let req = ModifyBearerRequest {
            sender_f_teid: Some(FTeid::new_ipv4(
                gtp2_f_teid_interface::S5_S8_SGW_GTP_C,
                0x12345678,
                Ipv4Addr::new(192, 168, 1, 1),
            )),
            ..Default::default()
        };

        let result = handle_modify_bearer_request(&mut sess, &mut bearers, &req);

        match result {
            ModifyBearerResult::NoModification { sgw_relocation } => {
                assert!(sgw_relocation);
                assert_eq!(sess.sgw_s5c_teid, 0x12345678);
            }
            _ => panic!("Expected no modification with SGW relocation"),
        }
    }

    #[test]
    fn test_create_bearer_response_rejected() {
        let sess = SmfSess::default();
        let mut bearer = SmfBearer::new(1, 1);
        let rsp = CreateBearerResponse {
            cause: Gtp2Cause::ContextNotFound,
            bearer_context: None,
        };

        let result = handle_create_bearer_response(&sess, &mut bearer, &rsp);

        match result {
            CreateBearerResponseResult::Rejected { bearer_id } => {
                assert_eq!(bearer_id, 1);
            }
            _ => panic!("Expected rejection"),
        }
    }

    #[test]
    fn test_update_bearer_response_accepted() {
        let sess = SmfSess::default();
        let rsp = UpdateBearerResponse {
            cause: Gtp2Cause::RequestAccepted,
            bearer_context: Some(BearerContextUpdated {
                ebi: 5,
                cause: Gtp2Cause::RequestAccepted,
            }),
        };

        let result = handle_update_bearer_response(&sess, 1, &rsp, true, false);

        match result {
            UpdateBearerResponseResult::Accepted { bearer_id, tft_update, qos_update } => {
                assert_eq!(bearer_id, 1);
                assert!(tft_update);
                assert!(!qos_update);
            }
            _ => panic!("Expected acceptance"),
        }
    }

    #[test]
    fn test_delete_bearer_response_default_bearer() {
        let sess = SmfSess::default();
        let rsp = DeleteBearerResponse {
            cause: Gtp2Cause::RequestAccepted,
            linked_ebi: Some(5),
            bearer_context: None,
        };

        let result = handle_delete_bearer_response(&sess, 1, &rsp);

        match result {
            DeleteBearerResponseResult::DefaultBearerDeleted => {}
            _ => panic!("Expected default bearer deleted"),
        }
    }

    #[test]
    fn test_delete_bearer_response_dedicated_bearer() {
        let sess = SmfSess::default();
        let rsp = DeleteBearerResponse {
            cause: Gtp2Cause::RequestAccepted,
            linked_ebi: None,
            bearer_context: Some(BearerContextDeleted {
                ebi: 6,
                cause: Gtp2Cause::RequestAccepted,
            }),
        };

        let result = handle_delete_bearer_response(&sess, 1, &rsp);

        match result {
            DeleteBearerResponseResult::DedicatedBearerDeleted { bearer_id } => {
                assert_eq!(bearer_id, 1);
            }
            _ => panic!("Expected dedicated bearer deleted"),
        }
    }

    #[test]
    fn test_bearer_resource_command_no_tad() {
        let sess = SmfSess::default();
        let mut bearer = SmfBearer::new(1, 1);
        let cmd = BearerResourceCommand {
            linked_ebi: 5,
            pti: 1,
            ..Default::default()
        };

        let result = handle_bearer_resource_command(&sess, &mut bearer, &cmd, false);

        match result {
            BearerResourceResult::Rejected(cause) => {
                assert_eq!(cause, Gtp2Cause::MandatoryIeMissing);
            }
            _ => panic!("Expected rejection"),
        }
    }

    #[test]
    fn test_indication_flags_parse() {
        let data = vec![0x03, 0x05];
        let flags = IndicationFlags::parse(&data);
        
        assert!(flags.handover_indication);
        assert!(flags.direct_forwarding_indication);
        assert!(!flags.operation_indication);
        assert!(flags.sgwci);
        assert!(!flags.sqci);
        assert!(flags.uimsi);
    }

    #[test]
    fn test_indication_flags_empty() {
        let data: Vec<u8> = vec![];
        let flags = IndicationFlags::parse(&data);
        
        assert!(!flags.handover_indication);
        assert!(!flags.sgwci);
    }

    #[test]
    fn test_flow_qos_default() {
        let qos = FlowQos::default();
        assert_eq!(qos.qci, 0);
        assert_eq!(qos.ul_mbr, 0);
        assert_eq!(qos.dl_mbr, 0);
    }

    use crate::gtp_build::gtp2_f_teid_interface;
}
