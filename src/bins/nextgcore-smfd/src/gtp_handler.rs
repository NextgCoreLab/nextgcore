//! GTP-C Message Handling

//!
//! Port of src/smf/s5c-handler.c - GTP-C message handling for SMF
//! Handles GTPv2-C (S5/S8) request and response processing

use crate::context::{SmfBearer, SmfSess, SmfUe};
use crate::gtp_build::{gtp2_rat_type, BearerQos, FTeid, Gtp2Cause, Paa};

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

    // Store the UE's REQUESTED session type from the PAA, converted into the numbering
    // `session_type` uses.
    //
    // `Paa::pdn_type` is the GTP PDN Type IE (TS 29.274 §8.34: 1=IPv4, 2=IPv6,
    // 3=IPv4v6); `PduSessionType` is the NAS/5G enum, where `Ipv4 == 0`.
    // `build_create_session_response` compares `ue_session_type != session_type as u8` to
    // decide between cause 16 and cause 18 "New PDN type due to network preference", so
    // storing the raw GTP value made EVERY IPv4 session answer 18 — a spurious "the
    // network chose differently" on a request the network honoured exactly.
    //
    // Latent until #52, because nothing called this handler or that builder in
    // production. Found by driving a real Create Session Request into the new socket.
    if let Some(ref paa) = req.paa {
        sess.ue_session_type = match paa.pdn_type {
            2 => crate::context::PduSessionType::Ipv6,
            3 => crate::context::PduSessionType::Ipv4v6,
            _ => crate::context::PduSessionType::Ipv4,
        } as u8;
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

    log::debug!(
        "    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.smf_n4_teid
    );

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

    log::info!(
        "UE IMSI[{}] APN[{}]",
        smf_ue.imsi_bcd,
        sess.session_name.as_deref().unwrap_or("")
    );

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
    _req: &DeleteSessionRequest,
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

    log::debug!(
        "    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.smf_n4_teid
    );

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
        log::debug!(
            "    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
            sess.sgw_s5c_teid,
            sess.smf_n4_teid
        );
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

                log::debug!(
                    "    SGW_S5U_TEID[0x{:x}] PGW_S5U_TEID[0x{:x}]",
                    bearer.sgw_s5u_teid,
                    bearer.pgw_s5u_teid
                );
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
        return CreateBearerResponseResult::Rejected {
            bearer_id: bearer.id,
        };
    }

    // Check bearer context
    let bc = match &rsp.bearer_context {
        Some(bc) => bc,
        None => {
            log::error!("No Bearer Context");
            return CreateBearerResponseResult::Rejected {
                bearer_id: bearer.id,
            };
        }
    };

    // Check bearer cause
    if bc.cause != Gtp2Cause::RequestAccepted {
        log::error!("GTP Bearer Cause [Value:{:?}]", bc.cause);
        return CreateBearerResponseResult::Rejected {
            bearer_id: bearer.id,
        };
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
        return CreateBearerResponseResult::Rejected {
            bearer_id: bearer.id,
        };
    }

    log::debug!(
        "Create Bearer Response : SGW[0x{:x}] --> SMF[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.smf_n4_teid
    );

    CreateBearerResponseResult::Accepted {
        bearer_id: bearer.id,
    }
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

    log::debug!(
        "    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.smf_n4_teid
    );

    log::debug!(
        "Update Bearer Response : SGW[0x{:x}] --> SMF[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.smf_n4_teid
    );

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

    log::debug!(
        "    SGW_S5C_TEID[0x{:x}] SMF_N4_TEID[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.smf_n4_teid
    );

    log::debug!(
        "Delete Bearer Response : SGW[0x{:x}] --> SMF[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.smf_n4_teid
    );

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

    log::debug!(
        "    SGW_S5C_TEID[0x{:x}] PGW_S5C_TEID[0x{:x}]",
        sess.sgw_s5c_teid,
        sess.smf_n4_teid
    );

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
// S5/S8 wire dispatch (#52)
// ============================================================================

use crate::gtp_build::gtp2_message_type;
use nextgcore_gtp::v2::{
    Gtp2AmbrIe, Gtp2ApnIe, Gtp2BearerContextIe, Gtp2FTeidIe, Gtp2IeType, Gtp2Message, Gtp2PaaIe,
};

/// Decode a Create Session Request off the wire into this module's own struct.
///
/// The IEs are decoded by the shared, round-trip-tested library and mapped onto
/// [`CreateSessionRequest`], which had no parser at all before #52 — it was
/// constructed only by tests, which is why `handle_create_session_request` had no
/// production caller.
///
/// Mandatory-IE absence is reported as the cause TS 29.274 §7.7 gives for it rather
/// than defaulted, because a request missing the Sender F-TEID or the Bearer Context
/// is one the PGW cannot answer usefully.
fn parse_create_session_request(msg: &Gtp2Message) -> Result<CreateSessionRequest, Gtp2Cause> {
    let mut req = CreateSessionRequest::default();

    let imsi = msg
        .get_ie(Gtp2IeType::Imsi as u8, 0)
        .ok_or(Gtp2Cause::MandatoryIeMissing)?;
    req.imsi = imsi.value.to_vec();

    req.msisdn = msg
        .get_ie(Gtp2IeType::Msisdn as u8, 0)
        .map(|ie| ie.value.to_vec());
    req.mei = msg
        .get_ie(Gtp2IeType::Mei as u8, 0)
        .map(|ie| ie.value.to_vec());
    req.serving_network = msg
        .get_ie(Gtp2IeType::ServingNetwork as u8, 0)
        .and_then(|ie| ie.value.get(..3).map(|v| [v[0], v[1], v[2]]));

    req.rat_type = msg
        .get_ie(Gtp2IeType::RatType as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .ok_or(Gtp2Cause::MandatoryIeMissing)?;

    let fteid_ie = msg
        .get_ie(Gtp2IeType::FTeid as u8, 0)
        .ok_or(Gtp2Cause::MandatoryIeMissing)?;
    let fteid =
        Gtp2FTeidIe::decode(&fteid_ie.value).map_err(|_| Gtp2Cause::MandatoryIeIncorrect)?;
    req.sender_f_teid = Some(FTeid::new_ipv4(
        fteid.interface_type,
        fteid.teid,
        std::net::Ipv4Addr::from(fteid.ipv4_addr.unwrap_or([0, 0, 0, 0])),
    ));

    let apn_ie = msg
        .get_ie(Gtp2IeType::Apn as u8, 0)
        .ok_or(Gtp2Cause::MandatoryIeMissing)?;
    let apn = Gtp2ApnIe::decode(&apn_ie.value)
        .map_err(|_| Gtp2Cause::MandatoryIeIncorrect)?
        .to_string();
    if apn.is_empty() {
        return Err(Gtp2Cause::MandatoryIeIncorrect);
    }
    req.apn = Some(apn);

    req.selection_mode = msg
        .get_ie(Gtp2IeType::SelectionMode as u8, 0)
        .and_then(|ie| ie.value.first().copied());
    req.pdn_type = msg
        .get_ie(Gtp2IeType::PdnType as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .map(|v| v & 0x07)
        .unwrap_or(1);

    // The PAA the SGW-C sends is a REQUEST, not an assignment: TS 23.401 §5.3.2.1
    // makes address allocation a PGW function. It is parsed so the handler's
    // conditional-IE check passes and then deliberately replaced by the address this
    // node allocates — see `dispatch_s5s8_request`.
    req.paa = msg
        .get_ie(Gtp2IeType::Paa as u8, 0)
        .and_then(|ie| Gtp2PaaIe::decode(&ie.value).ok())
        .map(|paa| {
            Paa::ipv4(std::net::Ipv4Addr::from(
                paa.ipv4_addr.unwrap_or([0, 0, 0, 0]),
            ))
        });

    req.ambr = msg
        .get_ie(Gtp2IeType::Ambr as u8, 0)
        .and_then(|ie| Gtp2AmbrIe::decode(&ie.value).ok())
        .map(|ambr| (ambr.uplink, ambr.downlink));

    let bc_ie = msg
        .get_ie(Gtp2IeType::BearerContext as u8, 0)
        .ok_or(Gtp2Cause::MandatoryIeMissing)?;
    let bc =
        Gtp2BearerContextIe::decode(&bc_ie.value).map_err(|_| Gtp2Cause::MandatoryIeIncorrect)?;
    let ebi = bc.ebi().map_err(|_| Gtp2Cause::MandatoryIeMissing)?;
    let qos = bc
        .bearer_qos()
        .map_err(|_| Gtp2Cause::MandatoryIeIncorrect)?
        .ok_or(Gtp2Cause::MandatoryIeMissing)?;
    // The SGW's S5/S8-U endpoint, at instance 2 (TS 29.274 Table 7.2.1-2). This is the
    // downlink tunnel the PGW-U forwards to.
    let s5u = bc.fteid(2).ok().flatten().map(|ft| {
        FTeid::new_ipv4(
            ft.interface_type,
            ft.teid,
            std::net::Ipv4Addr::from(ft.ipv4_addr.unwrap_or([0, 0, 0, 0])),
        )
    });
    req.bearer_contexts.push(BearerContextToCreate {
        ebi,
        bearer_qos: Some(BearerQos {
            qci: qos.qci,
            priority_level: qos.pl,
            pre_emption_capability: qos.pci,
            pre_emption_vulnerability: qos.pvi,
            ul_mbr: qos.mbr_ul,
            dl_mbr: qos.mbr_dl,
            ul_gbr: qos.gbr_ul,
            dl_gbr: qos.gbr_dl,
        }),
        s5u_sgw_f_teid: s5u,
        s2b_u_epdg_f_teid: None,
    });

    req.pco = msg
        .get_ie(Gtp2IeType::Pco as u8, 0)
        .map(|ie| ie.value.to_vec());
    // Extended PCO (TS 29.274 §8.128, IE type 197). Read by numeric type because the
    // library's `Gtp2IeType` does not model it; the alternative was to drop an IE the
    // SGW-C may legitimately send.
    const EXTENDED_PCO_IE_TYPE: u8 = 197;
    req.epco = msg
        .get_ie(EXTENDED_PCO_IE_TYPE, 0)
        .map(|ie| ie.value.to_vec());
    req.uli = msg
        .get_ie(Gtp2IeType::Uli as u8, 0)
        .map(|ie| ie.value.to_vec());

    Ok(req)
}

/// Route an initial S5/S8 message from the SGW-C.
pub async fn dispatch_s5s8_request(
    server: &crate::gtp_path::S5S8Server,
    msg_type: u8,
    sequence_number: u32,
    raw: &[u8],
    peer: std::net::SocketAddr,
) {
    match msg_type {
        gtp2_message_type::CREATE_SESSION_REQUEST => {
            create_session(server, sequence_number, raw, peer).await
        }
        other => {
            // TS 29.274 §7.7: answer with a cause rather than dropping the request, so
            // the SGW-C's transaction completes instead of expiring on T3.
            log::warn!(
                "S5/S8 message type {other} from {peer} is not implemented by this PGW-C; \
                 answering Service not supported"
            );
            let response = crate::gtp_build::build_error_message(
                other.wrapping_add(1),
                0,
                Gtp2Cause::ServiceNotSupported,
            );
            server.send_response_public(peer, &response).await;
        }
    }
}

/// Route a triggered S5/S8 message that closed one of this node's transactions.
pub fn dispatch_s5s8_response(msg_type: u8, _raw: &[u8], peer: std::net::SocketAddr) {
    log::info!("S5/S8 response type={msg_type} from {peer} correlated");
}

/// Terminate a Create Session Request: allocate the PDN Address, provision the PGW-U
/// over N4, and answer from what actually happened (#52 criterion 2).
///
/// TS 23.401 §5.3.2.1 makes address allocation a PGW function, which is why the PAA the
/// SGW-C sent is discarded rather than echoed — echoing it is precisely what sgwcd used
/// to do, and it meant no node in the deployment ever allocated an address.
async fn create_session(
    server: &crate::gtp_path::S5S8Server,
    sequence_number: u32,
    raw: &[u8],
    peer: std::net::SocketAddr,
) {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let msg = match Gtp2Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
            log::error!("S5/S8 Create Session Request from {peer} undecodable: {e}");
            return;
        }
    };

    let req = match parse_create_session_request(&msg) {
        Ok(req) => req,
        Err(cause) => {
            log::warn!("S5/S8 Create Session Request from {peer} rejected: cause {cause:?}");
            let response = crate::gtp_build::build_error_message(
                gtp2_message_type::CREATE_SESSION_RESPONSE,
                0,
                cause,
            );
            server.send_response_public(peer, &response).await;
            return;
        }
    };

    let apn = req.apn.clone().unwrap_or_default();
    let context = crate::context::smf_self();

    // The PDN Address. Allocated HERE, by the anchor, which is the whole point.
    let Some(ue_ipv4) = context.read().ok().and_then(|ctx| ctx.ipv4_pool.allocate()) else {
        log::error!("S5/S8 Create Session Request from {peer}: the IPv4 pool is exhausted");
        let response = crate::gtp_build::build_error_message(
            gtp2_message_type::CREATE_SESSION_RESPONSE,
            0,
            Gtp2Cause::AllDynamicAddressesAreOccupied,
        );
        server.send_response_public(peer, &response).await;
        return;
    };

    log::info!(
        "S5/S8 Create Session Request from {peer}: APN '{apn}', allocated PDN address {ue_ipv4}"
    );

    // The UE and the session. `sess_add_by_apn` is the EPS entry into the session model
    // — it sets `epc = true` and takes the APN and RAT type — and had no production
    // caller before #52, because nothing terminated S5/S8 to call it.
    //
    // The guard is taken and DROPPED before anything is awaited. A `std::sync` read
    // guard held across an `.await` is not `Send` (so this would not compile inside a
    // spawned task) and would hold the whole SMF context for the duration of an N4
    // round trip, blocking every 5G session on this daemon behind one LTE one.
    let created = match context.read() {
        Ok(ctx) => ctx
            .ue_find_by_imsi(&req.imsi)
            .or_else(|| ctx.ue_add_by_imsi(&req.imsi))
            .and_then(|ue| {
                ctx.sess_add_by_apn(ue.id, &apn, req.rat_type)
                    .map(|sess| (ue, sess))
            }),
        Err(_) => None,
    };
    let Some((mut smf_ue, mut sess)) = created else {
        release_and_reject(
            server,
            &context,
            ue_ipv4,
            peer,
            sequence_number,
            Gtp2Cause::NoResourcesAvailable,
        )
        .await;
        return;
    };

    // The SGW's control-plane TEID is what the response is addressed to, and the PDN
    // address is the one THIS node allocated rather than the one the SGW-C proposed.
    if let Some(ref sender) = req.sender_f_teid {
        sess.sgw_s5c_teid = sender.teid;
    }
    sess.ipv4_addr = Some(ue_ipv4);
    // What this PGW-C actually serves: IPv4 only, because `ipv4_pool` is the only address
    // pool it has. An IPv6 or IPv4v6 request therefore legitimately gets cause 18.
    sess.session_type = crate::context::PduSessionType::Ipv4;
    if let Some((ul_kbps, dl_kbps)) = req.ambr {
        sess.session_ambr.uplink = u64::from(ul_kbps) * 1000;
        sess.session_ambr.downlink = u64::from(dl_kbps) * 1000;
    }

    let bc = &req.bearer_contexts[0];
    let qos = bc.bearer_qos.as_ref().expect("checked by the parser");
    let mut bearer = crate::context::SmfBearer {
        ebi: bc.ebi,
        qos: crate::context::Qos {
            index: qos.qci,
            arp_priority_level: qos.priority_level,
            arp_preempt_cap: qos.pre_emption_capability,
            arp_preempt_vuln: qos.pre_emption_vulnerability,
            mbr_uplink: qos.ul_mbr,
            mbr_downlink: qos.dl_mbr,
            gbr_uplink: qos.ul_gbr,
            gbr_downlink: qos.dl_gbr,
        },
        ..Default::default()
    };
    if let Some(ref s5u) = bc.s5u_sgw_f_teid {
        bearer.sgw_s5u_teid = s5u.teid;
        bearer.sgw_s5u_ip.ipv4 = s5u.ipv4_addr;
    }

    // Validate through the handler this issue exists to make reachable. It has always
    // been correct; it just had `#[cfg(test)]` callers only.
    //
    // `has_policy_source` and not `has_gx_peer`: this daemon has Gx STATE
    // (`gsm_sm.rs`'s CCR/CCA fields) and no Gx transport, and TS 23.401 does not require
    // a PCRF for a PGW to serve a session. `policy::PolicyDecision::config_default_for_dnn`
    // is a policy source, and it is the same one the 5G path falls back to when no PCF is
    // configured (the recorded precedence is PCF, then subscription, then config
    // default). Passing `false` here would make this endpoint answer
    // `RemotePeerNotResponding` to every Create Session Request — a socket that binds and
    // refuses everything.
    match handle_create_session_request(&mut sess, &mut smf_ue, &req, true, true) {
        CreateSessionResult::Rejected(cause) => {
            log::warn!(
                "S5/S8 Create Session Request from {peer} rejected by the handler: {cause:?}"
            );
            release_and_reject(server, &context, ue_ipv4, peer, sequence_number, cause).await;
            return;
        }
        CreateSessionResult::Accepted => {}
    }

    // Provision the PGW-U over N4. TS 23.401 §5.3.2.1 has the PGW answer once the user
    // plane exists, and `RequestAccepted` means the request was actually fulfilled — so
    // the response is built AFTER this, from what the UPF gave.
    let session_qos = crate::SessionQos {
        qfi: bc.ebi,
        ambr_ul_bps: sess.session_ambr.uplink,
        ambr_dl_bps: sess.session_ambr.downlink,
        xr_flow: None,
    };
    let n4 = match crate::pfcp_session_establish(
        sess.smf_n4_seid,
        ue_ipv4.octets(),
        &apn,
        1,
        &session_qos,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!(
                "S5/S8 Create Session Request from {peer}: the PGW-U never provisioned the \
                 session ({e}); answering rather than leaving the SGW-C on T3"
            );
            release_and_reject(
                server,
                &context,
                ue_ipv4,
                peer,
                sequence_number,
                Gtp2Cause::RemotePeerNotResponding,
            )
            .await;
            return;
        }
    };

    // The PGW-U's F-TEID is the uplink endpoint the SGW-U will forward to.
    bearer.pgw_s5u_teid = n4.upf_teid;
    bearer.pgw_s5u_addr = Some(std::net::Ipv4Addr::from(n4.upf_addr));

    let local_ipv4 = match server.local_addr().ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(_) => None,
    };
    let response = crate::gtp_build::build_create_session_response(
        &sess,
        std::slice::from_ref(&bearer),
        local_ipv4,
        None,
        req.pco.as_deref(),
        req.apco.as_deref(),
        req.epco.as_deref(),
        true,
        true,
    );
    // The response echoes the request's sequence number: it is a triggered message.
    let response = with_sequence_number(response, sequence_number);
    server.send_response_public(peer, &response).await;
    log::info!(
        "S5/S8 Create Session Response to {peer}: PAA {ue_ipv4} (allocated here), PGW-U TEID \
         {:#x}, EBI {}",
        n4.upf_teid,
        bearer.ebi
    );
}

/// Release the allocated address and answer with a cause.
///
/// The address is returned to the pool on every failure path: leaking one per refused
/// request exhausts a /16 silently, and the UE never received it.
async fn release_and_reject(
    server: &crate::gtp_path::S5S8Server,
    context: &std::sync::Arc<std::sync::RwLock<crate::context::SmfContext>>,
    ue_ipv4: std::net::Ipv4Addr,
    peer: std::net::SocketAddr,
    sequence_number: u32,
    cause: Gtp2Cause,
) {
    if let Ok(ctx) = context.read() {
        ctx.ipv4_pool.release(ue_ipv4);
    }
    let response =
        crate::gtp_build::build_error_message(gtp2_message_type::CREATE_SESSION_RESPONSE, 0, cause);
    // A refusal is a triggered message too: it must echo the sequence number, or the
    // SGW-C waits out T3 on a rejection it already received.
    let response = with_sequence_number(response, sequence_number);
    server.send_response_public(peer, &response).await;
}

/// Set the sequence number of an encoded GTPv2-C message.
///
/// The builders in `gtp_build` do not take one — they were written when nothing was
/// transmitted — so rather than thread a sequence number through eight signatures for
/// one caller, the message is decoded, its header set, and re-encoded.
///
/// Decode-and-re-encode rather than patching the three octets in place: the offset
/// depends on whether the TEID-present flag is set, and the first version of this
/// function assumed it was and wrote the sequence four octets early. A triggered
/// message that does not echo the request's sequence cannot be correlated by the peer,
/// so getting this silently wrong is exactly the class of defect #52 is about.
fn with_sequence_number(encoded: Vec<u8>, sequence_number: u32) -> Vec<u8> {
    let mut bytes = bytes::Bytes::copy_from_slice(&encoded);
    match Gtp2Message::decode(&mut bytes) {
        Ok(mut msg) => {
            msg.header.sequence_number = sequence_number;
            msg.encode().to_vec()
        }
        Err(e) => {
            log::error!(
                "cannot set the sequence number on a message this node just built ({e}); sending \
                 it unchanged, which the peer will not be able to correlate"
            );
            encoded
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ================================================================
    // #52: the PGW-C role on the wire
    // ================================================================

    /// Build an S5/S8 Create Session Request the way sgwcd's builder does.
    fn s5c_csr(seq: u32, sgw_c_teid: u32, requested_paa: [u8; 4]) -> bytes::BytesMut {
        use nextgcore_gtp::v2::{
            Gtp2ApnIe, Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2FTeidIe, Gtp2Header, Gtp2Message,
            Gtp2PaaIe, Gtp2RatTypeIe,
        };
        let mut msg = Gtp2Message::new(Gtp2Header::new(
            gtp2_message_type::CREATE_SESSION_REQUEST,
            0,
            seq,
        ));
        msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &[0x09, 0x91, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01],
        ));
        let mut buf = bytes::BytesMut::new();
        Gtp2RatTypeIe::new(6).encode(&mut buf, 0);
        let mut b = buf.freeze();
        msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::decode(&mut b).unwrap());
        msg.add_ie(Gtp2FTeidIe::new_ipv4(7, sgw_c_teid, [127, 0, 0, 1]).to_ie(0));
        // Serving Network and ULI: what sgwcd's relay actually sends since #52, and what
        // this handler requires for an E-UTRAN session. The fixture carried neither at
        // first and the handler answered `ConditionalIeMissing` — which is the handler
        // being right, and is how the missing relay in sgwcd was found.
        msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
            Gtp2IeType::ServingNetwork as u8,
            0,
            &[0x99, 0xf9, 0x07],
        ));
        msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
            Gtp2IeType::Uli as u8,
            0,
            &[
                0x18, 0x99, 0xf9, 0x07, 0x00, 0x01, 0x99, 0xf9, 0x07, 0x00, 0x00, 0x00, 0x01,
            ],
        ));
        let mut buf = bytes::BytesMut::new();
        Gtp2ApnIe::from_string("internet").encode(&mut buf, 0);
        let mut b = buf.freeze();
        msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::decode(&mut b).unwrap());
        // The PAA the SGW-C proposes. TS 23.401 §5.3.2.1 makes this a REQUEST, and the
        // test asserts it is NOT what comes back.
        msg.add_ie(Gtp2PaaIe::ipv4(requested_paa).to_ie(0));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(5);
        bc.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));
        bc.set_fteid(2, &Gtp2FTeidIe::new_ipv4(4, 0x0505_0505, [127, 0, 0, 1]));
        msg.add_bearer_context(0, &bc);
        msg.encode()
    }

    /// #52 criterion 2, over the wire: the PGW-C allocates the PDN Address itself.
    ///
    /// The SGW-C's request proposes `10.99.99.99`; the response must carry an address from
    /// this node's own pool instead, because TS 23.401 §5.3.2.1 makes allocation a PGW
    /// function. Before #52 nothing terminated S5/S8 at all, so no address was ever
    /// allocated anywhere in the deployment.
    #[tokio::test]
    async fn a_create_session_request_is_answered_with_an_address_this_node_allocated() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        crate::context::smf_context_init(64, 256, 512);

        let server = crate::gtp_path::S5S8Server::open("127.0.0.1:0".parse().unwrap(), 3)
            .await
            .expect("bind");
        let sgw = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind sgw");

        const REQUESTED: [u8; 4] = [10, 99, 99, 99];
        sgw.send_to(&s5c_csr(0x77, 0x0A0A_0A0A, REQUESTED), server.local_addr())
            .await
            .expect("send csr");

        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), sgw.recv_from(&mut buf))
                .await
                .expect("the PGW-C must answer")
                .expect("recv");
        let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
        let resp = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).expect("decode");

        assert_eq!(
            resp.header.message_type,
            gtp2_message_type::CREATE_SESSION_RESPONSE
        );
        assert_eq!(
            resp.header.sequence_number, 0x77,
            "a triggered message echoes the request's sequence number"
        );
        assert_eq!(
            resp.get_ie(Gtp2IeType::Cause as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(16),
            "the session must be accepted once the PGW-U is provisioned"
        );

        let paa = resp
            .get_ie(Gtp2IeType::Paa as u8, 0)
            .and_then(|ie| Gtp2PaaIe::decode(&ie.value).ok())
            .expect("the response must carry a PAA");
        let allocated = paa.ipv4_addr.expect("an IPv4 address");
        assert_ne!(
            allocated, REQUESTED,
            "the PGW must ALLOCATE an address, not echo the one the SGW-C proposed"
        );
        assert_eq!(
            allocated[0], 10,
            "the address must come from this node's own pool"
        );

        // APN-Restriction is mandatory in the response for an E-UTRAN session.
        assert!(
            resp.get_ie(Gtp2IeType::ApnRestriction as u8, 0).is_some(),
            "TS 29.274 Table 7.2.2-1 makes APN-Restriction present for E-UTRAN"
        );
        server.close();
    }

    /// An Echo Request is answered with this node's Recovery (#52 criterion 3).
    #[tokio::test]
    async fn an_echo_request_is_answered_with_recovery() {
        let server = crate::gtp_path::S5S8Server::open("127.0.0.1:0".parse().unwrap(), 9)
            .await
            .expect("bind");
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let echo = nextgcore_gtp::v2::Gtp2Message::echo_request(5);
        peer.send_to(&echo.encode(), server.local_addr())
            .await
            .expect("send");

        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv_from(&mut buf))
                .await
                .expect("the PGW-C must answer an Echo")
                .expect("recv");
        let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
        let resp = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).expect("decode");
        assert_eq!(resp.header.message_type, gtp2_message_type::ECHO_RESPONSE);
        assert_eq!(resp.header.sequence_number, 5);
        assert_eq!(
            resp.get_ie(Gtp2IeType::Recovery as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(9),
            "Recovery is mandatory in an Echo Response (TS 29.274 §7.1.2)"
        );
        server.close();
    }

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

        let result = handle_create_session_request(&mut sess, &mut smf_ue, &req, true, true);

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

        let result = handle_create_session_request(&mut sess, &mut smf_ue, &req, true, true);

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
            UpdateBearerResponseResult::Accepted {
                bearer_id,
                tft_update,
                qos_update,
            } => {
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
