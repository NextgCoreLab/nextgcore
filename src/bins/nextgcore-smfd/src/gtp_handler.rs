//! GTP-C Message Handling
//!
//! Port of src/smf/s5c-handler.c - GTP-C message handling for SMF
//! Handles GTPv2-C (S5/S8) request and response processing — the **PGW-C role**. Gn/Gp
//! GTPv1-C is `gn_handler.rs`, which has no transport.
//!
//! # Which session model this is written against (#223)
//!
//! `SmfSess`/`SmfUe`/`SmfBearer`, and that is the SMF's session model on **both** accesses,
//! not an EPC-only parallel one. The recorded decision is in
//! `specs/decide-smf-session-model-and-wire-the-eps-procedures.md`; in short:
//!
//! * `SmfSess` is the indexed session store — by id, N4 SEID, TEID, UE address, APN and PSI.
//!   A GTPv2-C message carries a TEID and nothing else, so this is the only model a wire
//!   message can resolve. Produced by `sess_add_by_apn` here (EPS, #52) and by
//!   `sess_add_by_psi` via `main.rs`'s `register_sm_context` (5GC, #78).
//! * `context::PolicyBinding` is the 5GC **policy-association** model, keyed by
//!   `smContextRef`: the PCF `smPolicyId`, the EASDF DNS context, the UDM subscription, the
//!   `GsmFsm`. None of those legs exists on S5/S8, so nothing here touches it.
//!
//! #223 was filed believing this module was dead and `SmfSess` had no producer. That was true
//! when it was written and is not now: `dispatch_s5s8_request` is called from
//! `gtp_path::S5S8Server::handle_datagram`, which the receive loop drives.

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

/// Extended PCO (TS 29.274 §8.128). Read by numeric type because the shared library's
/// `Gtp2IeType` does not model it; the alternative was to drop an IE the SGW-C may
/// legitimately send.
const EXTENDED_PCO_IE_TYPE: u8 = 197;

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
    req.epco = msg
        .get_ie(EXTENDED_PCO_IE_TYPE, 0)
        .map(|ie| ie.value.to_vec());
    req.uli = msg
        .get_ie(Gtp2IeType::Uli as u8, 0)
        .map(|ie| ie.value.to_vec());

    Ok(req)
}

/// Decode a Delete Session Request (TS 29.274 §7.2.3).
///
/// Every IE in this message is optional or conditional — the request is addressed by the
/// TEID in the header, which is what identifies the session — so this cannot fail on a
/// missing IE the way the Create Session parser does.
fn parse_delete_session_request(msg: &Gtp2Message) -> DeleteSessionRequest {
    DeleteSessionRequest {
        // The Linked EPS Bearer ID names the default bearer whose removal takes the whole
        // PDN connection with it (TS 23.401 §5.4.4.1). Carried in the EBI IE, low nibble.
        //
        // **Not independently guarded, and recorded as such rather than claimed.** A revert
        // pass showed that replacing this with `None` breaks no test: every session this
        // PGW-C establishes has exactly one bearer, so `record_eps_release`'s fallback to the
        // stored default bearer arrives at the same identity. The two are distinguishable
        // only for a multi-bearer PDN connection, which nothing in this tree can create yet —
        // no dedicated-bearer procedure is originated (see `bearer_resource`). Reading the IE
        // is still the right behaviour: it is what the SGW-C actually asserts, and the
        // fallback is a fallback.
        linked_ebi: msg
            .get_ie(Gtp2IeType::Ebi as u8, 0)
            .and_then(|ie| ie.value.first().copied())
            .map(|v| v & 0x0f),
        pco: msg
            .get_ie(Gtp2IeType::Pco as u8, 0)
            .map(|ie| ie.value.to_vec()),
        epco: msg
            .get_ie(EXTENDED_PCO_IE_TYPE, 0)
            .map(|ie| ie.value.to_vec()),
        indication: msg
            .get_ie(Gtp2IeType::Indication as u8, 0)
            .map(|ie| ie.value.to_vec()),
    }
}

/// Decode a Modify Bearer Request (TS 29.274 §7.2.7).
///
/// The Sender F-TEID is absent on a plain Modify Bearer and present when the SGW has
/// relocated, which is precisely how [`handle_modify_bearer_request`] distinguishes the two —
/// so its absence is normal and not an error.
fn parse_modify_bearer_request(msg: &Gtp2Message) -> ModifyBearerRequest {
    let mut req = ModifyBearerRequest {
        sender_f_teid: msg
            .get_ie(Gtp2IeType::FTeid as u8, 0)
            .and_then(|ie| Gtp2FTeidIe::decode(&ie.value).ok())
            .map(|ft| {
                FTeid::new_ipv4(
                    ft.interface_type,
                    ft.teid,
                    std::net::Ipv4Addr::from(ft.ipv4_addr.unwrap_or([0, 0, 0, 0])),
                )
            }),
        indication: msg
            .get_ie(Gtp2IeType::Indication as u8, 0)
            .map(|ie| ie.value.to_vec()),
        uli: msg
            .get_ie(Gtp2IeType::Uli as u8, 0)
            .map(|ie| ie.value.to_vec()),
        bearer_contexts: Vec::new(),
    };

    // Bearer Contexts to be modified. The S1-U/S4-U eNodeB F-TEID sits at instance 1 in this
    // message (TS 29.274 Table 7.2.7-2), unlike the Create Session Request's instance 2 — the
    // field name `s4u_sgsn_f_teid` is the pre-existing struct's, and it is the downlink
    // endpoint the PGW-U forwards to either way.
    if let Some(bc_ie) = msg.get_ie(Gtp2IeType::BearerContext as u8, 0) {
        if let Ok(bc) = Gtp2BearerContextIe::decode(&bc_ie.value) {
            if let Ok(ebi) = bc.ebi() {
                req.bearer_contexts.push(BearerContextToModify {
                    ebi,
                    s4u_sgsn_f_teid: bc
                        .fteid(1)
                        .ok()
                        .flatten()
                        .or(bc.fteid(0).ok().flatten())
                        .map(|ft| {
                            FTeid::new_ipv4(
                                ft.interface_type,
                                ft.teid,
                                std::net::Ipv4Addr::from(ft.ipv4_addr.unwrap_or([0, 0, 0, 0])),
                            )
                        }),
                });
            }
        }
    }
    req
}

/// Decode a Bearer Resource Command (TS 29.274 §7.2.5).
///
/// The Linked EPS Bearer ID and the PTI are mandatory: the LBI names the PDN connection and
/// the PTI correlates the answer with the UE's own NAS transaction (TS 23.401 §5.4.5), so a
/// command missing either cannot be answered usefully and is reported as
/// `MandatoryIeMissing` rather than defaulted.
fn parse_bearer_resource_command(msg: &Gtp2Message) -> Result<BearerResourceCommand, Gtp2Cause> {
    let linked_ebi = msg
        .get_ie(Gtp2IeType::Ebi as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .map(|v| v & 0x0f)
        .ok_or(Gtp2Cause::MandatoryIeMissing)?;
    let pti = msg
        .get_ie(Gtp2IeType::Pti as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .ok_or(Gtp2Cause::MandatoryIeMissing)?;

    Ok(BearerResourceCommand {
        linked_ebi,
        // A second EBI at instance 1 names an existing dedicated bearer to modify; its
        // absence means the UE is asking for a new one.
        ebi: msg
            .get_ie(Gtp2IeType::Ebi as u8, 1)
            .and_then(|ie| ie.value.first().copied())
            .map(|v| v & 0x0f),
        pti,
        // The Traffic Aggregate Description is carried, NOT decoded. The handler's own
        // comment says a proper TFT-operation decision "would need to parse TAD", and this
        // change deliberately does not add that decoder — see the spec's ceilings.
        tad: msg
            .get_ie(Gtp2IeType::Tad as u8, 0)
            .map(|ie| ie.value.to_vec()),
        flow_qos: msg
            .get_ie(Gtp2IeType::FlowQos as u8, 0)
            .and_then(|ie| decode_flow_qos(&ie.value)),
    })
}

/// Decode a Flow QoS IE (TS 29.274 §8.16).
///
/// Written here rather than reusing `Gtp2BearerQosIe::decode` because **Flow QoS is not
/// Bearer QoS**: §8.16 is 21 octets — QCI then four 5-octet rates — while §8.15 prefixes an
/// ARP octet and is 22. Decoding one as the other reads the QCI out of the ARP byte and
/// shifts every rate by one octet, which yields plausible-looking garbage rather than an
/// error. The first version of this function did exactly that.
fn decode_flow_qos(value: &[u8]) -> Option<FlowQos> {
    if value.len() < 21 {
        return None;
    }
    // A 5-octet big-endian rate in kbps, at `off`.
    let rate = |off: usize| -> u64 {
        u64::from_be_bytes([
            0,
            0,
            0,
            value[off],
            value[off + 1],
            value[off + 2],
            value[off + 3],
            value[off + 4],
        ])
    };
    Some(FlowQos {
        qci: value[0],
        ul_mbr: rate(1),
        dl_mbr: rate(6),
        ul_gbr: rate(11),
        dl_gbr: rate(16),
    })
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
        // #223: the EPS procedures that make the session model's own handlers reachable.
        // Before this, every one of these fell into the `other` arm below and was answered
        // `ServiceNotSupported` — so a session this PGW-C had established could never be
        // torn down or modified by the SGW-C that established it.
        gtp2_message_type::DELETE_SESSION_REQUEST => {
            delete_session(server, sequence_number, raw, peer).await
        }
        gtp2_message_type::MODIFY_BEARER_REQUEST => {
            modify_bearer(server, sequence_number, raw, peer).await
        }
        gtp2_message_type::BEARER_RESOURCE_COMMAND => {
            bearer_resource(server, sequence_number, raw, peer).await
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
    sess.upf_n4_seid = n4.upf_seid;

    // STORE what this exchange settled (#223).
    //
    // `sess_add_by_apn` returns a CLONE — `context.rs` inserts into `sess_list` and hands
    // back a copy — so every field set above (the SGW's control TEID, the PDN address, the
    // session type, the AMBR) had been landing on a throwaway. The response on the wire was
    // right and the SMF's own state did not know what it had sent: the stored session carried
    // no address, no TEID and no bearer at all.
    //
    // That is why this is fixed HERE rather than filed: the §7.2.3 Delete Session and §7.2.7
    // Modify Bearer procedures below find their session by the TEID the SGW-C addresses them
    // to, and a stored `sgw_s5c_teid` of 0 matches nothing. Without this write-back those
    // procedures would be reachable and inert — the exact defect #223 exists to stop.
    //
    // The bearer is created through `bearer_add` (not a literal) so it gets a context-minted
    // id and is linked into `sess.bearer_ids`; the locally built `bearer` then carries that id
    // forward, because `build_create_session_response` and the modification path both read it.
    if let Ok(ctx) = context.read() {
        match ctx.bearer_add(sess.id) {
            Some(stored) => {
                bearer.id = stored.id;
                bearer.sess_id = stored.sess_id;
                bearer.qfi = bc.ebi;
                ctx.bearer_update(&bearer);
            }
            None => {
                // Not fatal: the session is established and the user plane exists, so refusing
                // it now would tear down a working session over bookkeeping. What is lost is
                // the ability to modify this bearer later, which is logged as such.
                log::error!(
                    "S5/S8 Create Session Request from {peer}: the bearer table is full, so EBI \
                     {} is not stored — this session cannot be modified or released by EBI",
                    bc.ebi
                );
            }
        }
        // After the bearer, so `sess.bearer_ids` (which `bearer_add` appends to under the
        // context's own lock) is not overwritten by this session's stale copy of it.
        if let Some(linked) = ctx.sess_find_by_id(sess.id) {
            sess.bearer_ids = linked.bearer_ids;
        }
        ctx.sess_update(&sess);
    }

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

/// Find the session an initial S5/S8 message is addressed to.
///
/// GTPv2-C addresses a session by the TEID in the header, which the peer learned from the
/// F-TEID this node sent in its Create Session Response — and that F-TEID carries
/// `sess.smf_n4_teid`, which `sess_add_by_*` sets equal to the N4 SEID. So the lookup is by
/// SEID, via `sess_find_by_teid`.
///
/// The TEID is `Option` because TS 29.274 §5.5.1 makes it absent on the path-management
/// messages (Echo, Version Not Supported). A session procedure that arrives without one is
/// malformed and names no session, so `None` propagates rather than being defaulted to 0.
///
/// **What that guard is and is not worth.** It is defence in depth, not a live fix: SEID 0 is
/// never handed out, because `context.rs`'s `n4_seid_generator` starts at 1, so today a
/// defaulted 0 would fail to match anyway. It is written this way because the safety of
/// `unwrap_or(0)` rests on that initial value, and a generator that ever started at 0 would
/// silently turn a malformed request into a teardown of an unrelated subscriber. Stated
/// rather than tested: a test would have to reach into a private field to occupy SEID 0, and
/// asserting on a state the allocator cannot produce would be asserting on the test's own
/// fixture.
///
/// `None` means this PGW-C holds no such session: TS 29.274 §7.7's `ContextNotFound` is the
/// answer, not a drop.
fn session_for_teid(teid: Option<u32>) -> Option<crate::context::SmfSess> {
    let teid = teid?;
    crate::context::smf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.sess_find_by_teid(teid))
}

/// The header TEID rendered for a log line, without inventing a value for its absence.
fn teid_label(teid: Option<u32>) -> String {
    match teid {
        Some(t) => format!("{t:#x}"),
        None => "absent".to_string(),
    }
}

/// Answer a triggered message with a cause, echoing the request's sequence number.
async fn reject(
    server: &crate::gtp_path::S5S8Server,
    response_type: u8,
    teid: u32,
    sequence_number: u32,
    peer: std::net::SocketAddr,
    cause: Gtp2Cause,
) {
    let response = crate::gtp_build::build_error_message(response_type, teid, cause);
    let response = with_sequence_number(response, sequence_number);
    server.send_response_public(peer, &response).await;
}

/// Run the 5GSM release handler over an EPS session and persist what it recorded (#223).
///
/// **This is the live caller `gsm_handler::handle_pdu_session_release_request` did not have.**
/// It validates the session identity and sets `ngap_state = DeleteTriggerUeRequested` — the
/// SMF's own note that a peer asked for this session to go — and the result is written back
/// with `sess_update`, so the mutation lands on the stored session rather than a temporary.
/// `sess` is left carrying it too, so the caller sees the same state the store does.
///
/// **Why the PSI is substituted.** `psi` is 0 on an EPS session (`sess_add_by_apn` sets the
/// APN, not a PSI) and the handler rejects `psi == 0` — correctly, because a 5GSM procedure
/// needs one. The EPS identity of a PDN connection is its default bearer, so the Linked EPS
/// Bearer ID stands in: TS 23.401 §5.4.4.1 makes the LBI the thing that names the PDN
/// connection, exactly as the PSI names the PDU session. Taken from the request when present,
/// falling back to the stored default bearer's EBI, so a request omitting the optional IE
/// still releases. Restored afterwards: the substitution is an argument to the handler, not a
/// change to the session's identity.
///
/// Returns whether the release was recorded. A separate function from [`delete_session`]
/// because that one answers the SGW-C and removes the session in the same breath — within one
/// scheduler tick of this call — so a test cannot observe this mutation through the socket. It
/// can observe it here.
fn record_eps_release(sess: &mut SmfSess, req: &DeleteSessionRequest) -> bool {
    let release_identity = req.linked_ebi.filter(|&ebi| ebi != 0).or_else(|| {
        crate::context::smf_self().read().ok().and_then(|ctx| {
            sess.bearer_ids
                .first()
                .and_then(|&id| ctx.bearer_find_by_id(id))
                .map(|b| b.ebi)
        })
    });
    let Some(identity) = release_identity.filter(|&i| i != 0) else {
        log::warn!(
            "S5/S8 Delete Session for session {}: neither the request nor the stored bearers \
             name an EPS Bearer Identity, so the 5GSM release is not recorded; the teardown \
             proceeds",
            sess.id
        );
        return false;
    };

    let restore_psi = sess.psi;
    sess.psi = identity;
    let release_req = crate::gsm_handler::PduSessionReleaseRequest {
        // The GTPv2 cause is not a 5GSM cause, so none is mapped: the handler only logs it,
        // and inventing a 5GSM value for an EPS teardown would be a fiction.
        gsm_cause: None,
        epco: req.epco.clone(),
        presencemask: 0,
    };
    let outcome = crate::gsm_handler::handle_pdu_session_release_request(sess, &release_req);
    sess.psi = restore_psi;

    match outcome {
        Ok(()) => {
            // Persisted BEFORE the N4 delete, so the recorded release survives a UPF that
            // never answers.
            if let Ok(ctx) = crate::context::smf_self().read() {
                ctx.sess_update(sess);
            }
            true
        }
        Err(cause) => {
            // Not fatal to the teardown. A session the SGW-C has asked to delete is going
            // away whatever the 5GSM validation thinks of its identity; refusing here would
            // strand it at both ends.
            log::warn!(
                "S5/S8 Delete Session for session {}: the 5GSM release handler refused identity \
                 {identity} ({cause:?}); tearing the session down anyway",
                sess.id
            );
            false
        }
    }
}

/// Terminate a Delete Session Request: tear the PDN connection down and answer (#223).
///
/// TS 29.274 §7.2.3 / TS 23.401 §5.4.4.1. Removing the default bearer removes the whole PDN
/// connection, which is why this deletes the session rather than one bearer.
///
/// **This is the live caller criterion 2 asks for.** Two handlers run, and the order is the
/// point: `handle_delete_session_request` is the GTPv2 guard (it refuses when the policy
/// source or, for WLAN, the S6b peer is absent), and
/// `gsm_handler::handle_pdu_session_release_request` is the **session-model** handler that
/// records the release on the session itself. The latter had no production caller at all
/// before this.
///
/// The mutation is observable because the session is re-read from the context, mutated, and
/// `sess_update`d — not built, handed over and dropped, which is the defect #223 was filed
/// about.
async fn delete_session(
    server: &crate::gtp_path::S5S8Server,
    sequence_number: u32,
    raw: &[u8],
    peer: std::net::SocketAddr,
) {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let msg = match Gtp2Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
            log::error!("S5/S8 Delete Session Request from {peer} undecodable: {e}");
            return;
        }
    };
    let teid = msg.header.teid;
    let teid_str = teid_label(teid);
    let req = parse_delete_session_request(&msg);

    let Some(mut sess) = session_for_teid(teid) else {
        log::warn!(
            "S5/S8 Delete Session Request from {peer} for TEID {teid_str}: no such session at this \
             PGW-C"
        );
        reject(
            server,
            gtp2_message_type::DELETE_SESSION_RESPONSE,
            0,
            sequence_number,
            peer,
            Gtp2Cause::ContextNotFound,
        )
        .await;
        return;
    };

    // `has_policy_source` / `has_s6b_peer` are both true for the same reason
    // `create_session` passes them: this deployment's policy source is the config default
    // (the 5G path's own fallback when no PCF is configured), and TS 23.401 does not require
    // a PCRF for a PGW to serve a session. Passing `false` would make this endpoint refuse
    // every teardown and leak the session forever, which is strictly worse than serving it.
    if let DeleteSessionResult::Rejected(cause) =
        handle_delete_session_request(&sess, &req, true, true)
    {
        log::warn!("S5/S8 Delete Session Request from {peer} rejected: {cause:?}");
        reject(
            server,
            gtp2_message_type::DELETE_SESSION_RESPONSE,
            sess.sgw_s5c_teid,
            sequence_number,
            peer,
            cause,
        )
        .await;
        return;
    }

    // Record the release on the session the context holds.
    record_eps_release(&mut sess, &req);

    // The user plane. Best-effort for the same reason the 5GC release path is: a UPF that
    // does not answer must not stop the SMF answering the SGW-C, or the SGW-C retransmits
    // into a session that is already half gone.
    if let Err(e) = crate::pfcp_session_delete(sess.smf_n4_seid, sess.upf_n4_seid).await {
        log::warn!("S5/S8 Delete Session for TEID {teid_str}: the PGW-U teardown failed ({e})");
    }

    let sgw_teid = sess.sgw_s5c_teid;
    // `sess_remove` releases the UE address back into the pool and drops the bearers.
    if let Ok(ctx) = crate::context::smf_self().read() {
        ctx.sess_remove(sess.id);
    }

    let response = crate::gtp_build::build_delete_session_response(
        sgw_teid,
        req.pco.as_deref(),
        req.epco.as_deref(),
    );
    let response = with_sequence_number(response, sequence_number);
    server.send_response_public(peer, &response).await;
    log::info!(
        "S5/S8 Delete Session Response to {peer}: session {} released",
        sess.id
    );
}

/// Terminate a Modify Bearer Request: re-point the downlink and answer (#223).
///
/// TS 29.274 §7.2.7. The SGW sends this after a handover or an idle-to-active transition, and
/// the F-TEID it carries is the new downlink endpoint the PGW-U must forward to.
///
/// **The second live caller criterion 2 asks for.** `handle_modify_bearer_request` decides
/// what changed, and `gsm_handler::handle_pdu_session_modification_request` — the other
/// function the criterion names — records the modification on the session. Both write back.
async fn modify_bearer(
    server: &crate::gtp_path::S5S8Server,
    sequence_number: u32,
    raw: &[u8],
    peer: std::net::SocketAddr,
) {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let msg = match Gtp2Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
            log::error!("S5/S8 Modify Bearer Request from {peer} undecodable: {e}");
            return;
        }
    };
    let teid = msg.header.teid;
    let teid_str = teid_label(teid);
    let req = parse_modify_bearer_request(&msg);

    let Some(mut sess) = session_for_teid(teid) else {
        log::warn!(
            "S5/S8 Modify Bearer Request from {peer} for TEID {teid_str}: no such session at this \
             PGW-C"
        );
        reject(
            server,
            gtp2_message_type::MODIFY_BEARER_RESPONSE,
            0,
            sequence_number,
            peer,
            Gtp2Cause::ContextNotFound,
        )
        .await;
        return;
    };

    // The session's stored bearers, by value: the handlers take `&mut [SmfBearer]` and the
    // context hands out clones, so these are written back explicitly below.
    let mut bearers: Vec<crate::context::SmfBearer> = match crate::context::smf_self().read() {
        Ok(ctx) => sess
            .bearer_ids
            .iter()
            .filter_map(|&id| ctx.bearer_find_by_id(id))
            .collect(),
        Err(_) => Vec::new(),
    };
    if bearers.is_empty() {
        log::warn!(
            "S5/S8 Modify Bearer Request for TEID {teid_str}: the session holds no bearer to \
             modify"
        );
        reject(
            server,
            gtp2_message_type::MODIFY_BEARER_RESPONSE,
            sess.sgw_s5c_teid,
            sequence_number,
            peer,
            Gtp2Cause::ContextNotFound,
        )
        .await;
        return;
    }

    let result = handle_modify_bearer_request(&mut sess, &mut bearers, &req);
    let sgw_relocation = match result {
        ModifyBearerResult::Rejected(cause) => {
            log::warn!("S5/S8 Modify Bearer Request from {peer} rejected: {cause:?}");
            reject(
                server,
                gtp2_message_type::MODIFY_BEARER_RESPONSE,
                sess.sgw_s5c_teid,
                sequence_number,
                peer,
                cause,
            )
            .await;
            return;
        }
        ModifyBearerResult::NoModification { sgw_relocation } => sgw_relocation,
        ModifyBearerResult::ModificationNeeded {
            bearers_to_modify,
            end_marker,
            sgw_relocation,
        } => {
            log::info!(
                "S5/S8 Modify Bearer for TEID {teid_str}: {} bearer(s) to modify, end_marker={}",
                bearers_to_modify.len(),
                end_marker
            );

            // The 5GSM modification handler, over the SAME bearer array the GTPv2 handler
            // just updated, so its decisions land on the bearers that are written back.
            //
            // The request is synthesised from the accepted bearer QoS rather than from a NAS
            // container, because an EPS Modify Bearer carries no 5GSM message — a QoS flow
            // description per modified bearer, which is what the handler consumes, and which
            // is the honest translation of "these bearers changed". The handler requires
            // exactly one entry in `qos_flow_to_modify_list` (TS 24.501 runs one procedure at
            // a time), so it is driven for the bearer the SGW actually re-pointed.
            let modification_scope: Vec<crate::gsm_handler::ParsedQosFlowDescription> = bearers
                .iter()
                .filter(|b| bearers_to_modify.contains(&b.id))
                .take(1)
                .map(|b| crate::gsm_handler::ParsedQosFlowDescription {
                    identifier: b.qfi,
                    code: crate::gsm_build::qos_flow_description_code::MODIFY_NEW_QOS_FLOW_DESCRIPTION,
                    e_bit: true,
                    params: vec![crate::gsm_handler::QosFlowParam {
                        identifier: crate::gsm_handler::qos_flow_param_id::FIVE_QI,
                        five_qi: b.qos.index,
                        bitrate: 0,
                    }],
                })
                .collect();
            if !modification_scope.is_empty() {
                let mod_req = crate::gsm_handler::PduSessionModificationRequest {
                    gsm_cause: None,
                    qos_rules: Vec::new(),
                    qos_flow_descriptions: modification_scope,
                    presencemask: 0,
                };
                match crate::gsm_handler::handle_pdu_session_modification_request(
                    &mut sess,
                    &mod_req,
                    &mut bearers,
                ) {
                    Ok(flags) => log::debug!(
                        "S5/S8 Modify Bearer for TEID {teid_str}: 5GSM modification recorded, \
                         PFCP flags {flags:#x}, {} flow(s) pending",
                        sess.qos_flow_to_modify_list.len()
                    ),
                    Err(cause) => log::warn!(
                        "S5/S8 Modify Bearer for TEID {teid_str}: the 5GSM modification handler \
                         refused the synthesised scope ({cause:?}); the GTPv2 endpoint update \
                         still stands"
                    ),
                }
            }

            // Re-point the PGW-U's downlink FAR at the endpoint the SGW just gave.
            if let Some(bearer) = bearers.iter().find(|b| bearers_to_modify.contains(&b.id)) {
                if let (teid_dl, Some(addr)) = (bearer.sgw_s5u_teid, bearer.sgw_s5u_ip.ipv4) {
                    if let Err(e) = crate::pfcp_session_modify(
                        sess.smf_n4_seid,
                        sess.upf_n4_seid,
                        teid_dl,
                        addr.octets(),
                    )
                    .await
                    {
                        // Answered anyway: the SGW-C's alternative is T3 expiry and a
                        // retransmission into the same failure.
                        log::error!(
                            "S5/S8 Modify Bearer for TEID {teid_str}: the PGW-U downlink was not \
                             re-pointed ({e}); answering so the SGW-C is not left on T3"
                        );
                    }
                }
            }
            sgw_relocation
        }
    };

    // Write back what the handlers changed: the session's SGW control TEID and modification
    // list, and each bearer's downlink endpoint.
    if let Ok(ctx) = crate::context::smf_self().read() {
        ctx.sess_update(&sess);
        for bearer in &bearers {
            ctx.bearer_update(bearer);
        }
    }

    let response =
        crate::gtp_build::build_modify_bearer_response(&sess, &bearers, None, sgw_relocation);
    let response = with_sequence_number(response, sequence_number);
    server.send_response_public(peer, &response).await;
    log::info!(
        "S5/S8 Modify Bearer Response to {peer} for session {} (sgw_relocation={sgw_relocation})",
        sess.id
    );
}

/// Terminate a Bearer Resource Command: the UE-requested bearer resource modification (#223).
///
/// TS 29.274 §7.2.5 / TS 23.401 §5.4.5. The UE asks, via the MME and SGW, for a TFT or QoS
/// change on a bearer; the PGW decides and would normally answer by *initiating* an Update or
/// Create Bearer Request under the command's PTI.
///
/// **What this does and does not do.** The command is parsed, the bearer is found, the
/// decision is taken by `handle_bearer_resource_command` and written back to the stored
/// bearer, and a refusal is answered with a Bearer Resource Failure Indication. It does
/// **not** initiate the follow-on Update Bearer Request: that is a PGW-initiated transaction
/// with its own T3/N3 budget and a Create/Update Bearer Response to correlate, and
/// `dispatch_s5s8_response` currently only logs. Accepting the command and silently running
/// no procedure would be the "correct but inert" shape this issue is about, so the accepted
/// case logs the decision it reached and says it is not yet transmitted.
async fn bearer_resource(
    server: &crate::gtp_path::S5S8Server,
    sequence_number: u32,
    raw: &[u8],
    peer: std::net::SocketAddr,
) {
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let msg = match Gtp2Message::decode(&mut bytes) {
        Ok(m) => m,
        Err(e) => {
            log::error!("S5/S8 Bearer Resource Command from {peer} undecodable: {e}");
            return;
        }
    };
    let teid = msg.header.teid;
    let teid_str = teid_label(teid);

    let cmd = match parse_bearer_resource_command(&msg) {
        Ok(cmd) => cmd,
        Err(cause) => {
            log::warn!("S5/S8 Bearer Resource Command from {peer} rejected: {cause:?}");
            reject(
                server,
                gtp2_message_type::BEARER_RESOURCE_FAILURE_INDICATION,
                0,
                sequence_number,
                peer,
                cause,
            )
            .await;
            return;
        }
    };

    let Some(sess) = session_for_teid(teid) else {
        log::warn!(
            "S5/S8 Bearer Resource Command from {peer} for TEID {teid_str}: no such session at \
             this PGW-C"
        );
        reject(
            server,
            gtp2_message_type::BEARER_RESOURCE_FAILURE_INDICATION,
            0,
            sequence_number,
            peer,
            Gtp2Cause::ContextNotFound,
        )
        .await;
        return;
    };

    // The bearer the command names: the dedicated one when an EBI at instance 1 is present,
    // the PDN connection's default bearer otherwise (TS 23.401 §5.4.5).
    let target_ebi = cmd.ebi.filter(|&e| e != 0).unwrap_or(cmd.linked_ebi);
    let Some(mut bearer) = crate::context::smf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.bearer_find_by_ebi(sess.id, target_ebi))
    else {
        log::warn!(
            "S5/S8 Bearer Resource Command for TEID {teid_str}: the session holds no bearer with \
             EBI {target_ebi}"
        );
        reject(
            server,
            gtp2_message_type::BEARER_RESOURCE_FAILURE_INDICATION,
            sess.sgw_s5c_teid,
            sequence_number,
            peer,
            Gtp2Cause::ContextNotFound,
        )
        .await;
        return;
    };

    // `has_packet_filters` is taken from the presence of a Flow QoS IE, NOT from decoded
    // TAD contents: the handler's own comment records that distinguishing the TFT operations
    // properly needs a TAD decoder, and this change deliberately adds none. So a command
    // carrying only a TAD is treated as a TFT delete, which is what the handler's
    // `!has_packet_filters && tft_update` branch means.
    let has_packet_filters = cmd.flow_qos.is_some();
    match handle_bearer_resource_command(&sess, &mut bearer, &cmd, has_packet_filters) {
        BearerResourceResult::Rejected(cause) => {
            log::warn!("S5/S8 Bearer Resource Command from {peer} rejected: {cause:?}");
            reject(
                server,
                gtp2_message_type::BEARER_RESOURCE_FAILURE_INDICATION,
                sess.sgw_s5c_teid,
                sequence_number,
                peer,
                cause,
            )
            .await;
        }
        accepted => {
            // The handler updated the bearer's QoS from the Flow QoS IE; persist it, so the
            // decision is observable rather than applied to a temporary.
            if let Ok(ctx) = crate::context::smf_self().read() {
                ctx.bearer_update(&bearer);
            }
            log::info!(
                "S5/S8 Bearer Resource Command for TEID {teid_str}, EBI {target_ebi}, PTI {}: \
                 decided {accepted:?}. The bearer's authorized QoS is updated; the follow-on \
                 PGW-initiated Update Bearer Request is NOT transmitted (see #223).",
                cmd.pti
            );
        }
    }
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

    // ================================================================
    // #223: the EPS procedures, and the session model they act on
    // ================================================================

    /// Establish a session over the real wire and return `(server, sgw_socket, session)`.
    ///
    /// Shared by the #223 tests because all three procedures below act on a session that a
    /// Create Session Request established — which is the point: an EPS teardown or
    /// modification is only meaningful against a session this PGW-C actually holds.
    ///
    /// The caller MUST already hold `PROCESS_STATE_TEST_LOCK` and a stand-in UPF.
    async fn establish_over_the_wire(
        restart_counter: u8,
        imsi_last_octet: u8,
        sgw_c_teid: u32,
    ) -> (
        std::sync::Arc<crate::gtp_path::S5S8Server>,
        tokio::net::UdpSocket,
        crate::context::SmfSess,
    ) {
        crate::context::smf_context_init(64, 256, 512);
        let server =
            crate::gtp_path::S5S8Server::open("127.0.0.1:0".parse().unwrap(), restart_counter)
                .await
                .expect("bind");
        let sgw = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind sgw");

        let mut csr = s5c_csr(0x21, sgw_c_teid, [10, 99, 99, 99]);
        // A distinct IMSI per test: the session store is process-global, and two tests
        // sharing an IMSI would share a UE and each other's session list. `s5c_csr`'s IMSI
        // ends `...01`, so the last octet is overwritten. The value must stay distinct from
        // every other #223 test's and from `s5c_csr`'s own default.
        let imsi_pos = csr
            .windows(8)
            .position(|w| w == [0x09, 0x91, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01])
            .expect("the fixture's IMSI is in the encoded request");
        csr[imsi_pos + 7] = imsi_last_octet;

        sgw.send_to(&csr, server.local_addr())
            .await
            .expect("send csr");
        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), sgw.recv_from(&mut buf))
                .await
                .expect("the PGW-C must answer the establishment")
                .expect("recv");
        let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
        let resp = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).expect("decode");
        assert_eq!(
            resp.get_ie(Gtp2IeType::Cause as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(16),
            "the fixture depends on the establishment being accepted"
        );

        // The session as the CONTEXT holds it, found the way the wire finds it: by the TEID
        // this node advertised in the response's F-TEID.
        let advertised = resp
            .get_ie(Gtp2IeType::FTeid as u8, 0)
            .and_then(|ie| nextgcore_gtp::v2::Gtp2FTeidIe::decode(&ie.value).ok())
            .expect("the response carries the PGW's control F-TEID")
            .teid;
        let sess = session_for_teid(Some(advertised))
            .expect("the established session must be findable by the TEID it advertised");
        (server, sgw, sess)
    }

    /// #223: a Create Session Request STORES what it settled.
    ///
    /// This is the defect found while verifying #223 and not named in the issue.
    /// `sess_add_by_apn` returns a clone, and `create_session` mutated that clone —
    /// so the address, the SGW TEID, the AMBR and the bearer never reached the context.
    ///
    /// Asserted by reading the session back OUT of the context, positively, field by field:
    /// a test that only checked the response would have passed throughout the defect, which
    /// is exactly how it survived #52.
    #[tokio::test]
    async fn an_established_eps_session_is_stored_with_its_address_teid_and_bearer() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        // IMSI ...0x31 and SGW TEID 0x3100_0001 are this test's alone — see the fixture.
        let (server, _sgw, sess) = establish_over_the_wire(3, 0x31, 0x3100_0001).await;

        assert_eq!(
            sess.sgw_s5c_teid, 0x3100_0001,
            "the stored session must carry the SGW's control TEID, or no later Delete Session \
             or Modify Bearer can be addressed to it"
        );
        let addr = sess
            .ipv4_addr
            .expect("the stored session must carry the PDN address this node allocated");
        assert_eq!(addr.octets()[0], 10, "and it comes from this node's pool");
        assert_eq!(
            sess.session_type,
            crate::context::PduSessionType::Ipv4,
            "the session type this PGW-C actually serves"
        );
        assert!(sess.epc, "sess_add_by_apn marks the EPS entry");

        // The bearer, which the modification and release paths look up by EBI.
        let ctx = crate::context::smf_self();
        let guard = ctx.read().expect("context");
        let bearer = guard
            .bearer_find_by_ebi(sess.id, 5)
            .expect("the accepted bearer context must be stored against the session");
        assert_eq!(
            bearer.pgw_s5u_teid, _upf.upf_teid,
            "the stored bearer must carry the PGW-U F-TEID the UPF allocated"
        );
        assert!(
            sess.bearer_ids.contains(&bearer.id),
            "and the session must link it, so the Modify Bearer path can enumerate it"
        );
        drop(guard);
        server.close();
    }

    /// #223 criterion 2, the release half: `gsm_handler::handle_pdu_session_release_request`
    /// runs over a session the CONTEXT holds, and its mutation is observable there.
    ///
    /// The assertion is POSITIVE and on state only this path produces: `ngap_state ==
    /// DeleteTriggerUeRequested`, read back from the store by id. Asserting the absence of an
    /// error, or the arrival of a Delete Session Response, would both be satisfied by a
    /// version that never called the handler — which is the whole complaint of #223.
    ///
    /// Driven through `record_eps_release` rather than through the socket **because** the
    /// full procedure answers the SGW-C and calls `sess_remove` within one scheduler tick of
    /// the handler returning: an earlier version of this test polled the store from a spawned
    /// task and lost the race every time. `a_delete_session_request_tears_the_pdn_connection_down`
    /// below covers the wire half. The session here is a real one, established over the wire,
    /// so this is not a synthesised fixture.
    #[tokio::test]
    async fn a_delete_session_request_records_the_release_on_the_stored_session() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        // IMSI ...0x35, SGW TEID 0x3500_0005: distinct from every other #223 test's.
        let (server, _sgw, mut sess) = establish_over_the_wire(8, 0x35, 0x3500_0005).await;

        assert_ne!(
            sess.ngap_state,
            crate::context::NgapState::DeleteTriggerUeRequested,
            "the fixture must start in a state the handler has to change, or this proves nothing"
        );

        let req = DeleteSessionRequest {
            linked_ebi: Some(5),
            ..Default::default()
        };
        assert!(
            record_eps_release(&mut sess, &req),
            "the 5GSM release handler must accept the default bearer as the session identity"
        );

        let stored = crate::context::smf_self()
            .read()
            .ok()
            .and_then(|c| c.sess_find_by_id(sess.id))
            .expect("the session is still held: the release is recorded before teardown");
        assert_eq!(
            stored.ngap_state,
            crate::context::NgapState::DeleteTriggerUeRequested,
            "handle_pdu_session_release_request's ONLY effect must reach the session the \
             CONTEXT holds — if this fails the handler was not called, or was called on a copy \
             nobody stored, which is the defect #223 was filed about"
        );
        assert_eq!(
            stored.psi, 0,
            "the EBI substituted for the PSI is an argument to the handler, not a change to \
             the session's identity"
        );
        server.close();
    }

    /// #223: the release is recorded even when the request omits the Linked EPS Bearer ID.
    ///
    /// The LBI is optional in a Delete Session Request (TS 29.274 §7.2.3 Table 7.2.3-1), so
    /// the session identity falls back to the stored default bearer's EBI. That matters
    /// because `handle_pdu_session_release_request` refuses identity 0, and an EPS session's
    /// `psi` IS 0 — so without the fallback a request with no LBI would be torn down with the
    /// release never recorded.
    ///
    /// Added after a revert pass showed the request-side parse and this fallback each covered
    /// for the other: removing either alone broke no test, because the sibling test above
    /// supplies an LBI and this path had none. Two halves, two tests.
    #[tokio::test]
    async fn a_delete_session_request_with_no_linked_ebi_still_records_the_release() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        // IMSI ...0x37, SGW TEID 0x3700_0007: distinct from every other #223 test's.
        let (server, _sgw, mut sess) = establish_over_the_wire(11, 0x37, 0x3700_0007).await;

        // The distinguishing input: NO Linked EPS Bearer ID.
        let req = DeleteSessionRequest::default();
        assert_eq!(
            req.linked_ebi, None,
            "this test is about the LBI being absent"
        );
        assert!(
            record_eps_release(&mut sess, &req),
            "with no LBI the identity must fall back to the stored default bearer's EBI — \
             without it the 5GSM handler refuses psi 0 and the release goes unrecorded"
        );

        let stored = crate::context::smf_self()
            .read()
            .ok()
            .and_then(|c| c.sess_find_by_id(sess.id))
            .expect("the session is still held");
        assert_eq!(
            stored.ngap_state,
            crate::context::NgapState::DeleteTriggerUeRequested,
            "and the release reaches the STORED session, not a copy"
        );
        server.close();
    }

    /// #223 criterion 2, the wire half: a Delete Session Request is answered and the PDN
    /// connection is gone (TS 29.274 §7.2.3, TS 23.401 §5.4.4.1).
    ///
    /// Before #223 this message fell into the `ServiceNotSupported` arm, so a session this
    /// PGW-C had established could never be torn down by the SGW-C that established it.
    #[tokio::test]
    async fn a_delete_session_request_tears_the_pdn_connection_down() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        // IMSI ...0x32, SGW TEID 0x3200_0002: distinct from every other #223 test's.
        let (server, sgw, sess) = establish_over_the_wire(4, 0x32, 0x3200_0002).await;
        let established_id = sess.id;

        let dsr = {
            use nextgcore_gtp::v2::{Gtp2Header, Gtp2Message};
            let mut msg = Gtp2Message::new(Gtp2Header::new(
                gtp2_message_type::DELETE_SESSION_REQUEST,
                // Addressed to the TEID this node advertised, which is how a real SGW-C
                // addresses it.
                sess.smf_n4_teid,
                0x22,
            ));
            // Linked EPS Bearer ID: the default bearer, whose removal takes the PDN
            // connection (TS 29.274 §7.2.3).
            msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
                Gtp2IeType::Ebi as u8,
                0,
                &[5],
            ));
            msg.encode()
        };
        sgw.send_to(&dsr, server.local_addr()).await.expect("send");

        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), sgw.recv_from(&mut buf))
                .await
                .expect("the PGW-C must answer a Delete Session Request")
                .expect("recv");
        let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
        let resp = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).expect("decode");

        assert_eq!(
            resp.header.message_type,
            gtp2_message_type::DELETE_SESSION_RESPONSE,
            "not Service not supported, which is what this answered before #223"
        );
        assert_eq!(
            resp.header.sequence_number, 0x22,
            "a triggered message echoes the request's sequence number"
        );
        assert_eq!(
            resp.get_ie(Gtp2IeType::Cause as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(16),
            "Request accepted (TS 29.274 §8.4)"
        );

        assert!(
            crate::context::smf_self()
                .read()
                .ok()
                .and_then(|c| c.sess_find_by_id(established_id))
                .is_none(),
            "the PDN connection must be gone once the response is out: TS 23.401 §5.4.4.1 \
             makes removing the default bearer remove the whole connection"
        );
        server.close();
    }

    /// #223 criterion 2, the modification half: a Modify Bearer Request reaches
    /// `gsm_handler::handle_pdu_session_modification_request`, and both handlers' mutations
    /// are observable on the stored session and bearer.
    ///
    /// Positive assertions on state only this path can produce: the bearer's downlink
    /// endpoint becomes the one the SGW just sent, and `qos_flow_to_modify_list` carries the
    /// flow the 5GSM handler selected. The latter is the mutation criterion 2 names — it is
    /// `handle_pdu_session_modification_request`'s entire effect, and nothing else in this
    /// daemon writes it.
    #[tokio::test]
    async fn a_modify_bearer_request_repoints_the_bearer_and_records_the_modification() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        // IMSI ...0x33, SGW TEID 0x3300_0003: distinct from every other #223 test's.
        let (server, sgw, sess) = establish_over_the_wire(5, 0x33, 0x3300_0003).await;

        // The endpoint the SGW relocates to. Deliberately different from the establishment's
        // `0x0505_0505` / 127.0.0.1, so "re-pointed" is distinguishable from "unchanged".
        const RELOCATED_TEID: u32 = 0x3300_5555;
        const RELOCATED_ADDR: [u8; 4] = [127, 0, 0, 2];

        let mbr = {
            use nextgcore_gtp::v2::{Gtp2BearerContextIe, Gtp2FTeidIe, Gtp2Header, Gtp2Message};
            let mut msg = Gtp2Message::new(Gtp2Header::new(
                gtp2_message_type::MODIFY_BEARER_REQUEST,
                sess.smf_n4_teid,
                0x23,
            ));
            let mut bc = Gtp2BearerContextIe::new();
            bc.set_ebi(5);
            // Instance 1: the S1-U/S4-U downlink endpoint in a Modify Bearer Request
            // (TS 29.274 Table 7.2.7-2).
            bc.set_fteid(1, &Gtp2FTeidIe::new_ipv4(4, RELOCATED_TEID, RELOCATED_ADDR));
            msg.add_bearer_context(0, &bc);
            msg.encode()
        };
        sgw.send_to(&mbr, server.local_addr()).await.expect("send");

        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), sgw.recv_from(&mut buf))
                .await
                .expect("the PGW-C must answer a Modify Bearer Request")
                .expect("recv");
        let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
        let resp = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).expect("decode");
        assert_eq!(
            resp.header.message_type,
            gtp2_message_type::MODIFY_BEARER_RESPONSE,
            "not Service not supported, which is what this answered before #223"
        );
        assert_eq!(resp.header.sequence_number, 0x23);
        assert_eq!(
            resp.get_ie(Gtp2IeType::Cause as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(16),
        );

        let ctx = crate::context::smf_self();
        let guard = ctx.read().expect("context");
        let bearer = guard
            .bearer_find_by_ebi(sess.id, 5)
            .expect("the bearer survives a modification");
        assert_eq!(
            bearer.sgw_s5u_teid, RELOCATED_TEID,
            "handle_modify_bearer_request's endpoint update must reach the STORED bearer"
        );
        assert_eq!(
            bearer.sgw_s5u_ip.ipv4,
            Some(std::net::Ipv4Addr::from(RELOCATED_ADDR)),
            "and so must the address"
        );

        let stored = guard
            .sess_find_by_id(sess.id)
            .expect("the session survives a modification");
        assert_eq!(
            stored.qos_flow_to_modify_list,
            vec![bearer.id],
            "handle_pdu_session_modification_request's ONLY effect is this list; if it is \
             empty the 5GSM handler was not reached, and if it landed on a temporary the \
             context would not show it"
        );
        drop(guard);
        server.close();
    }

    /// #223: a Bearer Resource Command is routed, and the authorized QoS it grants reaches
    /// the stored bearer (TS 29.274 §7.2.5, TS 23.401 §5.4.5).
    ///
    /// The positive assertion is the bearer's MBR read back from the context — a value only
    /// `handle_bearer_resource_command` writes, from the Flow QoS IE. The command is NOT
    /// answered with a message on the accept path (the follow-on Update Bearer Request is not
    /// transmitted; see the function's doc comment and the spec's ceilings), so asserting on
    /// a response would be asserting on something this change deliberately does not do.
    #[tokio::test]
    async fn a_bearer_resource_command_updates_the_stored_bearers_authorized_qos() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = crate::pfcp_path::stand_in::associated_upf().await;
        // IMSI ...0x34, SGW TEID 0x3400_0004: distinct from every other #223 test's.
        let (server, sgw, sess) = establish_over_the_wire(6, 0x34, 0x3400_0004).await;

        // The establishment's Bearer QoS carried all-zero rates, so a non-zero MBR here can
        // only have come from this command.
        const GRANTED_UL_MBR: u64 = 3_000;
        const GRANTED_DL_MBR: u64 = 7_000;

        let brc = {
            use nextgcore_gtp::v2::{Gtp2Header, Gtp2Message};
            let mut msg = Gtp2Message::new(Gtp2Header::new(
                gtp2_message_type::BEARER_RESOURCE_COMMAND,
                sess.smf_n4_teid,
                0x24,
            ));
            // Linked EPS Bearer ID and PTI are mandatory (TS 23.401 §5.4.5).
            msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
                Gtp2IeType::Ebi as u8,
                0,
                &[5],
            ));
            msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
                Gtp2IeType::Pti as u8,
                0,
                &[9],
            ));
            // Traffic Aggregate Description. Carried, not decoded — see `decode_flow_qos`'s
            // caller and the spec's ceilings.
            msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
                Gtp2IeType::Tad as u8,
                0,
                &[0x21, 0x01, 0x01],
            ));
            // Flow QoS (§8.16): QCI then four 5-octet rates, and NO ARP octet — which is what
            // makes it a different IE from Bearer QoS (§8.15).
            let mut flow_qos = vec![9u8];
            for rate in [GRANTED_UL_MBR, GRANTED_DL_MBR, 0u64, 0u64] {
                flow_qos.extend_from_slice(&rate.to_be_bytes()[3..8]);
            }
            msg.add_ie(nextgcore_gtp::v2::ie::Gtp2Ie::from_slice(
                Gtp2IeType::FlowQos as u8,
                0,
                &flow_qos,
            ));
            msg.encode()
        };
        sgw.send_to(&brc, server.local_addr()).await.expect("send");

        // The command is handled without a reply on the accept path, so the observable is the
        // stored bearer rather than a datagram.
        let mut granted = None;
        for _ in 0..600 {
            let found = crate::context::smf_self()
                .read()
                .ok()
                .and_then(|c| c.bearer_find_by_ebi(sess.id, 5))
                .filter(|b| b.qos.mbr_uplink == GRANTED_UL_MBR);
            if let Some(b) = found {
                granted = Some(b);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let granted = granted.expect(
            "handle_bearer_resource_command must write the granted Flow QoS to the STORED \
             bearer — before #223 this command was answered Service not supported and no \
             handler ran at all",
        );
        assert_eq!(
            granted.qos.mbr_downlink, GRANTED_DL_MBR,
            "the downlink rate must be the one the command granted, not the uplink one — \
             which is what decoding Flow QoS as Bearer QoS would produce"
        );
        server.close();
    }

    /// #223: a session procedure for a TEID this PGW-C does not hold is answered with a
    /// cause, not dropped and not acted on.
    ///
    /// TS 29.274 §7.7. Asserted because the alternative — silence — leaves the SGW-C to
    /// expire T3 three times over a session that will never exist, and because `Option<u32>`
    /// TEID handling defaulted to 0 would otherwise match whichever session holds SEID 0.
    #[tokio::test]
    async fn a_delete_session_for_an_unknown_teid_is_answered_with_context_not_found() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        crate::context::smf_context_init(64, 256, 512);
        let server = crate::gtp_path::S5S8Server::open("127.0.0.1:0".parse().unwrap(), 7)
            .await
            .expect("bind");
        let sgw = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind sgw");

        let dsr = {
            use nextgcore_gtp::v2::{Gtp2Header, Gtp2Message};
            // 0xDEAD_BEEF is no session's SEID in a context that was just initialised.
            Gtp2Message::new(Gtp2Header::new(
                gtp2_message_type::DELETE_SESSION_REQUEST,
                0xDEAD_BEEF,
                0x25,
            ))
            .encode()
        };
        sgw.send_to(&dsr, server.local_addr()).await.expect("send");

        let mut buf = vec![0u8; 4096];
        let (len, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), sgw.recv_from(&mut buf))
                .await
                .expect("an unknown TEID must still be ANSWERED")
                .expect("recv");
        let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
        let resp = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).expect("decode");
        assert_eq!(
            resp.header.message_type,
            gtp2_message_type::DELETE_SESSION_RESPONSE
        );
        assert_eq!(resp.header.sequence_number, 0x25);
        assert_eq!(
            resp.get_ie(Gtp2IeType::Cause as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(Gtp2Cause::ContextNotFound as u8),
            "TS 29.274 §7.7: Context not found, so the SGW-C stops rather than retrying"
        );
        server.close();
    }

    /// Flow QoS (§8.16) is not Bearer QoS (§8.15): 21 octets, no ARP.
    ///
    /// A unit guard on the decoder because the shared library models only Bearer QoS, and
    /// the first version of `decode_flow_qos` reused `Gtp2BearerQosIe::decode` — which reads
    /// the QCI out of the ARP octet and shifts every rate by one, producing plausible
    /// garbage rather than an error. This pins the octet layout directly.
    #[test]
    fn flow_qos_decodes_without_an_arp_octet() {
        let mut value = vec![7u8]; // QCI at octet 1, NOT an ARP byte
        for rate in [1_000u64, 2_000, 3_000, 4_000] {
            value.extend_from_slice(&rate.to_be_bytes()[3..8]);
        }
        assert_eq!(value.len(), 21, "TS 29.274 §8.16 is 21 octets");
        let qos = decode_flow_qos(&value).expect("a 21-octet Flow QoS decodes");
        assert_eq!(qos.qci, 7, "the QCI is the FIRST octet");
        assert_eq!(qos.ul_mbr, 1_000);
        assert_eq!(qos.dl_mbr, 2_000);
        assert_eq!(qos.ul_gbr, 3_000);
        assert_eq!(qos.dl_gbr, 4_000);

        assert!(
            decode_flow_qos(&value[..20]).is_none(),
            "a truncated IE must be reported as absent rather than decoded from short data"
        );
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
