//! SGWU SXA Handler
//!
//! Port of src/sgwu/sxa-handler.c - Handlers for PFCP messages from SGW-C

use crate::context::{sgwu_self, FSeid, SgwuBar, SgwuFar, SgwuPdr, SgwuQer, SgwuSess};
use crate::sxa_build::{pfcp_cause, CreatedPdr, UserPlaneReport};

// ============================================================================
// PFCP Interface Types
// ============================================================================

pub mod pfcp_interface {
    pub const ACCESS: u8 = 0;
    pub const CORE: u8 = 1;
    pub const SGI_LAN_N6_LAN: u8 = 2;
    pub const CP_FUNCTION: u8 = 3;
}

// ============================================================================
// Handler Result
// ============================================================================

/// Result of handler operations
#[derive(Debug)]
pub enum HandlerResult {
    /// Request accepted, send response
    Ok,
    /// Error with PFCP cause value
    Error(u8),
    /// Send session report request to SGWC
    SendSessionReport(UserPlaneReport),
}

// ============================================================================
// Session Establishment Request Data
// ============================================================================

/// Parsed Session Establishment Request
#[derive(Debug, Clone, Default)]
pub struct SessionEstablishmentRequest {
    /// CP F-SEID from SGWC
    pub cp_f_seid: Option<FSeid>,
    /// Create PDR list
    pub create_pdrs: Vec<CreatePdrRequest>,
    /// Create FAR list
    pub create_fars: Vec<CreateFarRequest>,
    /// Create QER list
    pub create_qers: Vec<CreateQerRequest>,
    /// Create BAR
    pub create_bar: Option<CreateBarRequest>,
    /// PFCPSEReq-Flags
    pub sereq_flags: SereqFlags,
}

/// PFCPSEReq-Flags
#[derive(Debug, Clone, Default)]
pub struct SereqFlags {
    /// Restoration Indication
    pub restoration_indication: bool,
}

/// Create PDR Request
#[derive(Debug, Clone, Default)]
pub struct CreatePdrRequest {
    pub pdr_id: u16,
    pub precedence: u32,
    pub pdi: Option<PdiRequest>,
    pub outer_header_removal: Option<u8>,
    pub far_id: Option<u32>,
    pub qer_id: Option<u32>,
}

/// PDI (Packet Detection Information)
#[derive(Debug, Clone, Default)]
pub struct PdiRequest {
    pub source_interface: u8,
    pub local_f_teid: Option<FTeidRequest>,
    pub network_instance: Option<String>,
    pub ue_ip_address: Option<UeIpAddress>,
}

/// F-TEID Request
#[derive(Debug, Clone, Default)]
pub struct FTeidRequest {
    pub ch: bool, // Choose flag - UPF allocates TEID
    pub teid: u32,
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

/// UE IP Address
#[derive(Debug, Clone, Default)]
pub struct UeIpAddress {
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

/// Create FAR Request
#[derive(Debug, Clone, Default)]
pub struct CreateFarRequest {
    pub far_id: u32,
    pub apply_action: u8,
    pub forwarding_parameters: Option<ForwardingParameters>,
}

/// Forwarding Parameters
#[derive(Debug, Clone, Default)]
pub struct ForwardingParameters {
    pub destination_interface: u8,
    pub outer_header_creation: Option<OuterHeaderCreation>,
}

/// Outer Header Creation
#[derive(Debug, Clone, Default)]
pub struct OuterHeaderCreation {
    pub teid: u32,
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

/// Create QER Request
#[derive(Debug, Clone, Default)]
pub struct CreateQerRequest {
    pub qer_id: u32,
    pub gate_status: Option<u8>,
    pub mbr: Option<Mbr>,
    pub gbr: Option<Gbr>,
}

/// Maximum Bit Rate
#[derive(Debug, Clone, Default)]
pub struct Mbr {
    pub ul: u64,
    pub dl: u64,
}

/// Guaranteed Bit Rate
#[derive(Debug, Clone, Default)]
pub struct Gbr {
    pub ul: u64,
    pub dl: u64,
}

/// Create BAR Request
#[derive(Debug, Clone, Default)]
pub struct CreateBarRequest {
    pub bar_id: u8,
    pub downlink_data_notification_delay: Option<u8>,
}

// ============================================================================
// Session Modification Request Data
// ============================================================================

/// Parsed Session Modification Request
#[derive(Debug, Clone, Default)]
pub struct SessionModificationRequest {
    /// Create PDR list
    pub create_pdrs: Vec<CreatePdrRequest>,
    /// Update PDR list
    pub update_pdrs: Vec<UpdatePdrRequest>,
    /// Remove PDR list
    pub remove_pdrs: Vec<u16>,
    /// Create FAR list
    pub create_fars: Vec<CreateFarRequest>,
    /// Update FAR list
    pub update_fars: Vec<UpdateFarRequest>,
    /// Remove FAR list
    pub remove_fars: Vec<u32>,
    /// Create QER list
    pub create_qers: Vec<CreateQerRequest>,
    /// Update QER list
    pub update_qers: Vec<UpdateQerRequest>,
    /// Remove QER list
    pub remove_qers: Vec<u32>,
    /// Create BAR
    pub create_bar: Option<CreateBarRequest>,
    /// Remove BAR
    pub remove_bar: Option<u8>,
}

/// Update PDR Request
#[derive(Debug, Clone, Default)]
pub struct UpdatePdrRequest {
    pub pdr_id: u16,
    pub pdi: Option<PdiRequest>,
    pub outer_header_removal: Option<u8>,
    pub far_id: Option<u32>,
}

/// Update FAR Request
#[derive(Debug, Clone, Default)]
pub struct UpdateFarRequest {
    pub far_id: u32,
    pub apply_action: Option<u8>,
    pub update_forwarding_parameters: Option<ForwardingParameters>,
    /// PFCPSMReq-Flags
    pub smreq_flags: SmreqFlags,
}

/// PFCPSMReq-Flags
#[derive(Debug, Clone, Default)]
pub struct SmreqFlags {
    /// Send End Marker Packets
    pub send_end_marker_packets: bool,
}

/// Update QER Request
#[derive(Debug, Clone, Default)]
pub struct UpdateQerRequest {
    pub qer_id: u32,
    pub gate_status: Option<u8>,
    pub mbr: Option<Mbr>,
    pub gbr: Option<Gbr>,
}

// ============================================================================
// Session Report Response Data
// ============================================================================

/// Parsed Session Report Response
#[derive(Debug, Clone, Default)]
pub struct SessionReportResponse {
    /// Cause value
    pub cause: Option<u8>,
}

// ============================================================================
// SXA Handlers (from SGW-C)
// ============================================================================

/// Handle Session Establishment Request from SGW-C
/// Port of sgwu_sxa_handle_session_establishment_request
pub fn handle_session_establishment_request(
    sess: Option<&SgwuSess>,
    _xact_id: u64,
    req: &SessionEstablishmentRequest,
) -> (HandlerResult, Vec<CreatedPdr>) {
    log::info!("Session Establishment Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return (
                HandlerResult::Error(pfcp_cause::MANDATORY_IE_MISSING),
                vec![],
            );
        }
    };

    let mut created_pdrs = Vec::new();
    let restoration_indication = req.sereq_flags.restoration_indication;

    // Process Create PDRs
    for create_pdr in &req.create_pdrs {
        match process_create_pdr(sess, create_pdr, restoration_indication) {
            Ok(created_pdr) => {
                if let Some(pdr) = created_pdr {
                    created_pdrs.push(pdr);
                }
            }
            Err(cause) => {
                log::error!("Failed to create PDR: cause={cause}");
                return (HandlerResult::Error(cause), vec![]);
            }
        }
    }

    // Process Create FARs
    for create_far in &req.create_fars {
        if let Err(cause) = process_create_far(sess, create_far) {
            log::error!("Failed to create FAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create QERs
    for create_qer in &req.create_qers {
        if let Err(cause) = process_create_qer(sess, create_qer) {
            log::error!("Failed to create QER: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create BAR
    if let Some(ref create_bar) = req.create_bar {
        if let Err(cause) = process_create_bar(sess, create_bar) {
            log::error!("Failed to create BAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    log::info!(
        "    SGWU_SXA_SEID[0x{:x}] SGWC_SXA_SEID[0x{:x}]",
        sess.sgwu_sxa_seid,
        sess.sgwc_sxa_f_seid.seid
    );
    log::info!(
        "    Created {} PDRs, {} FARs, {} QERs",
        req.create_pdrs.len(),
        req.create_fars.len(),
        req.create_qers.len()
    );

    (HandlerResult::Ok, created_pdrs)
}

/// Handle Session Modification Request from SGW-C
/// Port of sgwu_sxa_handle_session_modification_request
pub fn handle_session_modification_request(
    sess: Option<&SgwuSess>,
    _xact_id: u64,
    req: &SessionModificationRequest,
) -> (HandlerResult, Vec<CreatedPdr>) {
    log::info!("Session Modification Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return (
                HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND),
                vec![],
            );
        }
    };

    let mut created_pdrs = Vec::new();

    // Process Create PDRs
    for create_pdr in &req.create_pdrs {
        match process_create_pdr(sess, create_pdr, false) {
            Ok(created_pdr) => {
                if let Some(pdr) = created_pdr {
                    created_pdrs.push(pdr);
                }
            }
            Err(cause) => {
                log::error!("Failed to create PDR: cause={cause}");
                return (HandlerResult::Error(cause), vec![]);
            }
        }
    }

    // Process Update PDRs
    for update_pdr in &req.update_pdrs {
        if let Err(cause) = process_update_pdr(sess, update_pdr) {
            log::error!("Failed to update PDR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Remove PDRs
    for pdr_id in &req.remove_pdrs {
        if let Err(cause) = process_remove_pdr(sess, *pdr_id) {
            log::error!("Failed to remove PDR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create FARs
    for create_far in &req.create_fars {
        if let Err(cause) = process_create_far(sess, create_far) {
            log::error!("Failed to create FAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Send End Markers on the old path before re-pointing FARs
    // (TS 23.214 Section 5.7 / PFCPSMReq-Flags SNDEM)
    for update_far in &req.update_fars {
        if update_far.smreq_flags.send_end_marker_packets {
            if let Some(server) = crate::gtp_path::gtpu_server() {
                if let Err(e) = server.send_end_marker(sess.id, update_far.far_id) {
                    log::warn!("End Marker for FAR {} failed: {e}", update_far.far_id);
                }
            } else {
                log::warn!(
                    "GTP-U server not open: cannot send End Marker for FAR {}",
                    update_far.far_id
                );
            }
        }
    }

    // Process Update FARs
    for update_far in &req.update_fars {
        if let Err(cause) = process_update_far(sess, update_far) {
            log::error!("Failed to update FAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Remove FARs
    for far_id in &req.remove_fars {
        if let Err(cause) = process_remove_far(sess, *far_id) {
            log::error!("Failed to remove FAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create QERs
    for create_qer in &req.create_qers {
        if let Err(cause) = process_create_qer(sess, create_qer) {
            log::error!("Failed to create QER: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Update QERs
    for update_qer in &req.update_qers {
        if let Err(cause) = process_update_qer(sess, update_qer) {
            log::error!("Failed to update QER: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Remove QERs
    for qer_id in &req.remove_qers {
        if let Err(cause) = process_remove_qer(sess, *qer_id) {
            log::error!("Failed to remove QER: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Create BAR
    if let Some(ref create_bar) = req.create_bar {
        if let Err(cause) = process_create_bar(sess, create_bar) {
            log::error!("Failed to create BAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    // Process Remove BAR
    if let Some(bar_id) = req.remove_bar {
        if let Err(cause) = process_remove_bar(sess, bar_id) {
            log::error!("Failed to remove BAR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

    log::info!(
        "    SGWU_SXA_SEID[0x{:x}] SGWC_SXA_SEID[0x{:x}]",
        sess.sgwu_sxa_seid,
        sess.sgwc_sxa_f_seid.seid
    );

    (HandlerResult::Ok, created_pdrs)
}

/// Handle Session Deletion Request from SGW-C
/// Port of sgwu_sxa_handle_session_deletion_request
pub fn handle_session_deletion_request(sess: Option<&SgwuSess>, _xact_id: u64) -> HandlerResult {
    log::info!("Session Deletion Request");

    let sess = match sess {
        Some(s) => s,
        None => {
            log::error!("No Context");
            return HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND);
        }
    };

    log::info!(
        "    SGWU_SXA_SEID[0x{:x}] SGWC_SXA_SEID[0x{:x}]",
        sess.sgwu_sxa_seid,
        sess.sgwc_sxa_f_seid.seid
    );

    // Session will be removed after sending response
    HandlerResult::Ok
}

/// Handle Session Report Response from SGW-C
/// Port of sgwu_sxa_handle_session_report_response
pub fn handle_session_report_response(
    sess: Option<&SgwuSess>,
    _xact_id: u64,
    rsp: &SessionReportResponse,
) -> HandlerResult {
    log::info!("Session Report Response");

    let cause = rsp.cause.unwrap_or(pfcp_cause::MANDATORY_IE_MISSING);

    if sess.is_none() {
        log::warn!("No Context");
        return HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND);
    }

    if cause != pfcp_cause::REQUEST_ACCEPTED {
        log::error!("PFCP Cause[{cause}] : Not Accepted");
        return HandlerResult::Error(cause);
    }

    log::debug!("Session Report Response accepted");
    HandlerResult::Ok
}

// ============================================================================
// Internal Processing Functions
// ============================================================================

/// Process Create PDR: install the rule and allocate the local F-TEID when
/// the CH (CHOOSE) flag is set (TS 29.244 Section 8.2.3)
fn process_create_pdr(
    sess: &SgwuSess,
    req: &CreatePdrRequest,
    restoration_indication: bool,
) -> Result<Option<CreatedPdr>, u8> {
    log::debug!("Creating PDR: id={}", req.pdr_id);

    let ctx = sgwu_self();

    // Resolve the local F-TEID for the PDI
    let (local_teid, local_addr, created) = if let Some(ref pdi) = req.pdi {
        if let Some(ref f_teid) = pdi.local_f_teid {
            if f_teid.ch {
                // The UP function allocates the TEID and advertises its own
                // GTP-U address (no placeholder addresses)
                let Some(addr) = ctx.gtpu_address() else {
                    log::error!("No GTP-U address configured for F-TEID allocation");
                    return Err(pfcp_cause::NO_RESOURCES_AVAILABLE);
                };
                let teid = ctx.alloc_teid();
                (
                    teid,
                    Some(addr),
                    Some(crate::sxa_build::LocalFTeid {
                        teid,
                        ipv4: Some(addr),
                        ipv6: None,
                    }),
                )
            } else if restoration_indication {
                // Restoration: re-install the CP-provided TEID and echo it
                log::debug!("Restoration indication - reusing TEID 0x{:x}", f_teid.teid);
                (
                    f_teid.teid,
                    f_teid.ipv4,
                    Some(crate::sxa_build::LocalFTeid {
                        teid: f_teid.teid,
                        ipv4: f_teid.ipv4,
                        ipv6: f_teid.ipv6,
                    }),
                )
            } else {
                (f_teid.teid, f_teid.ipv4, None)
            }
        } else {
            (0, None, None)
        }
    } else {
        (0, None, None)
    };

    let pdi = req.pdi.clone().unwrap_or_default();
    if !ctx.pdr_install(SgwuPdr {
        sess_id: sess.id,
        pdr_id: req.pdr_id,
        precedence: req.precedence,
        source_interface: pdi.source_interface,
        local_teid,
        local_addr,
        outer_header_removal: req.outer_header_removal,
        far_id: req.far_id,
        qer_id: req.qer_id,
    }) {
        return Err(pfcp_cause::SYSTEM_FAILURE);
    }

    Ok(created.map(|local_f_teid| CreatedPdr {
        pdr_id: req.pdr_id,
        local_f_teid: Some(local_f_teid),
    }))
}

/// Process Create FAR: install the forwarding rule
fn process_create_far(sess: &SgwuSess, req: &CreateFarRequest) -> Result<(), u8> {
    log::debug!("Creating FAR: id={}", req.far_id);

    let ctx = sgwu_self();
    let (destination_interface, outer_header_creation) = match req.forwarding_parameters {
        Some(ref fp) => (
            fp.destination_interface,
            fp.outer_header_creation
                .as_ref()
                .map(|ohc| (ohc.teid, ohc.ipv4, ohc.ipv6)),
        ),
        None => (0, None),
    };

    if !ctx.far_install(SgwuFar {
        sess_id: sess.id,
        far_id: req.far_id,
        apply_action: req.apply_action,
        destination_interface,
        outer_header_creation,
        buffered: Vec::new(),
    }) {
        return Err(pfcp_cause::SYSTEM_FAILURE);
    }
    Ok(())
}

/// Process Create QER: store the rule (rate enforcement is a follow-up)
fn process_create_qer(sess: &SgwuSess, req: &CreateQerRequest) -> Result<(), u8> {
    log::debug!("Creating QER: id={}", req.qer_id);
    let ctx = sgwu_self();
    if !ctx.qer_install(SgwuQer {
        sess_id: sess.id,
        qer_id: req.qer_id,
        gate_status: req.gate_status,
        mbr_ul: req.mbr.as_ref().map(|m| m.ul).unwrap_or(0),
        mbr_dl: req.mbr.as_ref().map(|m| m.dl).unwrap_or(0),
    }) {
        return Err(pfcp_cause::SYSTEM_FAILURE);
    }
    Ok(())
}

/// Process Create BAR
fn process_create_bar(sess: &SgwuSess, req: &CreateBarRequest) -> Result<(), u8> {
    log::debug!("Creating BAR: id={}", req.bar_id);
    let ctx = sgwu_self();
    if !ctx.bar_install(SgwuBar {
        sess_id: sess.id,
        bar_id: req.bar_id,
        downlink_data_notification_delay: req.downlink_data_notification_delay,
    }) {
        return Err(pfcp_cause::SYSTEM_FAILURE);
    }
    Ok(())
}

/// Process Update PDR
fn process_update_pdr(sess: &SgwuSess, req: &UpdatePdrRequest) -> Result<(), u8> {
    log::debug!("Updating PDR: id={}", req.pdr_id);

    let ctx = sgwu_self();
    let Some(mut pdr) = ctx.pdr_find(sess.id, req.pdr_id) else {
        log::error!("Update PDR: id={} not found", req.pdr_id);
        return Err(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE);
    };

    if let Some(ref pdi) = req.pdi {
        pdr.source_interface = pdi.source_interface;
        if let Some(ref f_teid) = pdi.local_f_teid {
            if !f_teid.ch {
                pdr.local_teid = f_teid.teid;
                pdr.local_addr = f_teid.ipv4;
            }
        }
    }
    if let Some(ohr) = req.outer_header_removal {
        pdr.outer_header_removal = Some(ohr);
    }
    if let Some(far_id) = req.far_id {
        pdr.far_id = Some(far_id);
    }
    if !ctx.pdr_install(pdr) {
        return Err(pfcp_cause::SYSTEM_FAILURE);
    }
    Ok(())
}

/// Process Remove PDR
fn process_remove_pdr(sess: &SgwuSess, pdr_id: u16) -> Result<(), u8> {
    log::debug!("Removing PDR: id={pdr_id}");
    let ctx = sgwu_self();
    if ctx.pdr_remove(sess.id, pdr_id).is_none() {
        log::error!("Remove PDR: id={pdr_id} not found");
        return Err(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE);
    }
    Ok(())
}

/// Process Update FAR; when the action transitions to FORW any buffered
/// packets are flushed through the GTP-U server (TS 29.244 Section 5.3.1)
fn process_update_far(sess: &SgwuSess, req: &UpdateFarRequest) -> Result<(), u8> {
    log::debug!("Updating FAR: id={}", req.far_id);

    let ctx = sgwu_self();
    let Some(previous) = ctx.far_find(sess.id, req.far_id) else {
        log::error!("Update FAR: id={} not found", req.far_id);
        return Err(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE);
    };

    ctx.far_update_with(sess.id, req.far_id, |far| {
        if let Some(action) = req.apply_action {
            far.apply_action = action;
        }
        if let Some(ref fp) = req.update_forwarding_parameters {
            far.destination_interface = fp.destination_interface;
            if let Some(ref ohc) = fp.outer_header_creation {
                far.outer_header_creation = Some((ohc.teid, ohc.ipv4, ohc.ipv6));
            }
        }
    });

    // BUFF -> FORW transition: flush buffered downlink packets
    let became_forw = req
        .apply_action
        .map(|a| a & crate::context::apply_action::FORW != 0)
        .unwrap_or(false);
    let was_buff = previous.apply_action & crate::context::apply_action::BUFF != 0;
    if was_buff && became_forw {
        if let Some(server) = crate::gtp_path::gtpu_server() {
            server.send_buffered_packets(sess.id, req.far_id);
        } else if !previous.buffered.is_empty() {
            log::warn!(
                "GTP-U server not open: dropping {} buffered packets for FAR {}",
                previous.buffered.len(),
                req.far_id
            );
            ctx.far_take_buffered(sess.id, req.far_id);
        }
    }

    Ok(())
}

/// Process Remove FAR
fn process_remove_far(sess: &SgwuSess, far_id: u32) -> Result<(), u8> {
    log::debug!("Removing FAR: id={far_id}");
    let ctx = sgwu_self();
    if ctx.far_remove(sess.id, far_id).is_none() {
        log::error!("Remove FAR: id={far_id} not found");
        return Err(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE);
    }
    Ok(())
}

/// Process Update QER
fn process_update_qer(sess: &SgwuSess, req: &UpdateQerRequest) -> Result<(), u8> {
    log::debug!("Updating QER: id={}", req.qer_id);
    let ctx = sgwu_self();
    let Some(mut qer) = ctx.qer_find(sess.id, req.qer_id) else {
        log::error!("Update QER: id={} not found", req.qer_id);
        return Err(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE);
    };
    if let Some(gate) = req.gate_status {
        qer.gate_status = Some(gate);
    }
    if let Some(ref mbr) = req.mbr {
        qer.mbr_ul = mbr.ul;
        qer.mbr_dl = mbr.dl;
    }
    if !ctx.qer_install(qer) {
        return Err(pfcp_cause::SYSTEM_FAILURE);
    }
    Ok(())
}

/// Process Remove QER
fn process_remove_qer(sess: &SgwuSess, qer_id: u32) -> Result<(), u8> {
    log::debug!("Removing QER: id={qer_id}");
    let ctx = sgwu_self();
    if ctx.qer_remove(sess.id, qer_id).is_none() {
        log::error!("Remove QER: id={qer_id} not found");
        return Err(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE);
    }
    Ok(())
}

/// Process Remove BAR
fn process_remove_bar(sess: &SgwuSess, bar_id: u8) -> Result<(), u8> {
    log::debug!("Removing BAR: id={bar_id}");
    let ctx = sgwu_self();
    if ctx.bar_remove(sess.id, bar_id).is_none() {
        log::error!("Remove BAR: id={bar_id} not found");
        return Err(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE);
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_sess() -> SgwuSess {
        // F-TEID CH allocation requires a configured GTP-U address
        sgwu_self().set_gtpu_address(Some(Ipv4Addr::new(10, 0, 0, 99)));
        SgwuSess {
            id: 1,
            sgwu_sxa_seid: 0x1000,
            sgwc_sxa_f_seid: FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        }
    }

    #[test]
    fn test_handle_session_establishment_request_no_sess() {
        let req = SessionEstablishmentRequest::default();
        let (result, _) = handle_session_establishment_request(None, 1, &req);
        matches!(
            result,
            HandlerResult::Error(pfcp_cause::MANDATORY_IE_MISSING)
        );
    }

    #[test]
    fn test_handle_session_establishment_request_ok() {
        let sess = create_test_sess();
        let req = SessionEstablishmentRequest {
            create_pdrs: vec![CreatePdrRequest {
                pdr_id: 1,
                precedence: 100,
                pdi: Some(PdiRequest {
                    source_interface: pfcp_interface::ACCESS,
                    local_f_teid: Some(FTeidRequest {
                        ch: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            create_fars: vec![CreateFarRequest {
                far_id: 1,
                apply_action: 0x02, // FORW
                ..Default::default()
            }],
            ..Default::default()
        };

        let (result, created_pdrs) = handle_session_establishment_request(Some(&sess), 1, &req);
        assert!(matches!(result, HandlerResult::Ok));
        assert_eq!(created_pdrs.len(), 1);
    }

    #[test]
    fn test_handle_session_modification_request_no_sess() {
        let req = SessionModificationRequest::default();
        let (result, _) = handle_session_modification_request(None, 1, &req);
        matches!(
            result,
            HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND)
        );
    }

    #[test]
    fn test_handle_session_modification_request_ok() {
        let sess = create_test_sess();
        let req = SessionModificationRequest {
            update_fars: vec![UpdateFarRequest {
                far_id: 1,
                apply_action: Some(0x02),
                smreq_flags: SmreqFlags {
                    send_end_marker_packets: true,
                },
                ..Default::default()
            }],
            ..Default::default()
        };

        let (result, _) = handle_session_modification_request(Some(&sess), 1, &req);
        assert!(matches!(result, HandlerResult::Ok));
    }

    #[test]
    fn test_handle_session_deletion_request_no_sess() {
        let result = handle_session_deletion_request(None, 1);
        matches!(
            result,
            HandlerResult::Error(pfcp_cause::SESSION_CONTEXT_NOT_FOUND)
        );
    }

    #[test]
    fn test_handle_session_deletion_request_ok() {
        let sess = create_test_sess();
        let result = handle_session_deletion_request(Some(&sess), 1);
        assert!(matches!(result, HandlerResult::Ok));
    }

    #[test]
    fn test_handle_session_report_response_no_cause() {
        let sess = create_test_sess();
        let rsp = SessionReportResponse { cause: None };
        let result = handle_session_report_response(Some(&sess), 1, &rsp);
        matches!(
            result,
            HandlerResult::Error(pfcp_cause::MANDATORY_IE_MISSING)
        );
    }

    #[test]
    fn test_handle_session_report_response_ok() {
        let sess = create_test_sess();
        let rsp = SessionReportResponse {
            cause: Some(pfcp_cause::REQUEST_ACCEPTED),
        };
        let result = handle_session_report_response(Some(&sess), 1, &rsp);
        assert!(matches!(result, HandlerResult::Ok));
    }

    #[test]
    fn test_alloc_teid_unique() {
        let ctx = sgwu_self();
        let teid1 = ctx.alloc_teid();
        let teid2 = ctx.alloc_teid();
        assert_ne!(teid1, teid2);
    }

    #[test]
    fn test_create_pdr_ch_allocates_local_address_not_placeholder() {
        let sess = create_test_sess();
        let req = CreatePdrRequest {
            pdr_id: 77,
            precedence: 1,
            pdi: Some(PdiRequest {
                source_interface: pfcp_interface::ACCESS,
                local_f_teid: Some(FTeidRequest {
                    ch: true,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            far_id: Some(7),
            ..Default::default()
        };

        let created = process_create_pdr(&sess, &req, false).unwrap().unwrap();
        let fteid = created.local_f_teid.unwrap();
        assert_ne!(fteid.teid, 0);
        // Address comes from the configured GTP-U address, not a placeholder
        assert_eq!(fteid.ipv4, Some(Ipv4Addr::new(10, 0, 0, 99)));
        assert_ne!(fteid.ipv4, Some(Ipv4Addr::new(127, 0, 0, 1)));

        // The PDR is installed and matchable by TEID
        let pdr = sgwu_self().pdr_find_by_teid(fteid.teid).unwrap();
        assert_eq!(pdr.pdr_id, 77);
        assert_eq!(pdr.far_id, Some(7));
    }
}
