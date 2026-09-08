//! SGWU SXA Handler
//!
//! Port of src/sgwu/sxa-handler.c - Handlers for PFCP messages from SGW-C

use crate::context::{
    now_unix_secs, sgwu_self, FSeid, SgwuBar, SgwuFar, SgwuPdr, SgwuQer, SgwuSess, SgwuUrr,
    UsageReportTrigger, Volume,
};
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
    /// Create URR list (TS 29.244 Table 7.5.2.1-1 lists Create URR as applicable
    /// on Sxa). Issue #215.
    pub create_urrs: Vec<CreateUrrRequest>,
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
    /// URR ID(s) this PDR is measured against (TS 29.244 Table 7.5.2.2-1 allows
    /// several). Issue #215.
    pub urr_ids: Vec<u32>,
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

/// Create URR Request (TS 29.244 Table 7.5.2.4-1). Issue #215.
///
/// The SGW-U had no URR type at all, so `PfcpSess.urr_ids` was populated only in
/// a unit test and the USAR report-type bit was set only in a unit test — the
/// SGW-C could provision usage reporting and get nothing back, and SGW-CDR
/// charging (TS 32.251) had no volume input.
#[derive(Debug, Clone, Default)]
pub struct CreateUrrRequest {
    pub urr_id: u32,
    /// Measurement Method (§8.2.40): DURAT / VOLUM / EVENT bits.
    pub measurement_method: u8,
    /// Reporting Triggers (§8.2.41), both octets; octet 5 is the low byte.
    pub reporting_triggers: u16,
    /// Volume Threshold (§8.2.13).
    pub volume_threshold: Volume,
    /// Volume Quota (§8.2.14).
    pub volume_quota: Volume,
    /// Time Threshold in seconds (§8.2.15).
    pub time_threshold: Option<u32>,
    /// Measurement Period in seconds (§8.2.16).
    pub measurement_period: Option<u32>,
}

/// Update URR Request (TS 29.244 Table 7.5.4.4-1). Issue #215.
///
/// Every provisioning member is optional: an Update URR that names only a new
/// Volume Threshold must leave the Measurement Method and the other thresholds
/// alone, and must not disturb the volume measured so far.
#[derive(Debug, Clone, Default)]
pub struct UpdateUrrRequest {
    pub urr_id: u32,
    pub measurement_method: Option<u8>,
    pub reporting_triggers: Option<u16>,
    pub volume_threshold: Option<Volume>,
    pub volume_quota: Option<Volume>,
    pub time_threshold: Option<u32>,
    pub measurement_period: Option<u32>,
}

/// Create BAR Request
#[derive(Debug, Clone, Default)]
pub struct CreateBarRequest {
    pub bar_id: u8,
    /// Downlink Data Notification Delay in 50 ms units (TS 29.244 Section 8.2.28)
    pub downlink_data_notification_delay: Option<u8>,
    /// DL Buffering Duration (TS 29.244 Section 8.2.47)
    pub dl_buffering_duration: Option<u8>,
    /// DL Buffering Suggested Packet Count (TS 29.244 Section 8.2.48)
    pub dl_buffering_suggested_packet_count: Option<u16>,
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
    /// Create URR list (issue #215)
    pub create_urrs: Vec<CreateUrrRequest>,
    /// Update URR list (issue #215)
    pub update_urrs: Vec<UpdateUrrRequest>,
    /// Remove URR list (issue #215)
    pub remove_urrs: Vec<u32>,
    /// Create BAR
    pub create_bar: Option<CreateBarRequest>,
    /// Remove BAR
    pub remove_bar: Option<u8>,
}

/// Update PDR Request
#[derive(Debug, Clone, Default)]
pub struct UpdatePdrRequest {
    pub pdr_id: u16,
    /// URR ID(s) to re-point this PDR's measurement at (TS 29.244
    /// Table 7.5.4.2-1 lists URR ID as an Update PDR IE). #267: absent before, so
    /// an SGW-C moving a bearer's measurement from URR 3 to URR 4 got `Ok` and the
    /// SGW-U kept billing URR 3 forever, with no log line. `None` leaves the
    /// existing association alone; `Some` REPLACES it, because an Update states the
    /// PDR's current shape.
    pub urr_ids: Option<Vec<u32>>,
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
    /// Update BAR (TS 29.244 Table 7.5.9.2-1): the CP function's extended
    /// buffering instruction, previously parsed away and ignored.
    pub update_bar: Option<UpdateBarRequest>,
}

/// Update BAR carried in a Session Report Response or Session Modification
/// (TS 29.244 Table 7.5.9.2-1 / Section 7.5.4.11).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateBarRequest {
    pub bar_id: u8,
    pub downlink_data_notification_delay: Option<u8>,
    pub dl_buffering_duration: Option<u8>,
    pub dl_buffering_suggested_packet_count: Option<u16>,
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

    // Process Create URRs FIRST (issue #215): a Create PDR may name a URR ID, and
    // TS 29.244 §7.5.2 does not fix the IE order in the message, so installing
    // URRs before PDRs is what makes a single-message provisioning work regardless
    // of how the SGW-C ordered them.
    for create_urr in &req.create_urrs {
        if let Err(cause) = process_create_urr(sess, create_urr) {
            log::error!("Failed to create URR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

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
        "    Created {} PDRs, {} FARs, {} QERs, {} URRs",
        req.create_pdrs.len(),
        req.create_fars.len(),
        req.create_qers.len(),
        req.create_urrs.len()
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

    // #215: URR provisioning first, for the same reason as at establishment — a
    // Create PDR in the same message may name a URR ID.
    for create_urr in &req.create_urrs {
        if let Err(cause) = process_create_urr(sess, create_urr) {
            log::error!("Failed to create URR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }
    for update_urr in &req.update_urrs {
        if let Err(cause) = process_update_urr(sess, update_urr) {
            log::error!("Failed to update URR: cause={cause}");
            return (HandlerResult::Error(cause), vec![]);
        }
    }

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

    // Process Remove URRs LAST of the URR operations (issue #215), so a PDR that
    // referenced one has already been updated or removed above.
    for urr_id in &req.remove_urrs {
        if let Err(cause) = process_remove_urr(sess, *urr_id) {
            log::error!("Failed to remove URR: cause={cause}");
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

/// The final Usage Reports for a session being deleted (issue #215,
/// TS 29.244 §7.5.5.2).
///
/// Takes every URR out of the store and renders it, tagged TEBUR (termination by
/// the UP function) — the SGW-U's last chance to hand residual volume to the
/// SGW-C. A URR that measured nothing still reports: a zero report and no report
/// are different statements to a charging function, and only the first says "this
/// rule was installed and saw no traffic".
///
/// Separate from `handle_session_deletion_request` because the handler answers a
/// request while this DRAINS state, and the caller needs the reports to put in the
/// response before it removes the session.
pub fn take_final_usage_reports(sess_id: u64) -> Vec<crate::sxa_build::UsageReport> {
    let trigger = UsageReportTrigger {
        termination_report: true,
        ..Default::default()
    };
    sgwu_self()
        .urr_drain_for_sess(sess_id)
        .into_iter()
        .map(|urr| {
            let seqn = urr.next_ur_seqn;
            usage_report_from(&urr, seqn, trigger)
        })
        .collect()
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

    // TS 29.244 Table 7.5.9.2-1: the response may carry an Update BAR telling
    // the UP function how long to keep buffering and how much. This was parsed
    // away before, so extended-buffering instructions had no effect at all.
    if let (Some(sess), Some(update)) = (sess, rsp.update_bar.as_ref()) {
        let ctx = sgwu_self();
        if ctx.bar_update(
            sess.id,
            update.bar_id,
            update.downlink_data_notification_delay,
            update.dl_buffering_duration,
            update.dl_buffering_suggested_packet_count,
        ) {
            log::debug!(
                "Update BAR {} applied: ddn_delay={:?} dl_duration={:?} suggested_count={:?}",
                update.bar_id,
                update.downlink_data_notification_delay,
                update.dl_buffering_duration,
                update.dl_buffering_suggested_packet_count
            );
        } else {
            log::warn!(
                "Update BAR {} in Session Report Response matches no installed BAR",
                update.bar_id
            );
        }
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
        urr_ids: req.urr_ids.clone(),
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

/// Process Create URR: install the measurement rule and register its id on the
/// session (issue #215).
///
/// `PfcpSess.urr_ids` is populated **here**, in production. Before this it was
/// written only by a unit test, so the field described a capability the daemon did
/// not have.
fn process_create_urr(sess: &SgwuSess, req: &CreateUrrRequest) -> Result<(), u8> {
    log::debug!(
        "Creating URR: id={} method=0x{:02x} triggers=0x{:04x}",
        req.urr_id,
        req.measurement_method,
        req.reporting_triggers
    );
    let ctx = sgwu_self();
    if !ctx.urr_install(SgwuUrr {
        sess_id: sess.id,
        urr_id: req.urr_id,
        measurement_method: req.measurement_method,
        reporting_triggers: req.reporting_triggers,
        volume_threshold: req.volume_threshold,
        volume_quota: req.volume_quota,
        time_threshold: req.time_threshold,
        measurement_period: req.measurement_period,
        start_time: now_unix_secs(),
        ..Default::default()
    }) {
        return Err(pfcp_cause::SYSTEM_FAILURE);
    }
    ctx.sess_register_urr(sess.id, req.urr_id);
    Ok(())
}

/// Process Update URR: change provisioning, keep the measurement.
///
/// Every member is optional and an absent one leaves the installed value alone
/// (TS 29.244 Table 7.5.4.4-1). An unknown URR ID is
/// `RULE_CREATION_MODIFICATION_FAILURE` rather than a silent no-op, matching how
/// Update PDR/FAR/QER already answer — creating it here would install a URR whose
/// unspecified members the SGW-C never provisioned.
fn process_update_urr(sess: &SgwuSess, req: &UpdateUrrRequest) -> Result<(), u8> {
    log::debug!("Updating URR: id={}", req.urr_id);
    let ctx = sgwu_self();
    let Some(mut urr) = ctx.urr_find(sess.id, req.urr_id) else {
        log::error!("Update URR: id={} not found", req.urr_id);
        return Err(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE);
    };
    if let Some(method) = req.measurement_method {
        urr.measurement_method = method;
    }
    if let Some(triggers) = req.reporting_triggers {
        urr.reporting_triggers = triggers;
    }
    if let Some(threshold) = req.volume_threshold {
        urr.volume_threshold = threshold;
    }
    if let Some(quota) = req.volume_quota {
        urr.volume_quota = quota;
    }
    if let Some(secs) = req.time_threshold {
        urr.time_threshold = Some(secs);
    }
    if let Some(secs) = req.measurement_period {
        urr.measurement_period = Some(secs);
    }
    // `urr_install` preserves the measured counters and the UR-SEQN for an id
    // already present, which is what makes this an update rather than a reset.
    if !ctx.urr_install(urr) {
        return Err(pfcp_cause::SYSTEM_FAILURE);
    }
    Ok(())
}

/// Process Remove URR (issue #215).
///
/// The removed URR's measured volume is **discarded**, deliberately: TS 29.244
/// §5.2.2.3 has the CP function ask for a final report by setting the
/// Query URR / Query All URRs IE on the Session Modification Request, and this
/// build parses neither. Emitting an unrequested report here would invent a
/// message the SGW-C did not ask for; discarding silently would lose volume. So it
/// is logged at `warn` with the amount, which is the honest middle — see the spec's
/// Ceilings.
fn process_remove_urr(sess: &SgwuSess, urr_id: u32) -> Result<(), u8> {
    log::debug!("Removing URR: id={urr_id}");
    let ctx = sgwu_self();
    let Some(urr) = ctx.urr_remove(sess.id, urr_id) else {
        log::error!("Remove URR: id={urr_id} not found");
        return Err(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE);
    };
    if urr.total_bytes > 0 || urr.total_packets > 0 {
        log::warn!(
            "Removed URR {urr_id} still held unreported usage: {} bytes / {} packets \
             (no Query URR support, so no final report is sent — see issue #215)",
            urr.total_bytes,
            urr.total_packets
        );
    }
    ctx.sess_unregister_urr(sess.id, urr_id);
    // #267: strip the id from every PDR naming it. Leaving it dangling meant
    // `urr_record` returned `None` for the missing key and `measure_and_report`'s
    // `continue` swallowed it -- that PDR was then measured by NOTHING, with no
    // warning. Worse, a later re-Create of the same id (which this build supports)
    // silently re-attached the old PDR to a rule the SGW-C may have re-scoped.
    let detached = ctx.pdr_detach_urr(sess.id, urr_id);
    if detached > 0 {
        log::debug!("URR {urr_id} detached from {detached} PDR(s)");
    }
    Ok(())
}

/// Build the Usage Report for a URR and advance its UR-SEQN, resetting the
/// measurement period (issue #215).
///
/// Returns `None` when the URR has gone — a concurrent Remove URR or session
/// deletion — rather than reporting on a stale snapshot.
pub fn take_usage_report(
    sess_id: u64,
    urr_id: u32,
    trigger: UsageReportTrigger,
) -> Option<crate::sxa_build::UsageReport> {
    let (urr, ur_seqn) = sgwu_self().urr_take_report(sess_id, urr_id)?;
    Some(usage_report_from(&urr, ur_seqn, trigger))
}

/// Render a URR snapshot as a Usage Report (TS 29.244 §7.5.8.3).
pub fn usage_report_from(
    urr: &SgwuUrr,
    ur_seqn: u32,
    trigger: UsageReportTrigger,
) -> crate::sxa_build::UsageReport {
    let now = now_unix_secs();
    let packets = urr.measured_packets();
    crate::sxa_build::UsageReport {
        urr_id: urr.urr_id,
        ur_seqn,
        trigger,
        volume: urr.measured_volume(),
        // #267: `Some(..)` unconditionally here made a DURAT-only URR emit a Volume
        // Measurement IE with flags 0x38 -- "measured, all zero" for a measurement
        // the CP function never provisioned. `measured_packets` returns all-`None`
        // when the URR does not measure volume. Both tests that claimed otherwise
        // bypassed THIS function, so reverting the old lines broke nothing.
        total_packets: packets.0,
        uplink_packets: packets.1,
        downlink_packets: packets.2,
        duration_secs: urr.measured_duration(now),
        start_time: Some(urr.start_time),
        end_time: Some(now),
        time_of_first_packet: urr.first_packet_time,
        time_of_last_packet: urr.last_packet_time,
    }
}

/// Process Create BAR
fn process_create_bar(sess: &SgwuSess, req: &CreateBarRequest) -> Result<(), u8> {
    log::debug!("Creating BAR: id={}", req.bar_id);
    let ctx = sgwu_self();
    if !ctx.bar_install(SgwuBar {
        sess_id: sess.id,
        bar_id: req.bar_id,
        downlink_data_notification_delay: req.downlink_data_notification_delay,
        dl_buffering_duration: req.dl_buffering_duration,
        dl_buffering_suggested_packet_count: req.dl_buffering_suggested_packet_count,
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
    // #267: re-point the measurement when the Update names URRs. Replaces rather
    // than merges: an Update PDR states the PDR's current shape, so merging would
    // leave an association the SGW-C removed still billing.
    if let Some(ref urr_ids) = req.urr_ids {
        log::debug!(
            "PDR {} URR association {:?} -> {:?}",
            pdr.pdr_id,
            pdr.urr_ids,
            urr_ids
        );
        pdr.urr_ids = urr_ids.clone();
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
        // Install the FAR the request updates. sgwu_self() is a process-global
        // shared across tests, so set up our own state rather than relying on
        // another test having created FAR (sess 1, id 1) — that ordering
        // dependency made this test pass or fail by test-execution order.
        sgwu_self().far_install(crate::context::SgwuFar {
            sess_id: sess.id,
            far_id: 1,
            ..Default::default()
        });
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
        let rsp = SessionReportResponse {
            cause: None,
            update_bar: None,
        };
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
            update_bar: None,
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
    // -----------------------------------------------------------------
    // #215: URR provisioning
    // -----------------------------------------------------------------

    /// A session in the CONTEXT (not just a local struct), so
    /// `sess_register_urr` has something to write `PfcpSess.urr_ids` on.
    fn ctx_sess(seid: u64) -> SgwuSess {
        let ctx = sgwu_self();
        ctx.set_gtpu_address(Some(Ipv4Addr::new(10, 0, 0, 99)));
        ctx.sess_add(&FSeid::with_ipv4(seid, Ipv4Addr::new(10, 0, 0, 1)))
            .expect("session added")
    }

    fn volume_urr(urr_id: u32, total_threshold: u64) -> CreateUrrRequest {
        CreateUrrRequest {
            urr_id,
            measurement_method: crate::context::measurement_method::VOLUME,
            reporting_triggers: crate::context::reporting_trigger::VOLUME_THRESHOLD,
            volume_threshold: Volume {
                total: Some(total_threshold),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// **Issue #215.** A Create URR at establishment installs the rule, links it to
    /// the PDR that names it, and populates `PfcpSess.urr_ids` **in production**.
    ///
    /// That field existed before this change and was written only by a unit test, so
    /// it described a capability the daemon did not have.
    #[test]
    fn create_urr_installs_the_rule_and_populates_sess_urr_ids() {
        let ctx = sgwu_self();
        let sess = ctx_sess(0x8100);

        let req = SessionEstablishmentRequest {
            create_urrs: vec![volume_urr(3, 1_000), volume_urr(4, 2_000)],
            create_fars: vec![CreateFarRequest {
                far_id: 1,
                apply_action: crate::context::apply_action::FORW,
                ..Default::default()
            }],
            create_pdrs: vec![CreatePdrRequest {
                pdr_id: 1,
                far_id: Some(1),
                urr_ids: vec![3, 4],
                ..Default::default()
            }],
            ..Default::default()
        };
        let (result, _) = handle_session_establishment_request(Some(&sess), 1, &req);
        assert!(matches!(result, HandlerResult::Ok), "{result:?}");

        // Both URRs installed, with their provisioning.
        let urr = ctx.urr_find(sess.id, 3).expect("URR 3 installed");
        assert!(urr.measures_volume());
        assert_eq!(urr.volume_threshold.total, Some(1_000));
        assert_eq!(
            ctx.urr_find(sess.id, 4).unwrap().volume_threshold.total,
            Some(2_000)
        );
        assert_eq!(ctx.urr_find_for_sess(sess.id).len(), 2);

        // The PDR carries the link, so a matched packet has something to bill.
        let pdr = ctx.pdr_find(sess.id, 1).expect("PDR installed");
        assert_eq!(pdr.urr_ids, vec![3, 4]);

        // And `PfcpSess.urr_ids` is populated in production.
        let stored = ctx.sess_find_by_id(sess.id).expect("session");
        assert_eq!(
            stored.pfcp.urr_ids,
            vec![3u64, 4u64],
            "PfcpSess.urr_ids must be written by the handler, not only by a test"
        );

        ctx.sess_remove(sess.id);
    }

    /// **Issue #215.** An Update URR changes provisioning and **keeps** the
    /// measurement; a Remove URR takes it out; an unknown id is rejected.
    ///
    /// The keep-the-measurement half is the one that matters: zeroing the counters on
    /// every reprovisioning would lose billable traffic in a way a charging function
    /// cannot detect.
    #[test]
    fn update_urr_keeps_the_measurement_and_remove_urr_takes_it_out() {
        let ctx = sgwu_self();
        let sess = ctx_sess(0x8200);

        let est = SessionEstablishmentRequest {
            create_urrs: vec![volume_urr(11, 1_000)],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_establishment_request(Some(&sess), 1, &est).0,
            HandlerResult::Ok
        ));
        // Measure something, and spend a UR-SEQN, so both are observable.
        ctx.urr_record(sess.id, 11, 400, true);
        ctx.urr_take_report(sess.id, 11);
        ctx.urr_record(sess.id, 11, 250, true);
        // #267 FLIP: asserted `total_bytes == 250`. `total_bytes` is now CUMULATIVE
        // (650) and the per-period figure is the delta, which is what a report
        // carries. Both are asserted so the model is unambiguous.
        assert_eq!(ctx.urr_find(sess.id, 11).unwrap().total_bytes, 650);
        assert_eq!(
            ctx.urr_find(sess.id, 11).unwrap().measured_volume().total,
            Some(250)
        );
        assert_eq!(ctx.urr_find(sess.id, 11).unwrap().next_ur_seqn, 1);

        // Update only the threshold.
        let modify = SessionModificationRequest {
            update_urrs: vec![UpdateUrrRequest {
                urr_id: 11,
                volume_threshold: Some(Volume {
                    total: Some(9_999),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &modify).0,
            HandlerResult::Ok
        ));
        let urr = ctx.urr_find(sess.id, 11).expect("still installed");
        assert_eq!(
            urr.volume_threshold.total,
            Some(9_999),
            "the update applied"
        );
        // #267 FLIP: asserted 250. `total_bytes` is CUMULATIVE now; the per-period
        // figure a report carries is the delta, asserted next.
        assert_eq!(
            urr.total_bytes, 650,
            "an Update URR must NOT reset the measured volume"
        );
        assert_eq!(
            urr.measured_volume().total,
            Some(250),
            "nor the unreported delta"
        );
        assert_eq!(
            urr.next_ur_seqn, 1,
            "nor restart the UR-SEQN, which the SGW-C uses to order reports"
        );
        assert!(
            urr.measures_volume(),
            "an unnamed Measurement Method must be left alone"
        );

        // An Update for an unknown id is a rule failure, not a silent create: a
        // created-here URR would have every unspecified member unprovisioned.
        let bad = SessionModificationRequest {
            update_urrs: vec![UpdateUrrRequest {
                urr_id: 99,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &bad).0,
            HandlerResult::Error(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE)
        ));

        // Remove takes it out of the store and off the session.
        let remove = SessionModificationRequest {
            remove_urrs: vec![11],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &remove).0,
            HandlerResult::Ok
        ));
        assert!(ctx.urr_find(sess.id, 11).is_none());
        assert!(ctx
            .sess_find_by_id(sess.id)
            .unwrap()
            .pfcp
            .urr_ids
            .is_empty());
        // And removing it again is a rule failure rather than a silent success.
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &remove).0,
            HandlerResult::Error(pfcp_cause::RULE_CREATION_MODIFICATION_FAILURE)
        ));

        ctx.sess_remove(sess.id);
    }

    /// **Issue #215.** A **re-Create** URR for an id already installed keeps the
    /// measurement and the UR-SEQN.
    ///
    /// This is the case `urr_install`'s carry-over exists for, and it is NOT the same
    /// as the Update case above: `process_update_urr` reads the existing URR first,
    /// so it would survive a carry-over-free `urr_install` — reverting the carry-over
    /// broke no test until this one was added, which is exactly the false-guard shape
    /// the #210 session recorded. A re-Create starts from a fresh request, so only
    /// the store can protect the counters.
    #[test]
    fn re_creating_an_existing_urr_keeps_the_measurement() {
        let ctx = sgwu_self();
        let sess = ctx_sess(0x8600);

        let est = SessionEstablishmentRequest {
            create_urrs: vec![volume_urr(51, 1_000)],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_establishment_request(Some(&sess), 1, &est).0,
            HandlerResult::Ok
        ));
        ctx.urr_record(sess.id, 51, 600, true);
        ctx.urr_take_report(sess.id, 51);
        ctx.urr_record(sess.id, 51, 150, false);
        // #267 FLIP: cumulative, with the unreported delta alongside it.
        assert_eq!(ctx.urr_find(sess.id, 51).unwrap().total_bytes, 750);
        assert_eq!(
            ctx.urr_find(sess.id, 51).unwrap().measured_volume().total,
            Some(150)
        );
        assert_eq!(ctx.urr_find(sess.id, 51).unwrap().next_ur_seqn, 1);

        // A Session Modification re-Creating URR 51 with a new threshold.
        let modify = SessionModificationRequest {
            create_urrs: vec![volume_urr(51, 5_000)],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &modify).0,
            HandlerResult::Ok
        ));
        let urr = ctx.urr_find(sess.id, 51).expect("still installed");
        assert_eq!(urr.volume_threshold.total, Some(5_000), "re-provisioned");
        assert_eq!(
            urr.total_bytes, 750,
            "a re-Create must NOT zero the measured volume: that would lose billable \
             traffic on every reprovisioning, undetectably"
        );
        assert_eq!(
            urr.measured_volume().total,
            Some(150),
            "nor the unreported delta"
        );
        assert_eq!(
            urr.next_ur_seqn, 1,
            "nor restart the UR-SEQN the SGW-C orders reports by"
        );
        // And the session's id list is not duplicated.
        assert_eq!(
            ctx.sess_find_by_id(sess.id).unwrap().pfcp.urr_ids,
            vec![51u64]
        );

        ctx.sess_remove(sess.id);
    }

    /// **Issue #267.** An Update PDR can re-point the measurement, and a Remove URR
    /// leaves no dangling association behind.
    ///
    /// Both gaps were silent. `UpdatePdrRequest` had no `urr_ids`, so an SGW-C moving
    /// a bearer from URR 3 to URR 4 got `Ok` and the SGW-U kept billing URR 3. And
    /// `process_remove_urr` left the id on the PDR, so `urr_record` returned `None`
    /// for the missing key, `measure_and_report`'s `continue` swallowed it, and that
    /// PDR was measured by NOTHING -- until a re-Create of the same id silently
    /// re-attached it.
    #[test]
    fn update_pdr_repoints_the_urr_and_remove_urr_detaches_it() {
        let ctx = sgwu_self();
        let sess = ctx_sess(0x8700);

        let est = SessionEstablishmentRequest {
            create_urrs: vec![volume_urr(3, 1_000), volume_urr(4, 1_000)],
            create_fars: vec![CreateFarRequest {
                far_id: 1,
                apply_action: crate::context::apply_action::FORW,
                ..Default::default()
            }],
            create_pdrs: vec![CreatePdrRequest {
                pdr_id: 1,
                far_id: Some(1),
                urr_ids: vec![3],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_establishment_request(Some(&sess), 1, &est).0,
            HandlerResult::Ok
        ));
        assert_eq!(ctx.pdr_find(sess.id, 1).unwrap().urr_ids, vec![3]);

        // Re-point 3 -> 4. Replaces rather than merges: an Update states the PDR's
        // current shape, so a merge would leave URR 3 still billing.
        let modify = SessionModificationRequest {
            update_pdrs: vec![UpdatePdrRequest {
                pdr_id: 1,
                urr_ids: Some(vec![4]),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &modify).0,
            HandlerResult::Ok
        ));
        assert_eq!(
            ctx.pdr_find(sess.id, 1).unwrap().urr_ids,
            vec![4],
            "the measurement must move, not accumulate"
        );

        // An Update naming no URRs leaves the association alone.
        let modify = SessionModificationRequest {
            update_pdrs: vec![UpdatePdrRequest {
                pdr_id: 1,
                urr_ids: None,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &modify).0,
            HandlerResult::Ok
        ));
        assert_eq!(ctx.pdr_find(sess.id, 1).unwrap().urr_ids, vec![4]);

        // Removing URR 4 detaches it from the PDR, so nothing dangles.
        let remove = SessionModificationRequest {
            remove_urrs: vec![4],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &remove).0,
            HandlerResult::Ok
        ));
        assert!(
            ctx.pdr_find(sess.id, 1).unwrap().urr_ids.is_empty(),
            "a removed URR must not be left dangling on the PDR"
        );

        // And re-Creating id 4 does NOT silently re-attach the old PDR.
        let recreate = SessionModificationRequest {
            create_urrs: vec![volume_urr(4, 2_000)],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &recreate).0,
            HandlerResult::Ok
        ));
        assert!(
            ctx.pdr_find(sess.id, 1).unwrap().urr_ids.is_empty(),
            "a re-Created id must not resurrect an association the SGW-C removed"
        );

        ctx.sess_remove(sess.id);
    }

    /// **Issue #267.** A trigger outside octet 5 is reachable.
    ///
    /// `trigger_set` cast the 16-bit Reporting Triggers down to `u8`, so every
    /// octet-6/7 trigger was structurally unreachable -- and the `VOLUME_QUOTA`
    /// constant was declared as an octet-5 bit, which made the truncation invisible.
    /// The two defects hid each other.
    #[test]
    fn a_trigger_in_the_high_octet_is_reachable() {
        use crate::context::reporting_trigger;
        let ctx = sgwu_self();
        let sess = ctx_sess(0x8800);

        // VOLQU only -- octet 6 bit 1, i.e. the high byte of the field.
        let mut urr = volume_urr(61, 0);
        urr.reporting_triggers = reporting_trigger::VOLUME_QUOTA;
        urr.volume_quota = Volume {
            total: Some(100),
            ..Default::default()
        };
        urr.volume_threshold = Volume::default();
        let est = SessionEstablishmentRequest {
            create_urrs: vec![urr],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_establishment_request(Some(&sess), 1, &est).0,
            HandlerResult::Ok
        ));
        // VOLQU must live in the HIGH octet or this test proves nothing about the
        // truncation. A const assertion, because it is a compile-time fact: moving it
        // back to octet 5 fails the build here rather than silently weakening the test.
        const _: () = assert!(reporting_trigger::VOLUME_QUOTA > 0xFF);
        let (snapshot, _) = ctx
            .urr_record(sess.id, 61, 150, true)
            .expect("a high-octet trigger must be reachable");
        assert!(snapshot.fired_trigger.volume_quota);

        ctx.sess_remove(sess.id);
    }

    /// **Issue #215.** Session deletion produces one final Usage Report per URR,
    /// tagged TEBUR, and drains the store.
    ///
    /// A URR that measured nothing still reports: a zero report and no report are
    /// different statements, and only the first says "this rule was installed and saw
    /// no traffic".
    #[test]
    fn session_deletion_produces_a_final_usage_report_per_urr() {
        let ctx = sgwu_self();
        let sess = ctx_sess(0x8300);

        let est = SessionEstablishmentRequest {
            create_urrs: vec![volume_urr(21, 1_000_000), volume_urr(22, 1_000_000)],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_establishment_request(Some(&sess), 1, &est).0,
            HandlerResult::Ok
        ));
        ctx.urr_record(sess.id, 21, 700, true);
        ctx.urr_record(sess.id, 21, 300, false);
        // URR 22 sees no traffic at all.

        let reports = take_final_usage_reports(sess.id);
        assert_eq!(reports.len(), 2, "one report per URR, ordered by URR ID");
        assert_eq!(reports[0].urr_id, 21);
        assert_eq!(reports[1].urr_id, 22);
        assert!(
            reports.iter().all(|r| r.trigger.termination_report),
            "the final report is TEBUR: termination by the UP function"
        );
        assert_eq!(reports[0].volume.total, Some(1_000));
        assert_eq!(reports[0].volume.uplink, Some(700));
        assert_eq!(reports[0].volume.downlink, Some(300));
        assert_eq!(reports[0].total_packets, Some(2));
        assert_eq!(
            reports[1].volume.total,
            Some(0),
            "an idle URR reports zero rather than not reporting"
        );

        // The store is drained, so a second call cannot double-report.
        assert!(ctx.urr_find_for_sess(sess.id).is_empty());
        assert!(take_final_usage_reports(sess.id).is_empty());

        ctx.sess_remove(sess.id);
    }

    /// **Issue #215.** A threshold is only reportable when the SGW-C asked for that
    /// trigger (TS 29.244 §8.2.41).
    ///
    /// Reporting on a provisioned threshold whose trigger bit is clear would report
    /// where the CP function asked for silence.
    #[test]
    fn a_threshold_without_its_trigger_bit_does_not_report() {
        let ctx = sgwu_self();
        let sess = ctx_sess(0x8400);

        let mut urr = volume_urr(31, 100);
        urr.reporting_triggers = 0; // threshold provisioned, trigger NOT requested
        let est = SessionEstablishmentRequest {
            create_urrs: vec![urr],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_establishment_request(Some(&sess), 1, &est).0,
            HandlerResult::Ok
        ));
        // Well past the threshold, and still not reportable.
        assert!(ctx.urr_record(sess.id, 31, 5_000, true).is_none());
        assert_eq!(ctx.urr_find(sess.id, 31).unwrap().total_bytes, 5_000);

        // Turning the trigger on makes the same state reportable.
        let modify = SessionModificationRequest {
            update_urrs: vec![UpdateUrrRequest {
                urr_id: 31,
                reporting_triggers: Some(crate::context::reporting_trigger::VOLUME_THRESHOLD),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_modification_request(Some(&sess), 1, &modify).0,
            HandlerResult::Ok
        ));
        let (snapshot, _seqn) = ctx
            .urr_record(sess.id, 31, 1, true)
            .expect("now reportable");
        assert!(snapshot.fired_trigger.volume_threshold);

        ctx.sess_remove(sess.id);
    }

    /// **Issue #215.** A duration-only URR does not accumulate volume.
    ///
    /// Reporting a Volume Measurement the CP function never asked to measure would
    /// put a number in a CDR that no provisioning justifies.
    #[test]
    fn a_duration_only_urr_measures_no_volume() {
        let ctx = sgwu_self();
        let sess = ctx_sess(0x8500);

        let est = SessionEstablishmentRequest {
            create_urrs: vec![CreateUrrRequest {
                urr_id: 41,
                measurement_method: crate::context::measurement_method::DURATION,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(
            handle_session_establishment_request(Some(&sess), 1, &est).0,
            HandlerResult::Ok
        ));
        ctx.urr_record(sess.id, 41, 5_000, true);
        let urr = ctx.urr_find(sess.id, 41).expect("installed");
        assert_eq!(urr.total_bytes, 0, "DURAT-only must not count volume");
        assert_eq!(urr.total_packets, 1, "packet counts are kept regardless");
        assert!(
            !urr.measured_volume().is_set(),
            "so no Volume Measurement IE"
        );
        assert!(urr.measured_duration(now_unix_secs()).is_some());

        ctx.sess_remove(sess.id);
    }
}
