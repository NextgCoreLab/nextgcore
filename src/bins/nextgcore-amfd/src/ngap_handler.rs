//! NGAP Message Handling
//!
//! Port of src/amf/ngap-handler.c - NGAP message handling functions

use crate::context::{
    AmfContext, AmfGnb, NgapCause, NrCgi, PlmnId, SNssai, SupportedTa, Tai5gs,
    UavAuthorizationContext,
};
use crate::sbi_path;
use nextgcore_ngap::types::{NgReset, ResetType, UeAssociatedLogicalNgConnectionItem};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of cells in reset
pub const MAX_NUM_OF_CELLS_IN_RESET: usize = 256;

/// NGAP cause groups (TS 38.413 Section 9.3.1.2)
pub mod cause_group {
    pub const RADIO_NETWORK: u8 = 0;
    pub const TRANSPORT: u8 = 1;
    pub const NAS: u8 = 2;
    pub const PROTOCOL: u8 = 3;
    pub const MISC: u8 = 4;
}

/// NGAP CauseRadioNetwork values (TS 38.413 Section 9.3.1.2)
pub mod radio_network_cause {
    pub const UNSPECIFIED: i64 = 0;
    pub const TXNRELOCOVERALL_EXPIRY: i64 = 1;
    pub const SUCCESSFUL_HANDOVER: i64 = 2;
    pub const RELEASE_DUE_TO_NGRAN_GENERATED_REASON: i64 = 3;
    pub const RELEASE_DUE_TO_5GC_GENERATED_REASON: i64 = 4;
    pub const HANDOVER_CANCELLED: i64 = 5;
    pub const PARTIAL_HANDOVER: i64 = 6;
    pub const HO_FAILURE_IN_TARGET_5GC_NGRAN_NODE_OR_TARGET_SYSTEM: i64 = 7;
    pub const HO_TARGET_NOT_ALLOWED: i64 = 8;
    pub const TNGRELOCOVERALL_EXPIRY: i64 = 9;
    pub const TNGRELOCPREP_EXPIRY: i64 = 10;
    pub const CELL_NOT_AVAILABLE: i64 = 11;
    pub const UNKNOWN_TARGET_ID: i64 = 12;
    pub const NO_RADIO_RESOURCES_AVAILABLE_IN_TARGET_CELL: i64 = 13;
    pub const UNKNOWN_LOCAL_UE_NGAP_ID: i64 = 14;
    pub const INCONSISTENT_REMOTE_UE_NGAP_ID: i64 = 15;
    pub const HANDOVER_DESIRABLE_FOR_RADIO_REASON: i64 = 16;
    pub const TIME_CRITICAL_HANDOVER: i64 = 17;
    pub const RESOURCE_OPTIMISATION_HANDOVER: i64 = 18;
    pub const REDUCE_LOAD_IN_SERVING_CELL: i64 = 19;
    pub const USER_INACTIVITY: i64 = 20;
    pub const RADIO_CONNECTION_WITH_UE_LOST: i64 = 21;
    pub const RADIO_RESOURCES_NOT_AVAILABLE: i64 = 22;
    pub const INVALID_QOS_COMBINATION: i64 = 23;
    pub const FAILURE_IN_RADIO_INTERFACE_PROCEDURE: i64 = 24;
    pub const INTERACTION_WITH_OTHER_PROCEDURE: i64 = 25;
    pub const UNKNOWN_PDU_SESSION_ID: i64 = 26;
    pub const UNKNOWN_QOS_FLOW_ID: i64 = 27;
    pub const MULTIPLE_PDU_SESSION_ID_INSTANCES: i64 = 28;
    pub const MULTIPLE_QOS_FLOW_ID_INSTANCES: i64 = 29;
    pub const ENCRYPTION_AND_OR_INTEGRITY_PROTECTION_ALGORITHMS_NOT_SUPPORTED: i64 = 30;
    pub const NG_INTRA_SYSTEM_HANDOVER_TRIGGERED: i64 = 31;
    pub const NG_INTER_SYSTEM_HANDOVER_TRIGGERED: i64 = 32;
    pub const XN_HANDOVER_TRIGGERED: i64 = 33;
    pub const NOT_SUPPORTED_5QI_VALUE: i64 = 34;
    pub const UE_CONTEXT_TRANSFER: i64 = 35;
    pub const IMS_VOICE_EPS_FALLBACK_OR_RAT_FALLBACK_TRIGGERED: i64 = 36;
    pub const UP_INTEGRITY_PROTECTION_NOT_POSSIBLE: i64 = 37;
    pub const UP_CONFIDENTIALITY_PROTECTION_NOT_POSSIBLE: i64 = 38;
    pub const SLICE_NOT_SUPPORTED: i64 = 39;
    pub const UE_IN_RRC_INACTIVE_STATE_NOT_REACHABLE: i64 = 40;
    pub const REDIRECTION: i64 = 41;
    pub const RESOURCES_NOT_AVAILABLE_FOR_THE_SLICE: i64 = 42;
    pub const UE_MAX_INTEGRITY_PROTECTED_DATA_RATE_REASON: i64 = 43;
    pub const RELEASE_DUE_TO_CN_DETECTED_MOBILITY: i64 = 44;
}

/// NGAP CauseProtocol values (TS 38.413 Section 9.3.1.2)
pub mod protocol_cause {
    pub const TRANSFER_SYNTAX_ERROR: i64 = 0;
    pub const ABSTRACT_SYNTAX_ERROR_REJECT: i64 = 1;
    pub const ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY: i64 = 2;
    pub const MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE: i64 = 3;
    pub const SEMANTIC_ERROR: i64 = 4;
    pub const ABSTRACT_SYNTAX_ERROR_FALSELY_CONSTRUCTED_MESSAGE: i64 = 5;
    pub const UNSPECIFIED: i64 = 6;
}

/// NGAP CauseMisc values (TS 38.413 Section 9.3.1.2)
pub mod misc_cause {
    pub const CONTROL_PROCESSING_OVERLOAD: i64 = 0;
    pub const NOT_ENOUGH_USER_PLANE_PROCESSING_RESOURCES: i64 = 1;
    pub const HARDWARE_FAILURE: i64 = 2;
    pub const OM_INTERVENTION: i64 = 3;
    pub const UNKNOWN_PLMN_OR_SNPN: i64 = 4;
    pub const UNSPECIFIED: i64 = 5;
}

/// Time to wait values (in seconds)
pub mod time_to_wait {
    pub const V1S: u8 = 0;
    pub const V2S: u8 = 1;
    pub const V5S: u8 = 2;
    pub const V10S: u8 = 3;
    pub const V20S: u8 = 4;
    pub const V60S: u8 = 5;
}

// ============================================================================
// Parsed Message Structures
// ============================================================================

/// Parsed NG Setup Request
#[derive(Debug, Clone, Default)]
pub struct NgSetupRequest {
    /// Global RAN Node ID present
    pub global_ran_node_id_present: bool,
    /// gNB ID
    pub gnb_id: u32,
    /// gNB ID length (in bits)
    pub gnb_id_len: u8,
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// RAN Node Name
    pub ran_node_name: Option<String>,
    /// Supported TA List
    pub supported_ta_list: Vec<SupportedTa>,
    /// Default Paging DRX
    pub default_paging_drx: u8,
}

/// Parsed Initial UE Message
#[derive(Debug, Clone, Default)]
pub struct InitialUeMessage {
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// NAS PDU
    pub nas_pdu: Vec<u8>,
    /// User Location Information present
    pub user_location_present: bool,
    /// NR TAI
    pub nr_tai: Tai5gs,
    /// NR CGI
    pub nr_cgi: NrCgi,
    /// RRC Establishment Cause
    pub rrc_establishment_cause: u8,
    /// UE Context Request
    pub ue_context_request: bool,
    /// 5G-S-TMSI present
    pub five_g_s_tmsi_present: bool,
    /// AMF Set ID
    pub amf_set_id: u16,
    /// AMF Pointer
    pub amf_pointer: u8,
    /// 5G-TMSI
    pub tmsi: u32,
}

/// Parsed Uplink NAS Transport
#[derive(Debug, Clone, Default)]
pub struct UplinkNasTransport {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// NAS PDU
    pub nas_pdu: Vec<u8>,
    /// User Location Information present
    pub user_location_present: bool,
    /// NR TAI
    pub nr_tai: Tai5gs,
    /// NR CGI
    pub nr_cgi: NrCgi,
}

/// Parsed UE Context Release Request
#[derive(Debug, Clone, Default)]
pub struct UeContextReleaseRequest {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// Cause
    pub cause: NgapCause,
    /// PDU Session Resource List to Release
    pub pdu_session_list: Vec<u8>,
}

/// Parsed UE Context Release Complete
#[derive(Debug, Clone, Default)]
pub struct UeContextReleaseComplete {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// User Location Information present
    pub user_location_present: bool,
    /// NR TAI
    pub nr_tai: Tai5gs,
    /// NR CGI
    pub nr_cgi: NrCgi,
}

/// Parsed Initial Context Setup Response
#[derive(Debug, Clone, Default)]
pub struct InitialContextSetupResponse {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// PDU Session Resource Setup Response List
    pub pdu_session_setup_list: Vec<PduSessionSetupItem>,
    /// PDU Session Resource Failed to Setup List
    pub pdu_session_failed_list: Vec<PduSessionFailedItem>,
}

/// Parsed Initial Context Setup Failure
#[derive(Debug, Clone, Default)]
pub struct InitialContextSetupFailure {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// Cause
    pub cause: NgapCause,
}

/// PDU Session Setup Item
#[derive(Debug, Clone, Default)]
pub struct PduSessionSetupItem {
    /// PDU Session ID
    pub psi: u8,
    /// Transfer data
    pub transfer: Vec<u8>,
}

/// PDU Session Failed Item
#[derive(Debug, Clone, Default)]
pub struct PduSessionFailedItem {
    /// PDU Session ID
    pub psi: u8,
    /// Cause
    pub cause: NgapCause,
    /// Transfer data
    pub transfer: Vec<u8>,
}

/// Parsed Handover Required
#[derive(Debug, Clone, Default)]
pub struct HandoverRequired {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// Handover Type
    pub handover_type: u8,
    /// Cause
    pub cause: NgapCause,
    /// Target ID (TAI + Cell ID)
    pub target_tai: Tai5gs,
    pub target_cell_id: u64,
    /// Source to Target Transparent Container
    pub source_to_target_container: Vec<u8>,
}

/// Parsed Handover Request Acknowledge
#[derive(Debug, Clone, Default)]
pub struct HandoverRequestAck {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// Target to Source Transparent Container
    pub target_to_source_container: Vec<u8>,
    /// PDU Session Resource Admitted List
    pub pdu_session_admitted_list: Vec<PduSessionSetupItem>,
}

/// Parsed Path Switch Request
#[derive(Debug, Clone, Default)]
pub struct PathSwitchRequest {
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// Source AMF UE NGAP ID
    pub source_amf_ue_ngap_id: u64,
    /// User Location Information
    pub nr_tai: Tai5gs,
    pub nr_cgi: NrCgi,
    /// UE Security Capabilities
    pub ue_security_capabilities: Option<UeSecurityCapabilities>,
    /// PDU Session Resource to be Switched List
    pub pdu_session_list: Vec<PduSessionSetupItem>,
}

/// UE Security Capabilities from NGAP
#[derive(Debug, Clone, Default)]
pub struct UeSecurityCapabilities {
    /// NR encryption algorithms
    pub nr_encryption: u16,
    /// NR integrity algorithms
    pub nr_integrity: u16,
    /// E-UTRA encryption algorithms
    pub eutra_encryption: u16,
    /// E-UTRA integrity algorithms
    pub eutra_integrity: u16,
}

// ============================================================================
// Handler Result Types
// ============================================================================

/// Result of handling an NGAP message
#[derive(Debug, Clone)]
pub enum NgapHandlerResult {
    /// Success
    Success,
    /// Success with response message
    SuccessWithResponse(Vec<u8>),
    /// Failure with cause
    Failure(NgapCause),
    /// Need to send NAS message
    SendNas(Vec<u8>),
    /// Need to release UE context
    ReleaseUeContext(NgapCause),
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Handle NG Setup Request
pub fn handle_ng_setup_request(
    gnb: &mut AmfGnb,
    ctx: &AmfContext,
    request: &NgSetupRequest,
) -> NgapHandlerResult {
    log::info!("[{}] NG Setup Request from gNB", gnb.addr);

    // Validate Global RAN Node ID
    if !request.global_ran_node_id_present {
        log::error!("No Global RAN Node ID");
        // Missing mandatory IE -> Cause: Protocol / semantic-error (TS 38.413 Section 9.3.1.2)
        return NgapHandlerResult::Failure(NgapCause {
            group: cause_group::PROTOCOL,
            cause: protocol_cause::SEMANTIC_ERROR,
        });
    }

    // Store gNB ID
    gnb.gnb_id = request.gnb_id;
    gnb.gnb_id_presence = true;
    gnb.plmn_id = request.plmn_id.clone();

    // Validate Supported TA List
    if request.supported_ta_list.is_empty() {
        log::error!("No Supported TA List");
        // Missing mandatory IE -> Cause: Protocol / semantic-error (TS 38.413 Section 9.3.1.2)
        return NgapHandlerResult::Failure(NgapCause {
            group: cause_group::PROTOCOL,
            cause: protocol_cause::SEMANTIC_ERROR,
        });
    }

    // Check if any TAI is served by this AMF
    let mut tai_match_found = false;
    for supported_ta in &request.supported_ta_list {
        for bplmn in &supported_ta.bplmn_list {
            let tai = Tai5gs {
                plmn_id: bplmn.plmn_id.clone(),
                tac: supported_ta.tac,
            };
            if ctx.find_served_tai(&tai).is_some() {
                tai_match_found = true;
                break;
            }
        }
        if tai_match_found {
            break;
        }
    }

    if !tai_match_found {
        log::error!("No matching TAI found");
        // No served TAI overlap -> Cause: Misc / unknown-PLMN-or-SNPN (TS 38.413 Section 9.3.1.2)
        return NgapHandlerResult::Failure(NgapCause {
            group: cause_group::MISC,
            cause: misc_cause::UNKNOWN_PLMN_OR_SNPN,
        });
    }

    // Store Supported TA List
    gnb.supported_ta_list = request.supported_ta_list.clone();
    gnb.num_of_supported_ta_list = request.supported_ta_list.len();

    // Mark NG Setup as successful
    gnb.state.ng_setup_success = true;

    log::info!("[{}] NG Setup successful, gNB ID: {}", gnb.addr, gnb.gnb_id);

    NgapHandlerResult::Success
}

/// The gNB-initiated handlers that used to sit here (Initial UE Message,
/// Uplink NAS Transport, UE Context Release Request/Complete, Initial Context
/// Setup Response/Failure, the handover and path-switch handlers, AN release and
/// Error Indication) were **deleted, not moved**: `ngap_path.rs` reimplements
/// every one of them on its `ProcessNgap` impl, and the NGAP dispatch has only
/// ever called those. Nothing referenced the copies here except their own tests,
/// which passed and proved nothing about the code that actually runs.
///
/// What remains in this module is live: `handle_ng_setup_request`,
/// `handle_ng_reset` and `handle_uav_tracking_report` are called from
/// `ngap_path.rs` / `ngap_sm.rs`, and the cause-group constants are used across
/// the crate.
/// Handle NG Reset from a gNB (TS 38.413 Section 8.7.4.2)
///
/// Releases the UE contexts affected by the reset and returns the list of
/// UE-associated logical NG-connections to echo back in NG Reset Acknowledge.
/// A full NG-interface reset returns `None` (no connection list in the Ack);
/// a partial reset returns the received list per Section 8.7.4.2.2.
pub fn handle_ng_reset(
    gnb_pool_id: u64,
    reset: &NgReset,
) -> Option<Vec<UeAssociatedLogicalNgConnectionItem>> {
    log::info!(
        "[gNB pool id:{}] NG Reset received, cause: {:?}",
        gnb_pool_id,
        reset.cause
    );

    let amf_ctx = crate::context::amf_self();
    let Ok(context) = amf_ctx.read() else {
        log::error!("AMF context lock poisoned while handling NG Reset");
        return None;
    };

    match &reset.reset_type {
        ResetType::NgInterface => {
            // Release every UE-associated logical NG-connection on this gNB
            let affected = context.ran_ue_list_for_gnb(gnb_pool_id);
            log::info!(
                "NG Reset (NG interface): releasing {} UE context(s)",
                affected.len()
            );
            for ran_ue in &affected {
                trigger_smf_session_release_for_ue(ran_ue.amf_ue_id);
            }
            context.ran_ue_remove_all_for_gnb(gnb_pool_id);
            None
        }
        ResetType::PartOfNgInterface(connections) => {
            log::info!(
                "NG Reset (part of NG interface): {} connection(s) listed",
                connections.len()
            );
            for item in connections {
                let ran_ue = item
                    .amf_ue_ngap_id
                    .and_then(|id| context.ran_ue_find_by_amf_ue_ngap_id(id))
                    .or_else(|| {
                        item.ran_ue_ngap_id.and_then(|id| {
                            context.ran_ue_find_by_ran_ue_ngap_id(gnb_pool_id, id as u64)
                        })
                    });
                if let Some(ran_ue) = ran_ue {
                    trigger_smf_session_release_for_ue(ran_ue.amf_ue_id);
                    context.ran_ue_remove(ran_ue.id);
                } else {
                    log::warn!(
                        "NG Reset: no UE context for AMF-UE-NGAP-ID={:?}, RAN-UE-NGAP-ID={:?}",
                        item.amf_ue_ngap_id,
                        item.ran_ue_ngap_id
                    );
                }
            }
            // Echo the received list in the acknowledge (Section 8.7.4.2.2)
            Some(connections.clone())
        }
    }
}

// ============================================================================
// Rel-18 UAV Support (TS 23.256)
// ============================================================================

/// Parsed UAV Tracking Report
#[derive(Debug, Clone, Default)]
pub struct UavTrackingReport {
    /// AMF UE NGAP ID
    pub amf_ue_ngap_id: u64,
    /// RAN UE NGAP ID
    pub ran_ue_ngap_id: u64,
    /// UAV ID (UAVID)
    pub uav_id: String,
    /// Current latitude (decimal degrees)
    pub latitude: f64,
    /// Current longitude (decimal degrees)
    pub longitude: f64,
    /// Current altitude (meters)
    pub altitude: f64,
    /// Timestamp of position report
    pub timestamp: u64,
    /// Flight status (0=grounded, 1=flying, 2=emergency)
    pub flight_status: u8,
}

/// Handle UAV Tracking Report (Rel-18 TS 23.256)
///
/// Processes a position update from a UAV UE and checks it against the UAV
/// authorization context's geofence. Returns `true` when the position is
/// allowed (within the geofence and still authorized) and `false` on a
/// geofence violation; on a violation the caller revokes authorization and
/// notifies the USS/UTM and PCF. This is invoked from the live NGAP uplink
/// dispatch (see `ngap_path::handle_uav_tracking_report_nas`).
pub fn handle_uav_tracking_report(
    uav_auth: &mut UavAuthorizationContext,
    report: &UavTrackingReport,
    now: u64,
) -> bool {
    log::info!(
        "[UAV Tracking] Report received: UAV ID={}, position=({:.6}, {:.6}), altitude={:.1}m, status={}",
        report.uav_id,
        report.latitude,
        report.longitude,
        report.altitude,
        report.flight_status
    );

    // Run the geofence: update_position returns true when within bounds.
    let within_bounds = uav_auth.update_position(
        report.latitude,
        report.longitude,
        report.altitude,
        report.timestamp,
    );

    if within_bounds && uav_auth.is_authorized(now) {
        log::info!(
            "[UAV Tracking] Position update processed for UAV ID={} at ({:.6}, {:.6}), alt={:.1}m",
            report.uav_id,
            report.latitude,
            report.longitude,
            report.altitude
        );
        true
    } else {
        false
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if TAI is served by AMF
pub fn is_tai_served(ctx: &AmfContext, tai: &Tai5gs) -> bool {
    ctx.find_served_tai(tai).is_some()
}

/// Check if S-NSSAI is supported for PLMN
pub fn is_s_nssai_supported(ctx: &AmfContext, plmn_id: &PlmnId, s_nssai: &SNssai) -> bool {
    ctx.find_s_nssai(plmn_id, s_nssai).is_some()
}

/// Parse cause from NGAP message
pub fn parse_cause(group: u8, value: i64) -> NgapCause {
    NgapCause {
        group,
        cause: value,
    }
}

/// Fire-and-forget: release all SMF PDU sessions for the given AMF UE.
///
/// Called after UE Context Release to clean up Nsmf_PDUSession contexts.
/// Sessions without an sm_context_ref are silently skipped.
fn trigger_smf_session_release_for_ue(amf_ue_id: u64) {
    let amf_ctx = crate::context::amf_self();

    // Resolve SMF endpoint first; if unavailable, nothing to do.
    let (smf_host, smf_port) = match sbi_path::resolve_smf_endpoint() {
        Ok(ep) => ep,
        Err(e) => {
            log::debug!("SMF endpoint not resolved, skipping session cleanup: {e}");
            return;
        }
    };

    let sessions = {
        let ctx = match amf_ctx.read() {
            Ok(c) => c,
            Err(_) => return,
        };
        // Collect sm_context_ref for sessions that have a live SMF context
        ctx.sess_list_for_ue(amf_ue_id)
            .into_iter()
            .filter_map(|sess| sess.sm_context_ref.clone())
            .collect::<Vec<_>>()
    };

    for sm_context_ref in sessions {
        let host = smf_host.clone();
        let port = smf_port;
        tokio::spawn(async move {
            if let Err(e) =
                sbi_path::call_smf_release_sm_context(&host, port, &sm_context_ref).await
            {
                log::warn!("SMF SM Context Release failed for ref={sm_context_ref}: {e}");
            }
        });
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{AmfId, BplmnEntry};

    fn create_test_context() -> AmfContext {
        let mut ctx = AmfContext::new();
        ctx.num_of_served_guami = 1;
        ctx.served_guami.push(crate::context::Guami {
            plmn_id: PlmnId::new("001", "01"),
            amf_id: AmfId {
                region: 1,
                set: 1,
                pointer: 1,
            },
        });
        ctx.num_of_served_tai = 1;
        ctx.served_tai.push(crate::context::ServedTai {
            list0: crate::context::Tai0List {
                plmn_id: PlmnId::new("001", "01"),
                tac: vec![1],
            },
            ..Default::default()
        });
        ctx.num_of_plmn_support = 1;
        ctx.plmn_support.push(crate::context::PlmnSupport {
            plmn_id: PlmnId::new("001", "01"),
            num_of_s_nssai: 1,
            s_nssai: vec![SNssai { sst: 1, sd: None }],
        });
        ctx
    }

    fn create_test_gnb() -> AmfGnb {
        AmfGnb::new(1, "192.168.0.1:38412")
    }

    #[test]
    fn test_handle_ng_setup_request_success() {
        let ctx = create_test_context();
        let mut gnb = create_test_gnb();

        let request = NgSetupRequest {
            global_ran_node_id_present: true,
            gnb_id: 12345,
            gnb_id_len: 22,
            plmn_id: PlmnId::new("001", "01"),
            ran_node_name: Some("gNB-Test".to_string()),
            supported_ta_list: vec![SupportedTa {
                tac: 1,
                num_of_bplmn_list: 1,
                bplmn_list: vec![BplmnEntry {
                    plmn_id: PlmnId::new("001", "01"),
                    num_of_s_nssai: 1,
                    s_nssai: vec![SNssai { sst: 1, sd: None }],
                }],
            }],
            default_paging_drx: 0,
        };

        let result = handle_ng_setup_request(&mut gnb, &ctx, &request);

        match result {
            NgapHandlerResult::Success => {
                assert!(gnb.gnb_id_presence);
                assert_eq!(gnb.gnb_id, 12345);
                assert!(gnb.state.ng_setup_success);
            }
            _ => panic!("Expected Success"),
        }
    }

    #[test]
    fn test_handle_ng_setup_request_no_global_ran_node_id() {
        let ctx = create_test_context();
        let mut gnb = create_test_gnb();

        let request = NgSetupRequest {
            global_ran_node_id_present: false,
            ..Default::default()
        };

        let result = handle_ng_setup_request(&mut gnb, &ctx, &request);

        match result {
            NgapHandlerResult::Failure(_) => {}
            _ => panic!("Expected Failure"),
        }
    }

    #[test]
    fn test_handle_ng_setup_request_no_matching_tai() {
        let ctx = create_test_context();
        let mut gnb = create_test_gnb();

        let request = NgSetupRequest {
            global_ran_node_id_present: true,
            gnb_id: 12345,
            plmn_id: PlmnId::new("002", "02"), // Different PLMN
            supported_ta_list: vec![SupportedTa {
                tac: 999, // Different TAC
                num_of_bplmn_list: 1,
                bplmn_list: vec![BplmnEntry {
                    plmn_id: PlmnId::new("002", "02"),
                    num_of_s_nssai: 1,
                    s_nssai: vec![SNssai { sst: 1, sd: None }],
                }],
            }],
            ..Default::default()
        };

        let result = handle_ng_setup_request(&mut gnb, &ctx, &request);

        match result {
            NgapHandlerResult::Failure(_) => {}
            _ => panic!("Expected Failure"),
        }
    }

    #[test]
    fn test_is_tai_served() {
        let ctx = create_test_context();

        let tai_served = Tai5gs {
            plmn_id: PlmnId::new("001", "01"),
            tac: 1,
        };
        assert!(is_tai_served(&ctx, &tai_served));

        let tai_not_served = Tai5gs {
            plmn_id: PlmnId::new("002", "02"),
            tac: 999,
        };
        assert!(!is_tai_served(&ctx, &tai_not_served));
    }

    #[test]
    fn test_parse_cause() {
        let cause = parse_cause(
            cause_group::RADIO_NETWORK,
            radio_network_cause::USER_INACTIVITY,
        );
        assert_eq!(cause.group, cause_group::RADIO_NETWORK);
        assert_eq!(cause.cause, radio_network_cause::USER_INACTIVITY);
    }

    #[test]
    fn test_handle_ng_reset_full_interface_releases_all_gnb_ues() {
        use nextgcore_asn1c::ngap::cause::{Cause, CauseMisc};

        let gnb_pool_id = 987_001u64;
        let ctx = crate::context::amf_self();
        let (ue_a, ue_b) = {
            let context = ctx.read().unwrap();
            let a = context.ran_ue_add(gnb_pool_id, 11).unwrap();
            let b = context.ran_ue_add(gnb_pool_id, 12).unwrap();
            (a, b)
        };

        let reset = NgReset {
            cause: Cause::Misc(CauseMisc::HardwareFailure),
            reset_type: ResetType::NgInterface,
        };
        let ack_connections = handle_ng_reset(gnb_pool_id, &reset);

        // Full reset: no connection list echoed, all UE contexts released
        assert!(ack_connections.is_none());
        let context = ctx.read().unwrap();
        assert!(context.ran_ue_find_by_id(ue_a.id).is_none());
        assert!(context.ran_ue_find_by_id(ue_b.id).is_none());
    }

    #[test]
    fn test_handle_ng_reset_partial_releases_listed_ues_only() {
        use nextgcore_asn1c::ngap::cause::{Cause, CauseRadioNetwork};

        let gnb_pool_id = 987_002u64;
        let ctx = crate::context::amf_self();
        let (target, untouched) = {
            let context = ctx.read().unwrap();
            let a = context.ran_ue_add(gnb_pool_id, 21).unwrap();
            let b = context.ran_ue_add(gnb_pool_id, 22).unwrap();
            (a, b)
        };

        let connections = vec![UeAssociatedLogicalNgConnectionItem {
            amf_ue_ngap_id: Some(target.amf_ue_ngap_id),
            ran_ue_ngap_id: Some(target.ran_ue_ngap_id as u32),
        }];
        let reset = NgReset {
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            reset_type: ResetType::PartOfNgInterface(connections.clone()),
        };
        let ack_connections = handle_ng_reset(gnb_pool_id, &reset);

        // Partial reset: listed connections echoed, only listed UE released
        assert_eq!(ack_connections, Some(connections));
        let context = ctx.read().unwrap();
        assert!(context.ran_ue_find_by_id(target.id).is_none());
        assert!(context.ran_ue_find_by_id(untouched.id).is_some());

        // Cleanup so other tests using the global context are unaffected
        context.ran_ue_remove(untouched.id);
    }
}
