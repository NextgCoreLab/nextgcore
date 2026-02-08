//! NGAP Message Handling
//!
//! Port of src/amf/ngap-handler.c - NGAP message handling functions

use crate::context::{
    AmfContext, AmfGnb, RanUe, PlmnId, SNssai, Tai5gs, NrCgi,
    SupportedTa, NgapCause, NgapUeCtxRelAction,
};
use crate::ngap_build::{cause_group, radio_network_cause};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of cells in reset
pub const MAX_NUM_OF_CELLS_IN_RESET: usize = 256;

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
        return NgapHandlerResult::Failure(NgapCause {
            group: cause_group::MISC,
            cause: 0, // Unspecified
        });
    }

    // Store gNB ID
    gnb.gnb_id = request.gnb_id;
    gnb.gnb_id_presence = true;
    gnb.plmn_id = request.plmn_id.clone();

    // Validate Supported TA List
    if request.supported_ta_list.is_empty() {
        log::error!("No Supported TA List");
        return NgapHandlerResult::Failure(NgapCause {
            group: cause_group::MISC,
            cause: 0,
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
        return NgapHandlerResult::Failure(NgapCause {
            group: cause_group::MISC,
            cause: 0, // Unknown PLMN or TAC
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

/// Handle Initial UE Message
pub fn handle_initial_ue_message(
    gnb: &AmfGnb,
    ran_ue: &mut RanUe,
    message: &InitialUeMessage,
) -> NgapHandlerResult {
    log::debug!(
        "[gNB:{}] Initial UE Message, RAN UE NGAP ID: {}",
        gnb.gnb_id, message.ran_ue_ngap_id
    );

    // Store RAN UE NGAP ID
    ran_ue.ran_ue_ngap_id = message.ran_ue_ngap_id;

    // Store User Location Information
    if message.user_location_present {
        ran_ue.saved_nr_tai = message.nr_tai.clone();
        ran_ue.saved_nr_cgi = message.nr_cgi.clone();
    }

    // Store UE Context Request
    ran_ue.ue_context_requested = message.ue_context_request;

    // Return NAS PDU for processing
    NgapHandlerResult::SendNas(message.nas_pdu.clone())
}

/// Handle Uplink NAS Transport
pub fn handle_uplink_nas_transport(
    ran_ue: &mut RanUe,
    message: &UplinkNasTransport,
) -> NgapHandlerResult {
    log::debug!(
        "Uplink NAS Transport, AMF UE NGAP ID: {}, RAN UE NGAP ID: {}",
        message.amf_ue_ngap_id, message.ran_ue_ngap_id
    );

    // Validate AMF UE NGAP ID
    if ran_ue.amf_ue_ngap_id != message.amf_ue_ngap_id {
        log::error!(
            "AMF UE NGAP ID mismatch: expected {}, got {}",
            ran_ue.amf_ue_ngap_id, message.amf_ue_ngap_id
        );
        return NgapHandlerResult::Failure(NgapCause {
            group: cause_group::RADIO_NETWORK,
            cause: radio_network_cause::UNKNOWN_LOCAL_UE_NGAP_ID,
        });
    }

    // Update User Location Information
    if message.user_location_present {
        ran_ue.saved_nr_tai = message.nr_tai.clone();
        ran_ue.saved_nr_cgi = message.nr_cgi.clone();
    }

    // Return NAS PDU for processing
    NgapHandlerResult::SendNas(message.nas_pdu.clone())
}

/// Handle UE Context Release Request
pub fn handle_ue_context_release_request(
    ran_ue: &mut RanUe,
    message: &UeContextReleaseRequest,
) -> NgapHandlerResult {
    log::debug!(
        "UE Context Release Request, AMF UE NGAP ID: {}, RAN UE NGAP ID: {}",
        message.amf_ue_ngap_id, message.ran_ue_ngap_id
    );

    // Store the cause for later use
    ran_ue.deactivation = message.cause.clone();

    // Set release action
    ran_ue.ue_ctx_rel_action = NgapUeCtxRelAction::NgContextRemove;

    NgapHandlerResult::ReleaseUeContext(message.cause.clone())
}

/// Handle UE Context Release Complete
pub fn handle_ue_context_release_complete(
    ran_ue: &mut RanUe,
    message: &UeContextReleaseComplete,
) -> NgapHandlerResult {
    log::debug!(
        "UE Context Release Complete, AMF UE NGAP ID: {}, RAN UE NGAP ID: {}",
        message.amf_ue_ngap_id, message.ran_ue_ngap_id
    );

    // Update User Location Information if present
    if message.user_location_present {
        ran_ue.saved_nr_tai = message.nr_tai.clone();
        ran_ue.saved_nr_cgi = message.nr_cgi.clone();
    }

    NgapHandlerResult::Success
}

/// Handle Initial Context Setup Response
pub fn handle_initial_context_setup_response(
    ran_ue: &mut RanUe,
    message: &InitialContextSetupResponse,
) -> NgapHandlerResult {
    log::debug!(
        "Initial Context Setup Response, AMF UE NGAP ID: {}, RAN UE NGAP ID: {}",
        message.amf_ue_ngap_id, message.ran_ue_ngap_id
    );

    // Mark initial context setup as complete
    ran_ue.initial_context_setup_response_received = true;

    // Process PDU Session Setup Response List
    for item in &message.pdu_session_setup_list {
        log::debug!("PDU Session {} setup successful", item.psi);
        ran_ue.psimask_activated |= 1 << item.psi;
    }

    // Process PDU Session Failed List
    for item in &message.pdu_session_failed_list {
        log::warn!(
            "PDU Session {} setup failed: cause group={}, cause={}",
            item.psi, item.cause.group, item.cause.cause
        );
    }

    NgapHandlerResult::Success
}

/// Handle Initial Context Setup Failure
pub fn handle_initial_context_setup_failure(
    ran_ue: &mut RanUe,
    message: &InitialContextSetupFailure,
) -> NgapHandlerResult {
    log::warn!(
        "Initial Context Setup Failure, AMF UE NGAP ID: {}, cause: group={}, cause={}",
        message.amf_ue_ngap_id, message.cause.group, message.cause.cause
    );

    // Set release action
    ran_ue.ue_ctx_rel_action = NgapUeCtxRelAction::UeContextRemove;

    NgapHandlerResult::ReleaseUeContext(message.cause.clone())
}

/// Handle Handover Required
pub fn handle_handover_required(
    _ran_ue: &mut RanUe,
    message: &HandoverRequired,
) -> NgapHandlerResult {
    log::debug!(
        "Handover Required, AMF UE NGAP ID: {}, RAN UE NGAP ID: {}",
        message.amf_ue_ngap_id, message.ran_ue_ngap_id
    );

    // Validate handover type (only intra-5GS supported for now)
    if message.handover_type != 0 {
        log::error!("Unsupported handover type: {}", message.handover_type);
        return NgapHandlerResult::Failure(NgapCause {
            group: cause_group::RADIO_NETWORK,
            cause: radio_network_cause::HO_TARGET_NOT_ALLOWED,
        });
    }

    NgapHandlerResult::Success
}

/// Handle Handover Request Acknowledge
pub fn handle_handover_request_ack(
    target_ue: &mut RanUe,
    message: &HandoverRequestAck,
) -> NgapHandlerResult {
    log::debug!(
        "Handover Request Acknowledge, AMF UE NGAP ID: {}, RAN UE NGAP ID: {}",
        message.amf_ue_ngap_id, message.ran_ue_ngap_id
    );

    // Store RAN UE NGAP ID from target gNB
    target_ue.ran_ue_ngap_id = message.ran_ue_ngap_id;

    // Process PDU Session Admitted List
    for item in &message.pdu_session_admitted_list {
        log::debug!("PDU Session {} admitted for handover", item.psi);
        target_ue.psimask_activated |= 1 << item.psi;
    }

    NgapHandlerResult::Success
}

/// Handle Path Switch Request
pub fn handle_path_switch_request(
    ran_ue: &mut RanUe,
    message: &PathSwitchRequest,
) -> NgapHandlerResult {
    log::debug!(
        "Path Switch Request, RAN UE NGAP ID: {}, Source AMF UE NGAP ID: {}",
        message.ran_ue_ngap_id, message.source_amf_ue_ngap_id
    );

    // Store new RAN UE NGAP ID
    ran_ue.ran_ue_ngap_id = message.ran_ue_ngap_id;

    // Update User Location Information
    ran_ue.saved_nr_tai = message.nr_tai.clone();
    ran_ue.saved_nr_cgi = message.nr_cgi.clone();

    // Process PDU Session List
    for item in &message.pdu_session_list {
        log::debug!("PDU Session {} in path switch", item.psi);
        ran_ue.psimask_activated |= 1 << item.psi;
    }

    NgapHandlerResult::Success
}

/// Handle Handover Notification
pub fn handle_handover_notification(
    ran_ue: &mut RanUe,
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u64,
    nr_tai: &Tai5gs,
    nr_cgi: &NrCgi,
) -> NgapHandlerResult {
    log::debug!(
        "Handover Notification, AMF UE NGAP ID: {}, RAN UE NGAP ID: {}",
        amf_ue_ngap_id, ran_ue_ngap_id
    );

    // Update User Location Information
    ran_ue.saved_nr_tai = nr_tai.clone();
    ran_ue.saved_nr_cgi = nr_cgi.clone();

    NgapHandlerResult::Success
}

/// Handle Handover Cancel
pub fn handle_handover_cancel(
    ran_ue: &mut RanUe,
    amf_ue_ngap_id: u64,
    ran_ue_ngap_id: u64,
    cause: &NgapCause,
) -> NgapHandlerResult {
    log::debug!(
        "Handover Cancel, AMF UE NGAP ID: {}, RAN UE NGAP ID: {}, cause: group={}, cause={}",
        amf_ue_ngap_id, ran_ue_ngap_id, cause.group, cause.cause
    );

    // Set release action for target UE
    ran_ue.ue_ctx_rel_action = NgapUeCtxRelAction::NgHandoverCancel;

    NgapHandlerResult::Success
}

/// Handle Error Indication
pub fn handle_error_indication(
    gnb: &AmfGnb,
    amf_ue_ngap_id: Option<u64>,
    ran_ue_ngap_id: Option<u64>,
    cause: &NgapCause,
) -> NgapHandlerResult {
    log::warn!(
        "[gNB:{}] Error Indication, AMF UE NGAP ID: {:?}, RAN UE NGAP ID: {:?}, cause: group={}, cause={}",
        gnb.gnb_id, amf_ue_ngap_id, ran_ue_ngap_id, cause.group, cause.cause
    );

    NgapHandlerResult::Success
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

    fn create_test_ran_ue() -> RanUe {
        RanUe {
            id: 1,
            index: 1,
            gnb_id: 1,
            ran_ue_ngap_id: 1001,
            amf_ue_ngap_id: 2001,
            ..Default::default()
        }
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
    fn test_handle_initial_ue_message() {
        let gnb = create_test_gnb();
        let mut ran_ue = create_test_ran_ue();

        let message = InitialUeMessage {
            ran_ue_ngap_id: 5001,
            nas_pdu: vec![0x7e, 0x00, 0x41],
            user_location_present: true,
            nr_tai: Tai5gs {
                plmn_id: PlmnId::new("001", "01"),
                tac: 1,
            },
            nr_cgi: NrCgi {
                plmn_id: PlmnId::new("001", "01"),
                cell_id: 12345,
            },
            ue_context_request: true,
            ..Default::default()
        };

        let result = handle_initial_ue_message(&gnb, &mut ran_ue, &message);

        match result {
            NgapHandlerResult::SendNas(nas_pdu) => {
                assert_eq!(nas_pdu, vec![0x7e, 0x00, 0x41]);
                assert_eq!(ran_ue.ran_ue_ngap_id, 5001);
                assert!(ran_ue.ue_context_requested);
            }
            _ => panic!("Expected SendNas"),
        }
    }

    #[test]
    fn test_handle_uplink_nas_transport() {
        let mut ran_ue = create_test_ran_ue();

        let message = UplinkNasTransport {
            amf_ue_ngap_id: 2001,
            ran_ue_ngap_id: 1001,
            nas_pdu: vec![0x7e, 0x00, 0x57],
            user_location_present: true,
            nr_tai: Tai5gs {
                plmn_id: PlmnId::new("001", "01"),
                tac: 2,
            },
            nr_cgi: NrCgi {
                plmn_id: PlmnId::new("001", "01"),
                cell_id: 54321,
            },
        };

        let result = handle_uplink_nas_transport(&mut ran_ue, &message);

        match result {
            NgapHandlerResult::SendNas(nas_pdu) => {
                assert_eq!(nas_pdu, vec![0x7e, 0x00, 0x57]);
                assert_eq!(ran_ue.saved_nr_tai.tac, 2);
            }
            _ => panic!("Expected SendNas"),
        }
    }

    #[test]
    fn test_handle_uplink_nas_transport_id_mismatch() {
        let mut ran_ue = create_test_ran_ue();

        let message = UplinkNasTransport {
            amf_ue_ngap_id: 9999, // Wrong ID
            ran_ue_ngap_id: 1001,
            nas_pdu: vec![0x7e, 0x00, 0x57],
            ..Default::default()
        };

        let result = handle_uplink_nas_transport(&mut ran_ue, &message);

        match result {
            NgapHandlerResult::Failure(cause) => {
                assert_eq!(cause.group, cause_group::RADIO_NETWORK);
            }
            _ => panic!("Expected Failure"),
        }
    }

    #[test]
    fn test_handle_ue_context_release_request() {
        let mut ran_ue = create_test_ran_ue();

        let message = UeContextReleaseRequest {
            amf_ue_ngap_id: 2001,
            ran_ue_ngap_id: 1001,
            cause: NgapCause {
                group: cause_group::RADIO_NETWORK,
                cause: radio_network_cause::USER_INACTIVITY,
            },
            pdu_session_list: vec![],
        };

        let result = handle_ue_context_release_request(&mut ran_ue, &message);

        match result {
            NgapHandlerResult::ReleaseUeContext(cause) => {
                assert_eq!(cause.cause, radio_network_cause::USER_INACTIVITY);
                assert_eq!(ran_ue.ue_ctx_rel_action, NgapUeCtxRelAction::NgContextRemove);
            }
            _ => panic!("Expected ReleaseUeContext"),
        }
    }

    #[test]
    fn test_handle_initial_context_setup_response() {
        let mut ran_ue = create_test_ran_ue();

        let message = InitialContextSetupResponse {
            amf_ue_ngap_id: 2001,
            ran_ue_ngap_id: 1001,
            pdu_session_setup_list: vec![
                PduSessionSetupItem { psi: 5, transfer: vec![] },
                PduSessionSetupItem { psi: 6, transfer: vec![] },
            ],
            pdu_session_failed_list: vec![],
        };

        let result = handle_initial_context_setup_response(&mut ran_ue, &message);

        match result {
            NgapHandlerResult::Success => {
                assert!(ran_ue.initial_context_setup_response_received);
                assert_eq!(ran_ue.psimask_activated & (1 << 5), 1 << 5);
                assert_eq!(ran_ue.psimask_activated & (1 << 6), 1 << 6);
            }
            _ => panic!("Expected Success"),
        }
    }

    #[test]
    fn test_handle_initial_context_setup_failure() {
        let mut ran_ue = create_test_ran_ue();

        let message = InitialContextSetupFailure {
            amf_ue_ngap_id: 2001,
            ran_ue_ngap_id: 1001,
            cause: NgapCause {
                group: cause_group::RADIO_NETWORK,
                cause: radio_network_cause::RADIO_RESOURCES_NOT_AVAILABLE,
            },
        };

        let result = handle_initial_context_setup_failure(&mut ran_ue, &message);

        match result {
            NgapHandlerResult::ReleaseUeContext(cause) => {
                assert_eq!(cause.cause, radio_network_cause::RADIO_RESOURCES_NOT_AVAILABLE);
                assert_eq!(ran_ue.ue_ctx_rel_action, NgapUeCtxRelAction::UeContextRemove);
            }
            _ => panic!("Expected ReleaseUeContext"),
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
        let cause = parse_cause(cause_group::RADIO_NETWORK, radio_network_cause::USER_INACTIVITY);
        assert_eq!(cause.group, cause_group::RADIO_NETWORK);
        assert_eq!(cause.cause, radio_network_cause::USER_INACTIVITY);
    }
}
