//! S1AP Message Building
//!
//! Port of src/mme/s1ap-build.c - S1AP message building functions
//!
//! Note: S1AP uses ASN.1 PER encoding. This module provides Rust structures
//! and encoding functions for S1AP messages.

use crate::context::{MmeContext, EnbUe, MmeUe, MmeBearer, PlmnId, EpsTai, ECgi, S1apCause, S1apCauseGroup};

// ============================================================================
// S1AP Constants
// ============================================================================

/// S1AP Protocol IEs
pub mod protocol_ie_id {
    pub const MME_UE_S1AP_ID: u16 = 0;
    pub const ENB_UE_S1AP_ID: u16 = 8;
    pub const CAUSE: u16 = 2;
    pub const E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ: u16 = 24;
    pub const E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ: u16 = 52;
    pub const E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ: u16 = 16;
    pub const E_RAB_TO_BE_MODIFIED_LIST_BEARER_MOD_REQ: u16 = 30;
    pub const E_RAB_TO_BE_RELEASED_LIST: u16 = 33;
    pub const UE_AGGREGATE_MAXIMUM_BITRATE: u16 = 66;
    pub const UE_SECURITY_CAPABILITIES: u16 = 107;
    pub const SECURITY_KEY: u16 = 73;
    pub const NAS_PDU: u16 = 26;
    pub const TAI: u16 = 67;
    pub const EUTRAN_CGI: u16 = 100;
    pub const SERVED_GUMMEIS: u16 = 105;
    pub const RELATIVE_MME_CAPACITY: u16 = 87;
    pub const MME_NAME: u16 = 61;
    pub const TIME_TO_WAIT: u16 = 65;
    pub const CRITICALITY_DIAGNOSTICS: u16 = 58;
    pub const UE_RADIO_CAPABILITY: u16 = 74;
    pub const HANDOVER_TYPE: u16 = 1;
    pub const TARGET_ID: u16 = 4;
    pub const SOURCE_TO_TARGET_TRANSPARENT_CONTAINER: u16 = 104;
    pub const CS_FALLBACK_INDICATOR: u16 = 108;
}

/// S1AP Procedure Codes
pub mod procedure_code {
    pub const S1_SETUP: u8 = 17;
    pub const INITIAL_CONTEXT_SETUP: u8 = 9;
    pub const UE_CONTEXT_RELEASE: u8 = 23;
    pub const UE_CONTEXT_RELEASE_REQUEST: u8 = 18;
    pub const HANDOVER_PREPARATION: u8 = 0;
    pub const HANDOVER_RESOURCE_ALLOCATION: u8 = 1;
    pub const HANDOVER_NOTIFICATION: u8 = 2;
    pub const PATH_SWITCH_REQUEST: u8 = 3;
    pub const HANDOVER_CANCEL: u8 = 4;
    pub const E_RAB_SETUP: u8 = 5;
    pub const E_RAB_MODIFY: u8 = 6;
    pub const E_RAB_RELEASE: u8 = 7;
    pub const INITIAL_UE_MESSAGE: u8 = 12;
    pub const DOWNLINK_NAS_TRANSPORT: u8 = 11;
    pub const UPLINK_NAS_TRANSPORT: u8 = 13;
    pub const NAS_NON_DELIVERY_INDICATION: u8 = 16;
    pub const RESET: u8 = 14;
    pub const ERROR_INDICATION: u8 = 15;
    pub const ENB_CONFIGURATION_UPDATE: u8 = 29;
    pub const MME_CONFIGURATION_UPDATE: u8 = 30;
    pub const PAGING: u8 = 10;
}


/// S1AP Criticality
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Criticality {
    Reject = 0,
    Ignore = 1,
    Notify = 2,
}

/// S1AP PDU Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    InitiatingMessage = 0,
    SuccessfulOutcome = 1,
    UnsuccessfulOutcome = 2,
}

/// Time to wait values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimeToWait {
    V1s = 0,
    V2s = 1,
    V5s = 2,
    V10s = 3,
    V20s = 4,
    V60s = 5,
}

// ============================================================================
// S1AP Cause Codes
// ============================================================================

/// Radio Network cause values
pub mod radio_network_cause {
    pub const UNSPECIFIED: i64 = 0;
    pub const TX2_RELOCOVERALL_EXPIRY: i64 = 1;
    pub const SUCCESSFUL_HANDOVER: i64 = 2;
    pub const RELEASE_DUE_TO_EUTRAN_GENERATED_REASON: i64 = 3;
    pub const HANDOVER_CANCELLED: i64 = 4;
    pub const PARTIAL_HANDOVER: i64 = 5;
    pub const HO_FAILURE_IN_TARGET_EPC_ENB_OR_TARGET_SYSTEM: i64 = 6;
    pub const HO_TARGET_NOT_ALLOWED: i64 = 7;
    pub const TS1_RELOCOVERALL_EXPIRY: i64 = 8;
    pub const TS1_RELOCPREP_EXPIRY: i64 = 9;
    pub const CELL_NOT_AVAILABLE: i64 = 10;
    pub const UNKNOWN_TARGET_ID: i64 = 11;
    pub const NO_RADIO_RESOURCES_AVAILABLE_IN_TARGET_CELL: i64 = 12;
    pub const UNKNOWN_MME_UE_S1AP_ID: i64 = 13;
    pub const UNKNOWN_ENB_UE_S1AP_ID: i64 = 14;
    pub const UNKNOWN_PAIR_UE_S1AP_ID: i64 = 15;
    pub const HANDOVER_DESIRABLE_FOR_RADIO_REASON: i64 = 16;
    pub const TIME_CRITICAL_HANDOVER: i64 = 17;
    pub const RESOURCE_OPTIMISATION_HANDOVER: i64 = 18;
    pub const REDUCE_LOAD_IN_SERVING_CELL: i64 = 19;
    pub const USER_INACTIVITY: i64 = 20;
    pub const RADIO_CONNECTION_WITH_UE_LOST: i64 = 21;
    pub const LOAD_BALANCING_TAU_REQUIRED: i64 = 22;
    pub const CS_FALLBACK_TRIGGERED: i64 = 23;
    pub const UE_NOT_AVAILABLE_FOR_PS_SERVICE: i64 = 24;
    pub const RADIO_RESOURCES_NOT_AVAILABLE: i64 = 25;
    pub const FAILURE_IN_RADIO_INTERFACE_PROCEDURE: i64 = 26;
    pub const INVALID_QOS_COMBINATION: i64 = 27;
    pub const INTERRAT_REDIRECTION: i64 = 28;
    pub const INTERACTION_WITH_OTHER_PROCEDURE: i64 = 29;
    pub const UNKNOWN_E_RAB_ID: i64 = 30;
    pub const MULTIPLE_E_RAB_ID_INSTANCES: i64 = 31;
    pub const ENCRYPTION_AND_OR_INTEGRITY_PROTECTION_ALGORITHMS_NOT_SUPPORTED: i64 = 32;
    pub const S1_INTRA_SYSTEM_HANDOVER_TRIGGERED: i64 = 33;
    pub const S1_INTER_SYSTEM_HANDOVER_TRIGGERED: i64 = 34;
    pub const X2_HANDOVER_TRIGGERED: i64 = 35;
}

/// Transport cause values
pub mod transport_cause {
    pub const TRANSPORT_RESOURCE_UNAVAILABLE: i64 = 0;
    pub const UNSPECIFIED: i64 = 1;
}

/// NAS cause values
pub mod nas_cause {
    pub const NORMAL_RELEASE: i64 = 0;
    pub const AUTHENTICATION_FAILURE: i64 = 1;
    pub const DETACH: i64 = 2;
    pub const UNSPECIFIED: i64 = 3;
    pub const CSG_SUBSCRIPTION_EXPIRY: i64 = 4;
}

/// Protocol cause values
pub mod protocol_cause {
    pub const TRANSFER_SYNTAX_ERROR: i64 = 0;
    pub const ABSTRACT_SYNTAX_ERROR_REJECT: i64 = 1;
    pub const ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY: i64 = 2;
    pub const MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE: i64 = 3;
    pub const SEMANTIC_ERROR: i64 = 4;
    pub const ABSTRACT_SYNTAX_ERROR_FALSELY_CONSTRUCTED_MESSAGE: i64 = 5;
    pub const UNSPECIFIED: i64 = 6;
}

/// Misc cause values
pub mod misc_cause {
    pub const CONTROL_PROCESSING_OVERLOAD: i64 = 0;
    pub const NOT_ENOUGH_USER_PLANE_PROCESSING_RESOURCES: i64 = 1;
    pub const HARDWARE_FAILURE: i64 = 2;
    pub const OM_INTERVENTION: i64 = 3;
    pub const UNSPECIFIED: i64 = 4;
    pub const UNKNOWN_PLMN: i64 = 5;
}


// ============================================================================
// S1AP Message Buffer
// ============================================================================

/// S1AP message buffer for building messages
#[derive(Debug, Clone, Default)]
pub struct S1apBuffer {
    /// Message data
    pub data: Vec<u8>,
}

impl S1apBuffer {
    /// Create new buffer
    pub fn new() -> Self {
        Self { data: Vec::with_capacity(1024) }
    }
    
    /// Write byte
    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }
    
    /// Write 16-bit value (big endian)
    pub fn write_u16(&mut self, value: u16) {
        self.data.push((value >> 8) as u8);
        self.data.push(value as u8);
    }
    
    /// Write 32-bit value (big endian)
    pub fn write_u32(&mut self, value: u32) {
        self.data.push((value >> 24) as u8);
        self.data.push((value >> 16) as u8);
        self.data.push((value >> 8) as u8);
        self.data.push(value as u8);
    }
    
    /// Write bytes
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }
    
    /// Write length-prefixed bytes (1-byte length)
    pub fn write_lv(&mut self, bytes: &[u8]) {
        self.data.push(bytes.len() as u8);
        self.data.extend_from_slice(bytes);
    }
    
    /// Write length-prefixed bytes (2-byte length)
    pub fn write_lv16(&mut self, bytes: &[u8]) {
        self.write_u16(bytes.len() as u16);
        self.data.extend_from_slice(bytes);
    }
    
    /// Get data
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
    
    /// Get length
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode PLMN ID to 3 bytes
pub fn encode_plmn_id(plmn: &PlmnId) -> [u8; 3] {
    let mut bytes = [0u8; 3];
    bytes[0] = (plmn.mcc2 << 4) | plmn.mcc1;
    if plmn.mnc3 == 0x0f {
        bytes[1] = 0xf0 | plmn.mcc3;
    } else {
        bytes[1] = (plmn.mnc3 << 4) | plmn.mcc3;
    }
    bytes[2] = (plmn.mnc2 << 4) | plmn.mnc1;
    bytes
}

/// Encode TAI
pub fn encode_tai(tai: &EpsTai) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5);
    let plmn = encode_plmn_id(&tai.plmn_id);
    buf.extend_from_slice(&plmn);
    buf.push((tai.tac >> 8) as u8);
    buf.push(tai.tac as u8);
    buf
}

/// Encode E-CGI
pub fn encode_ecgi(ecgi: &ECgi) -> Vec<u8> {
    let mut buf = Vec::with_capacity(7);
    let plmn = encode_plmn_id(&ecgi.plmn_id);
    buf.extend_from_slice(&plmn);
    // Cell ID is 28 bits
    buf.push((ecgi.cell_id >> 24) as u8);
    buf.push((ecgi.cell_id >> 16) as u8);
    buf.push((ecgi.cell_id >> 8) as u8);
    buf.push(ecgi.cell_id as u8);
    buf
}

/// Encode S1AP cause
pub fn encode_cause(cause: &S1apCause) -> Vec<u8> {
    let mut buf = Vec::new();
    
    // Cause choice (3 bits) + extension (1 bit) + cause value
    let choice = match cause.group {
        S1apCauseGroup::RadioNetwork => 0,
        S1apCauseGroup::Transport => 1,
        S1apCauseGroup::Nas => 2,
        S1apCauseGroup::Protocol => 3,
        S1apCauseGroup::Misc => 4,
        S1apCauseGroup::Nothing => 0,
    };
    
    // Simple encoding: choice byte + cause value
    buf.push(choice);
    buf.push(cause.cause as u8);
    
    buf
}


// ============================================================================
// S1AP Message Building Functions
// ============================================================================

/// Build S1 Setup Response
/// 
/// This message is sent by MME to eNB in response to S1 Setup Request
pub fn build_setup_response(ctx: &MmeContext) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Successful Outcome
    buf.write_u8(PduType::SuccessfulOutcome as u8);
    
    // Procedure code: S1 Setup
    buf.write_u8(procedure_code::S1_SETUP);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME Name (optional)
    if let Some(ref name) = ctx.mme_name {
        ies.write_u16(protocol_ie_id::MME_NAME);
        ies.write_u8(Criticality::Ignore as u8);
        ies.write_lv16(name.as_bytes());
    }
    
    // Served GUMMEIs (mandatory)
    ies.write_u16(protocol_ie_id::SERVED_GUMMEIS);
    ies.write_u8(Criticality::Reject as u8);
    let gummeis = encode_served_gummeis(ctx);
    ies.write_lv16(&gummeis);
    
    // Relative MME Capacity (mandatory)
    ies.write_u16(protocol_ie_id::RELATIVE_MME_CAPACITY);
    ies.write_u8(Criticality::Ignore as u8);
    ies.write_u16(1); // Length
    ies.write_u8(ctx.relative_capacity);
    
    // Write IEs to main buffer
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

/// Build S1 Setup Failure
pub fn build_setup_failure(
    cause_group: S1apCauseGroup,
    cause_value: i64,
    time_to_wait: Option<TimeToWait>,
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Unsuccessful Outcome
    buf.write_u8(PduType::UnsuccessfulOutcome as u8);
    
    // Procedure code: S1 Setup
    buf.write_u8(procedure_code::S1_SETUP);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // Cause (mandatory)
    ies.write_u16(protocol_ie_id::CAUSE);
    ies.write_u8(Criticality::Ignore as u8);
    let cause = S1apCause { group: cause_group, cause: cause_value };
    let cause_encoded = encode_cause(&cause);
    ies.write_lv16(&cause_encoded);
    
    // Time to Wait (optional)
    if let Some(ttw) = time_to_wait {
        ies.write_u16(protocol_ie_id::TIME_TO_WAIT);
        ies.write_u8(Criticality::Ignore as u8);
        ies.write_u16(1); // Length
        ies.write_u8(ttw as u8);
    }
    
    // Write IEs to main buffer
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

/// Build eNB Configuration Update Acknowledge
pub fn build_enb_configuration_update_ack() -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Successful Outcome
    buf.write_u8(PduType::SuccessfulOutcome as u8);
    
    // Procedure code: eNB Configuration Update
    buf.write_u8(procedure_code::ENB_CONFIGURATION_UPDATE);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // No IEs for this message
    buf.write_u16(0);
    
    buf.into_vec()
}

/// Build eNB Configuration Update Failure
pub fn build_enb_configuration_update_failure(
    cause_group: S1apCauseGroup,
    cause_value: i64,
    time_to_wait: Option<TimeToWait>,
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Unsuccessful Outcome
    buf.write_u8(PduType::UnsuccessfulOutcome as u8);
    
    // Procedure code: eNB Configuration Update
    buf.write_u8(procedure_code::ENB_CONFIGURATION_UPDATE);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // Cause (mandatory)
    ies.write_u16(protocol_ie_id::CAUSE);
    ies.write_u8(Criticality::Ignore as u8);
    let cause = S1apCause { group: cause_group, cause: cause_value };
    let cause_encoded = encode_cause(&cause);
    ies.write_lv16(&cause_encoded);
    
    // Time to Wait (optional)
    if let Some(ttw) = time_to_wait {
        ies.write_u16(protocol_ie_id::TIME_TO_WAIT);
        ies.write_u8(Criticality::Ignore as u8);
        ies.write_u16(1);
        ies.write_u8(ttw as u8);
    }
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}


/// Build Initial Context Setup Request (full version with all parameters)
pub fn build_initial_context_setup_request_with_params(
    enb_ue: &EnbUe,
    mme_ue: &MmeUe,
    nas_pdu: Option<&[u8]>,
    security_key: &[u8; 32],
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: Initial Context Setup
    buf.write_u8(procedure_code::INITIAL_CONTEXT_SETUP);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME UE S1AP ID (mandatory)
    ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(enb_ue.mme_ue_s1ap_id);
    
    // eNB UE S1AP ID (mandatory)
    ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(enb_ue.enb_ue_s1ap_id);
    
    // UE Aggregate Maximum Bit Rate (mandatory)
    ies.write_u16(protocol_ie_id::UE_AGGREGATE_MAXIMUM_BITRATE);
    ies.write_u8(Criticality::Reject as u8);
    let ambr = encode_ue_ambr(mme_ue.ambr.downlink, mme_ue.ambr.uplink);
    ies.write_lv16(&ambr);
    
    // E-RAB to Be Setup List (mandatory) - simplified
    ies.write_u16(protocol_ie_id::E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ);
    ies.write_u8(Criticality::Reject as u8);
    // Placeholder for E-RAB list
    ies.write_u16(0);
    
    // UE Security Capabilities (mandatory)
    ies.write_u16(protocol_ie_id::UE_SECURITY_CAPABILITIES);
    ies.write_u8(Criticality::Reject as u8);
    let sec_cap = encode_ue_security_capabilities(mme_ue);
    ies.write_lv16(&sec_cap);
    
    // Security Key (mandatory)
    ies.write_u16(protocol_ie_id::SECURITY_KEY);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(32);
    ies.write_bytes(security_key);
    
    // NAS PDU (optional)
    if let Some(pdu) = nas_pdu {
        ies.write_u16(protocol_ie_id::NAS_PDU);
        ies.write_u8(Criticality::Ignore as u8);
        ies.write_lv16(pdu);
    }
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

/// Build UE Context Release Command
pub fn build_ue_context_release_command(
    enb_ue_s1ap_id: Option<u32>,
    mme_ue_s1ap_id: u32,
    cause_group: S1apCauseGroup,
    cause_value: i64,
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: UE Context Release
    buf.write_u8(procedure_code::UE_CONTEXT_RELEASE);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // UE S1AP IDs - can be pair or just MME ID
    if let Some(enb_id) = enb_ue_s1ap_id {
        // UE S1AP ID pair
        ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
        ies.write_u8(Criticality::Reject as u8);
        ies.write_u16(4);
        ies.write_u32(mme_ue_s1ap_id);
        
        ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
        ies.write_u8(Criticality::Reject as u8);
        ies.write_u16(4);
        ies.write_u32(enb_id);
    } else {
        // Just MME UE S1AP ID
        ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
        ies.write_u8(Criticality::Reject as u8);
        ies.write_u16(4);
        ies.write_u32(mme_ue_s1ap_id);
    }
    
    // Cause (mandatory)
    ies.write_u16(protocol_ie_id::CAUSE);
    ies.write_u8(Criticality::Ignore as u8);
    let cause = S1apCause { group: cause_group, cause: cause_value };
    let cause_encoded = encode_cause(&cause);
    ies.write_lv16(&cause_encoded);
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}


/// Build Paging message
pub fn build_paging(
    ue_identity: &[u8],
    tai_list: &[EpsTai],
    cn_domain: u8,
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: Paging
    buf.write_u8(procedure_code::PAGING);
    
    // Criticality: Ignore
    buf.write_u8(Criticality::Ignore as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // UE Identity Index Value (mandatory) - derived from IMSI
    // Simplified: just use first 10 bits
    ies.write_u16(0); // UE Identity Index Value IE ID
    ies.write_u8(Criticality::Ignore as u8);
    ies.write_u16(2);
    ies.write_u16(0); // Placeholder
    
    // UE Paging Identity (mandatory)
    ies.write_u16(1); // UE Paging Identity IE ID
    ies.write_u8(Criticality::Ignore as u8);
    ies.write_lv16(ue_identity);
    
    // CN Domain (mandatory)
    ies.write_u16(2); // CN Domain IE ID
    ies.write_u8(Criticality::Ignore as u8);
    ies.write_u16(1);
    ies.write_u8(cn_domain);
    
    // TAI List (mandatory)
    ies.write_u16(protocol_ie_id::TAI);
    ies.write_u8(Criticality::Ignore as u8);
    let tai_encoded = encode_tai_list(tai_list);
    ies.write_lv16(&tai_encoded);
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

/// Build Error Indication
pub fn build_error_indication(
    enb_ue_s1ap_id: Option<u32>,
    mme_ue_s1ap_id: Option<u32>,
    cause_group: S1apCauseGroup,
    cause_value: i64,
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: Error Indication
    buf.write_u8(procedure_code::ERROR_INDICATION);
    
    // Criticality: Ignore
    buf.write_u8(Criticality::Ignore as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME UE S1AP ID (optional)
    if let Some(id) = mme_ue_s1ap_id {
        ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
        ies.write_u8(Criticality::Ignore as u8);
        ies.write_u16(4);
        ies.write_u32(id);
    }
    
    // eNB UE S1AP ID (optional)
    if let Some(id) = enb_ue_s1ap_id {
        ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
        ies.write_u8(Criticality::Ignore as u8);
        ies.write_u16(4);
        ies.write_u32(id);
    }
    
    // Cause (optional but usually included)
    ies.write_u16(protocol_ie_id::CAUSE);
    ies.write_u8(Criticality::Ignore as u8);
    let cause = S1apCause { group: cause_group, cause: cause_value };
    let cause_encoded = encode_cause(&cause);
    ies.write_lv16(&cause_encoded);
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

// ============================================================================
// Encoding Helper Functions
// ============================================================================

/// Encode served GUMMEIs
fn encode_served_gummeis(ctx: &MmeContext) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // Number of served GUMMEIs
    buf.write_u8(ctx.num_of_served_gummei as u8);
    
    for gummei in &ctx.served_gummei {
        // Served PLMNs
        buf.write_u8(gummei.num_of_plmn_id as u8);
        for plmn in &gummei.plmn_id {
            let encoded = encode_plmn_id(plmn);
            buf.write_bytes(&encoded);
        }
        
        // Served Group IDs
        buf.write_u8(gummei.num_of_mme_gid as u8);
        for gid in &gummei.mme_gid {
            buf.write_u16(*gid);
        }
        
        // Served MMECs
        buf.write_u8(gummei.num_of_mme_code as u8);
        for code in &gummei.mme_code {
            buf.write_u8(*code);
        }
    }
    
    buf.into_vec()
}

/// Encode UE AMBR
fn encode_ue_ambr(dl: u64, ul: u64) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // Downlink (in bits per second, encoded as 32-bit)
    buf.write_u32((dl / 1000) as u32); // Convert to kbps
    
    // Uplink
    buf.write_u32((ul / 1000) as u32);
    
    buf.into_vec()
}

/// Encode UE security capabilities
fn encode_ue_security_capabilities(mme_ue: &MmeUe) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // Encryption algorithms (16 bits)
    buf.write_u16(mme_ue.ue_network_capability.eea as u16);
    
    // Integrity algorithms (16 bits)
    buf.write_u16(mme_ue.ue_network_capability.eia as u16);
    
    buf.into_vec()
}

/// Encode TAI list
fn encode_tai_list(tai_list: &[EpsTai]) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    buf.write_u8(tai_list.len() as u8);
    
    for tai in tai_list {
        let encoded = encode_tai(tai);
        buf.write_bytes(&encoded);
    }
    
    buf.into_vec()
}

// ============================================================================
// Wrapper Functions for nas_path.rs compatibility
// ============================================================================

/// Build downlink NAS transport (wrapper for nas_path.rs)
pub fn build_downlink_nas_transport(
    enb_ue: &EnbUe,
    nas_pdu: &[u8],
) -> Vec<u8> {
    build_downlink_nas_transport_with_ids(
        enb_ue.enb_ue_s1ap_id,
        enb_ue.mme_ue_s1ap_id,
        nas_pdu,
    )
}

/// Build downlink NAS transport (full version with explicit IDs)
pub fn build_downlink_nas_transport_with_ids(
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    nas_pdu: &[u8],
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: Downlink NAS Transport
    buf.write_u8(procedure_code::DOWNLINK_NAS_TRANSPORT);
    
    // Criticality: Ignore
    buf.write_u8(Criticality::Ignore as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME UE S1AP ID (mandatory)
    ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4); // Length
    ies.write_u32(mme_ue_s1ap_id);
    
    // eNB UE S1AP ID (mandatory)
    ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4); // Length
    ies.write_u32(enb_ue_s1ap_id);
    
    // NAS PDU (mandatory)
    ies.write_u16(protocol_ie_id::NAS_PDU);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_lv16(nas_pdu);
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

/// Build initial context setup request (wrapper for nas_path.rs)
pub fn build_initial_context_setup_request(
    mme_ue: &MmeUe,
    nas_pdu: &[u8],
) -> Vec<u8> {
    // Create a minimal EnbUe from mme_ue info
    let enb_ue = EnbUe {
        mme_ue_s1ap_id: 0, // Will be filled from context
        enb_ue_s1ap_id: 0,
        ..Default::default()
    };
    
    build_initial_context_setup_request_with_params(
        &enb_ue,
        mme_ue,
        Some(nas_pdu),
        &mme_ue.kenb,
    )
}

/// Build E-RAB setup request (wrapper for nas_path.rs)
pub fn build_e_rab_setup_request(
    bearer: &MmeBearer,
    nas_pdu: &[u8],
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: E-RAB Setup
    buf.write_u8(procedure_code::E_RAB_SETUP);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME UE S1AP ID (mandatory) - placeholder
    ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(0); // Would come from context
    
    // eNB UE S1AP ID (mandatory) - placeholder
    ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(0); // Would come from context
    
    // E-RAB to Be Setup List
    ies.write_u16(protocol_ie_id::E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ);
    ies.write_u8(Criticality::Reject as u8);
    
    // E-RAB item
    let mut erab = S1apBuffer::new();
    erab.write_u8(bearer.ebi); // E-RAB ID
    // E-RAB Level QoS Parameters (simplified)
    erab.write_u8(bearer.qos.qci);
    erab.write_u8(bearer.qos.arp.priority_level);
    // Transport Layer Address (SGW S1-U IP)
    erab.write_bytes(&bearer.sgw_s1u_ip.ipv4.unwrap_or([0; 4]));
    // GTP-TEID
    erab.write_u32(bearer.sgw_s1u_teid);
    // NAS PDU
    erab.write_lv16(nas_pdu);
    
    ies.write_lv16(&erab.into_vec());
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

/// Build E-RAB modify request (wrapper for nas_path.rs)
pub fn build_e_rab_modify_request(
    bearer: &MmeBearer,
    nas_pdu: &[u8],
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: E-RAB Modify
    buf.write_u8(procedure_code::E_RAB_MODIFY);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME UE S1AP ID (mandatory) - placeholder
    ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(0);
    
    // eNB UE S1AP ID (mandatory) - placeholder
    ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(0);
    
    // E-RAB to Be Modified List
    let mut erab = S1apBuffer::new();
    erab.write_u8(bearer.ebi); // E-RAB ID
    // E-RAB Level QoS Parameters
    erab.write_u8(bearer.qos.qci);
    erab.write_u8(bearer.qos.arp.priority_level);
    // NAS PDU
    erab.write_lv16(nas_pdu);
    
    ies.write_lv16(&erab.into_vec());
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

/// Build E-RAB release command (wrapper for nas_path.rs)
pub fn build_e_rab_release_command(
    bearer: &MmeBearer,
    nas_pdu: &[u8],
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: E-RAB Release
    buf.write_u8(procedure_code::E_RAB_RELEASE);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME UE S1AP ID (mandatory) - placeholder
    ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(0);
    
    // eNB UE S1AP ID (mandatory) - placeholder
    ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(0);
    
    // E-RAB to Be Released List
    let mut erab = S1apBuffer::new();
    erab.write_u8(bearer.ebi); // E-RAB ID
    // Cause
    erab.write_u8(S1apCauseGroup::Nas as u8);
    erab.write_u8(nas_cause::NORMAL_RELEASE as u8);
    
    ies.write_lv16(&erab.into_vec());
    
    // NAS PDU (optional)
    if !nas_pdu.is_empty() {
        ies.write_u16(protocol_ie_id::NAS_PDU);
        ies.write_u8(Criticality::Ignore as u8);
        ies.write_lv16(nas_pdu);
    }
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

// ============================================================================
// E-RAB Management Functions (with explicit parameters)
// ============================================================================

/// Build E-RAB Setup Request (with explicit parameters)
///
/// Port of s1ap_build_e_rab_setup_request() from s1ap-build.c
pub fn build_e_rab_setup_request_with_params(
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    ebi: u8,
    qci: u8,
    arp_priority: u8,
    sgw_s1u_teid: u32,
    sgw_s1u_addr: Option<[u8; 4]>,
    nas_pdu: &[u8],
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: E-RAB Setup
    buf.write_u8(procedure_code::E_RAB_SETUP);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME UE S1AP ID
    ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(mme_ue_s1ap_id);
    
    // eNB UE S1AP ID
    ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(enb_ue_s1ap_id);
    
    // E-RAB to be Setup List
    ies.write_u16(protocol_ie_id::E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ);
    ies.write_u8(Criticality::Reject as u8);
    
    // E-RAB to be Setup Item
    let mut erab_item = S1apBuffer::new();
    erab_item.write_u8(ebi); // E-RAB ID
    
    // E-RAB Level QoS Parameters
    erab_item.write_u8(qci);
    erab_item.write_u8(arp_priority);
    
    // Transport Layer Address (SGW S1-U)
    if let Some(addr) = sgw_s1u_addr {
        erab_item.write_bytes(&addr);
    }
    
    // GTP-TEID
    erab_item.write_u32(sgw_s1u_teid);
    
    // NAS-PDU
    erab_item.write_lv16(nas_pdu);
    
    ies.write_lv16(&erab_item.into_vec());
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

/// Build E-RAB Modify Request (with explicit parameters)
///
/// Port of s1ap_build_e_rab_modify_request() from s1ap-build.c
pub fn build_e_rab_modify_request_with_params(
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    ebi: u8,
    qci: u8,
    arp_priority: u8,
    nas_pdu: &[u8],
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: E-RAB Modify
    buf.write_u8(procedure_code::E_RAB_MODIFY);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME UE S1AP ID
    ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(mme_ue_s1ap_id);
    
    // eNB UE S1AP ID
    ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(enb_ue_s1ap_id);
    
    // E-RAB to be Modified List
    ies.write_u16(protocol_ie_id::E_RAB_TO_BE_MODIFIED_LIST_BEARER_MOD_REQ);
    ies.write_u8(Criticality::Reject as u8);
    
    // E-RAB to be Modified Item
    let mut erab_item = S1apBuffer::new();
    erab_item.write_u8(ebi); // E-RAB ID
    
    // E-RAB Level QoS Parameters
    erab_item.write_u8(qci);
    erab_item.write_u8(arp_priority);
    
    // NAS-PDU
    erab_item.write_lv16(nas_pdu);
    
    ies.write_lv16(&erab_item.into_vec());
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}

/// Build E-RAB Release Command (with explicit parameters)
///
/// Port of s1ap_build_e_rab_release_command() from s1ap-build.c
pub fn build_e_rab_release_command_with_params(
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    ebi: u8,
    cause_group: S1apCauseGroup,
    cause_value: i64,
    nas_pdu: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = S1apBuffer::new();
    
    // PDU type: Initiating Message
    buf.write_u8(PduType::InitiatingMessage as u8);
    
    // Procedure code: E-RAB Release
    buf.write_u8(procedure_code::E_RAB_RELEASE);
    
    // Criticality: Reject
    buf.write_u8(Criticality::Reject as u8);
    
    // Build IEs
    let mut ies = S1apBuffer::new();
    
    // MME UE S1AP ID
    ies.write_u16(protocol_ie_id::MME_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(mme_ue_s1ap_id);
    
    // eNB UE S1AP ID
    ies.write_u16(protocol_ie_id::ENB_UE_S1AP_ID);
    ies.write_u8(Criticality::Reject as u8);
    ies.write_u16(4);
    ies.write_u32(enb_ue_s1ap_id);
    
    // E-RAB to be Released List
    ies.write_u16(protocol_ie_id::E_RAB_TO_BE_RELEASED_LIST);
    ies.write_u8(Criticality::Ignore as u8);
    
    // E-RAB to be Released Item
    let mut erab_item = S1apBuffer::new();
    erab_item.write_u8(ebi); // E-RAB ID
    
    // Cause
    let cause = S1apCause { group: cause_group, cause: cause_value };
    let cause_encoded = encode_cause(&cause);
    erab_item.write_bytes(&cause_encoded);
    
    ies.write_lv16(&erab_item.into_vec());
    
    // NAS-PDU (optional)
    if let Some(pdu) = nas_pdu {
        ies.write_u16(protocol_ie_id::NAS_PDU);
        ies.write_u8(Criticality::Ignore as u8);
        ies.write_lv16(pdu);
    }
    
    buf.write_lv16(&ies.into_vec());
    
    buf.into_vec()
}


// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s1ap_buffer() {
        let mut buf = S1apBuffer::new();
        buf.write_u8(0x01);
        buf.write_u16(0x0203);
        buf.write_u32(0x04050607);
        
        let data = buf.into_vec();
        assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn test_encode_plmn_id() {
        let plmn = PlmnId::new("310", "410");
        let encoded = encode_plmn_id(&plmn);
        assert_eq!(encoded.len(), 3);
    }

    #[test]
    fn test_encode_tai() {
        let tai = EpsTai {
            plmn_id: PlmnId::new("310", "410"),
            tac: 0x1234,
        };
        let encoded = encode_tai(&tai);
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[3], 0x12);
        assert_eq!(encoded[4], 0x34);
    }

    #[test]
    fn test_encode_ecgi() {
        let ecgi = ECgi {
            plmn_id: PlmnId::new("310", "410"),
            cell_id: 0x12345678,
        };
        let encoded = encode_ecgi(&ecgi);
        assert_eq!(encoded.len(), 7);
    }

    #[test]
    fn test_encode_cause() {
        let cause = S1apCause {
            group: S1apCauseGroup::RadioNetwork,
            cause: radio_network_cause::UNSPECIFIED,
        };
        let encoded = encode_cause(&cause);
        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0], 0); // RadioNetwork
        assert_eq!(encoded[1], 0); // UNSPECIFIED
    }

    #[test]
    fn test_build_setup_failure() {
        let msg = build_setup_failure(
            S1apCauseGroup::Misc,
            misc_cause::UNSPECIFIED,
            Some(TimeToWait::V10s),
        );
        
        assert!(!msg.is_empty());
        assert_eq!(msg[0], PduType::UnsuccessfulOutcome as u8);
        assert_eq!(msg[1], procedure_code::S1_SETUP);
    }

    #[test]
    fn test_build_enb_configuration_update_ack() {
        let msg = build_enb_configuration_update_ack();
        
        assert!(!msg.is_empty());
        assert_eq!(msg[0], PduType::SuccessfulOutcome as u8);
        assert_eq!(msg[1], procedure_code::ENB_CONFIGURATION_UPDATE);
    }

    #[test]
    fn test_build_downlink_nas_transport() {
        let nas_pdu = vec![0x07, 0x41, 0x00]; // Sample NAS PDU
        let msg = build_downlink_nas_transport_with_ids(1, 2, &nas_pdu);
        
        assert!(!msg.is_empty());
        assert_eq!(msg[0], PduType::InitiatingMessage as u8);
        assert_eq!(msg[1], procedure_code::DOWNLINK_NAS_TRANSPORT);
    }

    #[test]
    fn test_build_ue_context_release_command() {
        let msg = build_ue_context_release_command(
            Some(1),
            2,
            S1apCauseGroup::Nas,
            nas_cause::NORMAL_RELEASE,
        );
        
        assert!(!msg.is_empty());
        assert_eq!(msg[0], PduType::InitiatingMessage as u8);
        assert_eq!(msg[1], procedure_code::UE_CONTEXT_RELEASE);
    }

    #[test]
    fn test_build_error_indication() {
        let msg = build_error_indication(
            Some(1),
            Some(2),
            S1apCauseGroup::Protocol,
            protocol_cause::UNSPECIFIED,
        );
        
        assert!(!msg.is_empty());
        assert_eq!(msg[0], PduType::InitiatingMessage as u8);
        assert_eq!(msg[1], procedure_code::ERROR_INDICATION);
    }

    #[test]
    fn test_time_to_wait_values() {
        assert_eq!(TimeToWait::V1s as u8, 0);
        assert_eq!(TimeToWait::V2s as u8, 1);
        assert_eq!(TimeToWait::V5s as u8, 2);
        assert_eq!(TimeToWait::V10s as u8, 3);
        assert_eq!(TimeToWait::V20s as u8, 4);
        assert_eq!(TimeToWait::V60s as u8, 5);
    }

    #[test]
    fn test_criticality_values() {
        assert_eq!(Criticality::Reject as u8, 0);
        assert_eq!(Criticality::Ignore as u8, 1);
        assert_eq!(Criticality::Notify as u8, 2);
    }
}
