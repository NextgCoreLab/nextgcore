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
    pub const BEARER_RESOURCE_COMMAND: u8 = 68;
    pub const BEARER_RESOURCE_FAILURE_INDICATION: u8 = 69;
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
    pub const PCO: u8 = 78;
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

/// GTP-C Cause values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum GtpCause {
    #[default]
    Reserved = 0,
    RequestAccepted = 16,
    RequestAcceptedPartially = 17,
    NewPdnTypeDueToNetworkPreference = 18,
    NewPdnTypeDueToSingleAddressBearerOnly = 19,
    ContextNotFound = 64,
    InvalidMessageFormat = 65,
    VersionNotSupported = 66,
    InvalidLength = 67,
    ServiceNotSupported = 68,
    MandatoryIeIncorrect = 69,
    MandatoryIeMissing = 70,
    SystemFailure = 72,
    NoResourcesAvailable = 73,
    SemanticErrorInTftOperation = 74,
    SyntacticErrorInTftOperation = 75,
    SemanticErrorsInPacketFilter = 76,
    SyntacticErrorsInPacketFilter = 77,
    MissingOrUnknownApn = 78,
    RequestRejected = 94,
    ConditionalIeMissing = 103,
}

impl From<u8> for GtpCause {
    fn from(value: u8) -> Self {
        match value {
            16 => GtpCause::RequestAccepted,
            17 => GtpCause::RequestAcceptedPartially,
            18 => GtpCause::NewPdnTypeDueToNetworkPreference,
            19 => GtpCause::NewPdnTypeDueToSingleAddressBearerOnly,
            64 => GtpCause::ContextNotFound,
            65 => GtpCause::InvalidMessageFormat,
            70 => GtpCause::MandatoryIeMissing,
            72 => GtpCause::SystemFailure,
            103 => GtpCause::ConditionalIeMissing,
            _ => GtpCause::Reserved,
        }
    }
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
            Self::MissingRequiredField(field) => write!(f, "Missing required field: {}", field),
            Self::BuildFailed(msg) => write!(f, "Build failed: {}", msg),
        }
    }
}

impl std::error::Error for S11BuildError {}

pub type S11BuildResult<T> = Result<T, S11BuildError>;


// ============================================================================
// GTP Buffer Helper
// ============================================================================

/// Buffer for building GTP-C messages
#[derive(Debug, Clone)]
pub struct GtpBuffer {
    data: Vec<u8>,
}

impl GtpBuffer {
    pub fn new() -> Self {
        Self { data: Vec::with_capacity(1024) }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Write GTP-C header with TEID
    pub fn write_gtp_header_with_teid(&mut self, msg_type: u8, teid: u32, seq_num: u32) {
        self.write_u8(0x48); // Version 2, T=1
        self.write_u8(msg_type);
        self.write_u16(0); // Length placeholder
        self.write_u32(teid);
        self.write_u8(((seq_num >> 16) & 0xff) as u8);
        self.write_u8(((seq_num >> 8) & 0xff) as u8);
        self.write_u8((seq_num & 0xff) as u8);
        self.write_u8(0); // Spare
    }

    /// Write GTP-C header without TEID
    pub fn write_gtp_header_no_teid(&mut self, msg_type: u8, seq_num: u32) {
        self.write_u8(0x40); // Version 2, T=0
        self.write_u8(msg_type);
        self.write_u16(0); // Length placeholder
        self.write_u8(((seq_num >> 16) & 0xff) as u8);
        self.write_u8(((seq_num >> 8) & 0xff) as u8);
        self.write_u8((seq_num & 0xff) as u8);
        self.write_u8(0); // Spare
    }

    /// Update message length in header
    pub fn update_length(&mut self) {
        let len = (self.data.len() - 4) as u16;
        self.data[2] = (len >> 8) as u8;
        self.data[3] = (len & 0xff) as u8;
    }

    /// Write IE header
    pub fn write_ie_header(&mut self, ie_type: u8, length: u16, instance: u8) {
        self.write_u8(ie_type);
        self.write_u16(length);
        self.write_u8(instance & 0x0f);
    }

    /// Write Recovery IE
    pub fn write_recovery(&mut self, recovery: u8, instance: u8) {
        self.write_ie_header(ie_type::RECOVERY, 1, instance);
        self.write_u8(recovery);
    }

    /// Write Cause IE
    pub fn write_cause(&mut self, cause: GtpCause, instance: u8) {
        self.write_ie_header(ie_type::CAUSE, 2, instance);
        self.write_u8(cause as u8);
        self.write_u8(0); // Spare
    }

    /// Write EBI IE
    pub fn write_ebi(&mut self, ebi: u8, instance: u8) {
        self.write_ie_header(ie_type::EBI, 1, instance);
        self.write_u8(ebi & 0x0f);
    }
}

impl Default for GtpBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Build Functions
// ============================================================================

/// Build Echo Request
pub fn build_echo_request(seq_num: u32, recovery: u8) -> Vec<u8> {
    let mut buf = GtpBuffer::new();
    buf.write_gtp_header_no_teid(message_type::ECHO_REQUEST, seq_num);
    buf.write_recovery(recovery, 0);
    buf.update_length();
    buf.into_vec()
}

/// Build Echo Response
pub fn build_echo_response(seq_num: u32, recovery: u8) -> Vec<u8> {
    let mut buf = GtpBuffer::new();
    buf.write_gtp_header_no_teid(message_type::ECHO_RESPONSE, seq_num);
    buf.write_recovery(recovery, 0);
    buf.update_length();
    buf.into_vec()
}

/// Build Create Session Request
pub fn build_create_session_request(
    _sess: &MmeSess,
    _mme_ue: &MmeUe,
    _sgw_ue: &SgwUe,
    _create_action: GtpCreateAction,
) -> S11BuildResult<Vec<u8>> {
    log::debug!("Build Create Session Request");
    // Placeholder - actual implementation would build full message
    Ok(Vec::new())
}

/// Build Modify Bearer Request
pub fn build_modify_bearer_request(
    _mme_ue: &MmeUe,
    _sgw_ue: &SgwUe,
    _bearers: &[&MmeBearer],
    _uli_presence: bool,
) -> S11BuildResult<Vec<u8>> {
    log::debug!("Build Modify Bearer Request");
    Ok(Vec::new())
}

/// Build Delete Session Request
pub fn build_delete_session_request(
    _sess: &MmeSess,
    _mme_ue: &MmeUe,
    _sgw_ue: &SgwUe,
    _default_bearer_ebi: u8,
    _action: GtpDeleteAction,
) -> S11BuildResult<Vec<u8>> {
    log::debug!("Build Delete Session Request");
    Ok(Vec::new())
}

/// Build Create Bearer Response
pub fn build_create_bearer_response(
    _bearer: &MmeBearer,
    _mme_ue: &MmeUe,
    _sgw_ue: &SgwUe,
    _cause_value: GtpCause,
) -> S11BuildResult<Vec<u8>> {
    log::debug!("Build Create Bearer Response");
    Ok(Vec::new())
}

/// Build Update Bearer Response
pub fn build_update_bearer_response(
    _bearer: &MmeBearer,
    _mme_ue: &MmeUe,
    _sgw_ue: &SgwUe,
    _cause_value: GtpCause,
) -> S11BuildResult<Vec<u8>> {
    log::debug!("Build Update Bearer Response");
    Ok(Vec::new())
}

/// Build Delete Bearer Response
pub fn build_delete_bearer_response(
    _bearer: &MmeBearer,
    _mme_ue: &MmeUe,
    _sgw_ue: &SgwUe,
    _cause_value: GtpCause,
) -> S11BuildResult<Vec<u8>> {
    log::debug!("Build Delete Bearer Response");
    Ok(Vec::new())
}

/// Build Release Access Bearers Request
pub fn build_release_access_bearers_request(teid: u32, seq_num: u32) -> Vec<u8> {
    let mut buf = GtpBuffer::new();
    buf.write_gtp_header_with_teid(message_type::RELEASE_ACCESS_BEARERS_REQUEST, teid, seq_num);
    buf.update_length();
    buf.into_vec()
}

/// Build Downlink Data Notification Ack
pub fn build_downlink_data_notification_ack(teid: u32, seq_num: u32, cause: GtpCause) -> Vec<u8> {
    let mut buf = GtpBuffer::new();
    buf.write_gtp_header_with_teid(message_type::DOWNLINK_DATA_NOTIFICATION_ACK, teid, seq_num);
    buf.write_cause(cause, 0);
    buf.update_length();
    buf.into_vec()
}

/// Build Create Indirect Data Forwarding Tunnel Request
pub fn build_create_indirect_data_forwarding_tunnel_request(
    _mme_ue: &MmeUe,
    _sgw_ue: &SgwUe,
    _bearers: &[&MmeBearer],
) -> S11BuildResult<Vec<u8>> {
    log::debug!("Build Create Indirect Data Forwarding Tunnel Request");
    Ok(Vec::new())
}

/// Build Bearer Resource Command
pub fn build_bearer_resource_command(
    _bearer: &MmeBearer,
    _mme_ue: &MmeUe,
    _sgw_ue: &SgwUe,
    _linked_bearer_ebi: u8,
    _pti: u8,
    _tad: &[u8],
    _qos: Option<&Gtp2BearerQos>,
) -> S11BuildResult<Vec<u8>> {
    log::debug!("Build Bearer Resource Command");
    Ok(Vec::new())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_cause_from_u8() {
        assert_eq!(GtpCause::from(16), GtpCause::RequestAccepted);
        assert_eq!(GtpCause::from(64), GtpCause::ContextNotFound);
        assert_eq!(GtpCause::from(0), GtpCause::Reserved);
    }

    #[test]
    fn test_build_echo_request() {
        let msg = build_echo_request(100, 5);
        assert!(!msg.is_empty());
        assert_eq!(msg[1], message_type::ECHO_REQUEST);
    }

    #[test]
    fn test_build_echo_response() {
        let msg = build_echo_response(100, 5);
        assert!(!msg.is_empty());
        assert_eq!(msg[1], message_type::ECHO_RESPONSE);
    }

    #[test]
    fn test_build_release_access_bearers_request() {
        let msg = build_release_access_bearers_request(0x12345678, 100);
        assert!(!msg.is_empty());
        assert_eq!(msg[1], message_type::RELEASE_ACCESS_BEARERS_REQUEST);
    }

    #[test]
    fn test_build_downlink_data_notification_ack() {
        let msg = build_downlink_data_notification_ack(0x12345678, 100, GtpCause::RequestAccepted);
        assert!(!msg.is_empty());
        assert_eq!(msg[1], message_type::DOWNLINK_DATA_NOTIFICATION_ACK);
    }

    #[test]
    fn test_gtp_buffer() {
        let mut buf = GtpBuffer::new();
        buf.write_u8(0x48);
        buf.write_u16(0x1234);
        buf.write_u32(0x12345678);
        assert_eq!(buf.len(), 7);
    }
}
