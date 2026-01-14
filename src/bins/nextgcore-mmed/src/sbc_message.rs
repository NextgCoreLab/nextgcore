//! SBC-AP Message Definitions
//!
//! Port of src/mme/sbc-message.h - SBc-AP message structures for PWS (Public Warning System)
//!
//! SBc-AP (SBc Application Part) is the protocol between MME and CBC (Cell Broadcast Centre)
//! for delivering emergency alerts (ETWS - Earthquake and Tsunami Warning System,
//! CMAS - Commercial Mobile Alert System, EU-Alert, etc.)
//!
//! Reference: 3GPP TS 29.168

use crate::context::EpsTai;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of TAIs in a warning message
pub const SBC_MAX_NUM_OF_TAI: usize = 65535;
/// Practical limit for TAI list
pub const SBC_PRACTICAL_MAX_TAI: usize = 16;
/// Maximum message content length (characters)
pub const SBC_MAX_MESSAGE_LENGTH: usize = 9600;
/// Practical limit for message content
pub const SBC_PRACTICAL_MAX_MESSAGE_LENGTH: usize = 1024;

/// Warning message type - ETWS Primary Notification
pub const SBC_MSG_TYPE_ETWS_PRIMARY: u8 = 0;
/// Warning message type - ETWS Secondary Notification
pub const SBC_MSG_TYPE_ETWS_SECONDARY: u8 = 1;
/// Warning message type - CMAS
pub const SBC_MSG_TYPE_CMAS: u8 = 2;
/// Warning message type - EU-Alert
pub const SBC_MSG_TYPE_EU_ALERT: u8 = 3;

// ============================================================================
// Message ID Ranges (3GPP TS 23.041)
// ============================================================================

/// ETWS Earthquake message ID
pub const MSG_ID_ETWS_EARTHQUAKE: u16 = 0x1100;
/// ETWS Tsunami message ID
pub const MSG_ID_ETWS_TSUNAMI: u16 = 0x1101;
/// ETWS Earthquake and Tsunami message ID
pub const MSG_ID_ETWS_EARTHQUAKE_AND_TSUNAMI: u16 = 0x1102;
/// ETWS Test message ID
pub const MSG_ID_ETWS_TEST: u16 = 0x1103;
/// ETWS Other Emergency message ID
pub const MSG_ID_ETWS_OTHER: u16 = 0x1104;
/// ETWS Future use start
pub const MSG_ID_ETWS_FUTURE_START: u16 = 0x1105;
/// ETWS Future use end
pub const MSG_ID_ETWS_FUTURE_END: u16 = 0x1107;

/// CMAS Presidential Alert
pub const MSG_ID_CMAS_PRESIDENTIAL: u16 = 0x1112;
/// CMAS Extreme Alert with severity Extreme, Urgency Immediate, Certainty Observed
pub const MSG_ID_CMAS_EXTREME_IMMEDIATE_OBSERVED: u16 = 0x1113;
/// CMAS Extreme Alert with severity Extreme, Urgency Immediate, Certainty Likely
pub const MSG_ID_CMAS_EXTREME_IMMEDIATE_LIKELY: u16 = 0x1114;
/// CMAS Severe Alert
pub const MSG_ID_CMAS_SEVERE_START: u16 = 0x1115;
/// CMAS Severe Alert End
pub const MSG_ID_CMAS_SEVERE_END: u16 = 0x111A;
/// CMAS Amber Alert (Child Abduction)
pub const MSG_ID_CMAS_AMBER: u16 = 0x111B;
/// CMAS Monthly Test
pub const MSG_ID_CMAS_TEST: u16 = 0x111C;
/// CMAS Exercise
pub const MSG_ID_CMAS_EXERCISE: u16 = 0x111D;
/// CMAS Operator defined use
pub const MSG_ID_CMAS_OPERATOR_DEFINED: u16 = 0x111E;
/// CMAS Public Safety
pub const MSG_ID_CMAS_PUBLIC_SAFETY: u16 = 0x111F;
/// CMAS State/Local Test
pub const MSG_ID_CMAS_STATE_LOCAL_TEST: u16 = 0x1120;

// ============================================================================
// Data Coding Scheme (3GPP TS 23.038)
// ============================================================================

/// GSM 7-bit default alphabet
pub const DCS_GSM7: u8 = 0x00;
/// 8-bit data
pub const DCS_8BIT: u8 = 0x04;
/// UCS2 (16-bit)
pub const DCS_UCS2: u8 = 0x08;

// ============================================================================
// SBC-AP Message Types
// ============================================================================

/// SBc-AP Procedure Code: Write-Replace Warning
pub const SBC_PROCEDURE_WRITE_REPLACE_WARNING: u8 = 0;
/// SBc-AP Procedure Code: Stop Warning
pub const SBC_PROCEDURE_STOP_WARNING: u8 = 1;
/// SBc-AP Procedure Code: Error Indication
pub const SBC_PROCEDURE_ERROR_INDICATION: u8 = 2;
/// SBc-AP Procedure Code: Write-Replace Warning Indication
pub const SBC_PROCEDURE_WRITE_REPLACE_WARNING_INDICATION: u8 = 3;
/// SBc-AP Procedure Code: Stop Warning Indication
pub const SBC_PROCEDURE_STOP_WARNING_INDICATION: u8 = 4;
/// SBc-AP Procedure Code: PWS Restart Indication
pub const SBC_PROCEDURE_PWS_RESTART_INDICATION: u8 = 5;
/// SBc-AP Procedure Code: PWS Failure Indication
pub const SBC_PROCEDURE_PWS_FAILURE_INDICATION: u8 = 6;

// ============================================================================
// PWS Data Structure
// ============================================================================

/// Public Warning System data for Write-Replace Warning Request / Stop Warning Request
#[derive(Debug, Clone)]
pub struct SbcPwsData {
    /// Message Identifier (3GPP TS 23.041)
    /// Identifies the source and type of the warning message
    pub message_id: u16,

    /// Serial Number
    /// Together with Message Identifier, uniquely identifies a warning message
    pub serial_number: u16,

    /// Number of TAIs (Tracking Area Identifiers)
    /// If 0, the warning is broadcast to all cells under the MME
    pub no_of_tai: u32,

    /// List of TAIs for targeted warning
    pub tai: Vec<EpsTai>,

    /// Repetition Period in seconds
    /// Indicates the period for which the warning message should be broadcast
    pub repetition_period: u32,

    /// Number of Broadcasts Requested
    /// 0 means unlimited broadcasts until stopped
    pub number_of_broadcast: u32,

    /// Data Coding Scheme (3GPP TS 23.038)
    pub data_coding_scheme: u8,

    /// Warning Message Content length
    pub message_length: u32,

    /// Warning Message Content
    pub message_contents: Vec<u8>,

    /// Warning Area Coordinates (optional, for location-based alerts)
    pub warning_area_coordinates: Option<WarningAreaCoordinates>,

    /// Concurrent Warning Message Indicator
    pub concurrent_warning_message_indicator: bool,

    /// Extended Repetition Period (optional, for extended duration alerts)
    pub extended_repetition_period: Option<u32>,

    /// Send Write-Replace-Warning-Indication flag
    pub send_write_replace_warning_indication: bool,

    /// ETWS specific: Warning Type (only for ETWS)
    pub warning_type: Option<EtwsWarningType>,
}

impl SbcPwsData {
    /// Create a new SBC PWS data structure
    pub fn new(message_id: u16, serial_number: u16) -> Self {
        Self {
            message_id,
            serial_number,
            no_of_tai: 0,
            tai: Vec::new(),
            repetition_period: 0,
            number_of_broadcast: 0,
            data_coding_scheme: DCS_GSM7,
            message_length: 0,
            message_contents: Vec::new(),
            warning_area_coordinates: None,
            concurrent_warning_message_indicator: false,
            extended_repetition_period: None,
            send_write_replace_warning_indication: false,
            warning_type: None,
        }
    }

    /// Add a TAI to the warning area
    pub fn add_tai(&mut self, tai: EpsTai) {
        self.tai.push(tai);
        self.no_of_tai = self.tai.len() as u32;
    }

    /// Set the message content
    pub fn set_message(&mut self, content: &[u8], dcs: u8) {
        self.message_contents = content.to_vec();
        self.message_length = content.len() as u32;
        self.data_coding_scheme = dcs;
    }

    /// Check if this is an ETWS message
    pub fn is_etws(&self) -> bool {
        self.message_id >= MSG_ID_ETWS_EARTHQUAKE && self.message_id <= MSG_ID_ETWS_FUTURE_END
    }

    /// Check if this is a CMAS message
    pub fn is_cmas(&self) -> bool {
        self.message_id >= MSG_ID_CMAS_PRESIDENTIAL && self.message_id <= MSG_ID_CMAS_STATE_LOCAL_TEST
    }

    /// Check if this is a test message
    pub fn is_test(&self) -> bool {
        self.message_id == MSG_ID_ETWS_TEST
            || self.message_id == MSG_ID_CMAS_TEST
            || self.message_id == MSG_ID_CMAS_EXERCISE
            || self.message_id == MSG_ID_CMAS_STATE_LOCAL_TEST
    }
}

impl Default for SbcPwsData {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ============================================================================
// ETWS Warning Type
// ============================================================================

/// ETWS Warning Type (3GPP TS 23.041)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtwsWarningType {
    /// Warning type value (bits 0-6)
    pub warning_type_value: u8,
    /// Emergency user alert (bit 8)
    pub emergency_user_alert: bool,
    /// Popup (bit 7)
    pub popup: bool,
}

impl EtwsWarningType {
    /// Earthquake warning type
    pub const EARTHQUAKE: u8 = 0;
    /// Tsunami warning type
    pub const TSUNAMI: u8 = 1;
    /// Earthquake and Tsunami warning type
    pub const EARTHQUAKE_AND_TSUNAMI: u8 = 2;
    /// Test warning type
    pub const TEST: u8 = 3;
    /// Other warning type
    pub const OTHER: u8 = 4;

    /// Create a new ETWS warning type
    pub fn new(warning_type_value: u8, emergency_user_alert: bool, popup: bool) -> Self {
        Self {
            warning_type_value,
            emergency_user_alert,
            popup,
        }
    }

    /// Encode to two octets as per 3GPP TS 23.041
    pub fn encode(&self) -> [u8; 2] {
        let mut octets = [0u8; 2];
        octets[0] = self.warning_type_value & 0x7F;
        if self.emergency_user_alert {
            octets[1] |= 0x01;
        }
        if self.popup {
            octets[0] |= 0x80;
        }
        octets
    }

    /// Decode from two octets
    pub fn decode(octets: [u8; 2]) -> Self {
        Self {
            warning_type_value: octets[0] & 0x7F,
            popup: (octets[0] & 0x80) != 0,
            emergency_user_alert: (octets[1] & 0x01) != 0,
        }
    }
}

// ============================================================================
// Warning Area Coordinates
// ============================================================================

/// Warning Area Coordinates for location-based alerts
#[derive(Debug, Clone)]
pub struct WarningAreaCoordinates {
    /// Latitude in degrees (-90.0 to 90.0)
    pub latitude: f64,
    /// Longitude in degrees (-180.0 to 180.0)
    pub longitude: f64,
    /// Radius in meters
    pub radius: u32,
}

impl WarningAreaCoordinates {
    /// Create new warning area coordinates
    pub fn new(latitude: f64, longitude: f64, radius: u32) -> Self {
        Self {
            latitude,
            longitude,
            radius,
        }
    }
}

// ============================================================================
// SBC-AP Response Types
// ============================================================================

/// Write-Replace Warning Response
#[derive(Debug, Clone)]
pub struct WriteReplaceWarningResponse {
    /// Message Identifier
    pub message_id: u16,
    /// Serial Number
    pub serial_number: u16,
    /// Cause (optional, present if failure)
    pub cause: Option<SbcCause>,
    /// Unknown TAI list (optional)
    pub unknown_tai_list: Vec<EpsTai>,
}

/// Stop Warning Response
#[derive(Debug, Clone)]
pub struct StopWarningResponse {
    /// Message Identifier
    pub message_id: u16,
    /// Serial Number
    pub serial_number: u16,
    /// Cause (optional, present if failure)
    pub cause: Option<SbcCause>,
    /// Unknown TAI list (optional)
    pub unknown_tai_list: Vec<EpsTai>,
}

/// SBc-AP Cause values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SbcCause {
    /// Message accepted
    MessageAccepted = 0,
    /// Parameter not recognised
    ParameterNotRecognised = 1,
    /// Parameter value invalid
    ParameterValueInvalid = 2,
    /// Valid message not identified
    ValidMessageNotIdentified = 3,
    /// Tracking area not valid
    TrackingAreaNotValid = 4,
    /// Unrecognised message
    UnrecognisedMessage = 5,
    /// Missing mandatory element
    MissingMandatoryElement = 6,
    /// MME capacity exceeded
    MmeCapacityExceeded = 7,
    /// MME memory exceeded
    MmeMemoryExceeded = 8,
    /// Warning broadcast not supported
    WarningBroadcastNotSupported = 9,
    /// Warning broadcast not operational
    WarningBroadcastNotOperational = 10,
    /// Message reference already used
    MessageReferenceAlreadyUsed = 11,
    /// Unspecified error
    UnspecifiedError = 12,
    /// Transfer syntax error
    TransferSyntaxError = 13,
    /// Semantic error
    SemanticError = 14,
    /// Message not compatible with receiver state
    MessageNotCompatibleWithReceiverState = 15,
    /// Abstract syntax error (reject)
    AbstractSyntaxErrorReject = 16,
    /// Abstract syntax error (ignore and notify)
    AbstractSyntaxErrorIgnoreAndNotify = 17,
    /// Abstract syntax error (falsely constructed message)
    AbstractSyntaxErrorFalselyConstructedMessage = 18,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PlmnId;

    #[test]
    fn test_sbc_pws_data_new() {
        let pws = SbcPwsData::new(MSG_ID_ETWS_EARTHQUAKE, 0x0001);
        assert_eq!(pws.message_id, MSG_ID_ETWS_EARTHQUAKE);
        assert_eq!(pws.serial_number, 0x0001);
        assert!(pws.is_etws());
        assert!(!pws.is_cmas());
    }

    #[test]
    fn test_cmas_message() {
        let pws = SbcPwsData::new(MSG_ID_CMAS_PRESIDENTIAL, 0x0001);
        assert!(!pws.is_etws());
        assert!(pws.is_cmas());
        assert!(!pws.is_test());
    }

    #[test]
    fn test_test_message() {
        let pws = SbcPwsData::new(MSG_ID_ETWS_TEST, 0x0001);
        assert!(pws.is_test());

        let pws2 = SbcPwsData::new(MSG_ID_CMAS_TEST, 0x0001);
        assert!(pws2.is_test());
    }

    #[test]
    fn test_etws_warning_type() {
        let wt = EtwsWarningType::new(EtwsWarningType::EARTHQUAKE, true, true);
        let encoded = wt.encode();
        let decoded = EtwsWarningType::decode(encoded);
        assert_eq!(decoded.warning_type_value, EtwsWarningType::EARTHQUAKE);
        assert!(decoded.emergency_user_alert);
        assert!(decoded.popup);
    }

    #[test]
    fn test_add_tai() {
        let mut pws = SbcPwsData::new(MSG_ID_CMAS_AMBER, 0x0001);
        let tai = EpsTai {
            plmn_id: PlmnId::default(),
            tac: 0x0001,
        };
        pws.add_tai(tai);
        assert_eq!(pws.no_of_tai, 1);
    }
}
