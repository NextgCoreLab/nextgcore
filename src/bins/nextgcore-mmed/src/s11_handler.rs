//! S11 (GTP-C) Message Handling
//!
//! Port of src/mme/mme-s11-handler.c - GTP-C message handling for S11 interface

use crate::s11_build::{message_type, ie_type};

// ============================================================================
// Error Types
// ============================================================================

/// S11 handler error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S11Error {
    ContextNotFound,
    MandatoryIeMissing(String),
    InvalidMessageFormat,
    InvalidCause(u8),
    TransactionError,
    InternalError(String),
}

impl std::fmt::Display for S11Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContextNotFound => write!(f, "Context not found"),
            Self::MandatoryIeMissing(ie) => write!(f, "Mandatory IE missing: {}", ie),
            Self::InvalidMessageFormat => write!(f, "Invalid message format"),
            Self::InvalidCause(c) => write!(f, "Invalid cause: {}", c),
            Self::TransactionError => write!(f, "Transaction error"),
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for S11Error {}

pub type S11Result<T> = Result<T, S11Error>;

// ============================================================================
// ESM Cause Mapping
// ============================================================================

/// ESM cause codes (3GPP TS 24.301)
pub mod esm_cause {
    pub const OPERATOR_DETERMINED_BARRING: u8 = 8;
    pub const INSUFFICIENT_RESOURCES: u8 = 26;
    pub const MISSING_OR_UNKNOWN_APN: u8 = 27;
    pub const USER_AUTHENTICATION_FAILED: u8 = 29;
    pub const REQUEST_REJECTED_BY_SERVING_GW_OR_PDN_GW: u8 = 30;
    pub const SERVICE_OPTION_NOT_SUPPORTED: u8 = 32;
    pub const REGULAR_DEACTIVATION: u8 = 36;
    pub const NETWORK_FAILURE: u8 = 38;
    pub const SEMANTIC_ERROR_IN_THE_TFT_OPERATION: u8 = 41;
    pub const SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION: u8 = 42;
    pub const INVALID_EPS_BEARER_IDENTITY: u8 = 43;
    pub const SEMANTIC_ERRORS_IN_PACKET_FILTERS: u8 = 44;
    pub const SYNTACTICAL_ERROR_IN_PACKET_FILTERS: u8 = 45;
}

/// Convert GTP cause to ESM cause
pub fn esm_cause_from_gtp(gtp_cause: u8) -> u8 {
    match gtp_cause {
        64 => esm_cause::INVALID_EPS_BEARER_IDENTITY,
        68 => esm_cause::SERVICE_OPTION_NOT_SUPPORTED,
        74 => esm_cause::SEMANTIC_ERROR_IN_THE_TFT_OPERATION,
        75 => esm_cause::SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION,
        76 => esm_cause::SEMANTIC_ERRORS_IN_PACKET_FILTERS,
        77 => esm_cause::SYNTACTICAL_ERROR_IN_PACKET_FILTERS,
        _ => esm_cause::NETWORK_FAILURE,
    }
}

// ============================================================================
// Parsed Message Structures
// ============================================================================

/// Parsed Create Session Response
#[derive(Debug, Clone, Default)]
pub struct CreateSessionResponseData {
    pub cause: u8,
    pub sgw_s11_teid: u32,
    pub sgw_s11_ipv4: Option<[u8; 4]>,
    pub pgw_s5c_teid: u32,
    pub pgw_s5c_ipv4: Option<[u8; 4]>,
    pub paa_pdn_type: u8,
    pub paa_ipv4: Option<[u8; 4]>,
    pub paa_ipv6: Option<[u8; 16]>,
    pub bearer_contexts: Vec<BearerContextCreated>,
    pub ambr_uplink: u64,
    pub ambr_downlink: u64,
    pub pco: Option<Vec<u8>>,
    pub epco: Option<Vec<u8>>,
}

/// Bearer context created
#[derive(Debug, Clone, Default)]
pub struct BearerContextCreated {
    pub ebi: u8,
    pub cause: u8,
    pub sgw_s1u_teid: u32,
    pub sgw_s1u_ipv4: Option<[u8; 4]>,
    pub pgw_s5u_teid: u32,
    pub pgw_s5u_ipv4: Option<[u8; 4]>,
    pub qci: u8,
    pub arp_priority: u8,
    pub arp_pec: u8,
    pub arp_pev: u8,
}

/// Parsed Modify Bearer Response
#[derive(Debug, Clone, Default)]
pub struct ModifyBearerResponseData {
    pub cause: u8,
    pub bearer_contexts: Vec<BearerContextModified>,
}

/// Bearer context modified
#[derive(Debug, Clone, Default)]
pub struct BearerContextModified {
    pub ebi: u8,
    pub cause: u8,
}

/// Parsed Delete Session Response
#[derive(Debug, Clone, Default)]
pub struct DeleteSessionResponseData {
    pub cause: u8,
}

/// Parsed Create Bearer Request
#[derive(Debug, Clone, Default)]
pub struct CreateBearerRequestData {
    pub linked_ebi: u8,
    pub pti: u8,
    pub bearer_context: BearerContextToBeCreated,
}

/// Bearer context to be created
#[derive(Debug, Clone, Default)]
pub struct BearerContextToBeCreated {
    pub ebi: u8,
    pub sgw_s1u_teid: u32,
    pub sgw_s1u_ipv4: Option<[u8; 4]>,
    pub pgw_s5u_teid: u32,
    pub pgw_s5u_ipv4: Option<[u8; 4]>,
    pub qci: u8,
    pub arp_priority: u8,
    pub arp_pec: u8,
    pub arp_pev: u8,
    pub mbr_uplink: u64,
    pub mbr_downlink: u64,
    pub gbr_uplink: u64,
    pub gbr_downlink: u64,
    pub tft: Vec<u8>,
}

/// Parsed Update Bearer Request
#[derive(Debug, Clone, Default)]
pub struct UpdateBearerRequestData {
    pub pti: u8,
    pub bearer_context: BearerContextToBeUpdated,
}

/// Bearer context to be updated
#[derive(Debug, Clone, Default)]
pub struct BearerContextToBeUpdated {
    pub ebi: u8,
    pub qci: Option<u8>,
    pub arp_priority: Option<u8>,
    pub arp_pec: Option<u8>,
    pub arp_pev: Option<u8>,
    pub mbr_uplink: Option<u64>,
    pub mbr_downlink: Option<u64>,
    pub gbr_uplink: Option<u64>,
    pub gbr_downlink: Option<u64>,
    pub tft: Option<Vec<u8>>,
}

/// Parsed Delete Bearer Request
#[derive(Debug, Clone, Default)]
pub struct DeleteBearerRequestData {
    pub linked_ebi: Option<u8>,
    pub ebi: Option<u8>,
    pub pti: u8,
}

/// Parsed Release Access Bearers Response
#[derive(Debug, Clone, Default)]
pub struct ReleaseAccessBearersResponseData {
    pub cause: u8,
}

/// Parsed Downlink Data Notification
#[derive(Debug, Clone, Default)]
pub struct DownlinkDataNotificationData {
    pub ebi: u8,
    pub cause: Option<u8>,
}


// ============================================================================
// Parsing Helper Functions
// ============================================================================

/// Parse GTP-C message header
pub fn parse_gtp_header(data: &[u8]) -> S11Result<(u8, u32, u32, &[u8])> {
    if data.len() < 8 {
        return Err(S11Error::InvalidMessageFormat);
    }
    
    let flags = data[0];
    let msg_type = data[1];
    let has_teid = (flags & 0x08) != 0;
    
    if has_teid {
        if data.len() < 12 {
            return Err(S11Error::InvalidMessageFormat);
        }
        let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let seq_num = ((data[8] as u32) << 16) | ((data[9] as u32) << 8) | (data[10] as u32);
        let payload = &data[12..];
        Ok((msg_type, teid, seq_num, payload))
    } else {
        let seq_num = ((data[4] as u32) << 16) | ((data[5] as u32) << 8) | (data[6] as u32);
        let payload = &data[8..];
        Ok((msg_type, 0, seq_num, payload))
    }
}

/// Parse IE header
pub fn parse_ie_header(data: &[u8]) -> Option<(u8, u16, u8, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    
    let ie_type = data[0];
    let length = u16::from_be_bytes([data[1], data[2]]);
    let instance = data[3] & 0x0f;
    
    if data.len() < 4 + length as usize {
        return None;
    }
    
    let value = &data[4..4 + length as usize];
    Some((ie_type, length, instance, value))
}

/// Parse F-TEID IE
pub fn parse_f_teid(data: &[u8]) -> Option<(u8, u32, Option<[u8; 4]>, Option<[u8; 16]>)> {
    if data.len() < 5 {
        return None;
    }
    
    let flags = data[0];
    let interface_type = flags & 0x3f;
    let has_v4 = (flags & 0x80) != 0;
    let has_v6 = (flags & 0x40) != 0;
    
    let teid = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    
    let mut offset = 5;
    let ipv4 = if has_v4 {
        if data.len() < offset + 4 {
            return None;
        }
        let addr = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
        offset += 4;
        Some(addr)
    } else {
        None
    };
    
    let ipv6 = if has_v6 {
        if data.len() < offset + 16 {
            return None;
        }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&data[offset..offset + 16]);
        Some(addr)
    } else {
        None
    };
    
    Some((interface_type, teid, ipv4, ipv6))
}

/// Parse Cause IE
pub fn parse_cause(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None;
    }
    Some(data[0])
}

/// Parse EBI IE
pub fn parse_ebi(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None;
    }
    Some(data[0] & 0x0f)
}

/// Parse PAA IE
pub fn parse_paa(data: &[u8]) -> Option<(u8, Option<[u8; 4]>, Option<[u8; 16]>)> {
    if data.is_empty() {
        return None;
    }
    
    let pdn_type = data[0] & 0x07;
    
    match pdn_type {
        1 => { // IPv4
            if data.len() < 5 {
                return None;
            }
            let addr = [data[1], data[2], data[3], data[4]];
            Some((pdn_type, Some(addr), None))
        }
        2 => { // IPv6
            if data.len() < 18 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&data[2..18]);
            Some((pdn_type, None, Some(addr)))
        }
        3 => { // IPv4v6
            if data.len() < 22 {
                return None;
            }
            let mut addr6 = [0u8; 16];
            addr6.copy_from_slice(&data[2..18]);
            let addr4 = [data[18], data[19], data[20], data[21]];
            Some((pdn_type, Some(addr4), Some(addr6)))
        }
        _ => Some((pdn_type, None, None))
    }
}

/// Parse AMBR IE
pub fn parse_ambr(data: &[u8]) -> Option<(u64, u64)> {
    if data.len() < 8 {
        return None;
    }
    
    let uplink = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64 * 1000;
    let downlink = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as u64 * 1000;
    
    Some((uplink, downlink))
}

/// Parse Bearer QoS IE
pub fn parse_bearer_qos(data: &[u8]) -> Option<(u8, u8, u8, u8, u64, u64, u64, u64)> {
    if data.len() < 22 {
        return None;
    }
    
    let arp = data[0];
    let arp_pec = (arp >> 6) & 0x01;
    let arp_priority = (arp >> 2) & 0x0f;
    let arp_pev = arp & 0x01;
    
    let qci = data[1];
    
    let mbr_ul = parse_bitrate(&data[2..7]);
    let mbr_dl = parse_bitrate(&data[7..12]);
    let gbr_ul = parse_bitrate(&data[12..17]);
    let gbr_dl = parse_bitrate(&data[17..22]);
    
    Some((qci, arp_priority, arp_pec, arp_pev, mbr_ul, mbr_dl, gbr_ul, gbr_dl))
}

/// Parse bitrate from 5-byte format
fn parse_bitrate(data: &[u8]) -> u64 {
    if data.len() < 5 {
        return 0;
    }
    let kbps = ((data[0] as u64) << 32)
        | ((data[1] as u64) << 24)
        | ((data[2] as u64) << 16)
        | ((data[3] as u64) << 8)
        | (data[4] as u64);
    kbps * 1000
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Handle Echo Request
pub fn handle_echo_request(recovery: u8) -> S11Result<u8> {
    Ok(recovery)
}

/// Handle Echo Response
pub fn handle_echo_response(recovery: u8) -> S11Result<u8> {
    Ok(recovery)
}

/// Handle Create Session Response
pub fn handle_create_session_response(data: &[u8]) -> S11Result<CreateSessionResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;
    
    if msg_type != message_type::CREATE_SESSION_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }
    
    let mut result = CreateSessionResponseData::default();
    let mut offset = 0;
    
    while offset < payload.len() {
        if let Some((ie_t, length, instance, value)) = parse_ie_header(&payload[offset..]) {
            match ie_t {
                ie_type::CAUSE => {
                    if let Some(cause) = parse_cause(value) {
                        result.cause = cause;
                    }
                }
                ie_type::F_TEID => {
                    if let Some((iface_type, teid, ipv4, _)) = parse_f_teid(value) {
                        match (iface_type, instance) {
                            (11, 0) => {
                                result.sgw_s11_teid = teid;
                                result.sgw_s11_ipv4 = ipv4;
                            }
                            (7, 1) => {
                                result.pgw_s5c_teid = teid;
                                result.pgw_s5c_ipv4 = ipv4;
                            }
                            _ => {}
                        }
                    }
                }
                ie_type::PAA => {
                    if let Some((pdn_type, ipv4, ipv6)) = parse_paa(value) {
                        result.paa_pdn_type = pdn_type;
                        result.paa_ipv4 = ipv4;
                        result.paa_ipv6 = ipv6;
                    }
                }
                ie_type::AMBR => {
                    if let Some((ul, dl)) = parse_ambr(value) {
                        result.ambr_uplink = ul;
                        result.ambr_downlink = dl;
                    }
                }
                ie_type::PCO => {
                    result.pco = Some(value.to_vec());
                }
                ie_type::EPCO => {
                    result.epco = Some(value.to_vec());
                }
                _ => {}
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }
    
    if result.cause == 0 {
        return Err(S11Error::MandatoryIeMissing("Cause".to_string()));
    }
    
    Ok(result)
}

/// Handle Modify Bearer Response
pub fn handle_modify_bearer_response(data: &[u8]) -> S11Result<ModifyBearerResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;
    
    if msg_type != message_type::MODIFY_BEARER_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }
    
    let mut result = ModifyBearerResponseData::default();
    let mut offset = 0;
    
    while offset < payload.len() {
        if let Some((ie_t, length, _, value)) = parse_ie_header(&payload[offset..]) {
            if ie_t == ie_type::CAUSE {
                if let Some(cause) = parse_cause(value) {
                    result.cause = cause;
                }
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }
    
    Ok(result)
}

/// Handle Delete Session Response
pub fn handle_delete_session_response(data: &[u8]) -> S11Result<DeleteSessionResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;
    
    if msg_type != message_type::DELETE_SESSION_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }
    
    let mut result = DeleteSessionResponseData::default();
    let mut offset = 0;
    
    while offset < payload.len() {
        if let Some((ie_t, length, _, value)) = parse_ie_header(&payload[offset..]) {
            if ie_t == ie_type::CAUSE {
                if let Some(cause) = parse_cause(value) {
                    result.cause = cause;
                }
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }
    
    Ok(result)
}

/// Handle Release Access Bearers Response
pub fn handle_release_access_bearers_response(data: &[u8]) -> S11Result<ReleaseAccessBearersResponseData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;
    
    if msg_type != message_type::RELEASE_ACCESS_BEARERS_RESPONSE {
        return Err(S11Error::InvalidMessageFormat);
    }
    
    let mut result = ReleaseAccessBearersResponseData::default();
    let mut offset = 0;
    
    while offset < payload.len() {
        if let Some((ie_t, length, _, value)) = parse_ie_header(&payload[offset..]) {
            if ie_t == ie_type::CAUSE {
                if let Some(cause) = parse_cause(value) {
                    result.cause = cause;
                }
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }
    
    Ok(result)
}

/// Handle Downlink Data Notification
pub fn handle_downlink_data_notification(data: &[u8]) -> S11Result<DownlinkDataNotificationData> {
    let (msg_type, _, _, payload) = parse_gtp_header(data)?;
    
    if msg_type != message_type::DOWNLINK_DATA_NOTIFICATION {
        return Err(S11Error::InvalidMessageFormat);
    }
    
    let mut result = DownlinkDataNotificationData::default();
    let mut offset = 0;
    
    while offset < payload.len() {
        if let Some((ie_t, length, _, value)) = parse_ie_header(&payload[offset..]) {
            match ie_t {
                ie_type::EBI => {
                    if let Some(ebi) = parse_ebi(value) {
                        result.ebi = ebi;
                    }
                }
                ie_type::CAUSE => {
                    if let Some(cause) = parse_cause(value) {
                        result.cause = Some(cause);
                    }
                }
                _ => {}
            }
            offset += 4 + length as usize;
        } else {
            break;
        }
    }
    
    if result.ebi == 0 {
        return Err(S11Error::MandatoryIeMissing("EPS Bearer ID".to_string()));
    }
    
    Ok(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s11_build::*;

    #[test]
    fn test_esm_cause_from_gtp() {
        assert_eq!(esm_cause_from_gtp(64), esm_cause::INVALID_EPS_BEARER_IDENTITY);
        assert_eq!(esm_cause_from_gtp(68), esm_cause::SERVICE_OPTION_NOT_SUPPORTED);
        assert_eq!(esm_cause_from_gtp(0), esm_cause::NETWORK_FAILURE);
    }

    #[test]
    fn test_handle_echo_request() {
        let result = handle_echo_request(5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);
    }

    #[test]
    fn test_parse_gtp_header_with_teid() {
        let msg = build_release_access_bearers_request(0x12345678, 100);
        let (msg_type, teid, seq_num, _) = parse_gtp_header(&msg).unwrap();
        
        assert_eq!(msg_type, message_type::RELEASE_ACCESS_BEARERS_REQUEST);
        assert_eq!(teid, 0x12345678);
        assert_eq!(seq_num, 100);
    }

    #[test]
    fn test_parse_gtp_header_no_teid() {
        let msg = build_echo_request(123, 5);
        let (msg_type, teid, seq_num, _) = parse_gtp_header(&msg).unwrap();
        
        assert_eq!(msg_type, message_type::ECHO_REQUEST);
        assert_eq!(teid, 0);
        assert_eq!(seq_num, 123);
    }

    #[test]
    fn test_parse_cause() {
        assert_eq!(parse_cause(&[16]), Some(16));
        assert_eq!(parse_cause(&[64]), Some(64));
        assert_eq!(parse_cause(&[]), None);
    }

    #[test]
    fn test_parse_ebi() {
        assert_eq!(parse_ebi(&[5]), Some(5));
        assert_eq!(parse_ebi(&[0x15]), Some(5));
        assert_eq!(parse_ebi(&[]), None);
    }

    #[test]
    fn test_parse_paa_ipv4() {
        let data = [1, 10, 0, 0, 1];
        let (pdn_type, ipv4, ipv6) = parse_paa(&data).unwrap();
        assert_eq!(pdn_type, 1);
        assert_eq!(ipv4, Some([10, 0, 0, 1]));
        assert!(ipv6.is_none());
    }

    #[test]
    fn test_parse_ambr() {
        let data = [0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x4E, 0x20];
        let (ul, dl) = parse_ambr(&data).unwrap();
        assert_eq!(ul, 10_000_000);
        assert_eq!(dl, 20_000_000);
    }

    #[test]
    fn test_parse_f_teid() {
        let data = [0x80 | 11, 0x12, 0x34, 0x56, 0x78, 192, 168, 1, 1];
        let (iface_type, teid, ipv4, ipv6) = parse_f_teid(&data).unwrap();
        assert_eq!(iface_type, 11);
        assert_eq!(teid, 0x12345678);
        assert_eq!(ipv4, Some([192, 168, 1, 1]));
        assert!(ipv6.is_none());
    }
}
