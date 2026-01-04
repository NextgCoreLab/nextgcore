//! S1AP Message Handling
//!
//! Port of src/mme/s1ap-handler.c - S1AP message handling functions

use crate::context::{MmeContext, MmeEnb, EnbUe, MmeUe, PlmnId, EpsTai, ECgi, S1apCause, S1apCauseGroup};
use crate::s1ap_build::{self, procedure_code, protocol_ie_id, Criticality, PduType};

// ============================================================================
// S1AP Error Types
// ============================================================================

/// S1AP error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S1apError {
    /// Invalid message format
    InvalidMessage(String),
    /// Missing mandatory IE
    MissingMandatoryIe(String),
    /// Unknown procedure
    UnknownProcedure(u8),
    /// Unknown eNB
    UnknownEnb,
    /// Unknown UE
    UnknownUe,
    /// Decoding error
    DecodingError(String),
    /// Protocol error
    ProtocolError(String),
}

impl std::fmt::Display for S1apError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S1apError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            S1apError::MissingMandatoryIe(ie) => write!(f, "Missing mandatory IE: {}", ie),
            S1apError::UnknownProcedure(code) => write!(f, "Unknown procedure: {}", code),
            S1apError::UnknownEnb => write!(f, "Unknown eNB"),
            S1apError::UnknownUe => write!(f, "Unknown UE"),
            S1apError::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            S1apError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
        }
    }
}

impl std::error::Error for S1apError {}

/// S1AP result type
pub type S1apResult<T> = Result<T, S1apError>;


// ============================================================================
// S1 Setup Request Data
// ============================================================================

/// S1 Setup Request data
#[derive(Debug, Clone, Default)]
pub struct S1SetupRequestData {
    /// Global eNB ID
    pub enb_id: u32,
    /// eNB name (optional)
    pub enb_name: Option<String>,
    /// Supported TAs
    pub supported_ta_list: Vec<SupportedTa>,
    /// Default paging DRX
    pub default_paging_drx: Option<u8>,
}

/// Supported TA entry
#[derive(Debug, Clone, Default)]
pub struct SupportedTa {
    /// TAC
    pub tac: u16,
    /// Broadcast PLMNs
    pub broadcast_plmn_list: Vec<PlmnId>,
}

// ============================================================================
// Initial UE Message Data
// ============================================================================

/// Initial UE Message data
#[derive(Debug, Clone, Default)]
pub struct InitialUeMessageData {
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// NAS PDU
    pub nas_pdu: Vec<u8>,
    /// TAI
    pub tai: EpsTai,
    /// E-CGI
    pub e_cgi: ECgi,
    /// RRC establishment cause
    pub rrc_establishment_cause: u8,
    /// S-TMSI (optional)
    pub s_tmsi: Option<STmsi>,
    /// CSG ID (optional)
    pub csg_id: Option<u32>,
    /// GUMMEI (optional)
    pub gummei: Option<Gummei>,
}

/// S-TMSI
#[derive(Debug, Clone, Default)]
pub struct STmsi {
    /// MME Code
    pub mme_code: u8,
    /// M-TMSI
    pub m_tmsi: u32,
}

/// GUMMEI
#[derive(Debug, Clone, Default)]
pub struct Gummei {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// MME Group ID
    pub mme_gid: u16,
    /// MME Code
    pub mme_code: u8,
}

// ============================================================================
// Uplink NAS Transport Data
// ============================================================================

/// Uplink NAS Transport data
#[derive(Debug, Clone, Default)]
pub struct UplinkNasTransportData {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// NAS PDU
    pub nas_pdu: Vec<u8>,
    /// E-CGI
    pub e_cgi: ECgi,
    /// TAI
    pub tai: EpsTai,
}

// ============================================================================
// UE Context Release Data
// ============================================================================

/// UE Context Release Request data
#[derive(Debug, Clone, Default)]
pub struct UeContextReleaseRequestData {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
    /// Cause
    pub cause: S1apCause,
}

/// UE Context Release Complete data
#[derive(Debug, Clone, Default)]
pub struct UeContextReleaseCompleteData {
    /// MME UE S1AP ID
    pub mme_ue_s1ap_id: u32,
    /// eNB UE S1AP ID
    pub enb_ue_s1ap_id: u32,
}


// ============================================================================
// S1AP Message Handling Functions
// ============================================================================

/// Handle S1 Setup Request
pub fn handle_s1_setup_request(
    _ctx: &MmeContext,
    _enb: &MmeEnb,
    data: &[u8],
) -> S1apResult<S1SetupRequestData> {
    if data.len() < 4 {
        return Err(S1apError::InvalidMessage("S1 Setup Request too short".to_string()));
    }
    
    let mut result = S1SetupRequestData::default();
    let mut offset = 0;
    
    // Parse IEs
    while offset + 4 <= data.len() {
        let ie_id = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        let _criticality = data[offset + 2];
        let ie_len = ((data[offset + 3] as usize) << 8) | (data[offset + 4] as usize);
        offset += 5;
        
        if offset + ie_len > data.len() {
            break;
        }
        
        match ie_id {
            // Global eNB ID
            59 => {
                if ie_len >= 4 {
                    // Extract eNB ID (simplified)
                    result.enb_id = ((data[offset + 3] as u32) << 24)
                        | ((data[offset + 4] as u32) << 16)
                        | ((data[offset + 5] as u32) << 8)
                        | (data[offset + 6] as u32);
                }
            }
            // eNB Name
            60 => {
                result.enb_name = Some(String::from_utf8_lossy(&data[offset..offset + ie_len]).to_string());
            }
            // Supported TAs
            64 => {
                result.supported_ta_list = parse_supported_ta_list(&data[offset..offset + ie_len]);
            }
            // Default Paging DRX
            137 => {
                if ie_len >= 1 {
                    result.default_paging_drx = Some(data[offset]);
                }
            }
            _ => {
                // Skip unknown IE
            }
        }
        
        offset += ie_len;
    }
    
    Ok(result)
}

/// Handle Initial UE Message
pub fn handle_initial_ue_message(
    _ctx: &MmeContext,
    _enb: &MmeEnb,
    data: &[u8],
) -> S1apResult<InitialUeMessageData> {
    if data.len() < 4 {
        return Err(S1apError::InvalidMessage("Initial UE Message too short".to_string()));
    }
    
    let mut result = InitialUeMessageData::default();
    let mut offset = 0;
    
    // Parse IEs
    while offset + 4 <= data.len() {
        let ie_id = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        let _criticality = data[offset + 2];
        let ie_len = ((data[offset + 3] as usize) << 8) | (data[offset + 4] as usize);
        offset += 5;
        
        if offset + ie_len > data.len() {
            break;
        }
        
        match ie_id {
            // eNB UE S1AP ID
            8 => {
                if ie_len >= 4 {
                    result.enb_ue_s1ap_id = ((data[offset] as u32) << 24)
                        | ((data[offset + 1] as u32) << 16)
                        | ((data[offset + 2] as u32) << 8)
                        | (data[offset + 3] as u32);
                }
            }
            // NAS PDU
            26 => {
                result.nas_pdu = data[offset..offset + ie_len].to_vec();
            }
            // TAI
            67 => {
                if ie_len >= 5 {
                    result.tai = parse_tai(&data[offset..offset + ie_len]);
                }
            }
            // E-CGI
            100 => {
                if ie_len >= 7 {
                    result.e_cgi = parse_ecgi(&data[offset..offset + ie_len]);
                }
            }
            // RRC Establishment Cause
            134 => {
                if ie_len >= 1 {
                    result.rrc_establishment_cause = data[offset];
                }
            }
            // S-TMSI
            96 => {
                if ie_len >= 5 {
                    result.s_tmsi = Some(parse_s_tmsi(&data[offset..offset + ie_len]));
                }
            }
            _ => {
                // Skip unknown IE
            }
        }
        
        offset += ie_len;
    }
    
    // Validate mandatory IEs
    if result.nas_pdu.is_empty() {
        return Err(S1apError::MissingMandatoryIe("NAS-PDU".to_string()));
    }
    
    Ok(result)
}


/// Handle Uplink NAS Transport
pub fn handle_uplink_nas_transport(
    _ctx: &MmeContext,
    _enb: &MmeEnb,
    data: &[u8],
) -> S1apResult<UplinkNasTransportData> {
    if data.len() < 4 {
        return Err(S1apError::InvalidMessage("Uplink NAS Transport too short".to_string()));
    }
    
    let mut result = UplinkNasTransportData::default();
    let mut offset = 0;
    
    // Parse IEs
    while offset + 4 <= data.len() {
        let ie_id = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        let _criticality = data[offset + 2];
        let ie_len = ((data[offset + 3] as usize) << 8) | (data[offset + 4] as usize);
        offset += 5;
        
        if offset + ie_len > data.len() {
            break;
        }
        
        match ie_id {
            // MME UE S1AP ID
            0 => {
                if ie_len >= 4 {
                    result.mme_ue_s1ap_id = ((data[offset] as u32) << 24)
                        | ((data[offset + 1] as u32) << 16)
                        | ((data[offset + 2] as u32) << 8)
                        | (data[offset + 3] as u32);
                }
            }
            // eNB UE S1AP ID
            8 => {
                if ie_len >= 4 {
                    result.enb_ue_s1ap_id = ((data[offset] as u32) << 24)
                        | ((data[offset + 1] as u32) << 16)
                        | ((data[offset + 2] as u32) << 8)
                        | (data[offset + 3] as u32);
                }
            }
            // NAS PDU
            26 => {
                result.nas_pdu = data[offset..offset + ie_len].to_vec();
            }
            // E-CGI
            100 => {
                if ie_len >= 7 {
                    result.e_cgi = parse_ecgi(&data[offset..offset + ie_len]);
                }
            }
            // TAI
            67 => {
                if ie_len >= 5 {
                    result.tai = parse_tai(&data[offset..offset + ie_len]);
                }
            }
            _ => {
                // Skip unknown IE
            }
        }
        
        offset += ie_len;
    }
    
    // Validate mandatory IEs
    if result.nas_pdu.is_empty() {
        return Err(S1apError::MissingMandatoryIe("NAS-PDU".to_string()));
    }
    
    Ok(result)
}

/// Handle UE Context Release Request
pub fn handle_ue_context_release_request(
    _ctx: &MmeContext,
    _enb: &MmeEnb,
    data: &[u8],
) -> S1apResult<UeContextReleaseRequestData> {
    if data.len() < 4 {
        return Err(S1apError::InvalidMessage("UE Context Release Request too short".to_string()));
    }
    
    let mut result = UeContextReleaseRequestData::default();
    let mut offset = 0;
    
    // Parse IEs
    while offset + 4 <= data.len() {
        let ie_id = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        let _criticality = data[offset + 2];
        let ie_len = ((data[offset + 3] as usize) << 8) | (data[offset + 4] as usize);
        offset += 5;
        
        if offset + ie_len > data.len() {
            break;
        }
        
        match ie_id {
            // MME UE S1AP ID
            0 => {
                if ie_len >= 4 {
                    result.mme_ue_s1ap_id = ((data[offset] as u32) << 24)
                        | ((data[offset + 1] as u32) << 16)
                        | ((data[offset + 2] as u32) << 8)
                        | (data[offset + 3] as u32);
                }
            }
            // eNB UE S1AP ID
            8 => {
                if ie_len >= 4 {
                    result.enb_ue_s1ap_id = ((data[offset] as u32) << 24)
                        | ((data[offset + 1] as u32) << 16)
                        | ((data[offset + 2] as u32) << 8)
                        | (data[offset + 3] as u32);
                }
            }
            // Cause
            2 => {
                if ie_len >= 2 {
                    result.cause = parse_cause(&data[offset..offset + ie_len]);
                }
            }
            _ => {
                // Skip unknown IE
            }
        }
        
        offset += ie_len;
    }
    
    Ok(result)
}

/// Handle UE Context Release Complete
pub fn handle_ue_context_release_complete(
    _ctx: &MmeContext,
    _enb: &MmeEnb,
    data: &[u8],
) -> S1apResult<UeContextReleaseCompleteData> {
    if data.len() < 4 {
        return Err(S1apError::InvalidMessage("UE Context Release Complete too short".to_string()));
    }
    
    let mut result = UeContextReleaseCompleteData::default();
    let mut offset = 0;
    
    // Parse IEs
    while offset + 4 <= data.len() {
        let ie_id = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        let _criticality = data[offset + 2];
        let ie_len = ((data[offset + 3] as usize) << 8) | (data[offset + 4] as usize);
        offset += 5;
        
        if offset + ie_len > data.len() {
            break;
        }
        
        match ie_id {
            // MME UE S1AP ID
            0 => {
                if ie_len >= 4 {
                    result.mme_ue_s1ap_id = ((data[offset] as u32) << 24)
                        | ((data[offset + 1] as u32) << 16)
                        | ((data[offset + 2] as u32) << 8)
                        | (data[offset + 3] as u32);
                }
            }
            // eNB UE S1AP ID
            8 => {
                if ie_len >= 4 {
                    result.enb_ue_s1ap_id = ((data[offset] as u32) << 24)
                        | ((data[offset + 1] as u32) << 16)
                        | ((data[offset + 2] as u32) << 8)
                        | (data[offset + 3] as u32);
                }
            }
            _ => {
                // Skip unknown IE
            }
        }
        
        offset += ie_len;
    }
    
    Ok(result)
}


// ============================================================================
// Parsing Helper Functions
// ============================================================================

/// Parse supported TA list
fn parse_supported_ta_list(data: &[u8]) -> Vec<SupportedTa> {
    let mut list = Vec::new();
    
    if data.is_empty() {
        return list;
    }
    
    let num_items = data[0] as usize;
    let mut offset = 1;
    
    for _ in 0..num_items {
        if offset + 2 > data.len() {
            break;
        }
        
        let mut ta = SupportedTa::default();
        
        // TAC (2 bytes)
        ta.tac = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        offset += 2;
        
        // Broadcast PLMNs
        if offset >= data.len() {
            break;
        }
        let num_plmns = data[offset] as usize;
        offset += 1;
        
        for _ in 0..num_plmns {
            if offset + 3 > data.len() {
                break;
            }
            let plmn = parse_plmn_id(&data[offset..offset + 3]);
            ta.broadcast_plmn_list.push(plmn);
            offset += 3;
        }
        
        list.push(ta);
    }
    
    list
}

/// Parse PLMN ID
fn parse_plmn_id(data: &[u8]) -> PlmnId {
    if data.len() < 3 {
        return PlmnId::default();
    }
    
    PlmnId {
        mcc1: data[0] & 0x0f,
        mcc2: (data[0] >> 4) & 0x0f,
        mcc3: data[1] & 0x0f,
        mnc3: (data[1] >> 4) & 0x0f,
        mnc1: data[2] & 0x0f,
        mnc2: (data[2] >> 4) & 0x0f,
    }
}

/// Parse TAI
fn parse_tai(data: &[u8]) -> EpsTai {
    if data.len() < 5 {
        return EpsTai::default();
    }
    
    EpsTai {
        plmn_id: parse_plmn_id(&data[0..3]),
        tac: ((data[3] as u16) << 8) | (data[4] as u16),
    }
}

/// Parse E-CGI
fn parse_ecgi(data: &[u8]) -> ECgi {
    if data.len() < 7 {
        return ECgi::default();
    }
    
    ECgi {
        plmn_id: parse_plmn_id(&data[0..3]),
        cell_id: ((data[3] as u32) << 24)
            | ((data[4] as u32) << 16)
            | ((data[5] as u32) << 8)
            | (data[6] as u32),
    }
}

/// Parse S-TMSI
fn parse_s_tmsi(data: &[u8]) -> STmsi {
    if data.len() < 5 {
        return STmsi::default();
    }
    
    STmsi {
        mme_code: data[0],
        m_tmsi: ((data[1] as u32) << 24)
            | ((data[2] as u32) << 16)
            | ((data[3] as u32) << 8)
            | (data[4] as u32),
    }
}

/// Parse cause
fn parse_cause(data: &[u8]) -> S1apCause {
    if data.len() < 2 {
        return S1apCause::default();
    }
    
    let group = match data[0] {
        0 => S1apCauseGroup::RadioNetwork,
        1 => S1apCauseGroup::Transport,
        2 => S1apCauseGroup::Nas,
        3 => S1apCauseGroup::Protocol,
        4 => S1apCauseGroup::Misc,
        _ => S1apCauseGroup::Nothing,
    };
    
    S1apCause {
        group,
        cause: data[1] as i64,
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s1ap_error_display() {
        let err = S1apError::InvalidMessage("test".to_string());
        assert!(err.to_string().contains("Invalid message"));
        
        let err = S1apError::MissingMandatoryIe("NAS-PDU".to_string());
        assert!(err.to_string().contains("Missing mandatory IE"));
        
        let err = S1apError::UnknownProcedure(99);
        assert!(err.to_string().contains("Unknown procedure"));
    }

    #[test]
    fn test_parse_plmn_id() {
        // MCC=310, MNC=410
        let data = [0x13, 0xf0, 0x14];
        let plmn = parse_plmn_id(&data);
        assert_eq!(plmn.mcc1, 3);
        assert_eq!(plmn.mcc2, 1);
        assert_eq!(plmn.mcc3, 0);
    }

    #[test]
    fn test_parse_tai() {
        let data = [0x13, 0xf0, 0x14, 0x12, 0x34];
        let tai = parse_tai(&data);
        assert_eq!(tai.tac, 0x1234);
    }

    #[test]
    fn test_parse_ecgi() {
        let data = [0x13, 0xf0, 0x14, 0x12, 0x34, 0x56, 0x78];
        let ecgi = parse_ecgi(&data);
        assert_eq!(ecgi.cell_id, 0x12345678);
    }

    #[test]
    fn test_parse_s_tmsi() {
        let data = [0x01, 0x12, 0x34, 0x56, 0x78];
        let s_tmsi = parse_s_tmsi(&data);
        assert_eq!(s_tmsi.mme_code, 0x01);
        assert_eq!(s_tmsi.m_tmsi, 0x12345678);
    }

    #[test]
    fn test_parse_cause() {
        let data = [0x00, 0x14]; // RadioNetwork, cause 20
        let cause = parse_cause(&data);
        assert_eq!(cause.group, S1apCauseGroup::RadioNetwork);
        assert_eq!(cause.cause, 20);
    }

    #[test]
    fn test_s1_setup_request_data_default() {
        let data = S1SetupRequestData::default();
        assert_eq!(data.enb_id, 0);
        assert!(data.enb_name.is_none());
        assert!(data.supported_ta_list.is_empty());
    }

    #[test]
    fn test_initial_ue_message_data_default() {
        let data = InitialUeMessageData::default();
        assert_eq!(data.enb_ue_s1ap_id, 0);
        assert!(data.nas_pdu.is_empty());
    }

    #[test]
    fn test_uplink_nas_transport_data_default() {
        let data = UplinkNasTransportData::default();
        assert_eq!(data.mme_ue_s1ap_id, 0);
        assert_eq!(data.enb_ue_s1ap_id, 0);
        assert!(data.nas_pdu.is_empty());
    }
}
