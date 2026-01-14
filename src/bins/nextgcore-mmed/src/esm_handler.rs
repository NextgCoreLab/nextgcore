//! ESM Message Handling
//!
//! Port of src/mme/esm-handler.c - ESM message handling functions

use crate::context::{MmeUe, MmeSess, MmeBearer, EnbUe};
use crate::esm_build::{EsmCause, PdnType, CreateAction};

// ============================================================================
// ESM Error Types
// ============================================================================

/// ESM error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EsmError {
    /// Invalid message format
    InvalidMessage(String),
    /// Missing mandatory IE
    MissingMandatoryIe(String),
    /// Invalid PDN type
    InvalidPdnType(u8),
    /// Invalid APN
    InvalidApn(String),
    /// Security context not available
    NoSecurityContext,
    /// Session not found
    SessionNotFound,
    /// Bearer not found
    BearerNotFound,
    /// Protocol error
    ProtocolError(String),
    /// Network failure
    NetworkFailure(String),
}

impl std::fmt::Display for EsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EsmError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            EsmError::MissingMandatoryIe(ie) => write!(f, "Missing mandatory IE: {}", ie),
            EsmError::InvalidPdnType(t) => write!(f, "Invalid PDN type: {}", t),
            EsmError::InvalidApn(apn) => write!(f, "Invalid APN: {}", apn),
            EsmError::NoSecurityContext => write!(f, "No security context"),
            EsmError::SessionNotFound => write!(f, "Session not found"),
            EsmError::BearerNotFound => write!(f, "Bearer not found"),
            EsmError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            EsmError::NetworkFailure(msg) => write!(f, "Network failure: {}", msg),
        }
    }
}

impl std::error::Error for EsmError {}

/// ESM result type
pub type EsmResult<T> = Result<T, EsmError>;


// ============================================================================
// PDN Connectivity Request Data
// ============================================================================

/// PDN connectivity request data
#[derive(Debug, Clone, Default)]
pub struct PdnConnectivityRequestData {
    /// Request type
    pub request_type: u8,
    /// PDN type
    pub pdn_type: PdnType,
    /// ESM information transfer flag
    pub esm_info_transfer_flag: bool,
    /// APN (if present)
    pub apn: Option<String>,
    /// Protocol configuration options
    pub pco: Option<Vec<u8>>,
    /// Extended protocol configuration options
    pub epco: Option<Vec<u8>>,
}

/// Request type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestType {
    /// Initial request
    InitialRequest = 1,
    /// Handover
    Handover = 2,
    /// Unused
    Unused = 3,
    /// Emergency
    Emergency = 4,
}

// ============================================================================
// ESM Information Response Data
// ============================================================================

/// ESM information response data
#[derive(Debug, Clone, Default)]
pub struct EsmInformationResponseData {
    /// APN (if present)
    pub apn: Option<String>,
    /// Protocol configuration options
    pub pco: Option<Vec<u8>>,
    /// Extended protocol configuration options
    pub epco: Option<Vec<u8>>,
}

// ============================================================================
// Bearer Resource Request Data
// ============================================================================

/// Bearer resource allocation request data
#[derive(Debug, Clone, Default)]
pub struct BearerResourceAllocationRequestData {
    /// Linked EPS bearer identity
    pub linked_ebi: u8,
    /// Traffic flow aggregate
    pub tfa: Vec<u8>,
    /// Required traffic flow QoS
    pub required_qos: Option<RequiredQos>,
}

/// Bearer resource modification request data
#[derive(Debug, Clone, Default)]
pub struct BearerResourceModificationRequestData {
    /// EPS bearer identity for packet filter
    pub ebi_for_pf: u8,
    /// Traffic flow aggregate
    pub tfa: Vec<u8>,
    /// Required traffic flow QoS
    pub required_qos: Option<RequiredQos>,
    /// ESM cause
    pub esm_cause: Option<EsmCause>,
}

/// Required QoS
#[derive(Debug, Clone, Default)]
pub struct RequiredQos {
    /// QCI
    pub qci: u8,
    /// GBR uplink
    pub gbr_ul: u64,
    /// GBR downlink
    pub gbr_dl: u64,
    /// MBR uplink
    pub mbr_ul: u64,
    /// MBR downlink
    pub mbr_dl: u64,
}


// ============================================================================
// ESM Message Handling Functions
// ============================================================================

/// Handle PDN connectivity request
pub fn handle_pdn_connectivity_request(
    _enb_ue: &EnbUe,
    mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    data: &[u8],
    _create_action: CreateAction,
) -> EsmResult<PdnConnectivityRequestData> {
    // Check security context
    if !mme_ue.security_context_available {
        return Err(EsmError::NoSecurityContext);
    }
    
    // Minimum length check: request type (1) + PDN type (1)
    if data.len() < 2 {
        return Err(EsmError::InvalidMessage("PDN connectivity request too short".to_string()));
    }
    
    let mut result = PdnConnectivityRequestData::default();
    let mut offset = 0;
    
    // Request type (4 bits) + PDN type (4 bits)
    let request_type_pdn_type = data[offset];
    result.request_type = request_type_pdn_type & 0x0f;
    let pdn_type_value = (request_type_pdn_type >> 4) & 0x07;
    result.pdn_type = match pdn_type_value {
        1 => PdnType::Ipv4,
        2 => PdnType::Ipv6,
        3 => PdnType::Ipv4v6,
        5 => PdnType::NonIp,
        _ => return Err(EsmError::InvalidPdnType(pdn_type_value)),
    };
    offset += 1;
    
    // Parse optional IEs
    while offset < data.len() {
        if offset >= data.len() {
            break;
        }
        
        let iei = data[offset];
        offset += 1;
        
        match iei {
            // ESM information transfer flag (type 1)
            0xd0..=0xdf => {
                result.esm_info_transfer_flag = (iei & 0x01) != 0;
            }
            // Access point name
            0x28 => {
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1;
                if offset + len > data.len() {
                    break;
                }
                result.apn = Some(parse_apn(&data[offset..offset + len]));
                offset += len;
            }
            // Protocol configuration options
            0x27 => {
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1;
                if offset + len > data.len() {
                    break;
                }
                result.pco = Some(data[offset..offset + len].to_vec());
                offset += len;
            }
            // Extended protocol configuration options
            0x7b => {
                if offset + 1 >= data.len() {
                    break;
                }
                let len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
                offset += 2;
                if offset + len > data.len() {
                    break;
                }
                result.epco = Some(data[offset..offset + len].to_vec());
                offset += len;
            }
            _ => {
                // Skip unknown IE
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1 + len;
            }
        }
    }
    
    Ok(result)
}


/// Handle ESM information response
pub fn handle_esm_information_response(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    data: &[u8],
) -> EsmResult<EsmInformationResponseData> {
    let mut result = EsmInformationResponseData::default();
    let mut offset = 0;
    
    // Parse optional IEs
    while offset < data.len() {
        if offset >= data.len() {
            break;
        }
        
        let iei = data[offset];
        offset += 1;
        
        match iei {
            // Access point name
            0x28 => {
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1;
                if offset + len > data.len() {
                    break;
                }
                result.apn = Some(parse_apn(&data[offset..offset + len]));
                offset += len;
            }
            // Protocol configuration options
            0x27 => {
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1;
                if offset + len > data.len() {
                    break;
                }
                result.pco = Some(data[offset..offset + len].to_vec());
                offset += len;
            }
            // Extended protocol configuration options
            0x7b => {
                if offset + 1 >= data.len() {
                    break;
                }
                let len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
                offset += 2;
                if offset + len > data.len() {
                    break;
                }
                result.epco = Some(data[offset..offset + len].to_vec());
                offset += len;
            }
            _ => {
                // Skip unknown IE
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1 + len;
            }
        }
    }
    
    Ok(result)
}

/// Handle bearer resource allocation request
pub fn handle_bearer_resource_allocation_request(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    data: &[u8],
) -> EsmResult<BearerResourceAllocationRequestData> {
    // Minimum length: linked EBI (1) + TFA length (1)
    if data.len() < 2 {
        return Err(EsmError::InvalidMessage("Bearer resource allocation request too short".to_string()));
    }
    
    let mut result = BearerResourceAllocationRequestData::default();
    let mut offset = 0;
    
    // Linked EPS bearer identity (4 bits) + spare (4 bits)
    result.linked_ebi = data[offset] & 0x0f;
    offset += 1;
    
    // Traffic flow aggregate
    if offset >= data.len() {
        return Err(EsmError::MissingMandatoryIe("Traffic flow aggregate".to_string()));
    }
    let tfa_len = data[offset] as usize;
    offset += 1;
    if offset + tfa_len > data.len() {
        return Err(EsmError::InvalidMessage("TFA length exceeds message".to_string()));
    }
    result.tfa = data[offset..offset + tfa_len].to_vec();
    offset += tfa_len;
    
    // Parse optional IEs
    while offset < data.len() {
        if offset >= data.len() {
            break;
        }
        
        let iei = data[offset];
        offset += 1;
        
        match iei {
            // Required traffic flow QoS
            0x5b => {
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1;
                if offset + len > data.len() {
                    break;
                }
                result.required_qos = Some(parse_required_qos(&data[offset..offset + len]));
                offset += len;
            }
            _ => {
                // Skip unknown IE
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1 + len;
            }
        }
    }
    
    Ok(result)
}


/// Handle bearer resource modification request
pub fn handle_bearer_resource_modification_request(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    data: &[u8],
) -> EsmResult<BearerResourceModificationRequestData> {
    // Minimum length: EBI for PF (1) + TFA length (1)
    if data.len() < 2 {
        return Err(EsmError::InvalidMessage("Bearer resource modification request too short".to_string()));
    }
    
    let mut result = BearerResourceModificationRequestData::default();
    let mut offset = 0;
    
    // EPS bearer identity for packet filter (4 bits) + spare (4 bits)
    result.ebi_for_pf = data[offset] & 0x0f;
    offset += 1;
    
    // Traffic flow aggregate
    if offset >= data.len() {
        return Err(EsmError::MissingMandatoryIe("Traffic flow aggregate".to_string()));
    }
    let tfa_len = data[offset] as usize;
    offset += 1;
    if offset + tfa_len > data.len() {
        return Err(EsmError::InvalidMessage("TFA length exceeds message".to_string()));
    }
    result.tfa = data[offset..offset + tfa_len].to_vec();
    offset += tfa_len;
    
    // Parse optional IEs
    while offset < data.len() {
        if offset >= data.len() {
            break;
        }
        
        let iei = data[offset];
        offset += 1;
        
        match iei {
            // Required traffic flow QoS
            0x5b => {
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1;
                if offset + len > data.len() {
                    break;
                }
                result.required_qos = Some(parse_required_qos(&data[offset..offset + len]));
                offset += len;
            }
            // ESM cause
            0x58 => {
                if offset >= data.len() {
                    break;
                }
                let cause_value = data[offset];
                offset += 1;
                result.esm_cause = Some(esm_cause_from_u8(cause_value));
            }
            _ => {
                // Skip unknown IE
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1 + len;
            }
        }
    }
    
    Ok(result)
}

/// Handle activate default EPS bearer context accept
pub fn handle_activate_default_bearer_context_accept(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    _data: &[u8],
) -> EsmResult<()> {
    // This message has no mandatory IEs beyond the header
    // Optional: Protocol configuration options
    Ok(())
}

/// Handle activate default EPS bearer context reject
pub fn handle_activate_default_bearer_context_reject(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    data: &[u8],
) -> EsmResult<EsmCause> {
    // ESM cause is mandatory
    if data.is_empty() {
        return Err(EsmError::MissingMandatoryIe("ESM cause".to_string()));
    }
    
    Ok(esm_cause_from_u8(data[0]))
}

/// Handle activate dedicated EPS bearer context accept
pub fn handle_activate_dedicated_bearer_context_accept(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    _data: &[u8],
) -> EsmResult<()> {
    // This message has no mandatory IEs beyond the header
    Ok(())
}

/// Handle activate dedicated EPS bearer context reject
pub fn handle_activate_dedicated_bearer_context_reject(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    data: &[u8],
) -> EsmResult<EsmCause> {
    // ESM cause is mandatory
    if data.is_empty() {
        return Err(EsmError::MissingMandatoryIe("ESM cause".to_string()));
    }
    
    Ok(esm_cause_from_u8(data[0]))
}


/// Handle modify EPS bearer context accept
pub fn handle_modify_bearer_context_accept(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    _data: &[u8],
) -> EsmResult<()> {
    // This message has no mandatory IEs beyond the header
    Ok(())
}

/// Handle modify EPS bearer context reject
pub fn handle_modify_bearer_context_reject(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    data: &[u8],
) -> EsmResult<EsmCause> {
    // ESM cause is mandatory
    if data.is_empty() {
        return Err(EsmError::MissingMandatoryIe("ESM cause".to_string()));
    }
    
    Ok(esm_cause_from_u8(data[0]))
}

/// Handle deactivate EPS bearer context accept
pub fn handle_deactivate_bearer_context_accept(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    _data: &[u8],
) -> EsmResult<()> {
    // This message has no mandatory IEs beyond the header
    Ok(())
}

/// Handle PDN disconnect request
pub fn handle_pdn_disconnect_request(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    data: &[u8],
) -> EsmResult<u8> {
    // Linked EPS bearer identity is mandatory
    if data.is_empty() {
        return Err(EsmError::MissingMandatoryIe("Linked EPS bearer identity".to_string()));
    }
    
    // Linked EBI (4 bits) + spare (4 bits)
    let linked_ebi = data[0] & 0x0f;
    
    Ok(linked_ebi)
}

/// Handle ESM status message
pub fn handle_esm_status(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    data: &[u8],
) -> EsmResult<EsmCause> {
    // ESM cause is mandatory
    if data.is_empty() {
        return Err(EsmError::MissingMandatoryIe("ESM cause".to_string()));
    }
    
    Ok(esm_cause_from_u8(data[0]))
}

/// Handle notification message
pub fn handle_notification(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    data: &[u8],
) -> EsmResult<u8> {
    // Notification indicator is mandatory
    if data.is_empty() {
        return Err(EsmError::MissingMandatoryIe("Notification indicator".to_string()));
    }
    
    // Notification indicator value
    let notification_indicator = data[0];
    
    Ok(notification_indicator)
}

// ============================================================================
// ESM Message Dispatcher
// ============================================================================

/// ESM message type for dispatching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EsmMessageType {
    /// Activate default EPS bearer context request
    ActivateDefaultEpsBearerContextRequest = 0xc1,
    /// Activate default EPS bearer context accept
    ActivateDefaultEpsBearerContextAccept = 0xc2,
    /// Activate default EPS bearer context reject
    ActivateDefaultEpsBearerContextReject = 0xc3,
    /// Activate dedicated EPS bearer context request
    ActivateDedicatedEpsBearerContextRequest = 0xc5,
    /// Activate dedicated EPS bearer context accept
    ActivateDedicatedEpsBearerContextAccept = 0xc6,
    /// Activate dedicated EPS bearer context reject
    ActivateDedicatedEpsBearerContextReject = 0xc7,
    /// Modify EPS bearer context request
    ModifyEpsBearerContextRequest = 0xc9,
    /// Modify EPS bearer context accept
    ModifyEpsBearerContextAccept = 0xca,
    /// Modify EPS bearer context reject
    ModifyEpsBearerContextReject = 0xcb,
    /// Deactivate EPS bearer context request
    DeactivateEpsBearerContextRequest = 0xcd,
    /// Deactivate EPS bearer context accept
    DeactivateEpsBearerContextAccept = 0xce,
    /// PDN connectivity request
    PdnConnectivityRequest = 0xd0,
    /// PDN connectivity reject
    PdnConnectivityReject = 0xd1,
    /// PDN disconnect request
    PdnDisconnectRequest = 0xd2,
    /// PDN disconnect reject
    PdnDisconnectReject = 0xd3,
    /// Bearer resource allocation request
    BearerResourceAllocationRequest = 0xd4,
    /// Bearer resource allocation reject
    BearerResourceAllocationReject = 0xd5,
    /// Bearer resource modification request
    BearerResourceModificationRequest = 0xd6,
    /// Bearer resource modification reject
    BearerResourceModificationReject = 0xd7,
    /// ESM information request
    EsmInformationRequest = 0xd9,
    /// ESM information response
    EsmInformationResponse = 0xda,
    /// Notification
    Notification = 0xdb,
    /// ESM dummy message
    EsmDummyMessage = 0xdc,
    /// ESM status
    EsmStatus = 0xe8,
}

impl TryFrom<u8> for EsmMessageType {
    type Error = EsmError;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xc1 => Ok(EsmMessageType::ActivateDefaultEpsBearerContextRequest),
            0xc2 => Ok(EsmMessageType::ActivateDefaultEpsBearerContextAccept),
            0xc3 => Ok(EsmMessageType::ActivateDefaultEpsBearerContextReject),
            0xc5 => Ok(EsmMessageType::ActivateDedicatedEpsBearerContextRequest),
            0xc6 => Ok(EsmMessageType::ActivateDedicatedEpsBearerContextAccept),
            0xc7 => Ok(EsmMessageType::ActivateDedicatedEpsBearerContextReject),
            0xc9 => Ok(EsmMessageType::ModifyEpsBearerContextRequest),
            0xca => Ok(EsmMessageType::ModifyEpsBearerContextAccept),
            0xcb => Ok(EsmMessageType::ModifyEpsBearerContextReject),
            0xcd => Ok(EsmMessageType::DeactivateEpsBearerContextRequest),
            0xce => Ok(EsmMessageType::DeactivateEpsBearerContextAccept),
            0xd0 => Ok(EsmMessageType::PdnConnectivityRequest),
            0xd1 => Ok(EsmMessageType::PdnConnectivityReject),
            0xd2 => Ok(EsmMessageType::PdnDisconnectRequest),
            0xd3 => Ok(EsmMessageType::PdnDisconnectReject),
            0xd4 => Ok(EsmMessageType::BearerResourceAllocationRequest),
            0xd5 => Ok(EsmMessageType::BearerResourceAllocationReject),
            0xd6 => Ok(EsmMessageType::BearerResourceModificationRequest),
            0xd7 => Ok(EsmMessageType::BearerResourceModificationReject),
            0xd9 => Ok(EsmMessageType::EsmInformationRequest),
            0xda => Ok(EsmMessageType::EsmInformationResponse),
            0xdb => Ok(EsmMessageType::Notification),
            0xdc => Ok(EsmMessageType::EsmDummyMessage),
            0xe8 => Ok(EsmMessageType::EsmStatus),
            _ => Err(EsmError::InvalidMessage(format!("Unknown ESM message type: 0x{:02x}", value))),
        }
    }
}

/// ESM header structure
#[derive(Debug, Clone, Default)]
pub struct EsmHeader {
    /// EPS bearer identity
    pub ebi: u8,
    /// Protocol discriminator
    pub protocol_discriminator: u8,
    /// Procedure transaction identity
    pub pti: u8,
    /// Message type
    pub message_type: u8,
}

impl EsmHeader {
    /// Parse ESM header from data
    pub fn parse(data: &[u8]) -> EsmResult<(Self, &[u8])> {
        if data.len() < 4 {
            return Err(EsmError::InvalidMessage("ESM header too short".to_string()));
        }
        
        let header = EsmHeader {
            ebi: data[0] & 0x0f,
            protocol_discriminator: data[1],
            pti: data[2],
            message_type: data[3],
        };
        
        Ok((header, &data[4..]))
    }
}

/// Protocol configuration options data
#[derive(Debug, Clone, Default)]
pub struct ProtocolConfigurationOptions {
    /// Configuration protocol
    pub config_protocol: u8,
    /// Protocol IDs and containers
    pub containers: Vec<PcoContainer>,
}

/// PCO container
#[derive(Debug, Clone)]
pub struct PcoContainer {
    /// Protocol ID
    pub protocol_id: u16,
    /// Container contents
    pub contents: Vec<u8>,
}

impl ProtocolConfigurationOptions {
    /// Parse PCO from data
    pub fn parse(data: &[u8]) -> EsmResult<Self> {
        if data.is_empty() {
            return Ok(Self::default());
        }
        
        let mut pco = ProtocolConfigurationOptions {
            config_protocol: data[0] & 0x07,
            containers: Vec::new(),
        };
        
        let mut offset = 1;
        while offset + 3 <= data.len() {
            let protocol_id = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
            let len = data[offset + 2] as usize;
            offset += 3;
            
            if offset + len > data.len() {
                break;
            }
            
            pco.containers.push(PcoContainer {
                protocol_id,
                contents: data[offset..offset + len].to_vec(),
            });
            
            offset += len;
        }
        
        Ok(pco)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse APN from encoded format
fn parse_apn(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    
    let mut result = String::new();
    let mut offset = 0;
    
    while offset < data.len() {
        let label_len = data[offset] as usize;
        offset += 1;
        
        if label_len == 0 || offset + label_len > data.len() {
            break;
        }
        
        if !result.is_empty() {
            result.push('.');
        }
        
        for &b in &data[offset..offset + label_len] {
            result.push(b as char);
        }
        
        offset += label_len;
    }
    
    result
}

/// Parse required QoS
fn parse_required_qos(data: &[u8]) -> RequiredQos {
    let mut qos = RequiredQos::default();
    
    if data.is_empty() {
        return qos;
    }
    
    // QCI
    qos.qci = data[0];
    
    // For GBR bearers (QCI 1-4), parse bitrates
    if data.len() >= 5 && qos.qci >= 1 && qos.qci <= 4 {
        qos.mbr_ul = decode_bitrate(data[1]);
        qos.mbr_dl = decode_bitrate(data[2]);
        qos.gbr_ul = decode_bitrate(data[3]);
        qos.gbr_dl = decode_bitrate(data[4]);
    }
    
    qos
}

/// Decode bitrate value
fn decode_bitrate(value: u8) -> u64 {
    if value == 0 || value == 0xff {
        return 0;
    }
    
    if value <= 63 {
        return value as u64;
    }
    
    if value <= 127 {
        return 64 + ((value - 64) as u64) * 8;
    }
    
    // 128-254
    576 + ((value - 128) as u64) * 64
}

/// Convert u8 to EsmCause
fn esm_cause_from_u8(value: u8) -> EsmCause {
    match value {
        8 => EsmCause::OperatorDeterminedBarring,
        26 => EsmCause::InsufficientResources,
        27 => EsmCause::MissingOrUnknownApn,
        28 => EsmCause::UnknownPdnType,
        29 => EsmCause::UserAuthenticationFailed,
        30 => EsmCause::RequestRejectedByGw,
        31 => EsmCause::RequestRejectedUnspecified,
        32 => EsmCause::ServiceOptionNotSupported,
        33 => EsmCause::RequestedServiceOptionNotSubscribed,
        34 => EsmCause::ServiceOptionTemporarilyOutOfOrder,
        35 => EsmCause::PtiAlreadyInUse,
        36 => EsmCause::RegularDeactivation,
        37 => EsmCause::EpsQosNotAccepted,
        38 => EsmCause::NetworkFailure,
        39 => EsmCause::ReactivationRequested,
        50 => EsmCause::PdnTypeIpv4OnlyAllowed,
        51 => EsmCause::PdnTypeIpv6OnlyAllowed,
        52 => EsmCause::SingleAddressBearersOnlyAllowed,
        95 => EsmCause::SemanticallyIncorrectMessage,
        96 => EsmCause::InvalidMandatoryInformation,
        97 => EsmCause::MessageTypeNonExistent,
        98 => EsmCause::MessageTypeNotCompatible,
        99 => EsmCause::InformationElementNonExistent,
        100 => EsmCause::ConditionalIeError,
        101 => EsmCause::MessageNotCompatible,
        _ => EsmCause::ProtocolErrorUnspecified,
    }
}


// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esm_error_display() {
        let err = EsmError::InvalidMessage("test".to_string());
        assert!(err.to_string().contains("Invalid message"));
        
        let err = EsmError::MissingMandatoryIe("APN".to_string());
        assert!(err.to_string().contains("Missing mandatory IE"));
        
        let err = EsmError::InvalidPdnType(99);
        assert!(err.to_string().contains("Invalid PDN type"));
        
        let err = EsmError::NoSecurityContext;
        assert!(err.to_string().contains("No security context"));
    }

    #[test]
    fn test_parse_apn() {
        // Empty APN
        assert_eq!(parse_apn(&[]), "");
        
        // Single label: "ims"
        let data = [3, b'i', b'm', b's'];
        assert_eq!(parse_apn(&data), "ims");
        
        // Two labels: "ims.mnc001.mcc001.3gppnetwork.org"
        let data = [3, b'i', b'm', b's', 6, b'm', b'n', b'c', b'0', b'0', b'1'];
        assert_eq!(parse_apn(&data), "ims.mnc001");
    }

    #[test]
    fn test_decode_bitrate() {
        // 0 and 0xff = 0 kbps
        assert_eq!(decode_bitrate(0), 0);
        assert_eq!(decode_bitrate(0xff), 0);
        
        // 1-63: direct value
        assert_eq!(decode_bitrate(1), 1);
        assert_eq!(decode_bitrate(63), 63);
        
        // 64-127: 64 + (value - 64) * 8
        assert_eq!(decode_bitrate(64), 64);
        assert_eq!(decode_bitrate(65), 72);
        assert_eq!(decode_bitrate(127), 568);
        
        // 128-254: 576 + (value - 128) * 64
        assert_eq!(decode_bitrate(128), 576);
        assert_eq!(decode_bitrate(129), 640);
    }

    #[test]
    fn test_esm_cause_from_u8() {
        assert_eq!(esm_cause_from_u8(8), EsmCause::OperatorDeterminedBarring);
        assert_eq!(esm_cause_from_u8(26), EsmCause::InsufficientResources);
        assert_eq!(esm_cause_from_u8(27), EsmCause::MissingOrUnknownApn);
        assert_eq!(esm_cause_from_u8(36), EsmCause::RegularDeactivation);
        assert_eq!(esm_cause_from_u8(38), EsmCause::NetworkFailure);
        assert_eq!(esm_cause_from_u8(50), EsmCause::PdnTypeIpv4OnlyAllowed);
        assert_eq!(esm_cause_from_u8(51), EsmCause::PdnTypeIpv6OnlyAllowed);
        assert_eq!(esm_cause_from_u8(111), EsmCause::ProtocolErrorUnspecified);
        
        // Unknown cause should map to protocol error
        assert_eq!(esm_cause_from_u8(200), EsmCause::ProtocolErrorUnspecified);
    }

    #[test]
    fn test_parse_required_qos() {
        // Empty data
        let qos = parse_required_qos(&[]);
        assert_eq!(qos.qci, 0);
        
        // Non-GBR bearer (QCI 9)
        let qos = parse_required_qos(&[9]);
        assert_eq!(qos.qci, 9);
        assert_eq!(qos.mbr_ul, 0);
        
        // GBR bearer (QCI 1) with bitrates
        let qos = parse_required_qos(&[1, 64, 64, 32, 32]);
        assert_eq!(qos.qci, 1);
        assert_eq!(qos.mbr_ul, 64);
        assert_eq!(qos.mbr_dl, 64);
        assert_eq!(qos.gbr_ul, 32);
        assert_eq!(qos.gbr_dl, 32);
    }

    #[test]
    fn test_pdn_connectivity_request_data_default() {
        let data = PdnConnectivityRequestData::default();
        assert_eq!(data.request_type, 0);
        assert_eq!(data.pdn_type, PdnType::Ipv4);
        assert!(!data.esm_info_transfer_flag);
        assert!(data.apn.is_none());
    }

    #[test]
    fn test_esm_information_response_data_default() {
        let data = EsmInformationResponseData::default();
        assert!(data.apn.is_none());
        assert!(data.pco.is_none());
        assert!(data.epco.is_none());
    }

    #[test]
    fn test_bearer_resource_allocation_request_data_default() {
        let data = BearerResourceAllocationRequestData::default();
        assert_eq!(data.linked_ebi, 0);
        assert!(data.tfa.is_empty());
        assert!(data.required_qos.is_none());
    }
}
