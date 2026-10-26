//! ESM Message Handling
//!
//! Port of src/mme/esm-handler.c - ESM message handling functions

use crate::context::{EnbUe, MmeBearer, MmeSess, MmeUe};
use crate::esm_build::{CreateAction, EsmCause, PdnType};

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
            EsmError::InvalidMessage(msg) => write!(f, "Invalid message: {msg}"),
            EsmError::MissingMandatoryIe(ie) => write!(f, "Missing mandatory IE: {ie}"),
            EsmError::InvalidPdnType(t) => write!(f, "Invalid PDN type: {t}"),
            EsmError::InvalidApn(apn) => write!(f, "Invalid APN: {apn}"),
            EsmError::NoSecurityContext => write!(f, "No security context"),
            EsmError::SessionNotFound => write!(f, "Session not found"),
            EsmError::BearerNotFound => write!(f, "Bearer not found"),
            EsmError::ProtocolError(msg) => write!(f, "Protocol error: {msg}"),
            EsmError::NetworkFailure(msg) => write!(f, "Network failure: {msg}"),
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
    /// Required traffic flow QoS (mandatory: `Some` for every parsed request)
    pub required_qos: Option<RequiredQos>,
    /// Protocol configuration options, copied to the Bearer Resource Command
    /// (TS 29.274 Table 7.2.5-1)
    pub pco: Option<Vec<u8>>,
    /// Extended protocol configuration options, copied likewise
    pub epco: Option<Vec<u8>>,
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
    /// Protocol configuration options
    pub pco: Option<Vec<u8>>,
    /// Extended protocol configuration options
    pub epco: Option<Vec<u8>>,
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

    // Minimum length: one octet. TS 24.301 Table 8.3.20.1 packs PDN type (high
    // nibble) and request type (low nibble) into a SINGLE octet; everything after
    // it is optional. The old check required two and rejected a minimal request
    // such as `02 01 D0 11` (#481).
    if data.is_empty() {
        return Err(EsmError::InvalidMessage(
            "PDN connectivity request too short".to_string(),
        ));
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

/// The non-imperative part of an ESM message (TS 24.301 §8.3, TS 24.007 §11.2.4):
/// `(IEI, value)` per IE.
///
/// - IEI bit 8 set: a type 1 (IEI in the high half octet) or type 2 IE, one octet; the
///   whole octet is returned as the IEI and the value is empty.
/// - An IEI in `tv`: a type 3 (TV) IE of that total length, for example ESM cause
///   (58, two octets).
/// - IEI 0x7_: TLV-E, two length octets (TS 24.301 IEIs 0x7B ePCO and the like).
/// - Anything else: TLV, one length octet.
///
/// An IE that runs past the end is an error, not a silent stop: the old walkers
/// skipped every unknown IE as TLV, so a type 1 Device properties (0xC-) or a
/// TLV-E ePCO desynchronised the rest of the message.
fn optional_ies<'a>(data: &'a [u8], tv: &[(u8, usize)]) -> EsmResult<Vec<(u8, &'a [u8])>> {
    let mut ies = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let iei = data[offset];
        offset += 1;
        if iei & 0x80 != 0 {
            ies.push((iei, &data[offset..offset]));
            continue;
        }
        if let Some(&(_, total)) = tv.iter().find(|(i, _)| *i == iei) {
            let Some(value) = data.get(offset..offset + total - 1) else {
                return Err(EsmError::InvalidMessage(format!(
                    "IE 0x{iei:02x} truncated"
                )));
            };
            ies.push((iei, value));
            offset += total - 1;
            continue;
        }
        let len = if iei & 0xf0 == 0x70 {
            let Some(l) = data.get(offset..offset + 2) else {
                return Err(EsmError::InvalidMessage(format!(
                    "IE 0x{iei:02x}: truncated length"
                )));
            };
            offset += 2;
            usize::from(u16::from_be_bytes([l[0], l[1]]))
        } else {
            let Some(&l) = data.get(offset) else {
                return Err(EsmError::InvalidMessage(format!(
                    "IE 0x{iei:02x}: truncated length"
                )));
            };
            offset += 1;
            usize::from(l)
        };
        let Some(value) = data.get(offset..offset + len) else {
            return Err(EsmError::InvalidMessage(format!(
                "IE 0x{iei:02x}: {len} octets run past the message"
            )));
        };
        ies.push((iei, value));
        offset += len;
    }
    Ok(ies)
}

/// A mandatory LV IE at `offset`: its value, and the offset after it.
fn mandatory_lv<'a>(data: &'a [u8], offset: usize, name: &str) -> EsmResult<(&'a [u8], usize)> {
    let Some(&len) = data.get(offset) else {
        return Err(EsmError::MissingMandatoryIe(name.to_string()));
    };
    let start = offset + 1;
    let end = start + usize::from(len);
    let value = data
        .get(start..end)
        .ok_or_else(|| EsmError::InvalidMessage(format!("{name}: length exceeds message")))?;
    Ok((value, end))
}

/// Handle BEARER RESOURCE ALLOCATION REQUEST (TS 24.301 §8.3.8, Table 8.3.8.1).
///
/// `data` is the message after its message type: Linked EPS bearer identity (bits
/// 1-4) with a spare half octet, Traffic flow aggregate (LV, M), Required traffic
/// flow QoS (LV, M; it was read as an optional TLV with IEI 0x5B, which this
/// message does not have), then PCO (27), Device properties (C-), NBIFOM container
/// (33), ePCO (7B) and Extended EPS QoS (5C).
pub fn handle_bearer_resource_allocation_request(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    data: &[u8],
) -> EsmResult<BearerResourceAllocationRequestData> {
    let Some(&first) = data.first() else {
        return Err(EsmError::MissingMandatoryIe(
            "Linked EPS bearer identity".to_string(),
        ));
    };
    let mut result = BearerResourceAllocationRequestData {
        linked_ebi: first & 0x0f,
        ..Default::default()
    };
    let (tfa, offset) = mandatory_lv(data, 1, "Traffic flow aggregate")?;
    if tfa.is_empty() {
        return Err(EsmError::InvalidMessage(
            "Traffic flow aggregate is empty".to_string(),
        ));
    }
    result.tfa = tfa.to_vec();
    let (qos, offset) = mandatory_lv(data, offset, "Required traffic flow QoS")?;
    if qos.is_empty() {
        return Err(EsmError::InvalidMessage(
            "Required traffic flow QoS is empty".to_string(),
        ));
    }
    result.required_qos = Some(parse_required_qos(qos));
    for (iei, value) in optional_ies(&data[offset..], &[])? {
        match iei {
            0x27 => result.pco = Some(value.to_vec()),
            0x7b => result.epco = Some(value.to_vec()),
            _ => {}
        }
    }
    Ok(result)
}

/// Handle BEARER RESOURCE MODIFICATION REQUEST (TS 24.301 §8.3.10, Table 8.3.10.1).
///
/// `data` is the message after its message type: EPS bearer identity for packet
/// filter (bits 1-4) with a spare half octet, Traffic flow aggregate (LV, M), then
/// Required traffic flow QoS (5B, TLV), ESM cause (58, TV), PCO (27), Device
/// properties (C-), NBIFOM container (33), Header compression configuration (66),
/// ePCO (7B) and Extended EPS QoS (5C).
pub fn handle_bearer_resource_modification_request(
    _enb_ue: &EnbUe,
    _mme_ue: &MmeUe,
    _sess: &MmeSess,
    _bearer: &MmeBearer,
    data: &[u8],
) -> EsmResult<BearerResourceModificationRequestData> {
    let Some(&first) = data.first() else {
        return Err(EsmError::MissingMandatoryIe(
            "EPS bearer identity for packet filter".to_string(),
        ));
    };
    let mut result = BearerResourceModificationRequestData {
        ebi_for_pf: first & 0x0f,
        ..Default::default()
    };
    let (tfa, offset) = mandatory_lv(data, 1, "Traffic flow aggregate")?;
    if tfa.is_empty() {
        return Err(EsmError::InvalidMessage(
            "Traffic flow aggregate is empty".to_string(),
        ));
    }
    result.tfa = tfa.to_vec();
    let ies = optional_ies(&data[offset..], &[(0x58, 2)])?;
    for (iei, value) in ies {
        match iei {
            0x5b if !value.is_empty() => result.required_qos = Some(parse_required_qos(value)),
            0x58 => result.esm_cause = value.first().map(|c| esm_cause_from_u8(*c)),
            0x27 => result.pco = Some(value.to_vec()),
            0x7b => result.epco = Some(value.to_vec()),
            _ => {}
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
        return Err(EsmError::MissingMandatoryIe(
            "Linked EPS bearer identity".to_string(),
        ));
    }

    // Linked EBI (4 bits) + spare (4 bits)
    let linked_ebi = data[0] & 0x0f;

    Ok(linked_ebi)
}

/// Handle ESM status message
pub fn handle_esm_status(_enb_ue: &EnbUe, _mme_ue: &MmeUe, data: &[u8]) -> EsmResult<EsmCause> {
    // ESM cause is mandatory
    if data.is_empty() {
        return Err(EsmError::MissingMandatoryIe("ESM cause".to_string()));
    }

    Ok(esm_cause_from_u8(data[0]))
}

/// Handle notification message
pub fn handle_notification(_enb_ue: &EnbUe, _mme_ue: &MmeUe, data: &[u8]) -> EsmResult<u8> {
    // Notification indicator is mandatory
    if data.is_empty() {
        return Err(EsmError::MissingMandatoryIe(
            "Notification indicator".to_string(),
        ));
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
            _ => Err(EsmError::InvalidMessage(format!(
                "Unknown ESM message type: 0x{value:02x}"
            ))),
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
    // TS 24.301 §9.9.4.3: QCI, then the four base rate octets (MBR UL, MBR DL, GBR
    // UL, GBR DL), then their extended and extended-2 octets; 1, 5, 9 or 13
    // octets of contents. The rates are read whatever the QCI: the PGW decides
    // what a non-GBR QCI's rates mean (§9.9.4.3: "ignored"). In kbit/s.
    let mut qos = RequiredQos {
        qci: data.first().copied().unwrap_or(0),
        ..Default::default()
    };
    let octet = |i: usize| data.get(i).copied().unwrap_or(0);
    let rate = |i: usize| {
        if data.len() <= i {
            return 0;
        }
        decode_bitrate_ext2(octet(i + 8))
            .or_else(|| decode_bitrate_ext(octet(i + 4)))
            .unwrap_or_else(|| decode_bitrate(octet(i)))
    };
    qos.mbr_ul = rate(1);
    qos.mbr_dl = rate(2);
    qos.gbr_ul = rate(3);
    qos.gbr_dl = rate(4);
    qos
}

/// Decode bitrate value (TS 24.008 Table 10.5.156, base octet), kbit/s. 0xFF is
/// 0 kbit/s; 0 is "subscribed" from the UE, passed on as 0 (the PGW decides).
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

/// The extended octet (TS 24.301 Table 9.9.4.3.1), kbit/s; `None` for 0, "use the
/// base octet".
fn decode_bitrate_ext(value: u8) -> Option<u64> {
    let v = u64::from(value);
    match value {
        0 => None,
        0x01..=0x4a => Some(8600 + v * 100),
        0x4b..=0xba => Some(16_000 + (v - 0x4a) * 1000),
        _ => Some(128_000 + (v.min(0xfa) - 0xba) * 2000),
    }
}

/// The extended-2 octet (TS 24.301 Table 9.9.4.3.1), kbit/s; `None` for 0, "use
/// the extended octet".
fn decode_bitrate_ext2(value: u8) -> Option<u64> {
    let v = u64::from(value);
    match value {
        0 => None,
        0x01..=0x3d => Some(256_000 + v * 4000),
        0x3e..=0xa1 => Some(500_000 + (v - 0x3d) * 10_000),
        _ => Some(1_500_000 + (v.min(0xf6) - 0xa1) * 100_000),
    }
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

    /// #481: `02 01 D0 11` -- PD 2, PTI 1, PDN CONNECTIVITY REQUEST, then ONE
    /// octet holding PDN type IPv4 (high nibble 1) and request type initial (1),
    /// TS 24.301 Table 8.3.20.1. No optional IEs. The handler is given the body
    /// after the message type, which is that single octet.
    #[test]
    fn a_minimal_pdn_connectivity_request_is_accepted() {
        let wire = [0x02u8, 0x01, 0xD0, 0x11];
        let mme_ue = MmeUe {
            security_context_available: true,
            ..Default::default()
        };
        let parsed = handle_pdn_connectivity_request(
            &EnbUe::default(),
            &mme_ue,
            &MmeSess::default(),
            &MmeBearer::default(),
            &wire[3..],
            CreateAction::InAttachRequest,
        )
        .expect("a one-octet PDN CONNECTIVITY REQUEST body is valid");
        assert_eq!(parsed.request_type, 1);
        assert_eq!(parsed.pdn_type, PdnType::Ipv4);
        assert!(parsed.apn.is_none());
    }

    #[test]
    fn an_empty_pdn_connectivity_request_body_is_refused() {
        let mme_ue = MmeUe {
            security_context_available: true,
            ..Default::default()
        };
        assert!(handle_pdn_connectivity_request(
            &EnbUe::default(),
            &mme_ue,
            &MmeSess::default(),
            &MmeBearer::default(),
            &[],
            CreateAction::InAttachRequest,
        )
        .is_err());
    }

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

    /// #1282, TS 24.301 Table 8.3.8.1: the Required traffic flow QoS is a mandatory LV
    /// after the TFA (it was read as an optional 0x5B TLV, so it was never found), and
    /// the optional part has a type 1 Device properties (C-) and a TLV-E ePCO (7B)
    /// that the old walker skipped as TLVs.
    #[test]
    fn a_bearer_resource_allocation_request_is_parsed_as_table_8_3_8_1_says() {
        let body = [
            0x05, // spare | linked EBI 5
            0x02, 0x21, 0x31, // TFA
            0x05, 0x01, 0x48, 0x48, 0x40, 0x40, // QCI 1, MBR 128, GBR 64
            0xc1, // Device properties
            0x7b, 0x00, 0x03, 0x80, 0x00, 0x0d, // ePCO
            0x27, 0x01, 0x80, // PCO
        ];
        let r = handle_bearer_resource_allocation_request(
            &EnbUe::default(),
            &MmeUe::default(),
            &MmeSess::default(),
            &MmeBearer::default(),
            &body,
        )
        .unwrap();
        assert_eq!(r.linked_ebi, 5);
        assert_eq!(r.tfa, vec![0x21, 0x31]);
        let q = r.required_qos.unwrap();
        assert_eq!(
            (q.qci, q.mbr_ul, q.mbr_dl, q.gbr_ul, q.gbr_dl),
            (1, 128, 128, 64, 64)
        );
        assert_eq!(r.epco, Some(vec![0x80, 0x00, 0x0d]));
        assert_eq!(r.pco, Some(vec![0x80]));
        // Without the mandatory QoS, and with an IE running past the end.
        for bad in [&body[..4], &body[..18]] {
            assert!(handle_bearer_resource_allocation_request(
                &EnbUe::default(),
                &MmeUe::default(),
                &MmeSess::default(),
                &MmeBearer::default(),
                bad,
            )
            .is_err());
        }
    }

    /// #1282, TS 24.301 Table 8.3.10.1: Required traffic flow QoS (5B, TLV, here with
    /// the extended octets: MBR 20 Mbit/s), ESM cause (58, TV), Device properties
    /// (C-, type 1) and ePCO (7B, TLV-E).
    #[test]
    fn a_bearer_resource_modification_request_is_parsed_as_table_8_3_10_1_says() {
        let body = [
            0x06, // spare | EBI for packet filter 6
            0x02, 0xa1, 0x01, // TFA: delete filter 1
            0xc1, // Device properties
            0x58, 0x24, // ESM cause #36
            0x5b, 0x09, 0x01, 0xfe, 0xfe, 0x40, 0x40, 0x4e, 0x4e, 0x00, 0x00, // QoS
            0x7b, 0x00, 0x01, 0x80, // ePCO
        ];
        let r = handle_bearer_resource_modification_request(
            &EnbUe::default(),
            &MmeUe::default(),
            &MmeSess::default(),
            &MmeBearer::default(),
            &body,
        )
        .unwrap();
        assert_eq!(r.ebi_for_pf, 6);
        assert_eq!(r.tfa, vec![0xa1, 0x01]);
        assert_eq!(r.esm_cause, Some(EsmCause::RegularDeactivation));
        let q = r.required_qos.unwrap();
        // 0x4e extended: 16 Mbit/s + (0x4e - 0x4a) x 1 Mbit/s.
        assert_eq!((q.qci, q.mbr_ul, q.gbr_ul), (1, 20_000, 64));
        assert_eq!(r.epco, Some(vec![0x80]));
    }

    #[test]
    fn test_bearer_resource_allocation_request_data_default() {
        let data = BearerResourceAllocationRequestData::default();
        assert_eq!(data.linked_ebi, 0);
        assert!(data.tfa.is_empty());
        assert!(data.required_qos.is_none());
    }
}
