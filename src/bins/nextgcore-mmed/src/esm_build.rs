//! ESM Message Building
//!
//! Port of src/mme/esm-build.c - ESM message building functions

use crate::context::{MmeSess, MmeBearer, Paa};
use crate::emm_build::{NasBuffer, SecurityHeaderType, NAS_PROTOCOL_DISCRIMINATOR_EMM};

// ============================================================================
// ESM Protocol Discriminator
// ============================================================================

/// NAS Protocol Discriminator for ESM
pub const NAS_PROTOCOL_DISCRIMINATOR_ESM: u8 = 0x02;

/// Procedure Transaction Identity - Unassigned
pub const PTI_UNASSIGNED: u8 = 0;

// ============================================================================
// ESM Cause Codes (3GPP TS 24.301)
// ============================================================================

/// ESM Cause codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EsmCause {
    /// Operator determined barring
    OperatorDeterminedBarring = 8,
    /// Insufficient resources
    InsufficientResources = 26,
    /// Missing or unknown APN
    MissingOrUnknownApn = 27,
    /// Unknown PDN type
    UnknownPdnType = 28,
    /// User authentication failed
    UserAuthenticationFailed = 29,
    /// Request rejected by Serving GW or PDN GW
    RequestRejectedByGw = 30,
    /// Request rejected, unspecified
    RequestRejectedUnspecified = 31,
    /// Service option not supported
    ServiceOptionNotSupported = 32,
    /// Requested service option not subscribed
    RequestedServiceOptionNotSubscribed = 33,
    /// Service option temporarily out of order
    ServiceOptionTemporarilyOutOfOrder = 34,
    /// PTI already in use
    PtiAlreadyInUse = 35,
    /// Regular deactivation
    RegularDeactivation = 36,
    /// EPS QoS not accepted
    EpsQosNotAccepted = 37,
    /// Network failure
    NetworkFailure = 38,
    /// Reactivation requested
    ReactivationRequested = 39,
    /// Semantic error in the TFT operation
    SemanticErrorInTftOperation = 41,
    /// Syntactical error in the TFT operation
    SyntacticalErrorInTftOperation = 42,
    /// Invalid EPS bearer identity
    InvalidEpsBearerIdentity = 43,
    /// Semantic errors in packet filter(s)
    SemanticErrorsInPacketFilters = 44,
    /// Syntactical errors in packet filter(s)
    SyntacticalErrorsInPacketFilters = 45,
    /// EPS bearer context without TFT already activated
    EpsBearerContextWithoutTftAlreadyActivated = 46,
    /// PTI mismatch
    PtiMismatch = 47,
    /// Last PDN disconnection not allowed
    LastPdnDisconnectionNotAllowed = 49,
    /// PDN type IPv4 only allowed
    PdnTypeIpv4OnlyAllowed = 50,
    /// PDN type IPv6 only allowed
    PdnTypeIpv6OnlyAllowed = 51,
    /// Single address bearers only allowed
    SingleAddressBearersOnlyAllowed = 52,
    /// ESM information not received
    EsmInformationNotReceived = 53,
    /// PDN connection does not exist
    PdnConnectionDoesNotExist = 54,
    /// Multiple PDN connections for a given APN not allowed
    MultiplePdnConnectionsNotAllowed = 55,
    /// Collision with network initiated request
    CollisionWithNetworkInitiatedRequest = 56,
    /// PDN type Ethernet only allowed
    PdnTypeEthernetOnlyAllowed = 57,
    /// Unsupported QCI value
    UnsupportedQciValue = 59,
    /// Bearer handling not supported
    BearerHandlingNotSupported = 60,
    /// Maximum number of EPS bearers reached
    MaximumNumberOfEpsBearersReached = 65,
    /// Requested APN not supported in current RAT and PLMN combination
    RequestedApnNotSupportedInCurrentRatAndPlmn = 66,
    /// Invalid PTI value
    InvalidPtiValue = 81,
    /// Semantically incorrect message
    SemanticallyIncorrectMessage = 95,
    /// Invalid mandatory information
    InvalidMandatoryInformation = 96,
    /// Message type non-existent or not implemented
    MessageTypeNonExistent = 97,
    /// Message type not compatible with protocol state
    MessageTypeNotCompatible = 98,
    /// Information element non-existent or not implemented
    InformationElementNonExistent = 99,
    /// Conditional IE error
    ConditionalIeError = 100,
    /// Message not compatible with protocol state
    MessageNotCompatible = 101,
    /// Protocol error, unspecified
    ProtocolErrorUnspecified = 111,
    /// APN restriction value incompatible with active EPS bearer context
    ApnRestrictionValueIncompatible = 112,
    /// Multiple accesses to a PDN connection not allowed
    MultipleAccessesToPdnConnectionNotAllowed = 113,
}

impl Default for EsmCause {
    fn default() -> Self {
        EsmCause::ProtocolErrorUnspecified
    }
}


// ============================================================================
// ESM Message Types (3GPP TS 24.301)
// ============================================================================

/// ESM Message Types
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

// ============================================================================
// PDN Types
// ============================================================================

/// PDN Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PdnType {
    #[default]
    /// IPv4
    Ipv4 = 1,
    /// IPv6
    Ipv6 = 2,
    /// IPv4v6
    Ipv4v6 = 3,
    /// Non-IP
    NonIp = 5,
    /// Ethernet
    Ethernet = 6,
}


// ============================================================================
// QCI Values (3GPP TS 23.203)
// ============================================================================

/// QCI (QoS Class Identifier) values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Qci {
    /// QCI 1 - Conversational Voice
    Qci1 = 1,
    /// QCI 2 - Conversational Video
    Qci2 = 2,
    /// QCI 3 - Real Time Gaming
    Qci3 = 3,
    /// QCI 4 - Non-Conversational Video
    Qci4 = 4,
    /// QCI 5 - IMS Signaling
    Qci5 = 5,
    /// QCI 6 - Video, TCP-based
    Qci6 = 6,
    /// QCI 7 - Voice, Video, Interactive Gaming
    Qci7 = 7,
    /// QCI 8 - Video, TCP-based
    Qci8 = 8,
    /// QCI 9 - Video, TCP-based (default)
    Qci9 = 9,
    /// QCI 65 - Mission Critical user plane Push To Talk voice
    Qci65 = 65,
    /// QCI 66 - Non-Mission-Critical user plane Push To Talk voice
    Qci66 = 66,
    /// QCI 69 - Mission Critical delay sensitive signaling
    Qci69 = 69,
    /// QCI 70 - Mission Critical Data
    Qci70 = 70,
}

// ============================================================================
// Create Action Types
// ============================================================================

/// GTP Create Action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateAction {
    /// Create in attach request
    InAttachRequest,
    /// Create in TAU request
    InTauRequest,
    /// Create in PDN connectivity request
    InPdnConnectivityRequest,
    /// Create in handover
    InHandover,
}

// ============================================================================
// EPS QoS Building
// ============================================================================

/// Build EPS QoS IE
pub fn eps_qos_build(
    qci: u8,
    mbr_dl: u64,
    mbr_ul: u64,
    gbr_dl: u64,
    gbr_ul: u64,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // QCI
    buf.write_u8(qci);
    
    // Check if GBR bearer (QCI 1-4)
    let is_gbr = qci >= 1 && qci <= 4;
    
    if is_gbr {
        // MBR for uplink
        buf.write_u8(encode_bitrate(mbr_ul));
        // MBR for downlink
        buf.write_u8(encode_bitrate(mbr_dl));
        // GBR for uplink
        buf.write_u8(encode_bitrate(gbr_ul));
        // GBR for downlink
        buf.write_u8(encode_bitrate(gbr_dl));
    }
    
    // Extended values if needed
    if mbr_ul > 8640000 || mbr_dl > 8640000 || gbr_ul > 8640000 || gbr_dl > 8640000 {
        if is_gbr {
            buf.write_u8(encode_bitrate_ext(mbr_ul));
            buf.write_u8(encode_bitrate_ext(mbr_dl));
            buf.write_u8(encode_bitrate_ext(gbr_ul));
            buf.write_u8(encode_bitrate_ext(gbr_dl));
        }
    }
    
    buf.into_vec()
}


/// Encode bitrate value (3GPP TS 24.301 9.9.4.3)
fn encode_bitrate(kbps: u64) -> u8 {
    if kbps == 0 {
        return 0xff; // 0 kbps
    }
    
    // 1-63: value * 1 kbps
    if kbps <= 63 {
        return kbps as u8;
    }
    
    // 64-127: 64 + (value - 64) * 8 kbps
    if kbps <= 568 {
        return (64 + (kbps - 64) / 8) as u8;
    }
    
    // 128-254: 576 + (value - 128) * 64 kbps
    if kbps <= 8640 {
        return (128 + (kbps - 576) / 64) as u8;
    }
    
    // Maximum value
    0xfe
}

/// Encode extended bitrate value (3GPP TS 24.301 9.9.4.3)
fn encode_bitrate_ext(kbps: u64) -> u8 {
    if kbps <= 8640 {
        return 0;
    }
    
    // 1-74: 8600 + value * 100 kbps
    if kbps <= 16000 {
        return ((kbps - 8600) / 100) as u8;
    }
    
    // 75-186: 16000 + (value - 74) * 1000 kbps
    if kbps <= 128000 {
        return (74 + (kbps - 16000) / 1000) as u8;
    }
    
    // 187-250: 128000 + (value - 186) * 2000 kbps
    if kbps <= 256000 {
        return (186 + (kbps - 128000) / 2000) as u8;
    }
    
    // Maximum
    0xfa
}

// ============================================================================
// APN-AMBR Building
// ============================================================================

/// Build APN-AMBR IE
pub fn apn_ambr_build(dl: u64, ul: u64) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // APN-AMBR for downlink
    buf.write_u8(encode_apn_ambr(dl));
    // APN-AMBR for uplink
    buf.write_u8(encode_apn_ambr(ul));
    
    // Extended values
    let dl_ext = encode_apn_ambr_ext(dl);
    let ul_ext = encode_apn_ambr_ext(ul);
    
    if dl_ext > 0 || ul_ext > 0 {
        buf.write_u8(dl_ext);
        buf.write_u8(ul_ext);
        
        // Extended-2 values
        let dl_ext2 = encode_apn_ambr_ext2(dl);
        let ul_ext2 = encode_apn_ambr_ext2(ul);
        
        if dl_ext2 > 0 || ul_ext2 > 0 {
            buf.write_u8(dl_ext2);
            buf.write_u8(ul_ext2);
        }
    }
    
    buf.into_vec()
}

/// Encode APN-AMBR value (3GPP TS 24.301 9.9.4.2)
fn encode_apn_ambr(kbps: u64) -> u8 {
    if kbps == 0 {
        return 0xff;
    }
    
    // 1-63: value * 1 kbps
    if kbps <= 63 {
        return kbps as u8;
    }
    
    // 64-127: 64 + (value - 64) * 8 kbps
    if kbps <= 568 {
        return (64 + (kbps - 64) / 8) as u8;
    }
    
    // 128-254: 576 + (value - 128) * 64 kbps
    if kbps <= 8640 {
        return (128 + (kbps - 576) / 64) as u8;
    }
    
    0xfe
}


/// Encode APN-AMBR extended value
fn encode_apn_ambr_ext(kbps: u64) -> u8 {
    if kbps <= 8640 {
        return 0;
    }
    
    // 1-74: 8600 + value * 100 kbps
    if kbps <= 16000 {
        return ((kbps - 8600) / 100) as u8;
    }
    
    // 75-186: 16000 + (value - 74) * 1000 kbps
    if kbps <= 128000 {
        return (74 + (kbps - 16000) / 1000) as u8;
    }
    
    // 187-250: 128000 + (value - 186) * 2000 kbps
    if kbps <= 256000 {
        return (186 + (kbps - 128000) / 2000) as u8;
    }
    
    0xfa
}

/// Encode APN-AMBR extended-2 value
fn encode_apn_ambr_ext2(kbps: u64) -> u8 {
    if kbps <= 256000 {
        return 0;
    }
    
    // 1-254: 256 Mbps + value * 4 Mbps
    if kbps <= 1272000 {
        return ((kbps - 256000) / 4000) as u8;
    }
    
    // 255: 1280 Mbps
    0xff
}

// ============================================================================
// PDN Address Encoding
// ============================================================================

/// PDN Address lengths
pub const NAS_PDU_ADDRESS_IPV4_LEN: u8 = 5;
pub const NAS_PDU_ADDRESS_IPV6_LEN: u8 = 9;
pub const NAS_PDU_ADDRESS_IPV4V6_LEN: u8 = 13;

/// Encode PDN address
pub fn encode_pdn_address(paa: &Paa) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    match paa.pdn_type {
        PdnType::Ipv4 => {
            buf.write_u8(PdnType::Ipv4 as u8);
            buf.write_bytes(&paa.addr);
        }
        PdnType::Ipv6 => {
            buf.write_u8(PdnType::Ipv6 as u8);
            // Only interface identifier (last 8 bytes)
            buf.write_bytes(&paa.addr6[8..16]);
        }
        PdnType::Ipv4v6 => {
            buf.write_u8(PdnType::Ipv4v6 as u8);
            // Interface identifier (last 8 bytes of IPv6)
            buf.write_bytes(&paa.addr6[8..16]);
            // IPv4 address
            buf.write_bytes(&paa.addr);
        }
        _ => {
            buf.write_u8(PdnType::Ipv4 as u8);
            buf.write_bytes(&[0, 0, 0, 0]);
        }
    }
    
    buf.into_vec()
}

// ============================================================================
// ESM Message Building Functions
// ============================================================================

/// Build PDN connectivity reject message (with full parameters)
pub fn build_pdn_connectivity_reject_with_params(
    pti: u8,
    esm_cause: EsmCause,
    create_action: CreateAction,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Add security header if not in attach request
    if create_action != CreateAction::InAttachRequest {
        buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                     | NAS_PROTOCOL_DISCRIMINATOR_EMM);
        buf.write_u32(0); // MAC placeholder
        buf.write_u8(0);  // Sequence number placeholder
    }
    
    // ESM header
    buf.write_u8(0); // EPS bearer identity (0 for this message)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::PdnConnectivityReject as u8);
    
    // ESM cause
    buf.write_u8(esm_cause as u8);
    
    buf.into_vec()
}

/// Build PDN connectivity reject (simplified - for nas_path.rs)
pub fn build_pdn_connectivity_reject(esm_cause: EsmCause) -> Vec<u8> {
    build_pdn_connectivity_reject_with_params(PTI_UNASSIGNED, esm_cause, CreateAction::InPdnConnectivityRequest)
}


/// Build ESM information request message
pub fn build_esm_information_request(pti: u8) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // ESM header
    buf.write_u8(0); // EPS bearer identity
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::EsmInformationRequest as u8);
    
    buf.into_vec()
}

/// Build activate default EPS bearer context request message (with full parameters)
pub fn build_activate_default_bearer_context_request_with_params(
    sess: &MmeSess,
    bearer: &MmeBearer,
    create_action: CreateAction,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Add security header if not in attach request
    if create_action != CreateAction::InAttachRequest {
        buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                     | NAS_PROTOCOL_DISCRIMINATOR_EMM);
        buf.write_u32(0); // MAC placeholder
        buf.write_u8(0);  // Sequence number placeholder
    }
    
    // ESM header
    buf.write_u8(bearer.ebi); // EPS bearer identity
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(sess.pti);
    buf.write_u8(EsmMessageType::ActivateDefaultEpsBearerContextRequest as u8);
    
    // EPS QoS
    let eps_qos = eps_qos_build(
        bearer.qos.qci,
        bearer.qos.mbr.downlink,
        bearer.qos.mbr.uplink,
        bearer.qos.gbr.downlink,
        bearer.qos.gbr.uplink,
    );
    buf.write_lv(&eps_qos);
    
    // Access Point Name
    buf.write_lv(sess.apn.as_bytes());
    
    // PDN address
    let pdn_addr = encode_pdn_address(&sess.paa);
    buf.write_lv(&pdn_addr);
    
    // Optional: ESM cause (for PDN type restriction)
    if let Some(esm_cause) = get_pdn_type_restriction_cause(sess) {
        buf.write_u8(0x58); // ESM cause IEI
        buf.write_u8(esm_cause as u8);
    }
    
    // Optional: APN-AMBR
    if sess.ambr.downlink > 0 || sess.ambr.uplink > 0 {
        buf.write_u8(0x5e); // APN-AMBR IEI
        let apn_ambr = apn_ambr_build(sess.ambr.downlink, sess.ambr.uplink);
        buf.write_lv(&apn_ambr);
    }
    
    // Optional: Protocol configuration options
    if !sess.pgw_pco.is_empty() {
        buf.write_u8(0x27); // PCO IEI
        buf.write_lv(&sess.pgw_pco);
    }
    
    buf.into_vec()
}

/// Build activate default bearer context request (simplified - for nas_path.rs)
/// Uses GtpCreateAction from nas_path module
pub fn build_activate_default_bearer_context_request(
    sess: &MmeSess,
    create_action: crate::nas_path::GtpCreateAction,
) -> Vec<u8> {
    // Get default bearer from session (first bearer)
    let default_bearer = MmeBearer {
        ebi: 5, // Default EBI
        qos: sess.session.as_ref().map(|s| s.qos.clone()).unwrap_or_default(),
        ..Default::default()
    };
    
    // Convert GtpCreateAction to CreateAction
    let action = match create_action {
        crate::nas_path::GtpCreateAction::InAttachRequest => CreateAction::InAttachRequest,
        crate::nas_path::GtpCreateAction::InTau => CreateAction::InTauRequest,
        crate::nas_path::GtpCreateAction::InPdnConnectivity => CreateAction::InPdnConnectivityRequest,
        crate::nas_path::GtpCreateAction::InHandover => CreateAction::InHandover,
    };
    
    build_activate_default_bearer_context_request_with_params(sess, &default_bearer, action)
}

/// Get PDN type restriction cause if applicable
fn get_pdn_type_restriction_cause(sess: &MmeSess) -> Option<EsmCause> {
    // Check if UE requested IPv4v6 but got restricted
    if sess.ue_request_pdn_type == PdnType::Ipv4v6 {
        match sess.paa.pdn_type {
            PdnType::Ipv4 => Some(EsmCause::PdnTypeIpv4OnlyAllowed),
            PdnType::Ipv6 => Some(EsmCause::PdnTypeIpv6OnlyAllowed),
            _ => None,
        }
    } else {
        None
    }
}


/// Build activate dedicated EPS bearer context request message (with full parameters)
pub fn build_activate_dedicated_bearer_context_request_with_params(
    bearer: &MmeBearer,
    linked_ebi: u8,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // ESM header
    buf.write_u8(bearer.ebi); // EPS bearer identity
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(PTI_UNASSIGNED); // PTI is unassigned for dedicated bearer
    buf.write_u8(EsmMessageType::ActivateDedicatedEpsBearerContextRequest as u8);
    
    // Linked EPS bearer identity (4 bits) + spare (4 bits)
    buf.write_u8(linked_ebi & 0x0f);
    
    // EPS QoS
    let eps_qos = eps_qos_build(
        bearer.qos.qci,
        bearer.qos.mbr.downlink,
        bearer.qos.mbr.uplink,
        bearer.qos.gbr.downlink,
        bearer.qos.gbr.uplink,
    );
    buf.write_lv(&eps_qos);
    
    // TFT (Traffic Flow Template)
    if !bearer.tft.is_empty() {
        buf.write_lv(&bearer.tft);
    } else {
        buf.write_u8(0); // Empty TFT
    }
    
    buf.into_vec()
}

/// Build activate dedicated bearer context request (simplified - for nas_path.rs)
pub fn build_activate_dedicated_bearer_context_request(bearer: &MmeBearer) -> Vec<u8> {
    // Use default linked EBI (5 for default bearer)
    build_activate_dedicated_bearer_context_request_with_params(bearer, 5)
}

/// Build modify EPS bearer context request message (with full parameters)
pub fn build_modify_bearer_context_request_with_params(
    bearer: &MmeBearer,
    pti: u8,
    qos_presence: bool,
    tft_presence: bool,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // ESM header
    buf.write_u8(bearer.ebi); // EPS bearer identity
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::ModifyEpsBearerContextRequest as u8);
    
    // Optional: New EPS QoS
    if qos_presence {
        buf.write_u8(0x5b); // New EPS QoS IEI
        let eps_qos = eps_qos_build(
            bearer.qos.qci,
            bearer.qos.mbr.downlink,
            bearer.qos.mbr.uplink,
            bearer.qos.gbr.downlink,
            bearer.qos.gbr.uplink,
        );
        buf.write_lv(&eps_qos);
    }
    
    // Optional: TFT
    if tft_presence && !bearer.tft.is_empty() {
        buf.write_u8(0x36); // TFT IEI
        buf.write_lv(&bearer.tft);
    }
    
    buf.into_vec()
}

/// Build modify bearer context request (simplified - for nas_path.rs)
pub fn build_modify_bearer_context_request(
    bearer: &MmeBearer,
    qos_presence: bool,
    tft_presence: bool,
) -> Vec<u8> {
    build_modify_bearer_context_request_with_params(bearer, PTI_UNASSIGNED, qos_presence, tft_presence)
}


/// Build deactivate bearer context request (with explicit parameters)
pub fn build_deactivate_bearer_context_request_with_params(
    ebi: u8,
    pti: u8,
    esm_cause: EsmCause,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // ESM header
    buf.write_u8(ebi); // EPS bearer identity
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::DeactivateEpsBearerContextRequest as u8);
    
    // ESM cause
    buf.write_u8(esm_cause as u8);
    
    buf.into_vec()
}

/// Build deactivate bearer context request (simplified - for nas_path.rs)
pub fn build_deactivate_bearer_context_request(
    bearer: &MmeBearer,
    esm_cause: EsmCause,
) -> Vec<u8> {
    build_deactivate_bearer_context_request_with_params(bearer.ebi, PTI_UNASSIGNED, esm_cause)
}

/// Build bearer resource allocation reject message
pub fn build_bearer_resource_allocation_reject(
    pti: u8,
    esm_cause: EsmCause,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // ESM header
    buf.write_u8(0); // EPS bearer identity (0 for this message)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::BearerResourceAllocationReject as u8);
    
    // ESM cause
    buf.write_u8(esm_cause as u8);
    
    buf.into_vec()
}

/// Build bearer resource modification reject message
pub fn build_bearer_resource_modification_reject(
    pti: u8,
    esm_cause: EsmCause,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // ESM header
    buf.write_u8(0); // EPS bearer identity (0 for this message)
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::BearerResourceModificationReject as u8);
    
    // ESM cause
    buf.write_u8(esm_cause as u8);
    
    buf.into_vec()
}

/// Build PDN disconnect reject message
pub fn build_pdn_disconnect_reject(
    pti: u8,
    esm_cause: EsmCause,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // ESM header
    buf.write_u8(0); // EPS bearer identity
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::PdnDisconnectReject as u8);
    
    // ESM cause
    buf.write_u8(esm_cause as u8);
    
    buf.into_vec()
}


/// Build ESM status message
pub fn build_esm_status(
    ebi: u8,
    pti: u8,
    esm_cause: EsmCause,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    
    // Security header
    buf.write_u8((SecurityHeaderType::IntegrityProtectedAndCiphered as u8) << 4 
                 | NAS_PROTOCOL_DISCRIMINATOR_EMM);
    buf.write_u32(0); // MAC placeholder
    buf.write_u8(0);  // Sequence number placeholder
    
    // ESM header
    buf.write_u8(ebi); // EPS bearer identity
    buf.write_u8(NAS_PROTOCOL_DISCRIMINATOR_ESM);
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::EsmStatus as u8);
    
    // ESM cause
    buf.write_u8(esm_cause as u8);
    
    buf.into_vec()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esm_cause_values() {
        assert_eq!(EsmCause::OperatorDeterminedBarring as u8, 8);
        assert_eq!(EsmCause::InsufficientResources as u8, 26);
        assert_eq!(EsmCause::MissingOrUnknownApn as u8, 27);
        assert_eq!(EsmCause::RegularDeactivation as u8, 36);
        assert_eq!(EsmCause::NetworkFailure as u8, 38);
        assert_eq!(EsmCause::PdnTypeIpv4OnlyAllowed as u8, 50);
        assert_eq!(EsmCause::PdnTypeIpv6OnlyAllowed as u8, 51);
        assert_eq!(EsmCause::ProtocolErrorUnspecified as u8, 111);
    }

    #[test]
    fn test_esm_message_type_values() {
        assert_eq!(EsmMessageType::ActivateDefaultEpsBearerContextRequest as u8, 0xc1);
        assert_eq!(EsmMessageType::ActivateDedicatedEpsBearerContextRequest as u8, 0xc5);
        assert_eq!(EsmMessageType::ModifyEpsBearerContextRequest as u8, 0xc9);
        assert_eq!(EsmMessageType::DeactivateEpsBearerContextRequest as u8, 0xcd);
        assert_eq!(EsmMessageType::PdnConnectivityRequest as u8, 0xd0);
        assert_eq!(EsmMessageType::PdnConnectivityReject as u8, 0xd1);
        assert_eq!(EsmMessageType::EsmInformationRequest as u8, 0xd9);
        assert_eq!(EsmMessageType::BearerResourceAllocationReject as u8, 0xd5);
    }

    #[test]
    fn test_encode_bitrate() {
        // 0 kbps
        assert_eq!(encode_bitrate(0), 0xff);
        
        // 1-63 kbps: direct value
        assert_eq!(encode_bitrate(1), 1);
        assert_eq!(encode_bitrate(63), 63);
        
        // 64-568 kbps: 64 + (value - 64) / 8
        assert_eq!(encode_bitrate(64), 64);
        assert_eq!(encode_bitrate(128), 72);
        
        // 576-8640 kbps: 128 + (value - 576) / 64
        assert_eq!(encode_bitrate(576), 128);
        assert_eq!(encode_bitrate(8640), 254);
    }


    #[test]
    fn test_encode_apn_ambr() {
        // 0 kbps
        assert_eq!(encode_apn_ambr(0), 0xff);
        
        // 1-63 kbps
        assert_eq!(encode_apn_ambr(1), 1);
        assert_eq!(encode_apn_ambr(63), 63);
        
        // 64-568 kbps
        assert_eq!(encode_apn_ambr(64), 64);
        
        // 576-8640 kbps
        assert_eq!(encode_apn_ambr(576), 128);
    }

    #[test]
    fn test_eps_qos_build() {
        // Non-GBR bearer (QCI 9)
        let qos = eps_qos_build(9, 0, 0, 0, 0);
        assert_eq!(qos.len(), 1);
        assert_eq!(qos[0], 9);
        
        // GBR bearer (QCI 1)
        let qos = eps_qos_build(1, 64, 64, 32, 32);
        assert_eq!(qos.len(), 5);
        assert_eq!(qos[0], 1); // QCI
    }

    #[test]
    fn test_apn_ambr_build() {
        let ambr = apn_ambr_build(1000, 500);
        assert!(ambr.len() >= 2);
    }

    #[test]
    fn test_build_pdn_connectivity_reject() {
        let msg = build_pdn_connectivity_reject_with_params(
            1,
            EsmCause::MissingOrUnknownApn,
            CreateAction::InAttachRequest,
        );
        
        // Without security header (in attach request)
        assert_eq!(msg[0], 0); // EBI
        assert_eq!(msg[1], NAS_PROTOCOL_DISCRIMINATOR_ESM);
        assert_eq!(msg[2], 1); // PTI
        assert_eq!(msg[3], EsmMessageType::PdnConnectivityReject as u8);
        assert_eq!(msg[4], EsmCause::MissingOrUnknownApn as u8);
    }

    #[test]
    fn test_build_esm_information_request() {
        let msg = build_esm_information_request(5);
        
        // With security header
        assert!(msg.len() > 6);
        // Check ESM header after security header
        let esm_start = 6; // After security header
        assert_eq!(msg[esm_start], 0); // EBI
        assert_eq!(msg[esm_start + 1], NAS_PROTOCOL_DISCRIMINATOR_ESM);
        assert_eq!(msg[esm_start + 2], 5); // PTI
        assert_eq!(msg[esm_start + 3], EsmMessageType::EsmInformationRequest as u8);
    }

    #[test]
    fn test_build_deactivate_bearer_context_request() {
        let msg = build_deactivate_bearer_context_request_with_params(
            5, // EBI
            1, // PTI
            EsmCause::RegularDeactivation,
        );
        
        // With security header
        assert!(msg.len() > 6);
        let esm_start = 6;
        assert_eq!(msg[esm_start], 5); // EBI
        assert_eq!(msg[esm_start + 1], NAS_PROTOCOL_DISCRIMINATOR_ESM);
        assert_eq!(msg[esm_start + 2], 1); // PTI
        assert_eq!(msg[esm_start + 3], EsmMessageType::DeactivateEpsBearerContextRequest as u8);
        assert_eq!(msg[esm_start + 4], EsmCause::RegularDeactivation as u8);
    }

    #[test]
    fn test_build_bearer_resource_allocation_reject() {
        let msg = build_bearer_resource_allocation_reject(
            3, // PTI
            EsmCause::NetworkFailure,
        );
        
        let esm_start = 6;
        assert_eq!(msg[esm_start], 0); // EBI
        assert_eq!(msg[esm_start + 1], NAS_PROTOCOL_DISCRIMINATOR_ESM);
        assert_eq!(msg[esm_start + 2], 3); // PTI
        assert_eq!(msg[esm_start + 3], EsmMessageType::BearerResourceAllocationReject as u8);
        assert_eq!(msg[esm_start + 4], EsmCause::NetworkFailure as u8);
    }

    #[test]
    fn test_build_bearer_resource_modification_reject() {
        let msg = build_bearer_resource_modification_reject(
            4, // PTI
            EsmCause::ServiceOptionNotSupported,
        );
        
        let esm_start = 6;
        assert_eq!(msg[esm_start], 0); // EBI
        assert_eq!(msg[esm_start + 1], NAS_PROTOCOL_DISCRIMINATOR_ESM);
        assert_eq!(msg[esm_start + 2], 4); // PTI
        assert_eq!(msg[esm_start + 3], EsmMessageType::BearerResourceModificationReject as u8);
        assert_eq!(msg[esm_start + 4], EsmCause::ServiceOptionNotSupported as u8);
    }
}
