//! ESM Message Building
//!
//! Port of src/mme/esm-build.c - ESM message building functions

use crate::context::{MmeBearer, MmeSess, Paa};
use crate::emm_build::NasBuffer;

// ============================================================================
// ESM Protocol Discriminator
// ============================================================================

/// NAS Protocol Discriminator for ESM
pub const NAS_PROTOCOL_DISCRIMINATOR_ESM: u8 = 0x02;

/// Octet 1 of an ESM message: the EPS bearer identity in bits 8-5 and the
/// protocol discriminator in bits 4-1 (TS 24.301 §9.3.1, TS 24.007 §11.2.3.1.5).
///
/// One octet, not two: writing the EBI and the PD as separate octets (#496)
/// shifted every ESM message mmed sent by one octet, so a conformant UE read
/// PD 5 and refused it.
pub fn esm_header_octet(ebi: u8) -> u8 {
    ((ebi & 0x0f) << 4) | NAS_PROTOCOL_DISCRIMINATOR_ESM
}

/// Procedure Transaction Identity - Unassigned
pub const PTI_UNASSIGNED: u8 = 0;

// ============================================================================
// ESM Cause Codes (3GPP TS 24.301)
// ============================================================================

/// ESM Cause codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
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
    #[default]
    ProtocolErrorUnspecified = 111,
    /// APN restriction value incompatible with active EPS bearer context
    ApnRestrictionValueIncompatible = 112,
    /// Multiple accesses to a PDN connection not allowed
    MultipleAccessesToPdnConnectionNotAllowed = 113,
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

/// Build the EPS quality of service IE value (TS 24.301 §9.9.4.3).
///
/// The rates are the bearer's, in **bit/s**, as `MmeBearer::qos` holds them (the S11
/// Bearer QoS is parsed into bit/s). The IE codes kbit/s (TS 24.008 Table 10.5.156), so
/// they are converted here; before #641 the bit/s values were coded as if they were
/// kbit/s, so a 64 kbit/s GBR went out as the 8640 kbit/s ceiling. The rate octets are
/// present for a GBR QCI only (TS 23.203 Table 6.1.7), with the extended octets when a
/// rate exceeds 8640 kbit/s.
pub fn eps_qos_build(qci: u8, mbr_dl: u64, mbr_ul: u64, gbr_dl: u64, gbr_ul: u64) -> Vec<u8> {
    let mut buf = NasBuffer::new();
    buf.write_u8(qci);
    let is_gbr = matches!(qci, 1..=4 | 65..=67 | 71..=76);
    if is_gbr {
        let kbps = |bps: u64| bps.div_ceil(1000);
        let rates = [kbps(mbr_ul), kbps(mbr_dl), kbps(gbr_ul), kbps(gbr_dl)];
        for r in rates {
            buf.write_u8(encode_bitrate(r));
        }
        if rates.iter().any(|&r| r > 8640) {
            for r in rates {
                buf.write_u8(encode_bitrate_ext(r));
            }
        }
    }
    buf.into_vec()
}

/// A bit rate octet (TS 24.008 Table 10.5.156): 1-63 kbit/s in 1 kbit/s steps,
/// 64-568 in 8, 576-8640 in 64, rounded up; 0 kbit/s is 0xFF, and anything above 8640
/// is 0xFE with the rest in the extended octet.
fn encode_bitrate(kbps: u64) -> u8 {
    match kbps {
        0 => 0xff,
        1..=63 => kbps as u8,
        64..=568 => (0x40 + (kbps - 64).div_ceil(8)) as u8,
        569..=8640 => (0x80 + kbps.saturating_sub(576).div_ceil(64)) as u8,
        _ => 0xfe,
    }
}

/// An extended bit rate octet (TS 24.008 Table 10.5.156): 0 when the base octet says
/// it all; 8700-16000 kbit/s in 100 kbit/s steps, 17-128 Mbit/s in 1, 130-256 Mbit/s
/// in 2, rounded up and capped at 256 Mbit/s.
fn encode_bitrate_ext(kbps: u64) -> u8 {
    match kbps {
        0..=8640 => 0,
        8641..=16000 => kbps.saturating_sub(8600).div_ceil(100) as u8,
        16001..=128_000 => (0x4a + (kbps - 16000).div_ceil(1000)) as u8,
        128_001..=256_000 => (0xba + (kbps - 128_000).div_ceil(2000)) as u8,
        _ => 0xfa,
    }
}

// ============================================================================
// APN-AMBR Building
// ============================================================================

/// The APN-AMBR IE contents (TS 24.301 §9.9.4.2) for `dl_bps` / `ul_bps`, which
/// are in **bit/s**: the session AMBR is the HSS's (TS 29.272 §7.3.41), stored
/// unchanged. The IE is coded in kbit/s, rounded up so the UE is never given
/// less than its subscription (#1181). The contents are octets 3-4, 3-6 when
/// either direction needs the extended octet, or 3-8 when either needs the
/// extended-2 one (an IE of 4, 6 or 8 octets).
pub fn apn_ambr_build(dl_bps: u64, ul_bps: u64) -> Vec<u8> {
    let dl = apn_ambr_octets(dl_bps.div_ceil(1000));
    let ul = apn_ambr_octets(ul_bps.div_ceil(1000));
    let mut buf = NasBuffer::new();
    buf.write_u8(dl.0);
    buf.write_u8(ul.0);
    if dl.1 != 0 || ul.1 != 0 || dl.2 != 0 || ul.2 != 0 {
        buf.write_u8(dl.1);
        buf.write_u8(ul.1);
        if dl.2 != 0 || ul.2 != 0 {
            buf.write_u8(dl.2);
            buf.write_u8(ul.2);
        }
    }
    buf.into_vec()
}

/// APN-AMBR above which the extended-2 octet is needed: 256 Mbit/s, in kbit/s.
const APN_AMBR_EXT_MAX_KBPS: u64 = 256_000;

/// One direction's (octet 3, octet 5, octet 7) of Table 9.9.4.2.1 for `kbps`:
/// the smallest coded value not below it, capped at 65280 Mbit/s.
fn apn_ambr_octets(kbps: u64) -> (u8, u8, u8) {
    if kbps == 0 {
        // "1 1 1 1 1 1 1 1 0kbps"
        return (0xff, 0, 0);
    }
    if kbps <= APN_AMBR_EXT_MAX_KBPS {
        let (o3, o5) = apn_ambr_base(kbps);
        return (o3, o5, 0);
    }
    // Extended-2: (octet 7) * 256 Mbps + the value of octets 3 and 5, with
    // octets 3/5 carrying the rest (more than 0, at most 256 Mbps).
    let o7 = kbps.div_ceil(APN_AMBR_EXT_MAX_KBPS) - 1;
    if o7 > 0xfe {
        // 65280 Mbps: octet 5 "11111010", octet 7 "11111110" (§9.9.4.2).
        return (0xfe, 0xfa, 0xfe);
    }
    let (o3, o5) = apn_ambr_base(kbps - o7 * APN_AMBR_EXT_MAX_KBPS);
    (o3, o5, o7 as u8)
}

/// Octets 3 and 5 for 1..=256000 kbit/s, rounding up to the next step.
fn apn_ambr_base(kbps: u64) -> (u8, u8) {
    match kbps {
        // 1-63 kbps in 1 kbps steps.
        1..=63 => (kbps as u8, 0),
        // 64-568 kbps in 8 kbps steps: 64 + (v - 0b0100_0000) * 8.
        64..=568 => ((0x40 + (kbps - 64).div_ceil(8)) as u8, 0),
        // 569-575 kbps fall between the 8 and the 64 kbps ranges: the next step
        // up is 576 kbps (the underflow #1181 found was here).
        569..=8640 => ((0x80 + kbps.saturating_sub(576).div_ceil(64)) as u8, 0),
        // Above 8640 kbps octet 3 says 8640 ("11111110") and octet 5 holds the
        // value: 8600 + v * 100 kbps (8700-16000), 16 Mbps + (v - 0b0100_1010)
        // * 1 Mbps (17-128 Mbps), 128 Mbps + (v - 0b1011_1010) * 2 Mbps
        // (130-256 Mbps).
        8641..=16_000 => (0xfe, (kbps - 8600).div_ceil(100) as u8),
        16_001..=128_000 => (0xfe, (0x4a + (kbps - 16_000).div_ceil(1000)) as u8),
        _ => (
            0xfe,
            (0xba + (kbps.min(APN_AMBR_EXT_MAX_KBPS) - 128_000).div_ceil(2000)) as u8,
        ),
    }
}

/// The kbit/s that (octet 3, octet 5, octet 7) of Table 9.9.4.2.1 stand for.
#[cfg(test)]
fn apn_ambr_kbps(o3: u8, o5: u8, o7: u8) -> u64 {
    let base = if o5 != 0 {
        let v = u64::from(o5.min(0xfa));
        match v {
            1..=0x4a => 8600 + v * 100,
            0x4b..=0xba => 16_000 + (v - 0x4a) * 1000,
            _ => 128_000 + (v - 0xba) * 2000,
        }
    } else {
        let v = u64::from(o3);
        match v {
            0xff => 0,
            1..=0x3f => v,
            0x40..=0x7f => 64 + (v - 0x40) * 8,
            _ => 576 + (v - 0x80) * 64,
        }
    };
    let o7 = if o7 == 0xff { 0 } else { u64::from(o7) };
    o7 * 256_000 + base
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
///
/// Every ESM builder returns the PLAIN ESM message (#497). Inside an ATTACH it is
/// carried in the EMM message's ESM container; standalone, the sender protects it
/// with `nas_path::protect_esm`. `_create_action` no longer selects a placeholder
/// security header, and is kept so callers name the context they build for.
pub fn build_pdn_connectivity_reject_with_params(
    pti: u8,
    esm_cause: EsmCause,
    _create_action: CreateAction,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(0)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::PdnConnectivityReject as u8);

    // ESM cause
    buf.write_u8(esm_cause as u8);

    buf.into_vec()
}

/// Build PDN connectivity reject (simplified - for nas_path.rs)
pub fn build_pdn_connectivity_reject(esm_cause: EsmCause) -> Vec<u8> {
    build_pdn_connectivity_reject_with_params(
        PTI_UNASSIGNED,
        esm_cause,
        CreateAction::InPdnConnectivityRequest,
    )
}

/// Build ESM information request message
pub fn build_esm_information_request(pti: u8) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(0)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::EsmInformationRequest as u8);

    buf.into_vec()
}

/// Build activate default EPS bearer context request message (with full parameters)
pub fn build_activate_default_bearer_context_request_with_params(
    sess: &MmeSess,
    bearer: &MmeBearer,
    _create_action: CreateAction,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(bearer.ebi)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
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

    // Access Point Name (TS 24.301 §9.9.4.1 -> TS 24.008 §10.5.6.1): the APN as
    // TS 23.003 §9.1 labels, not the dotted string (#1350: the UE read the raw
    // `internet` as a 105-octet label and got APN "").
    buf.write_lv(&crate::s11_build::encode_apn_dns(&sess.apn));

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
    // The bearer this message activates.
    //
    // #329: `sess.session.as_ref()...expect("value expected")` used to be here, and it
    // was a REACHABLE PANIC — `sess.session` is the subscription record, absent for any
    // session the HSS has not populated, and this function is on the Attach Accept path.
    // It survived only because that path had no caller (see the issue). A crashing MME
    // is strictly worse than one that activates a bearer with default QoS and says so.
    let subscribed_qos = sess.session.as_ref().map(|s| s.qos.clone());
    if subscribed_qos.is_none() {
        log::warn!(
            "session for APN '{}' carries no subscribed QoS; activating the default \
             bearer with default QoS values",
            sess.apn
        );
    }
    let default_bearer = MmeBearer {
        // EBI 5 is the lowest value TS 24.007 §11.2.3.1.5 assigns to an EPS bearer, so
        // it is the right FALLBACK for a caller that has no bearer to name — but a
        // caller that does have one should use
        // `build_activate_default_bearer_context_request_with_params` and pass it,
        // which is what the Attach Accept path now does (#329). Leaving this to
        // fabricate an EBI for that path made the UE bind whatever bearer the message
        // named rather than the one the MME had created.
        ebi: 5,
        qos: subscribed_qos.unwrap_or_default(),
        ..Default::default()
    };

    // Convert GtpCreateAction to CreateAction
    let action = match create_action {
        crate::nas_path::GtpCreateAction::InAttachRequest => CreateAction::InAttachRequest,
        crate::nas_path::GtpCreateAction::InTau => CreateAction::InTauRequest,
        crate::nas_path::GtpCreateAction::InPdnConnectivity => {
            CreateAction::InPdnConnectivityRequest
        }
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
///
/// `pti` is the UE's PTI when the activation answers its BEARER RESOURCE ALLOCATION
/// REQUEST (TS 24.301 §6.4.2.2), else [`PTI_UNASSIGNED`] (network-initiated).
pub fn build_activate_dedicated_bearer_context_request_with_params(
    bearer: &MmeBearer,
    linked_ebi: u8,
    pti: u8,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(bearer.ebi)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
    buf.write_u8(pti);
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
    build_activate_dedicated_bearer_context_request_with_params(bearer, 5, PTI_UNASSIGNED)
}

/// Build modify EPS bearer context request message (with full parameters)
pub fn build_modify_bearer_context_request_with_params(
    bearer: &MmeBearer,
    pti: u8,
    qos_presence: bool,
    tft_presence: bool,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(bearer.ebi)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
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

/// MODIFY EPS BEARER CONTEXT REQUEST (TS 24.301 §8.3.18) with the New EPS QoS
/// (`qos_presence`), the TFT (`tft_presence`) and, when the PDN connection's
/// APN-AMBR changed, the APN-AMBR (`apn_ambr`, bit/s (dl, ul); IEI 0x5E, after
/// the TFT in the message's IE order) (#641 Update half).
pub fn build_modify_bearer_context_request_with_ambr(
    bearer: &MmeBearer,
    pti: u8,
    qos_presence: bool,
    tft_presence: bool,
    apn_ambr: Option<(u64, u64)>,
) -> Vec<u8> {
    let mut msg =
        build_modify_bearer_context_request_with_params(bearer, pti, qos_presence, tft_presence);
    if let Some((dl, ul)) = apn_ambr {
        let mut buf = NasBuffer::new();
        buf.write_u8(0x5e); // APN-AMBR IEI
        buf.write_lv(&apn_ambr_build(dl, ul));
        msg.extend_from_slice(&buf.into_vec());
    }
    msg
}

/// Build modify bearer context request (simplified - for nas_path.rs)
pub fn build_modify_bearer_context_request(
    bearer: &MmeBearer,
    qos_presence: bool,
    tft_presence: bool,
) -> Vec<u8> {
    build_modify_bearer_context_request_with_params(
        bearer,
        PTI_UNASSIGNED,
        qos_presence,
        tft_presence,
    )
}

/// Build deactivate bearer context request (with explicit parameters)
pub fn build_deactivate_bearer_context_request_with_params(
    ebi: u8,
    pti: u8,
    esm_cause: EsmCause,
) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(ebi)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::DeactivateEpsBearerContextRequest as u8);

    // ESM cause
    buf.write_u8(esm_cause as u8);

    buf.into_vec()
}

/// Build deactivate bearer context request (simplified - for nas_path.rs)
pub fn build_deactivate_bearer_context_request(bearer: &MmeBearer, esm_cause: EsmCause) -> Vec<u8> {
    build_deactivate_bearer_context_request_with_params(bearer.ebi, PTI_UNASSIGNED, esm_cause)
}

/// Build bearer resource allocation reject message
pub fn build_bearer_resource_allocation_reject(pti: u8, esm_cause: EsmCause) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(0)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::BearerResourceAllocationReject as u8);

    // ESM cause
    buf.write_u8(esm_cause as u8);

    buf.into_vec()
}

/// Build bearer resource modification reject message
pub fn build_bearer_resource_modification_reject(pti: u8, esm_cause: EsmCause) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(0)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::BearerResourceModificationReject as u8);

    // ESM cause
    buf.write_u8(esm_cause as u8);

    buf.into_vec()
}

/// Build PDN disconnect reject message
pub fn build_pdn_disconnect_reject(pti: u8, esm_cause: EsmCause) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(0)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
    buf.write_u8(pti);
    buf.write_u8(EsmMessageType::PdnDisconnectReject as u8);

    // ESM cause
    buf.write_u8(esm_cause as u8);

    buf.into_vec()
}

/// Build ESM status message
pub fn build_esm_status(ebi: u8, pti: u8, esm_cause: EsmCause) -> Vec<u8> {
    let mut buf = NasBuffer::new();

    // ESM header
    buf.write_u8(esm_header_octet(ebi)); // octet 1: EBI | PD (TS 24.301 §9.3.1)
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
        assert_eq!(
            EsmMessageType::ActivateDefaultEpsBearerContextRequest as u8,
            0xc1
        );
        assert_eq!(
            EsmMessageType::ActivateDedicatedEpsBearerContextRequest as u8,
            0xc5
        );
        assert_eq!(EsmMessageType::ModifyEpsBearerContextRequest as u8, 0xc9);
        assert_eq!(
            EsmMessageType::DeactivateEpsBearerContextRequest as u8,
            0xcd
        );
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
        // Table 9.9.4.2.1 boundaries, in kbit/s.
        assert_eq!(apn_ambr_octets(0), (0xff, 0, 0));
        assert_eq!(apn_ambr_octets(1), (1, 0, 0));
        assert_eq!(apn_ambr_octets(63), (63, 0, 0));
        assert_eq!(apn_ambr_octets(64), (0x40, 0, 0));
        assert_eq!(apn_ambr_octets(568), (0x7f, 0, 0));
        assert_eq!(apn_ambr_octets(576), (0x80, 0, 0));
        assert_eq!(apn_ambr_octets(8640), (0xfe, 0, 0));
        assert_eq!(apn_ambr_octets(8700), (0xfe, 0x01, 0));
        assert_eq!(apn_ambr_octets(16_000), (0xfe, 0x4a, 0));
        assert_eq!(apn_ambr_octets(17_000), (0xfe, 0x4b, 0));
        assert_eq!(apn_ambr_octets(128_000), (0xfe, 0xba, 0));
        assert_eq!(apn_ambr_octets(130_000), (0xfe, 0xbb, 0));
        assert_eq!(apn_ambr_octets(256_000), (0xfe, 0xfa, 0));
        // 512 Mbps = 1 * 256 Mbps + 256 Mbps.
        assert_eq!(apn_ambr_octets(512_000), (0xfe, 0xfa, 0x01));
        // 65280 Mbps is the ceiling.
        assert_eq!(apn_ambr_octets(65_280_000), (0xfe, 0xfa, 0xfe));
        assert_eq!(apn_ambr_octets(99_000_000), (0xfe, 0xfa, 0xfe));
    }

    /// #1181: 569-575 kbit/s no longer underflow; they take the 576 kbit/s step.
    #[test]
    fn apn_ambr_between_the_8_and_64_kbps_ranges_is_576() {
        for kbps in 569..=575 {
            assert_eq!(apn_ambr_octets(kbps), (0x80, 0, 0), "{kbps} kbit/s");
        }
        // Hand-worked: 570 kbit/s = 570_000 bit/s -> octet 3 "10000000".
        assert_eq!(apn_ambr_build(570_000, 570_000), vec![0x80, 0x80]);
    }

    /// #1181: every coded value is the smallest one not below the request, over
    /// the whole range (no step lost, no rounding down).
    #[test]
    fn apn_ambr_rounds_up_to_the_next_coded_value() {
        let mut kbps = 1u64;
        while kbps <= 66_000_000 {
            let (o3, o5, o7) = apn_ambr_octets(kbps);
            let coded = apn_ambr_kbps(o3, o5, o7);
            if kbps <= 65_280_000 {
                assert!(coded >= kbps, "{kbps} kbit/s coded as {coded}");
                if kbps > 1 {
                    let (p3, p5, p7) = apn_ambr_octets(kbps - 1);
                    let below = apn_ambr_kbps(p3, p5, p7);
                    assert!(below < kbps || below == coded, "{kbps}: not the smallest");
                }
            } else {
                assert_eq!(coded, 65_280_000);
            }
            kbps += if kbps < 20_000 { 1 } else { 997 };
        }
    }

    /// #1181: the session AMBR is in bit/s (the HSS's, TS 29.272 §7.3.41): a
    /// 10 Mbit/s subscription is coded as 10000 kbit/s, by hand: octet 3
    /// "11111110" (8640 kbps), octet 5 = (10000 - 8600) / 100 = 14 = 0x0e.
    #[test]
    fn test_apn_ambr_build() {
        // 10 Mbit/s DL: octet 3 "11111110" (8640 kbps), octet 5 = (10000 - 8600)
        // / 100 = 14. 5 Mbit/s UL: 576 + 70 * 64 = 5056 kbps, the first step not
        // below 5000, so octet 4 = 0x80 + 70 = 0xc6; its octet 6 is 0.
        assert_eq!(
            apn_ambr_build(10_000_000, 5_000_000),
            vec![0xfe, 0xc6, 0x0e, 0x00]
        );
        // Below 8640 kbit/s both ways, 4 octets: 1000 kbps -> 576 + 7 * 64 =
        // 1024 (0x87); 500 kbps -> 64 + 55 * 8 = 504 (0x77).
        assert_eq!(apn_ambr_build(1_000_000, 500_000), vec![0x87, 0x77]);
        // 1 Gbit/s downlink needs extended-2: 3 * 256 Mbps + 232 Mbps.
        let ambr = apn_ambr_build(1_000_000_000, 1_000_000);
        assert_eq!(ambr.len(), 6, "contents octets 3-8");
        assert_eq!(apn_ambr_kbps(ambr[0], ambr[2], ambr[4]), 1_000_000);
        assert_eq!(
            apn_ambr_kbps(ambr[1], ambr[3], ambr[5]),
            1024,
            "1000 rounded up"
        );
        // #1187 review: an uplink-only need sizes the IE too. UL 10 Mbit/s over
        // a 1 Mbit/s DL: octets 3-6 (4 contents octets).
        let ambr = apn_ambr_build(1_000_000, 10_000_000);
        assert_eq!(ambr.len(), 4, "the uplink needs octet 6");
        assert_eq!(apn_ambr_kbps(ambr[0], ambr[2], 0), 1024);
        assert_eq!(apn_ambr_kbps(ambr[1], ambr[3], 0), 10_000);
        // UL 300 Mbit/s over a 100 Mbit/s DL: octets 3-8 (6 contents octets).
        let ambr = apn_ambr_build(100_000_000, 300_000_000);
        assert_eq!(ambr.len(), 6, "the uplink needs octet 8");
        assert_eq!(apn_ambr_kbps(ambr[0], ambr[2], ambr[4]), 100_000);
        assert_eq!(apn_ambr_kbps(ambr[1], ambr[3], ambr[5]), 300_000);
    }

    /// #1181, TS 24.301 §8.3.6: a 10 / 5 Mbit/s session (bit/s, as the HSS
    /// gives it) reaches the UE in ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST as
    /// APN-AMBR 5E 04 FE C6 0E 00, not 1000 times higher.
    #[test]
    fn the_default_bearer_request_carries_the_apn_ambr_in_kbps() {
        let mut sess = MmeSess::default();
        sess.ambr.downlink = 10_000_000;
        sess.ambr.uplink = 5_000_000;
        let bearer = MmeBearer {
            ebi: 5,
            ..Default::default()
        };
        let msg = build_activate_default_bearer_context_request_with_params(
            &sess,
            &bearer,
            CreateAction::InAttachRequest,
        );
        assert!(
            msg.windows(6)
                .any(|w| w == [0x5e, 0x04, 0xfe, 0xc6, 0x0e, 0x00]),
            "APN-AMBR IE in {msg:02x?}"
        );
    }

    /// #1350, TS 24.008 §10.5.6.1 / TS 23.003 §9.1: the Access Point Name IE after the
    /// EPS QoS carries `internet` as one length-prefixed label, and a dotted APN as one
    /// label per dot-separated part.
    #[test]
    fn the_default_bearer_request_carries_the_apn_as_labels() {
        let bearer = MmeBearer {
            ebi: 5,
            ..Default::default()
        };
        for (apn, labels) in [
            ("internet", b"\x08internet".to_vec()),
            (
                "ims.mnc070.mcc999.gprs",
                b"\x03ims\x06mnc070\x06mcc999\x04gprs".to_vec(),
            ),
        ] {
            let sess = MmeSess {
                apn: apn.to_string(),
                ..Default::default()
            };
            let msg = build_activate_default_bearer_context_request_with_params(
                &sess,
                &bearer,
                CreateAction::InAttachRequest,
            );
            // Header (3) + EPS QoS LV, then the APN LV.
            let qos_len = usize::from(msg[3]);
            let at = 4 + qos_len;
            assert_eq!(
                usize::from(msg[at]),
                labels.len(),
                "APN length for {apn}: {msg:02x?}"
            );
            assert_eq!(
                &msg[at + 1..at + 1 + labels.len()],
                &labels[..],
                "APN value for {apn}"
            );
        }
    }

    #[test]
    fn test_eps_qos_build() {
        // Non-GBR bearer (QCI 9)
        let qos = eps_qos_build(9, 0, 0, 0, 0);
        assert_eq!(qos.len(), 1);
        assert_eq!(qos[0], 9);

        // GBR bearer (QCI 1), rates in bit/s: 64 kbit/s MBR, 32 kbit/s GBR.
        let qos = eps_qos_build(1, 64_000, 64_000, 32_000, 32_000);
        assert_eq!(qos, vec![1, 0x40, 0x40, 0x20, 0x20]);
    }

    /// #641: the TS 24.008 Table 10.5.156 boundaries, rounded up, and the 569-575 kbit/s
    /// range that underflowed.
    #[test]
    fn eps_qos_bit_rates_follow_ts_24_008_table_10_5_156() {
        assert_eq!(encode_bitrate(0), 0xff);
        assert_eq!(encode_bitrate(63), 63);
        assert_eq!(encode_bitrate(64), 0x40);
        assert_eq!(encode_bitrate(568), 0x7f);
        assert_eq!(encode_bitrate(570), 0x80, "rounded up to 576");
        assert_eq!(encode_bitrate(576), 0x80);
        assert_eq!(encode_bitrate(8640), 0xfe);
        assert_eq!(encode_bitrate_ext(8640), 0);
        assert_eq!(encode_bitrate_ext(8700), 0x01);
        assert_eq!(encode_bitrate_ext(16000), 0x4a);
        assert_eq!(encode_bitrate_ext(17000), 0x4b);
        assert_eq!(encode_bitrate_ext(128_000), 0xba);
        assert_eq!(encode_bitrate_ext(256_000), 0xfa);
        // 10 Mbit/s MBR on a GBR bearer: base octets 0xFE, extended 8600 + 14 * 100.
        let qos = eps_qos_build(1, 10_000_000, 10_000_000, 64_000, 64_000);
        assert_eq!(qos, vec![1, 0xfe, 0xfe, 0x40, 0x40, 14, 14, 0, 0]);
    }

    #[test]
    fn test_build_pdn_connectivity_reject() {
        let msg = build_pdn_connectivity_reject_with_params(
            1,
            EsmCause::MissingOrUnknownApn,
            CreateAction::InAttachRequest,
        );

        // Without security header (in attach request)
        assert_eq!(msg[0], 0x02); // octet 1: EBI 0 | PD 2, one octet (TS 24.301 §9.3.1)
        assert_eq!(msg[1], 1); // PTI
        assert_eq!(msg[2], EsmMessageType::PdnConnectivityReject as u8);
        assert_eq!(msg[3], EsmCause::MissingOrUnknownApn as u8);
    }

    #[test]
    fn test_build_esm_information_request() {
        let msg = build_esm_information_request(5);

        // Plain: the sender protects it (#497).
        assert_eq!(msg.len(), 3);
        let esm_start = 0;
        assert_eq!(msg[esm_start], 0x02); // octet 1: EBI 0 | PD 2, one octet (TS 24.301 §9.3.1)
        assert_eq!(msg[esm_start + 1], 5); // PTI
        assert_eq!(
            msg[esm_start + 2],
            EsmMessageType::EsmInformationRequest as u8
        );
    }

    #[test]
    fn test_build_deactivate_bearer_context_request() {
        let msg = build_deactivate_bearer_context_request_with_params(
            5, // EBI
            1, // PTI
            EsmCause::RegularDeactivation,
        );

        // Plain: the sender protects it (#497).
        assert_eq!(msg.len(), 4);
        let esm_start = 0;
        assert_eq!(msg[esm_start], 0x52); // octet 1: EBI 5 | PD 2, one octet (TS 24.301 §9.3.1)
        assert_eq!(msg[esm_start + 1], 1); // PTI
        assert_eq!(
            msg[esm_start + 2],
            EsmMessageType::DeactivateEpsBearerContextRequest as u8
        );
        assert_eq!(msg[esm_start + 3], EsmCause::RegularDeactivation as u8);
    }

    #[test]
    fn test_build_bearer_resource_allocation_reject() {
        let msg = build_bearer_resource_allocation_reject(
            3, // PTI
            EsmCause::NetworkFailure,
        );

        let esm_start = 0; // plain: the sender protects it (#497)
        assert_eq!(msg[esm_start], 0x02); // octet 1: EBI 0 | PD 2, one octet (TS 24.301 §9.3.1)
        assert_eq!(msg[esm_start + 1], 3); // PTI
        assert_eq!(
            msg[esm_start + 2],
            EsmMessageType::BearerResourceAllocationReject as u8
        );
        assert_eq!(msg[esm_start + 3], EsmCause::NetworkFailure as u8);
    }

    #[test]
    fn test_build_bearer_resource_modification_reject() {
        let msg = build_bearer_resource_modification_reject(
            4, // PTI
            EsmCause::ServiceOptionNotSupported,
        );

        let esm_start = 0; // plain: the sender protects it (#497)
        assert_eq!(msg[esm_start], 0x02); // octet 1: EBI 0 | PD 2, one octet (TS 24.301 §9.3.1)
        assert_eq!(msg[esm_start + 1], 4); // PTI
        assert_eq!(
            msg[esm_start + 2],
            EsmMessageType::BearerResourceModificationReject as u8
        );
        assert_eq!(
            msg[esm_start + 3],
            EsmCause::ServiceOptionNotSupported as u8
        );
    }

    /// Golden bytes derived by hand from TS 24.301 rather than from this
    /// module (#496): octet 1 carries the EPS bearer identity in bits 8-5 and
    /// PD 2 in bits 4-1, then PTI, then the message type (§9.3.1, §8.3.18,
    /// §8.3.12). A builder that wrote EBI and PD as two octets fails these.
    #[test]
    fn esm_messages_match_hand_derived_ts_24_301_octets() {
        // PDN CONNECTIVITY REJECT, plain (in ATTACH REQUEST): EBI 0, PTI 1,
        // type 0xd1, ESM cause #27 = 0x1b.
        let reject = build_pdn_connectivity_reject_with_params(
            1,
            EsmCause::MissingOrUnknownApn,
            CreateAction::InAttachRequest,
        );
        assert_eq!(&reject[..4], &[0x02, 0x01, 0xd1, 0x1b]);

        // DEACTIVATE EPS BEARER CONTEXT REQUEST for EBI 5, PTI 1, cause #36
        // = 0x24. Plain: since #497 no builder writes a security header.
        let deact = build_deactivate_bearer_context_request_with_params(
            5,
            1,
            EsmCause::RegularDeactivation,
        );
        assert_eq!(&deact[..], &[0x52, 0x01, 0xcd, 0x24]);
    }

    /// Cross-decode with nextgcore-nas's independent EPS ESM header codec,
    /// which packs octet 1 per TS 24.301 §9.3.1 (#496).
    #[test]
    fn esm_messages_decode_with_the_independent_eps_header_codec() {
        use bytes::Bytes;
        use nextgcore_nas::eps::EpsNasEsmHeader;

        let deact = build_deactivate_bearer_context_request_with_params(
            5,
            1,
            EsmCause::RegularDeactivation,
        );
        let mut esm = Bytes::copy_from_slice(&deact);
        let hdr = EpsNasEsmHeader::decode(&mut esm).expect("ESM header decodes");
        assert_eq!(hdr.eps_bearer_identity, 5);
        assert_eq!(hdr.protocol_discriminator, NAS_PROTOCOL_DISCRIMINATOR_ESM);
        assert_eq!(hdr.procedure_transaction_identity, 1);
    }
}
