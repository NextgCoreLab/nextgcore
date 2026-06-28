//! GMM Message Building
//!
//! Port of src/amf/gmm-build.c - GMM message building functions for 5G NAS

use crate::context::{AmfUe, Guti5gs};
use bytes::{BufMut, BytesMut};

// ============================================================================
// Constants
// ============================================================================

/// Extended protocol discriminator for 5GMM
pub const OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM: u8 = 0x7e;
/// Extended protocol discriminator for 5GSM
pub const OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM: u8 = 0x2e;

/// Security header types
pub mod security_header {
    pub const PLAIN_NAS_MESSAGE: u8 = 0x00;
    pub const INTEGRITY_PROTECTED: u8 = 0x01;
    pub const INTEGRITY_PROTECTED_AND_CIPHERED: u8 = 0x02;
    pub const INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT: u8 = 0x03;
    pub const INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_5G_NAS_SECURITY_CONTEXT: u8 = 0x04;
}

/// 5GS message types
pub mod message_type {
    pub const REGISTRATION_REQUEST: u8 = 0x41;
    pub const REGISTRATION_ACCEPT: u8 = 0x42;
    pub const REGISTRATION_COMPLETE: u8 = 0x43;
    pub const REGISTRATION_REJECT: u8 = 0x44;
    pub const DEREGISTRATION_REQUEST_FROM_UE: u8 = 0x45;
    pub const DEREGISTRATION_ACCEPT_FROM_UE: u8 = 0x46;
    pub const DEREGISTRATION_REQUEST_TO_UE: u8 = 0x47;
    pub const DEREGISTRATION_ACCEPT_TO_UE: u8 = 0x48;
    pub const SERVICE_REQUEST: u8 = 0x4c;
    pub const SERVICE_REJECT: u8 = 0x4d;
    pub const SERVICE_ACCEPT: u8 = 0x4e;
    pub const CONFIGURATION_UPDATE_COMMAND: u8 = 0x54;
    pub const CONFIGURATION_UPDATE_COMPLETE: u8 = 0x55;
    pub const AUTHENTICATION_REQUEST: u8 = 0x56;
    pub const AUTHENTICATION_RESPONSE: u8 = 0x57;
    pub const AUTHENTICATION_REJECT: u8 = 0x58;
    pub const AUTHENTICATION_FAILURE: u8 = 0x59;
    pub const AUTHENTICATION_RESULT: u8 = 0x5a;
    pub const IDENTITY_REQUEST: u8 = 0x5b;
    pub const IDENTITY_RESPONSE: u8 = 0x5c;
    pub const SECURITY_MODE_COMMAND: u8 = 0x5d;
    pub const SECURITY_MODE_COMPLETE: u8 = 0x5e;
    pub const SECURITY_MODE_REJECT: u8 = 0x5f;
    pub const GMM_STATUS: u8 = 0x64;
    pub const NOTIFICATION: u8 = 0x65;
    pub const NOTIFICATION_RESPONSE: u8 = 0x66;
    pub const UL_NAS_TRANSPORT: u8 = 0x67;
    pub const DL_NAS_TRANSPORT: u8 = 0x68;
    /// UAV tracking report — **sim-private, NOT 3GPP-conformant** (Wave 4,
    /// T4.3 — honest reframe). Per TS 24.501 v18 §8.2.10 / §9.11.3.40 there is
    /// no UE-originated UAV position/tracking NAS message: real-time UAV
    /// tracking / Remote-ID is application-layer (USS/UTM over the user plane),
    /// and network-based UAV location uses LCS (TS 23.273). This unassigned code
    /// carries a sim-only position report for a self-contained geofence demo;
    /// it has no conformant NAS equivalent. (Conformant UAS registration/UUAA
    /// uses the Service-level-AA container, IEI 0x72.) Kept in sync with the
    /// nextgsim UE (`UAV_TRACKING_REPORT_MSG_TYPE`). See
    /// `.context/WAVE6-DOWNGRADED-FEATURES.md` §6.
    pub const UAV_TRACKING_REPORT: u8 = 0x6a;
}

/// 5GMM cause codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GmmCause {
    IllegalUe = 3,
    PeiNotAccepted = 5,
    IllegalMe = 6,
    FiveGsServicesNotAllowed = 7,
    UeIdentityCannotBeDerivedByTheNetwork = 9,
    ImplicitlyDeregistered = 10,
    PlmnNotAllowed = 11,
    TrackingAreaNotAllowed = 12,
    RoamingNotAllowedInThisTrackingArea = 13,
    NoSuitableCellsInTrackingArea = 15,
    MacFailure = 20,
    SynchFailure = 21,
    Congestion = 22,
    UeSecurityCapabilitiesMismatch = 23,
    SecurityModeRejectedUnspecified = 24,
    NonFiveGAuthenticationUnacceptable = 26,
    N1ModeNotAllowed = 27,
    RestrictedServiceArea = 28,
    RedirectionToEpcRequired = 31,
    LaaiNotAllowed = 35,
    NoNetworkSlicesAvailable = 62,
    MaximumNumberOfPduSessionsReached = 65,
    InsufficientResourcesForSpecificSliceAndDnn = 67,
    InsufficientResourcesForSpecificSlice = 69,
    NgksiAlreadyInUse = 71,
    Non3gppAccessTo5gcnNotAllowed = 72,
    ServingNetworkNotAuthorized = 73,
    TemporarilyNotAuthorized = 74,
    PermanentlyNotAuthorized = 75,
    NotAuthorizedForThisCag = 76,
    WirelessanNotAllowed = 77,
    PayloadWasNotForwarded = 90,
    DnnNotSupportedOrNotSubscribedInTheSlice = 91,
    InsufficientUserPlaneResourcesForThePduSession = 92,
    SemanticallyIncorrectMessage = 95,
    InvalidMandatoryInformation = 96,
    MessageTypeNonExistentOrNotImplemented = 97,
    MessageTypeNotCompatibleWithTheProtocolState = 98,
    InformationElementNonExistentOrNotImplemented = 99,
    ConditionalIeError = 100,
    MessageNotCompatibleWithTheProtocolState = 101,
    ProtocolErrorUnspecified = 111,
    RequestAccepted = 0,
}

impl From<u8> for GmmCause {
    fn from(value: u8) -> Self {
        match value {
            3 => GmmCause::IllegalUe,
            5 => GmmCause::PeiNotAccepted,
            6 => GmmCause::IllegalMe,
            7 => GmmCause::FiveGsServicesNotAllowed,
            9 => GmmCause::UeIdentityCannotBeDerivedByTheNetwork,
            10 => GmmCause::ImplicitlyDeregistered,
            11 => GmmCause::PlmnNotAllowed,
            12 => GmmCause::TrackingAreaNotAllowed,
            13 => GmmCause::RoamingNotAllowedInThisTrackingArea,
            15 => GmmCause::NoSuitableCellsInTrackingArea,
            20 => GmmCause::MacFailure,
            21 => GmmCause::SynchFailure,
            22 => GmmCause::Congestion,
            23 => GmmCause::UeSecurityCapabilitiesMismatch,
            24 => GmmCause::SecurityModeRejectedUnspecified,
            26 => GmmCause::NonFiveGAuthenticationUnacceptable,
            27 => GmmCause::N1ModeNotAllowed,
            28 => GmmCause::RestrictedServiceArea,
            31 => GmmCause::RedirectionToEpcRequired,
            35 => GmmCause::LaaiNotAllowed,
            62 => GmmCause::NoNetworkSlicesAvailable,
            65 => GmmCause::MaximumNumberOfPduSessionsReached,
            67 => GmmCause::InsufficientResourcesForSpecificSliceAndDnn,
            69 => GmmCause::InsufficientResourcesForSpecificSlice,
            71 => GmmCause::NgksiAlreadyInUse,
            72 => GmmCause::Non3gppAccessTo5gcnNotAllowed,
            73 => GmmCause::ServingNetworkNotAuthorized,
            74 => GmmCause::TemporarilyNotAuthorized,
            75 => GmmCause::PermanentlyNotAuthorized,
            76 => GmmCause::NotAuthorizedForThisCag,
            77 => GmmCause::WirelessanNotAllowed,
            90 => GmmCause::PayloadWasNotForwarded,
            91 => GmmCause::DnnNotSupportedOrNotSubscribedInTheSlice,
            92 => GmmCause::InsufficientUserPlaneResourcesForThePduSession,
            95 => GmmCause::SemanticallyIncorrectMessage,
            96 => GmmCause::InvalidMandatoryInformation,
            97 => GmmCause::MessageTypeNonExistentOrNotImplemented,
            98 => GmmCause::MessageTypeNotCompatibleWithTheProtocolState,
            99 => GmmCause::InformationElementNonExistentOrNotImplemented,
            100 => GmmCause::ConditionalIeError,
            101 => GmmCause::MessageNotCompatibleWithTheProtocolState,
            111 => GmmCause::ProtocolErrorUnspecified,
            0 => GmmCause::RequestAccepted,
            _ => GmmCause::ProtocolErrorUnspecified,
        }
    }
}

/// Mobile identity types
pub mod mobile_identity_type {
    pub const NO_IDENTITY: u8 = 0;
    pub const SUCI: u8 = 1;
    pub const GUTI: u8 = 2;
    pub const IMEI: u8 = 3;
    pub const S_TMSI: u8 = 4;
    pub const IMEISV: u8 = 5;
    pub const MAC_ADDRESS: u8 = 6;
    pub const EUI64: u8 = 7;
}

/// Registration type values
pub mod registration_type {
    pub const INITIAL: u8 = 1;
    pub const MOBILITY_UPDATING: u8 = 2;
    pub const PERIODIC_UPDATING: u8 = 3;
    pub const EMERGENCY: u8 = 4;
}

/// Deregistration reason
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeregistrationReason {
    UeSwitchOff,
    UeNotSwitchOff,
    ReregistrationRequired,
}

/// Configuration update command parameters
#[derive(Debug, Clone, Default)]
pub struct ConfigurationUpdateCommandParam {
    /// Registration requested
    pub registration_requested: bool,
    /// Acknowledgement requested
    pub acknowledgement_requested: bool,
    /// Include NITZ (Network Identity and Time Zone)
    pub nitz: bool,
    /// Include GUTI
    pub guti: bool,
}

// ============================================================================
// NAS Message Builder
// ============================================================================

/// NAS message builder for 5G GMM messages
#[derive(Debug)]
pub struct NasMessageBuilder {
    buffer: BytesMut,
}

impl NasMessageBuilder {
    /// Create a new NAS message builder
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(1024),
        }
    }

    /// Create a new NAS message builder with security header
    pub fn with_security_header(security_header_type: u8) -> Self {
        let mut builder = Self::new();
        builder
            .buffer
            .put_u8(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        builder.buffer.put_u8(security_header_type);
        builder
    }

    /// Write extended protocol discriminator
    pub fn write_epd(&mut self, epd: u8) -> &mut Self {
        self.buffer.put_u8(epd);
        self
    }

    /// Write message type
    pub fn write_message_type(&mut self, msg_type: u8) -> &mut Self {
        self.buffer.put_u8(msg_type);
        self
    }

    /// Write a single byte
    pub fn write_u8(&mut self, value: u8) -> &mut Self {
        self.buffer.put_u8(value);
        self
    }

    /// Write two bytes (big endian)
    pub fn write_u16(&mut self, value: u16) -> &mut Self {
        self.buffer.put_u16(value);
        self
    }

    /// Write four bytes (big endian)
    pub fn write_u32(&mut self, value: u32) -> &mut Self {
        self.buffer.put_u32(value);
        self
    }

    /// Write bytes
    pub fn write_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.put_slice(data);
        self
    }

    /// Write length-value pair
    pub fn write_lv(&mut self, data: &[u8]) -> &mut Self {
        self.buffer.put_u8(data.len() as u8);
        self.buffer.put_slice(data);
        self
    }

    /// Write type-length-value triplet
    pub fn write_tlv(&mut self, iei: u8, data: &[u8]) -> &mut Self {
        self.buffer.put_u8(iei);
        self.buffer.put_u8(data.len() as u8);
        self.buffer.put_slice(data);
        self
    }

    /// Write type-length-value with 2-byte length
    pub fn write_tlv_e(&mut self, iei: u8, data: &[u8]) -> &mut Self {
        self.buffer.put_u8(iei);
        self.buffer.put_u16(data.len() as u16);
        self.buffer.put_slice(data);
        self
    }

    /// Build the message and return the buffer
    pub fn build(self) -> Vec<u8> {
        self.buffer.to_vec()
    }

    /// Get current buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Default for NasMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GMM Message Building Functions
// ============================================================================

/// Build Registration Accept message (TS 24.501 Section 8.2.7)
///
/// Produces the PLAIN inner NAS message (EPD + plain security header).
/// Callers MUST wrap it with `nas_security::nas_5gs_security_encode`
/// (integrity protected + ciphered) before sending — there is no
/// unprotected Registration Accept path.
///
/// Includes: 5GS registration result (mandatory), 5G-GUTI (0x77),
/// TAI list (0x54), Allowed NSSAI (0x15) and T3512 (0x5E).
pub fn build_registration_accept(amf_ue: &AmfUe) -> Option<Vec<u8>> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain inner message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(security_header::PLAIN_NAS_MESSAGE);
    builder.write_message_type(message_type::REGISTRATION_ACCEPT);

    // 5GS registration result (mandatory, LV): bits 1-3 = access type
    builder.write_u8(1); // length
    builder.write_u8(amf_ue.access_type & 0x07);

    // 5G-GUTI (optional, IEI = 0x77, TLV-E)
    if amf_ue.next_guti.tmsi != 0 {
        let guti_data = encode_guti(&amf_ue.next_guti);
        builder.write_tlv_e(0x77, &guti_data);
    }

    // TAI list (IEI = 0x54, TLV) — registration area assigned to the UE
    let tai_list = encode_tai_list(&amf_ue.nr_tai);
    builder.write_tlv(0x54, &tai_list);

    // Allowed NSSAI (IEI = 0x15, TLV)
    let nssai_source: &[crate::context::SNssai] = if !amf_ue.allowed_nssai.is_empty() {
        &amf_ue.allowed_nssai
    } else {
        &amf_ue.requested_nssai
    };
    let nssai = encode_nssai_value(nssai_source);
    if !nssai.is_empty() {
        builder.write_tlv(0x15, &nssai);
    }

    // T3512 value (IEI = 0x5E, GPRS timer 3 TLV): 9 minutes
    // unit = multiples of 1 minute (010), value = 9 → 0b010_01001
    builder.write_tlv(0x5E, &[0x49]);

    Some(builder.build())
}

/// Encode a single-TAI "TAI list" per TS 24.501 Section 9.11.3.9
/// (list type 00 = one PLMN, non-consecutive TAC values).
pub fn encode_tai_list(tai: &crate::context::Tai5gs) -> Vec<u8> {
    let mut data = Vec::with_capacity(7);
    // Type of list = 00, number of elements = 1 (encoded as 0)
    data.push(0x00);
    // PLMN
    data.push((tai.plmn_id.mcc2 << 4) | tai.plmn_id.mcc1);
    data.push((tai.plmn_id.mnc3 << 4) | tai.plmn_id.mcc3);
    data.push((tai.plmn_id.mnc2 << 4) | tai.plmn_id.mnc1);
    // TAC (24 bits)
    data.push((tai.tac >> 16) as u8);
    data.push((tai.tac >> 8) as u8);
    data.push(tai.tac as u8);
    data
}

/// Encode an NSSAI IE value (list of S-NSSAIs) per TS 24.501 Section 9.11.3.37
pub fn encode_nssai_value(snssais: &[crate::context::SNssai]) -> Vec<u8> {
    let mut data = Vec::new();
    for snssai in snssais {
        match snssai.sd {
            Some(sd) => {
                data.push(4); // length of S-NSSAI contents: SST + SD
                data.push(snssai.sst);
                data.push((sd >> 16) as u8);
                data.push((sd >> 8) as u8);
                data.push(sd as u8);
            }
            None => {
                data.push(1); // SST only
                data.push(snssai.sst);
            }
        }
    }
    data
}

/// Build Registration Reject message
pub fn build_registration_reject(gmm_cause: GmmCause) -> Vec<u8> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain NAS message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(0); // Security header type (plain)
    builder.write_message_type(message_type::REGISTRATION_REJECT);

    // 5GMM cause (mandatory)
    builder.write_u8(gmm_cause as u8);

    builder.build()
}

/// Build Security Mode Reject message (TS 24.501 Section 8.2.27).
///
/// Sent as a plain NAS message when the AMF aborts the security-mode procedure,
/// e.g. on detection of a UE-security-capabilities mismatch / bidding-down
/// attack (TS 33.501 Section 6.7.2 → 5GMM cause #23).
pub fn build_security_mode_reject(gmm_cause: GmmCause) -> Vec<u8> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain NAS message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(security_header::PLAIN_NAS_MESSAGE);
    builder.write_message_type(message_type::SECURITY_MODE_REJECT);

    // 5GMM cause (mandatory)
    builder.write_u8(gmm_cause as u8);

    builder.build()
}

/// Build Service Accept message (plain inner; wrap with nas_5gs_security_encode)
pub fn build_service_accept(amf_ue: &AmfUe) -> Option<Vec<u8>> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain inner message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(security_header::PLAIN_NAS_MESSAGE);
    builder.write_message_type(message_type::SERVICE_ACCEPT);

    // PDU session status (optional, IEI = 0x50)
    if amf_ue.pdu_session_status_present {
        let psi = get_pdu_session_status(amf_ue);
        builder.write_u8(0x50); // IEI
        builder.write_u8(2); // length
        builder.write_u16(psi);
    }

    Some(builder.build())
}

/// Build Service Reject message
pub fn build_service_reject(amf_ue: &AmfUe, gmm_cause: GmmCause) -> Vec<u8> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain NAS message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(0); // Security header type (plain)
    builder.write_message_type(message_type::SERVICE_REJECT);

    // 5GMM cause (mandatory)
    builder.write_u8(gmm_cause as u8);

    // PDU session status (optional, IEI = 0x50)
    if amf_ue.pdu_session_status_present {
        let psi = get_pdu_session_status(amf_ue);
        builder.write_u8(0x50); // IEI
        builder.write_u8(2); // length
        builder.write_u16(psi);
    }

    builder.build()
}

/// Build Deregistration Accept message (UE-initiated; plain inner)
pub fn build_deregistration_accept(_amf_ue: &AmfUe) -> Option<Vec<u8>> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain inner message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(security_header::PLAIN_NAS_MESSAGE);
    builder.write_message_type(message_type::DEREGISTRATION_ACCEPT_FROM_UE);

    Some(builder.build())
}

/// Build Deregistration Request message (network-initiated; plain inner,
/// TS 24.501 Section 8.2.11; wrap with nas_5gs_security_encode)
pub fn build_deregistration_request(
    _amf_ue: &AmfUe,
    dereg_reason: DeregistrationReason,
    gmm_cause: Option<GmmCause>,
) -> Option<Vec<u8>> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain inner message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(security_header::PLAIN_NAS_MESSAGE);
    builder.write_message_type(message_type::DEREGISTRATION_REQUEST_TO_UE);

    // De-registration type
    let re_registration_required =
        matches!(dereg_reason, DeregistrationReason::ReregistrationRequired);
    let dereg_type = if re_registration_required { 0x01 } else { 0x00 };
    builder.write_u8(dereg_type);

    // 5GMM cause (optional, IEI = 0x58)
    if let Some(cause) = gmm_cause {
        builder.write_u8(0x58); // IEI
        builder.write_u8(cause as u8);
    }

    Some(builder.build())
}

/// Build Identity Request message (TS 24.501 Section 8.2.21)
///
/// `identity_type` is one of `mobile_identity_type::*` (SUCI for the
/// subscription identity before authentication, IMEI/IMEISV for PEI).
pub fn build_identity_request(identity_type: u8) -> Vec<u8> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain NAS message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(0); // Security header type (plain)
    builder.write_message_type(message_type::IDENTITY_REQUEST);

    // Identity type (mandatory, V)
    builder.write_u8(identity_type & 0x07);

    builder.build()
}

/// Build Authentication Request message
pub fn build_authentication_request(amf_ue: &AmfUe) -> Vec<u8> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain NAS message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(0); // Security header type (plain)
    builder.write_message_type(message_type::AUTHENTICATION_REQUEST);

    // ngKSI (TS 24.501 9.11.3.32: bit 4 = TSC, bits 1-3 = key set id;
    // spare half octet in bits 5-8)
    let ngksi = ((amf_ue.nas_tsc & 0x01) << 3) | (amf_ue.nas_ksi & 0x07);
    builder.write_u8(ngksi);

    // ABBA (mandatory)
    builder.write_lv(&amf_ue.abba[..amf_ue.abba_len as usize]);

    // Authentication parameter RAND (optional, IEI = 0x21)
    builder.write_u8(0x21); // IEI
    builder.write_bytes(&amf_ue.rand);

    // Authentication parameter AUTN (optional, IEI = 0x20)
    builder.write_u8(0x20); // IEI
    builder.write_u8(amf_ue.autn.len() as u8);
    builder.write_bytes(&amf_ue.autn);

    builder.build()
}

/// Build Authentication Reject message
pub fn build_authentication_reject() -> Vec<u8> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain NAS message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(0); // Security header type (plain)
    builder.write_message_type(message_type::AUTHENTICATION_REJECT);

    builder.build()
}

/// Build Security Mode Command message (TS 24.501 Section 8.2.25)
///
/// Plain inner message; callers MUST wrap it with
/// `nas_5gs_security_encode(.., INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT)`.
/// Replays the UE security capability exactly as received in the
/// Registration Request (anti-bidding-down, TS 33.501 Section 6.7.2).
pub fn build_security_mode_command(amf_ue: &AmfUe) -> Option<Vec<u8>> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain inner message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(security_header::PLAIN_NAS_MESSAGE);
    builder.write_message_type(message_type::SECURITY_MODE_COMMAND);

    // Selected NAS security algorithms (TS 24.501 9.11.3.34:
    // bits 8-5 = type of ciphering algorithm, bits 4-1 = type of integrity)
    let security_algorithms =
        ((amf_ue.selected_enc_algorithm & 0x0f) << 4) | (amf_ue.selected_int_algorithm & 0x0f);
    builder.write_u8(security_algorithms);

    // ngKSI (bit 4 = TSC, bits 1-3 = key set id)
    let ngksi = ((amf_ue.nas_tsc & 0x01) << 3) | (amf_ue.nas_ksi & 0x07);
    builder.write_u8(ngksi);

    // Replayed UE security capabilities
    let mut ue_sec_cap = vec![
        amf_ue.ue_security_capability.ea,
        amf_ue.ue_security_capability.ia,
    ];
    if amf_ue.ue_security_capability.eea != 0 || amf_ue.ue_security_capability.eia != 0 {
        ue_sec_cap.push(amf_ue.ue_security_capability.eea);
        ue_sec_cap.push(amf_ue.ue_security_capability.eia);
    }
    builder.write_lv(&ue_sec_cap);

    // IMEISV request (optional, IEI = 0xE)
    builder.write_u8(0xE1); // IEI (0xE) + IMEISV requested (1)

    // Additional 5G security information (optional, IEI = 0x36)
    builder.write_u8(0x36); // IEI
    builder.write_u8(1); // length
    builder.write_u8(0x01); // Retransmission of initial NAS message requested

    Some(builder.build())
}

/// Build Configuration Update Command message
pub fn build_configuration_update_command(
    amf_ue: &AmfUe,
    param: &ConfigurationUpdateCommandParam,
) -> Option<Vec<u8>> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain inner message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(security_header::PLAIN_NAS_MESSAGE);
    builder.write_message_type(message_type::CONFIGURATION_UPDATE_COMMAND);

    // Configuration update indication (optional, IEI = 0xD)
    if param.registration_requested || param.acknowledgement_requested {
        let mut indication = 0u8;
        if param.acknowledgement_requested {
            indication |= 0x01;
        }
        if param.registration_requested {
            indication |= 0x02;
        }
        builder.write_u8(0xD0 | indication);
    }

    // 5G-GUTI (optional, IEI = 0x77)
    if param.guti && amf_ue.next_guti.tmsi != 0 {
        let guti_data = encode_guti(&amf_ue.next_guti);
        builder.write_tlv_e(0x77, &guti_data);
    }

    // NITZ information would be added here if param.nitz is true

    Some(builder.build())
}

/// Build DL NAS Transport message
pub fn build_dl_nas_transport(
    psi: Option<u8>,
    payload_container_type: u8,
    payload_container: &[u8],
    gmm_cause: Option<GmmCause>,
    backoff_time: Option<u8>,
) -> Option<Vec<u8>> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain inner message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(security_header::PLAIN_NAS_MESSAGE);
    builder.write_message_type(message_type::DL_NAS_TRANSPORT);

    // Payload container type (mandatory)
    builder.write_u8(payload_container_type);

    // Payload container (mandatory, LV-E)
    builder.write_u16(payload_container.len() as u16);
    builder.write_bytes(payload_container);

    // PDU session ID (optional, IEI = 0x12) — only for N1 SM payloads
    if let Some(psi) = psi {
        builder.write_u8(0x12); // IEI
        builder.write_u8(psi);
    }

    // 5GMM cause (optional, IEI = 0x58)
    if let Some(cause) = gmm_cause {
        builder.write_u8(0x58); // IEI
        builder.write_u8(cause as u8);
    }

    // Back-off timer value (optional, IEI = 0x37)
    if let Some(time) = backoff_time {
        if time >= 2 {
            builder.write_u8(0x37); // IEI
            builder.write_u8(1); // length
                                 // Timer unit: multiples of 2 seconds (unit = 0)
            builder.write_u8(time / 2);
        }
    }

    Some(builder.build())
}

/// Build 5GMM Status message (plain inner; wrap with nas_5gs_security_encode)
pub fn build_gmm_status(gmm_cause: GmmCause) -> Option<Vec<u8>> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain inner message)
    builder.write_epd(OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    builder.write_u8(security_header::PLAIN_NAS_MESSAGE);
    builder.write_message_type(message_type::GMM_STATUS);

    // 5GMM cause (mandatory)
    builder.write_u8(gmm_cause as u8);

    Some(builder.build())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode GUTI to bytes
fn encode_guti(guti: &Guti5gs) -> Vec<u8> {
    let mut data = Vec::with_capacity(13);

    // Type of identity (GUTI = 2) in lower 3 bits
    data.push(0xf0 | mobile_identity_type::GUTI);

    // MCC/MNC (3 bytes)
    data.push((guti.plmn_id.mcc2 << 4) | guti.plmn_id.mcc1);
    data.push((guti.plmn_id.mnc3 << 4) | guti.plmn_id.mcc3);
    data.push((guti.plmn_id.mnc2 << 4) | guti.plmn_id.mnc1);

    // AMF Region ID (1 byte)
    data.push(guti.amf_region_id);

    // AMF Set ID (10 bits) + AMF Pointer (6 bits) = 2 bytes
    data.push((guti.amf_set_id >> 2) as u8);
    data.push(((guti.amf_set_id & 0x03) << 6) as u8 | (guti.amf_pointer & 0x3f));

    // 5G-TMSI (4 bytes)
    data.push((guti.tmsi >> 24) as u8);
    data.push((guti.tmsi >> 16) as u8);
    data.push((guti.tmsi >> 8) as u8);
    data.push(guti.tmsi as u8);

    data
}

/// Get PDU session status bitmap
fn get_pdu_session_status(amf_ue: &AmfUe) -> u16 {
    let mut psimask: u16 = 0;

    for sess in &amf_ue.sessions {
        psimask |= 1 << sess.psi;
    }

    // Swap bytes for NAS encoding
    psimask.rotate_right(8)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PlmnId;

    fn create_test_amf_ue() -> AmfUe {
        AmfUe {
            id: 1,
            ran_ue_id: 1,
            access_type: 1,
            nas_tsc: 0,
            nas_ksi: 1,
            selected_enc_algorithm: 1,
            selected_int_algorithm: 2,
            abba: [0x00, 0x00],
            abba_len: 2,
            rand: [0u8; 16],
            autn: vec![0u8; 16],
            ue_security_capability: crate::context::UeSecurityCapability {
                ea: 0xf0,
                ia: 0xf0,
                eea: 0,
                eia: 0,
            },
            next_guti: Guti5gs {
                plmn_id: PlmnId::new("001", "01"),
                amf_region_id: 1,
                amf_set_id: 1,
                amf_pointer: 1,
                tmsi: 0x12345678,
            },
            pdu_session_status_present: false,
            sessions: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn test_nas_message_builder() {
        let mut builder = NasMessageBuilder::new();
        builder.write_u8(0x7e);
        builder.write_u8(0x00);
        builder.write_message_type(0x41);

        let msg = builder.build();
        assert_eq!(msg.len(), 3);
        assert_eq!(msg[0], 0x7e);
        assert_eq!(msg[1], 0x00);
        assert_eq!(msg[2], 0x41);
    }

    #[test]
    fn test_build_registration_reject() {
        let msg = build_registration_reject(GmmCause::IllegalUe);

        assert!(!msg.is_empty());
        assert_eq!(msg[0], OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        assert_eq!(msg[1], 0x00); // Plain NAS
        assert_eq!(msg[2], message_type::REGISTRATION_REJECT);
        assert_eq!(msg[3], GmmCause::IllegalUe as u8);
    }

    #[test]
    fn test_build_identity_request() {
        let msg = build_identity_request(mobile_identity_type::SUCI);

        assert!(!msg.is_empty());
        assert_eq!(msg[0], OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        assert_eq!(msg[1], 0x00); // Plain NAS
        assert_eq!(msg[2], message_type::IDENTITY_REQUEST);
        assert_eq!(msg[3], mobile_identity_type::SUCI);

        let pei_msg = build_identity_request(mobile_identity_type::IMEISV);
        assert_eq!(pei_msg[3], mobile_identity_type::IMEISV);
    }

    #[test]
    fn test_build_authentication_reject() {
        let msg = build_authentication_reject();

        assert!(!msg.is_empty());
        assert_eq!(msg[0], OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        assert_eq!(msg[1], 0x00); // Plain NAS
        assert_eq!(msg[2], message_type::AUTHENTICATION_REJECT);
    }

    #[test]
    fn test_build_authentication_request() {
        let amf_ue = create_test_amf_ue();
        let msg = build_authentication_request(&amf_ue);

        assert!(!msg.is_empty());
        assert_eq!(msg[0], OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        assert_eq!(msg[1], 0x00); // Plain NAS
        assert_eq!(msg[2], message_type::AUTHENTICATION_REQUEST);
    }

    #[test]
    fn test_build_security_mode_command() {
        let amf_ue = create_test_amf_ue();
        let msg = build_security_mode_command(&amf_ue);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(!msg.is_empty());
        // First two bytes are security header
        assert_eq!(msg[0], OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    }

    // ------------------------------------------------------------------
    // nas-06 Phase 0: cross-stack drift bridge (amfd <-> ogs-nas)
    //
    // amfd hand-rolls its 5GMM encoders; ogs-nas is the conformant library
    // but is not yet on the runtime path. These tests lock the two stacks
    // together until convergence completes: every byte-compatible amfd-built
    // message must (a) parse through ogs-nas and (b) re-encode byte-for-byte
    // identically. Any divergence fails CI — the intent of the "land first"
    // safety net. (DL NAS Transport and the non-3GPP bearer case diverge and
    // are tracked separately; they are NOT asserted green here.)
    // ------------------------------------------------------------------

    /// Assert amfd-built plain 5GMM bytes parse via ogs-nas and re-encode
    /// byte-identically.
    fn assert_drift_roundtrip(amfd_bytes: &[u8], label: &str) {
        use ogs_nas::fiveg::message::{build_5gmm_message, parse_5gmm_message};
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(amfd_bytes))
            .unwrap_or_else(|e| panic!("ogs-nas must parse amfd {label}: {e:?}"));
        let re = build_5gmm_message(&parsed);
        assert_eq!(
            &re[..],
            amfd_bytes,
            "amfd {label} must round-trip byte-equal through ogs-nas"
        );
    }

    #[test]
    fn drift_authentication_reject_through_ogs_nas() {
        use ogs_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_authentication_reject();
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::AuthenticationReject(_)));
        assert_drift_roundtrip(&amfd, "AuthenticationReject");
    }

    #[test]
    fn drift_registration_reject_through_ogs_nas() {
        use ogs_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_registration_reject(GmmCause::PlmnNotAllowed);
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::RegistrationReject(_)));
        assert_drift_roundtrip(&amfd, "RegistrationReject");
    }

    #[test]
    fn drift_security_mode_reject_through_ogs_nas() {
        use ogs_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_security_mode_reject(GmmCause::PlmnNotAllowed);
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::SecurityModeReject(_)));
        assert_drift_roundtrip(&amfd, "SecurityModeReject");
    }

    #[test]
    fn drift_gmm_status_through_ogs_nas() {
        use ogs_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_gmm_status(GmmCause::PlmnNotAllowed).unwrap();
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::FiveGmmStatus(_)));
        assert_drift_roundtrip(&amfd, "FiveGmmStatus");
    }

    #[test]
    fn drift_identity_request_through_ogs_nas() {
        use ogs_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_identity_request(mobile_identity_type::SUCI);
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::IdentityRequest(_)));
        assert_drift_roundtrip(&amfd, "IdentityRequest");
    }

    #[test]
    fn drift_authentication_request_through_ogs_nas() {
        use ogs_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_authentication_request(&create_test_amf_ue());
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::AuthenticationRequest(_)));
        assert_drift_roundtrip(&amfd, "AuthenticationRequest");
    }

    #[test]
    fn drift_security_mode_command_through_ogs_nas() {
        use ogs_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_security_mode_command(&create_test_amf_ue()).unwrap();
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::SecurityModeCommand(_)));
        assert_drift_roundtrip(&amfd, "SecurityModeCommand");
    }

    /// KNOWN DIVERGENCE LOCK (nas-06): amfd writes the PDU-session-id as a
    /// 2-octet type-3 TV (`12 <psi>`, spec-correct per TS 24.501 §9.11.3.41),
    /// but ogs-nas `DlNasTransport` decode/encode treats it as a 3-octet TLV
    /// (`12 01 <psi>`). So an amfd-built DL NAS Transport does NOT yet
    /// round-trip byte-equal through ogs-nas. This guard fails the moment the
    /// divergence is fixed (ogs-nas `message.rs` ~1411 encode / ~1461 decode,
    /// TLV->TV) — at which point convert it into a positive drift round-trip.
    #[test]
    fn drift_dl_nas_transport_psi_divergence_locked() {
        use ogs_nas::fiveg::message::{build_5gmm_message, parse_5gmm_message};
        let payload = [0x2eu8, 0x01, 0x01, 0xc1]; // minimal N1-SM-ish container
        let amfd = build_dl_nas_transport(Some(5), 1, &payload, None, None).unwrap();
        let roundtrips = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd))
            .map(|parsed| build_5gmm_message(&parsed)[..] == amfd[..])
            .unwrap_or(false);
        assert!(
            !roundtrips,
            "DL NAS Transport now round-trips through ogs-nas — the PSI TLV/TV \
             divergence is fixed; convert this guard into a byte-equal drift test"
        );
    }

    #[test]
    fn drift_registration_accept_minimal_through_ogs_nas() {
        use ogs_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        // Minimal happy-path Registration Accept: tmsi=0 skips the GUTI IE and
        // the default (empty) NSSAI skips the 0x15 IE, leaving reg-result +
        // TAI list (0x54) + T3512 (0x5E) — the registration-critical core.
        let mut ue = create_test_amf_ue();
        ue.next_guti.tmsi = 0;
        let amfd = build_registration_accept(&ue).unwrap();
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::RegistrationAccept(_)));
        assert_drift_roundtrip(&amfd, "RegistrationAccept(minimal)");
    }

    #[test]
    fn test_build_registration_accept() {
        let amf_ue = create_test_amf_ue();
        let msg = build_registration_accept(&amf_ue);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_build_service_reject() {
        let amf_ue = create_test_amf_ue();
        let msg = build_service_reject(&amf_ue, GmmCause::Congestion);

        assert!(!msg.is_empty());
        assert_eq!(msg[0], OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        assert_eq!(msg[2], message_type::SERVICE_REJECT);
        assert_eq!(msg[3], GmmCause::Congestion as u8);
    }

    #[test]
    fn test_build_dl_nas_transport() {
        let payload = vec![0x01, 0x02, 0x03];
        let msg = build_dl_nas_transport(Some(5), 0x01, &payload, None, None);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg[0], OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        assert_eq!(msg[1], 0x00); // plain inner
        assert_eq!(msg[2], message_type::DL_NAS_TRANSPORT);
        assert_eq!(msg[3], 0x01); // container type
        assert_eq!(msg[4], 0x00); // container len high
        assert_eq!(msg[5], 0x03); // container len low

        // Without PSI (e.g. cause-90 reflection of an SMS container)
        let msg2 = build_dl_nas_transport(
            None,
            0x02,
            &payload,
            Some(GmmCause::PayloadWasNotForwarded),
            None,
        )
        .unwrap();
        // 0x58 cause IEI must be present, no 0x12 PSI IEI
        assert!(msg2.windows(2).any(|w| w == [0x58, 90]));
        assert!(!msg2[6..].starts_with(&[0x12]));
    }

    #[test]
    fn test_build_gmm_status() {
        let msg = build_gmm_status(GmmCause::ProtocolErrorUnspecified);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_encode_guti() {
        let guti = Guti5gs {
            plmn_id: PlmnId::new("001", "01"),
            amf_region_id: 1,
            amf_set_id: 1,
            amf_pointer: 1,
            tmsi: 0x12345678,
        };

        let encoded = encode_guti(&guti);
        assert_eq!(encoded.len(), 11);
        assert_eq!(encoded[0] & 0x07, mobile_identity_type::GUTI);
    }

    #[test]
    fn test_gmm_cause_conversion() {
        assert_eq!(GmmCause::from(3), GmmCause::IllegalUe);
        assert_eq!(GmmCause::from(11), GmmCause::PlmnNotAllowed);
        assert_eq!(GmmCause::from(0), GmmCause::RequestAccepted);
        assert_eq!(GmmCause::from(255), GmmCause::ProtocolErrorUnspecified);
    }
}
