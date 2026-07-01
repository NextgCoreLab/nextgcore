//! GMM Message Building
//!
//! Port of src/amf/gmm-build.c - GMM message building functions for 5G NAS

use crate::context::{AmfUe, Guti5gs, NEXTGCORE_AUTN_LEN};
use bytes::{BufMut, BytesMut};
// nas-06: the conformant 5GMM encoder library. amfd is migrating its hand-rolled
// builders onto nextgcore-nas message-by-message (Phase 1 = the cause-only builders).
use nextgcore_nas::common::types as nextgcore_types;
use nextgcore_nas::fiveg::ie::{FiveGsIdentityType, Nssai, PduSessionStatus};
use nextgcore_nas::fiveg::message as nextgcore_msg;
use nextgcore_nas::fiveg::types as nextgcore_ftypes;

// ============================================================================
// Constants
// ============================================================================

/// Extended protocol discriminator for 5GMM
pub const NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM: u8 = 0x7e;
/// Extended protocol discriminator for 5GSM
pub const NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM: u8 = 0x2e;

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
            .put_u8(NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
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
    // nas-06 Phase 2 (Tier C, REGISTRATION-CRITICAL): encoded via nextgcore-nas. Byte-
    // identical to the prior hand-rolled output — 5GS registration result LV
    // [01, access&7]; 5G-GUTI (0x77 TLV-E) when a next-GUTI is assigned; single-TAI
    // partial list type-00 (0x54 TLV); Allowed NSSAI (0x15 TLV, omitted when empty);
    // T3512 = 9 minutes (GPRS timer 3, 0x49). Locked by
    // `drift_registration_accept_minimal_through_nextgcore_nas` (reg-result+TAI+T3512) and
    // `golden_registration_accept_full` (GUTI + multi-S-NSSAI branches, derived from
    // the still-present encode_guti/encode_tai_list/encode_nssai_value helpers).
    debug_assert!(
        matches!(amf_ue.access_type & 0x07, 1..=3),
        "5GS registration result access type must be 1/2/3"
    );
    let registration_result = nextgcore_ftypes::RegistrationResult {
        sms_allowed: false,
        value: match amf_ue.access_type & 0x07 {
            2 => nextgcore_ftypes::RegistrationResultValue::Non3gppAccess,
            3 => nextgcore_ftypes::RegistrationResultValue::ThreeGppAndNon3gppAccess,
            _ => nextgcore_ftypes::RegistrationResultValue::ThreeGppAccess,
        },
    };

    // 5G-GUTI (optional, IEI 0x77 TLV-E) — only when a next-GUTI has been assigned.
    let guti = if amf_ue.next_guti.tmsi != 0 {
        let g = &amf_ue.next_guti;
        Some(nextgcore_ftypes::MobileIdentity::FiveGGuti(
            nextgcore_ftypes::FiveGGuti {
                plmn_id: to_nextgcore_plmn(&g.plmn_id),
                amf_region_id: g.amf_region_id,
                amf_set_id: g.amf_set_id,
                amf_pointer: g.amf_pointer,
                tmsi: g.tmsi,
            },
        ))
    } else {
        None
    };

    // TAI list (single TAI, list type 00 = one PLMN). The nextgcore-nas encoder backfills
    // the length octet; one TAC -> num-elements field 0, matching encode_tai_list.
    let tai = &amf_ue.nr_tai;
    let tai_list = Some(nextgcore_ftypes::TaiList {
        length: 0,
        elements: vec![nextgcore_ftypes::TaiListElement::PartialTaiList0 {
            plmn_id: to_nextgcore_plmn(&tai.plmn_id),
            tacs: vec![[(tai.tac >> 16) as u8, (tai.tac >> 8) as u8, tai.tac as u8]],
        }],
    });

    // Allowed NSSAI (allowed if present, else requested); omitted when empty.
    let nssai_source: &[crate::context::SNssai] = if !amf_ue.allowed_nssai.is_empty() {
        &amf_ue.allowed_nssai
    } else {
        &amf_ue.requested_nssai
    };
    let allowed_nssai = if nssai_source.is_empty() {
        None
    } else {
        Some(Nssai {
            length: 0,
            s_nssai_list: nssai_source
                .iter()
                .map(|s| match s.sd {
                    Some(sd) => nextgcore_types::SNssai::with_sd(
                        s.sst,
                        [(sd >> 16) as u8, (sd >> 8) as u8, sd as u8],
                    ),
                    None => nextgcore_types::SNssai::new(s.sst),
                })
                .collect(),
        })
    };

    // T3512 value (IEI 0x5E): 9 minutes — unit 010 (multiples of 1 minute), value 9.
    let t3512_value = Some(nextgcore_types::GprsTimer3::new(2, 9));

    let msg =
        nextgcore_msg::FiveGmmMessage::RegistrationAccept(nextgcore_msg::RegistrationAccept {
            registration_result,
            presencemask: 0,
            guti,
            equivalent_plmns: None,
            tai_list,
            allowed_nssai,
            rejected_nssai: None,
            pdu_session_status: None,
            t3512_value,
            t3502_value: None,
        });
    Some(nextgcore_msg::build_5gmm_message(&msg).to_vec())
}

/// Convert amfd's nibble-encoded PLMN into the nextgcore-nas digit-array `PlmnId` so the
/// two encoders emit identical bytes. amfd marks a 2-digit MNC with `mnc3 == 0xf`;
/// nextgcore-nas derives the 0xF filler from `mnc_len == 2`, so the two agree byte-for-byte.
fn to_nextgcore_plmn(p: &crate::context::PlmnId) -> nextgcore_types::PlmnId {
    let mnc_len = if p.mnc3 == 0x0f { 2 } else { 3 };
    nextgcore_types::PlmnId::new([p.mcc1, p.mcc2, p.mcc3], [p.mnc1, p.mnc2, p.mnc3], mnc_len)
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

/// Build Registration Reject message (TS 24.501 Section 8.2.8).
///
/// nas-06 Phase 1: encoded via the conformant `nextgcore-nas` library. Byte-identical
/// to the previous hand-rolled output (plain header + mandatory 5GMM cause; the
/// optional T3346/T3502/EAP IEs are not emitted by amfd). Locked by
/// `drift_registration_reject_through_nextgcore_nas` and `golden_registration_reject`.
pub fn build_registration_reject(gmm_cause: GmmCause) -> Vec<u8> {
    let msg =
        nextgcore_msg::FiveGmmMessage::RegistrationReject(nextgcore_msg::RegistrationReject {
            gmm_cause: gmm_cause as u8,
            ..Default::default()
        });
    nextgcore_msg::build_5gmm_message(&msg).to_vec()
}

/// Build Security Mode Reject message (TS 24.501 Section 8.2.27).
///
/// Sent as a plain NAS message when the AMF aborts the security-mode procedure,
/// e.g. on detection of a UE-security-capabilities mismatch / bidding-down
/// attack (TS 33.501 Section 6.7.2 → 5GMM cause #23).
pub fn build_security_mode_reject(gmm_cause: GmmCause) -> Vec<u8> {
    // nas-06 Phase 1: encoded via nextgcore-nas (plain header + mandatory 5GMM cause).
    // Byte-identical to the prior hand-rolled output; locked by
    // `drift_security_mode_reject_through_nextgcore_nas` + `golden_security_mode_reject`.
    let msg =
        nextgcore_msg::FiveGmmMessage::SecurityModeReject(nextgcore_msg::SecurityModeReject {
            gmm_cause: gmm_cause as u8,
        });
    nextgcore_msg::build_5gmm_message(&msg).to_vec()
}

/// Build Service Accept message (plain inner; wrap with nas_5gs_security_encode).
///
/// nas-06 Phase 2 (Tier C): encoded via nextgcore-nas. Byte-identical to the prior hand-
/// rolled output — bare header, plus the optional PDU session status (0x50, LV: len
/// 2 + the rotate_right(8)-swapped PSI bitmap). Locked by `golden_service_accept`.
pub fn build_service_accept(amf_ue: &AmfUe) -> Option<Vec<u8>> {
    let msg = nextgcore_msg::FiveGmmMessage::ServiceAccept(nextgcore_msg::ServiceAccept {
        pdu_session_status: pdu_session_status_ie(amf_ue),
        pdu_session_reactivation_result: None,
        eap_message: None,
        t3448_value: None,
    });
    Some(nextgcore_msg::build_5gmm_message(&msg).to_vec())
}

/// Build Service Reject message (TS 24.501 Section 8.2.18).
///
/// nas-06 Phase 2 (Tier C): encoded via nextgcore-nas. Byte-identical to the prior hand-
/// rolled output — mandatory 5GMM cause, then the optional PDU session status
/// (0x50). Locked by `golden_service_reject`.
pub fn build_service_reject(amf_ue: &AmfUe, gmm_cause: GmmCause) -> Vec<u8> {
    let msg = nextgcore_msg::FiveGmmMessage::ServiceReject(nextgcore_msg::ServiceReject {
        gmm_cause: gmm_cause as u8,
        pdu_session_status: pdu_session_status_ie(amf_ue),
        t3346_value: None,
        eap_message: None,
    });
    nextgcore_msg::build_5gmm_message(&msg).to_vec()
}

/// The optional PDU-session-status IE (0x50) shared by Service Accept/Reject:
/// present only when the UE has session status to report, carrying the
/// rotate_right(8)-swapped PSI bitmap verbatim (the nextgcore-nas encoder writes the
/// fixed length octet 2 and the u16 with no further byte-swap).
fn pdu_session_status_ie(amf_ue: &AmfUe) -> Option<PduSessionStatus> {
    if amf_ue.pdu_session_status_present {
        Some(PduSessionStatus {
            length: 2,
            psi: get_pdu_session_status(amf_ue),
        })
    } else {
        None
    }
}

/// Build Deregistration Accept message (UE-initiated; plain inner).
///
/// nas-06 Phase 2 (Tier D): encoded via nextgcore-nas. The UE-initiated Deregistration
/// Accept has no body, so this is the bare plain header — byte-identical to the
/// prior hand-rolled output. Locked by `golden_deregistration_accept`.
pub fn build_deregistration_accept(_amf_ue: &AmfUe) -> Option<Vec<u8>> {
    let msg = nextgcore_msg::FiveGmmMessage::DeregistrationAcceptFromUe;
    Some(nextgcore_msg::build_5gmm_message(&msg).to_vec())
}

/// Build Deregistration Request message (network-initiated; plain inner,
/// TS 24.501 Section 8.2.11; wrap with nas_5gs_security_encode).
///
/// nas-06: NOT migrated to nextgcore-nas (deferred). amfd writes the de-registration
/// type as a bare 0x00 (non-re-reg) / 0x01 (re-reg) byte — its own non-conformant
/// convention (re-reg flag placed in bit 0 rather than the spec's bit 3, switch-off
/// bit never set, access-type sub-field left 0). nextgcore-nas `DeRegistrationType` packs
/// a real `AccessType` whose minimum value is 1, so it cannot represent the 0x00
/// access-type sub-field; an amfd-built non-re-reg request does not round-trip
/// byte-equal through nextgcore-nas (0x00 -> 0x01). Locked by
/// `drift_deregistration_request_divergence_locked`; migrate once amfd adopts the
/// conformant de-reg-type bit layout (or nextgcore-nas gains a raw-byte escape).
pub fn build_deregistration_request(
    _amf_ue: &AmfUe,
    dereg_reason: DeregistrationReason,
    gmm_cause: Option<GmmCause>,
) -> Option<Vec<u8>> {
    let mut builder = NasMessageBuilder::new();

    // GMM header (plain inner message)
    builder.write_epd(NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
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
    // nas-06 Phase 2 (Tier A): encoded via nextgcore-nas (plain header + mandatory
    // type-of-identity V field, low 3 bits). Byte-identical to the prior hand-
    // rolled output for every valid identity type; locked by
    // `drift_identity_request_through_nextgcore_nas` + `golden_identity_request`.
    // Identity type 0 ("no identity") is invalid in an Identity Request (callers
    // pass SUCI/IMEISV); nextgcore-nas floors it to SUCI, so guard it in debug builds.
    debug_assert!(
        identity_type & 0x07 != 0,
        "Identity Request with identity type 0 (no identity) is invalid"
    );
    let msg = nextgcore_msg::FiveGmmMessage::IdentityRequest(nextgcore_msg::IdentityRequest {
        identity_type: FiveGsIdentityType::from(identity_type),
    });
    nextgcore_msg::build_5gmm_message(&msg).to_vec()
}

/// Build Authentication Request message (TS 24.501 Section 8.2.1).
///
/// nas-06 Phase 2 (Tier B, LIVE 5G-AKA path): encoded via nextgcore-nas. Byte-identical
/// to the prior hand-rolled output — ngKSI half-octet (TS 24.501 9.11.3.32: bit 4
/// = TSC, bits 1-3 = key set id), mandatory ABBA (LV), RAND (type-3 TV, IEI 0x21,
/// no length octet), AUTN (TLV, IEI 0x20). AUTN is the fixed 128-bit field, always
/// 16 octets per TS 33.501 — nextgcore-nas hard-codes the length octet to 16, matching
/// amfd's `autn.len()` for every real input (guarded by debug_assert). Locked by
/// `drift_authentication_request_through_nextgcore_nas` + `golden_authentication_request`.
pub fn build_authentication_request(amf_ue: &AmfUe) -> Vec<u8> {
    debug_assert_eq!(
        amf_ue.autn.len(),
        NEXTGCORE_AUTN_LEN,
        "AUTN must be 16 octets (TS 33.501) for a conformant Authentication Request"
    );
    let mut autn = [0u8; NEXTGCORE_AUTN_LEN];
    let n = amf_ue.autn.len().min(NEXTGCORE_AUTN_LEN);
    autn[..n].copy_from_slice(&amf_ue.autn[..n]);

    let msg = nextgcore_msg::FiveGmmMessage::AuthenticationRequest(
        nextgcore_msg::AuthenticationRequest {
            ngksi: nextgcore_types::KeySetIdentifier::new(amf_ue.nas_tsc, amf_ue.nas_ksi),
            abba: nextgcore_types::Abba::new(amf_ue.abba[..amf_ue.abba_len as usize].to_vec()),
            rand: Some(amf_ue.rand),
            autn: Some(autn),
            eap_message: None,
        },
    );
    nextgcore_msg::build_5gmm_message(&msg).to_vec()
}

/// Build Authentication Reject message (TS 24.501 Section 8.2.4).
///
/// nas-06 Phase 1: encoded via nextgcore-nas. amfd never carries the optional EAP
/// message IE, so the output is the bare plain header — byte-identical to the
/// prior hand-rolled output. Locked by `drift_authentication_reject_through_nextgcore_nas`
/// + `golden_authentication_reject`.
pub fn build_authentication_reject() -> Vec<u8> {
    let msg =
        nextgcore_msg::FiveGmmMessage::AuthenticationReject(nextgcore_msg::AuthenticationReject {
            eap_message: None,
        });
    nextgcore_msg::build_5gmm_message(&msg).to_vec()
}

/// Build Security Mode Command message (TS 24.501 Section 8.2.25)
///
/// Plain inner message; callers MUST wrap it with
/// `nas_5gs_security_encode(.., INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT)`.
/// Replays the UE security capability exactly as received in the
/// Registration Request (anti-bidding-down, TS 33.501 Section 6.7.2).
pub fn build_security_mode_command(amf_ue: &AmfUe) -> Option<Vec<u8>> {
    // nas-06 Phase 2 (Tier B, LIVE registration/security-mode path): encoded via
    // nextgcore-nas. Byte-identical to the prior hand-rolled output:
    //   - Selected NAS security algorithms (9.11.3.34: bits 8-5 ciphering, 4-1 integrity)
    //   - ngKSI (bit 4 = TSC, bits 1-3 = key set id)
    //   - Replayed UE security capabilities (LV): 2 octets, OR 4 when EPS algorithms
    //     are present — replicating amfd's exact `eea != 0 || eia != 0` conditional.
    //   - IMEISV request (type-1 TV, IEI 0xE, value 1 -> 0xE1)
    //   - Additional 5G security information (TLV, IEI 0x36, "retransmission requested")
    // ABBA is intentionally not carried (matches the prior encoder). Locked by
    // `drift_security_mode_command_through_nextgcore_nas` + `golden_security_mode_command`
    // (the golden covers BOTH the 2- and 4-octet UE-sec-cap branches).
    let cap = &amf_ue.ue_security_capability;
    let replayed = if cap.eea != 0 || cap.eia != 0 {
        nextgcore_types::UeSecurityCapability::with_eps(cap.ea, cap.ia, cap.eea, cap.eia)
    } else {
        nextgcore_types::UeSecurityCapability::new(cap.ea, cap.ia)
    };

    let msg =
        nextgcore_msg::FiveGmmMessage::SecurityModeCommand(nextgcore_msg::SecurityModeCommand {
            selected_nas_security_algorithms: nextgcore_types::SecurityAlgorithms::new(
                amf_ue.selected_enc_algorithm,
                amf_ue.selected_int_algorithm,
            ),
            ngksi: nextgcore_types::KeySetIdentifier::new(amf_ue.nas_tsc, amf_ue.nas_ksi),
            replayed_ue_security_capabilities: replayed,
            imeisv_request: Some(1),
            selected_eps_nas_security_algorithms: None,
            additional_5g_security_information: Some(1),
            eap_message: None,
            abba: None,
            replayed_s1_ue_security_capabilities: None,
        });
    Some(nextgcore_msg::build_5gmm_message(&msg).to_vec())
}

/// Build Configuration Update Command message
pub fn build_configuration_update_command(
    amf_ue: &AmfUe,
    param: &ConfigurationUpdateCommandParam,
) -> Option<Vec<u8>> {
    // nas-06 Phase 2 (Tier D): encoded via nextgcore-nas. Byte-identical to the prior
    // hand-rolled output — optional configuration update indication (type-1 TV,
    // IEI 0xD: bit 1 = ack, bit 2 = registration) and optional 5G-GUTI (0x77 TLV-E,
    // reusing to_nextgcore_plmn). amfd carries no other configuration IE (NITZ is a
    // future TODO and was never emitted). Locked by golden_configuration_update_command.
    let configuration_update_indication =
        if param.registration_requested || param.acknowledgement_requested {
            let mut ind = 0u8;
            if param.acknowledgement_requested {
                ind |= 0x01;
            }
            if param.registration_requested {
                ind |= 0x02;
            }
            Some(ind)
        } else {
            None
        };

    let guti = if param.guti && amf_ue.next_guti.tmsi != 0 {
        let g = &amf_ue.next_guti;
        Some(nextgcore_ftypes::MobileIdentity::FiveGGuti(
            nextgcore_ftypes::FiveGGuti {
                plmn_id: to_nextgcore_plmn(&g.plmn_id),
                amf_region_id: g.amf_region_id,
                amf_set_id: g.amf_set_id,
                amf_pointer: g.amf_pointer,
                tmsi: g.tmsi,
            },
        ))
    } else {
        None
    };

    let msg = nextgcore_msg::FiveGmmMessage::ConfigurationUpdateCommand(
        nextgcore_msg::ConfigurationUpdateCommand {
            configuration_update_indication,
            guti,
            tai_list: None,
            allowed_nssai: None,
            service_area_list: None,
            full_name_for_network: None,
            short_name_for_network: None,
            local_time_zone: None,
            universal_time_and_local_time_zone: None,
            network_daylight_saving_time: None,
            ladn_information: None,
            configured_nssai: None,
            rejected_nssai: None,
        },
    );
    Some(nextgcore_msg::build_5gmm_message(&msg).to_vec())
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
    builder.write_epd(NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
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

/// Build 5GMM Status message (plain inner; wrap with nas_5gs_security_encode).
///
/// nas-06 Phase 1: encoded via nextgcore-nas (plain header + mandatory 5GMM cause).
/// Byte-identical to the prior hand-rolled output; locked by
/// `drift_gmm_status_through_nextgcore_nas` + `golden_gmm_status`.
pub fn build_gmm_status(gmm_cause: GmmCause) -> Option<Vec<u8>> {
    let msg = nextgcore_msg::FiveGmmMessage::FiveGmmStatus(nextgcore_msg::FiveGmmStatus {
        gmm_cause: gmm_cause as u8,
    });
    Some(nextgcore_msg::build_5gmm_message(&msg).to_vec())
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
    use crate::context::{PlmnId, NEXTGCORE_RAND_LEN};

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
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        assert_eq!(msg[1], 0x00); // Plain NAS
        assert_eq!(msg[2], message_type::REGISTRATION_REJECT);
        assert_eq!(msg[3], GmmCause::IllegalUe as u8);
    }

    #[test]
    fn test_build_identity_request() {
        let msg = build_identity_request(mobile_identity_type::SUCI);

        assert!(!msg.is_empty());
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
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
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        assert_eq!(msg[1], 0x00); // Plain NAS
        assert_eq!(msg[2], message_type::AUTHENTICATION_REJECT);
    }

    #[test]
    fn test_build_authentication_request() {
        let amf_ue = create_test_amf_ue();
        let msg = build_authentication_request(&amf_ue);

        assert!(!msg.is_empty());
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
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
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
    }

    // ------------------------------------------------------------------
    // nas-06 Phase 0: cross-stack drift bridge (amfd <-> nextgcore-nas)
    //
    // amfd hand-rolls its 5GMM encoders; nextgcore-nas is the conformant library
    // but is not yet on the runtime path. These tests lock the two stacks
    // together until convergence completes: every byte-compatible amfd-built
    // message must (a) parse through nextgcore-nas and (b) re-encode byte-for-byte
    // identically. Any divergence fails CI — the intent of the "land first"
    // safety net. (DL NAS Transport and the non-3GPP bearer case diverge and
    // are tracked separately; they are NOT asserted green here.)
    // ------------------------------------------------------------------

    /// Assert amfd-built plain 5GMM bytes parse via nextgcore-nas and re-encode
    /// byte-identically.
    fn assert_drift_roundtrip(amfd_bytes: &[u8], label: &str) {
        use nextgcore_nas::fiveg::message::{build_5gmm_message, parse_5gmm_message};
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(amfd_bytes))
            .unwrap_or_else(|e| panic!("nextgcore-nas must parse amfd {label}: {e:?}"));
        let re = build_5gmm_message(&parsed);
        assert_eq!(
            &re[..],
            amfd_bytes,
            "amfd {label} must round-trip byte-equal through nextgcore-nas"
        );
    }

    #[test]
    fn drift_authentication_reject_through_nextgcore_nas() {
        use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_authentication_reject();
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::AuthenticationReject(_)));
        assert_drift_roundtrip(&amfd, "AuthenticationReject");
    }

    #[test]
    fn drift_registration_reject_through_nextgcore_nas() {
        use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_registration_reject(GmmCause::PlmnNotAllowed);
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::RegistrationReject(_)));
        assert_drift_roundtrip(&amfd, "RegistrationReject");
    }

    #[test]
    fn drift_security_mode_reject_through_nextgcore_nas() {
        use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_security_mode_reject(GmmCause::PlmnNotAllowed);
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::SecurityModeReject(_)));
        assert_drift_roundtrip(&amfd, "SecurityModeReject");
    }

    #[test]
    fn drift_gmm_status_through_nextgcore_nas() {
        use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_gmm_status(GmmCause::PlmnNotAllowed).unwrap();
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::FiveGmmStatus(_)));
        assert_drift_roundtrip(&amfd, "FiveGmmStatus");
    }

    #[test]
    fn drift_identity_request_through_nextgcore_nas() {
        use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_identity_request(mobile_identity_type::SUCI);
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::IdentityRequest(_)));
        assert_drift_roundtrip(&amfd, "IdentityRequest");
    }

    #[test]
    fn drift_authentication_request_through_nextgcore_nas() {
        use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_authentication_request(&create_test_amf_ue());
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::AuthenticationRequest(_)));
        assert_drift_roundtrip(&amfd, "AuthenticationRequest");
    }

    #[test]
    fn drift_security_mode_command_through_nextgcore_nas() {
        use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
        let amfd = build_security_mode_command(&create_test_amf_ue()).unwrap();
        let parsed = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd)).unwrap();
        assert!(matches!(parsed, FiveGmmMessage::SecurityModeCommand(_)));
        assert_drift_roundtrip(&amfd, "SecurityModeCommand");
    }

    /// KNOWN DIVERGENCE LOCK (nas-06): amfd writes the PDU-session-id as a
    /// 2-octet type-3 TV (`12 <psi>`, spec-correct per TS 24.501 §9.11.3.41),
    /// but nextgcore-nas `DlNasTransport` decode/encode treats it as a 3-octet TLV
    /// (`12 01 <psi>`). So an amfd-built DL NAS Transport does NOT yet
    /// round-trip byte-equal through nextgcore-nas. This guard fails the moment the
    /// divergence is fixed (nextgcore-nas `message.rs` ~1411 encode / ~1461 decode,
    /// TLV->TV) — at which point convert it into a positive drift round-trip.
    #[test]
    fn drift_dl_nas_transport_psi_divergence_locked() {
        use nextgcore_nas::fiveg::message::{build_5gmm_message, parse_5gmm_message};
        let payload = [0x2eu8, 0x01, 0x01, 0xc1]; // minimal N1-SM-ish container
        let amfd = build_dl_nas_transport(Some(5), 1, &payload, None, None).unwrap();
        let roundtrips = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd))
            .map(|parsed| build_5gmm_message(&parsed)[..] == amfd[..])
            .unwrap_or(false);
        assert!(
            !roundtrips,
            "DL NAS Transport now round-trips through nextgcore-nas — the PSI TLV/TV \
             divergence is fixed; convert this guard into a byte-equal drift test"
        );
    }

    #[test]
    fn drift_registration_accept_minimal_through_nextgcore_nas() {
        use nextgcore_nas::fiveg::message::{parse_5gmm_message, FiveGmmMessage};
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

    // ------------------------------------------------------------------
    // nas-06 Phase 1: golden wire vectors for the migrated cause-only builders.
    //
    // These pin the EXACT bytes the (now nextgcore-nas-backed) builders emit. They are
    // the pre-migration ground truth — hand-rolled output for these four messages
    // was a plain 3-byte 5GMM header (EPD 0x7E, SHT 0x00, msg-type) followed by the
    // single mandatory 5GMM-cause octet (none for Authentication Reject). The drift
    // tests above already prove nextgcore-nas round-trips amfd's bytes; these guard the
    // absolute wire image so a future nextgcore-nas encoding change cannot silently shift
    // amfd's output without tripping CI.
    // ------------------------------------------------------------------

    #[test]
    fn golden_authentication_reject() {
        // EPD | SHT(plain) | AUTHENTICATION REJECT (0x58); no EAP IE.
        assert_eq!(build_authentication_reject(), vec![0x7e, 0x00, 0x58]);
    }

    #[test]
    fn golden_registration_reject() {
        // EPD | SHT(plain) | REGISTRATION REJECT (0x44) | 5GMM cause.
        assert_eq!(
            build_registration_reject(GmmCause::PlmnNotAllowed),
            vec![0x7e, 0x00, 0x44, 11]
        );
    }

    #[test]
    fn golden_security_mode_reject() {
        // EPD | SHT(plain) | SECURITY MODE REJECT (0x5f) | 5GMM cause.
        assert_eq!(
            build_security_mode_reject(GmmCause::UeSecurityCapabilitiesMismatch),
            vec![0x7e, 0x00, 0x5f, 23]
        );
    }

    #[test]
    fn golden_gmm_status() {
        // EPD | SHT(plain) | 5GMM STATUS (0x64) | 5GMM cause.
        // ProtocolErrorUnspecified is 3GPP cause #111 (0x6f) — distinct from the
        // From<u8> fallback (which maps *unknown* octets like 255 onto this enum).
        assert_eq!(
            build_gmm_status(GmmCause::ProtocolErrorUnspecified),
            Some(vec![0x7e, 0x00, 0x64, 111])
        );
    }

    #[test]
    fn golden_identity_request() {
        // EPD | SHT(plain) | IDENTITY REQUEST (0x5b) | type-of-identity (V, low 3 bits).
        // The two identity types amfd ever requests: SUCI (1) and IMEISV (5).
        assert_eq!(
            build_identity_request(mobile_identity_type::SUCI),
            vec![0x7e, 0x00, 0x5b, 0x01]
        );
        assert_eq!(
            build_identity_request(mobile_identity_type::IMEISV),
            vec![0x7e, 0x00, 0x5b, 0x05]
        );
    }

    #[test]
    fn golden_authentication_request() {
        // Discriminating fixture so a field/IEI/order regression is caught:
        // tsc=1, ksi=3 -> ngksi 0x0b; abba [ab cd]; rand 0xAA*16; autn 0xBB*16.
        let mut ue = create_test_amf_ue();
        ue.nas_tsc = 1;
        ue.nas_ksi = 3;
        ue.abba = [0xab, 0xcd];
        ue.abba_len = 2;
        ue.rand = [0xaa; NEXTGCORE_RAND_LEN];
        ue.autn = vec![0xbb; NEXTGCORE_AUTN_LEN];

        // EPD|SHT|AUTH REQ(0x56) | ngksi | ABBA LV(02 ab cd) | RAND TV(21 + 16) | AUTN TLV(20 10 + 16)
        let mut expected = vec![0x7e, 0x00, 0x56, 0x0b, 0x02, 0xab, 0xcd, 0x21];
        expected.extend_from_slice(&[0xaa; 16]);
        expected.extend_from_slice(&[0x20, 0x10]);
        expected.extend_from_slice(&[0xbb; 16]);
        assert_eq!(build_authentication_request(&ue), expected);
    }

    #[test]
    fn golden_security_mode_command() {
        // 2-octet UE-sec-cap branch (no EPS algorithms): fixture enc=1/int=2 -> 0x12,
        // tsc=0/ksi=1 -> 0x01, ea=ia=0xf0, eea=eia=0.
        let mut ue = create_test_amf_ue();
        ue.ue_security_capability = crate::context::UeSecurityCapability {
            ea: 0xf0,
            ia: 0xf0,
            eea: 0,
            eia: 0,
        };
        // EPD|SHT|SEC MODE CMD(0x5d) | sel-algs | ngksi | UE-cap LV(02 f0 f0) | IMEISV(0xE1) | add-5g(36 01 01)
        assert_eq!(
            build_security_mode_command(&ue),
            Some(vec![
                0x7e, 0x00, 0x5d, 0x12, 0x01, 0x02, 0xf0, 0xf0, 0xe1, 0x36, 0x01, 0x01
            ])
        );

        // 4-octet branch (EPS algorithms present): eea/eia != 0 -> LV grows to 04 f0 f0 0c 0c.
        ue.ue_security_capability.eea = 0x0c;
        ue.ue_security_capability.eia = 0x0c;
        assert_eq!(
            build_security_mode_command(&ue),
            Some(vec![
                0x7e, 0x00, 0x5d, 0x12, 0x01, 0x04, 0xf0, 0xf0, 0x0c, 0x0c, 0xe1, 0x36, 0x01, 0x01
            ])
        );
    }

    #[test]
    fn golden_registration_accept_full() {
        // Exercises the GUTI (0x77 TLV-E) and Allowed-NSSAI (0x15, SD + SST-only)
        // branches that the minimal drift test does NOT cover. The expected wire
        // image is reconstructed from the OLD, still-present byte helpers
        // (encode_guti/encode_tai_list/encode_nssai_value) + the documented IE
        // framing, so this asserts new(nextgcore-nas) == old(hand-rolled) directly.
        let mut ue = create_test_amf_ue();
        ue.access_type = 1; // 3GPP access
        ue.nr_tai = crate::context::Tai5gs {
            plmn_id: crate::context::PlmnId::new("001", "01"),
            tac: 0x010203,
        };
        // next_guti already has tmsi 0x12345678 (!= 0) -> GUTI emitted.
        ue.allowed_nssai = vec![
            crate::context::SNssai {
                sst: 1,
                sd: Some(0x010203),
            },
            crate::context::SNssai { sst: 2, sd: None },
        ];

        let mut expected = vec![0x7e, 0x00, 0x42, 0x01, ue.access_type & 0x07];
        let g = encode_guti(&ue.next_guti); // 0x77 is TLV-E (2-octet length)
        expected.extend_from_slice(&[0x77, (g.len() >> 8) as u8, g.len() as u8]);
        expected.extend_from_slice(&g);
        let t = encode_tai_list(&ue.nr_tai); // 0x54 TLV (1-octet length)
        expected.extend_from_slice(&[0x54, t.len() as u8]);
        expected.extend_from_slice(&t);
        let n = encode_nssai_value(&ue.allowed_nssai); // 0x15 TLV
        expected.extend_from_slice(&[0x15, n.len() as u8]);
        expected.extend_from_slice(&n);
        expected.extend_from_slice(&[0x5e, 0x01, 0x49]); // T3512

        assert_eq!(build_registration_accept(&ue), Some(expected));
    }

    #[test]
    fn golden_registration_accept_no_guti_no_nssai() {
        // Omission path: tmsi == 0 -> no 0x77; empty NSSAI -> no 0x15.
        let mut ue = create_test_amf_ue();
        ue.next_guti.tmsi = 0;
        ue.allowed_nssai.clear();
        ue.requested_nssai.clear();
        ue.nr_tai = crate::context::Tai5gs {
            plmn_id: crate::context::PlmnId::new("001", "01"),
            tac: 0x000001,
        };

        let mut expected = vec![0x7e, 0x00, 0x42, 0x01, ue.access_type & 0x07];
        let t = encode_tai_list(&ue.nr_tai);
        expected.extend_from_slice(&[0x54, t.len() as u8]);
        expected.extend_from_slice(&t);
        expected.extend_from_slice(&[0x5e, 0x01, 0x49]);

        let out = build_registration_accept(&ue).unwrap();
        assert_eq!(out, expected);
        assert!(
            !out.contains(&0x77) || out[5] != 0x77,
            "GUTI must be omitted"
        );
    }

    #[test]
    fn golden_registration_accept_3digit_mnc() {
        // 3-digit MNC (310/260): to_nextgcore_plmn must use mnc_len=3 and the real 3rd
        // digit, NOT the 0xf filler used for 2-digit MNCs. Exercises the GUTI and
        // TAI PLMN bytes on the 3-digit path (analytically proven, now golden-locked
        // via the self-verifying reconstruction from the old nibble helpers).
        let mut ue = create_test_amf_ue();
        ue.access_type = 1;
        ue.nr_tai = crate::context::Tai5gs {
            plmn_id: crate::context::PlmnId::new("310", "260"),
            tac: 0x00abcd,
        };
        ue.next_guti.plmn_id = crate::context::PlmnId::new("310", "260");
        ue.allowed_nssai.clear();
        ue.requested_nssai.clear();

        let mut expected = vec![0x7e, 0x00, 0x42, 0x01, ue.access_type & 0x07];
        let g = encode_guti(&ue.next_guti);
        expected.extend_from_slice(&[0x77, (g.len() >> 8) as u8, g.len() as u8]);
        expected.extend_from_slice(&g);
        let t = encode_tai_list(&ue.nr_tai);
        expected.extend_from_slice(&[0x54, t.len() as u8]);
        expected.extend_from_slice(&t);
        expected.extend_from_slice(&[0x5e, 0x01, 0x49]);

        let out = build_registration_accept(&ue).unwrap();
        assert_eq!(out, expected);
        // Explicitly lock the 3-digit MNC nibble: PLMN byte 1 = (mnc3<<4)|mcc3 with
        // mnc3 = 0 (real digit), mcc3 = 0 -> 0x00, NOT 0xf0. PLMN bytes are 13 00 62
        // (MCC 310, MNC 260) and appear in the TAI element.
        assert!(
            out.windows(3).any(|w| w == [0x13, 0x00, 0x62]),
            "3-digit MNC PLMN must encode 13 00 62 (mnc3 nibble is the real 0, not 0xf)"
        );
    }

    #[test]
    fn golden_service_accept() {
        let mut ue = create_test_amf_ue();
        // PSS absent -> bare header.
        ue.pdu_session_status_present = false;
        assert_eq!(build_service_accept(&ue), Some(vec![0x7e, 0x00, 0x4e]));
        // PSS present, one session PSI=1 -> bitmap 0x0002, byte-swapped (rotate_right
        // 8) to 0x0200. Hard-coded asymmetric expected independently locks the
        // 0x50 / length-2 / big-endian framing (a swap regression would not pass).
        ue.pdu_session_status_present = true;
        ue.sessions = vec![crate::context::AmfSessRef {
            psi: 1,
            sm_context_in_smf: false,
        }];
        assert_eq!(
            build_service_accept(&ue),
            Some(vec![0x7e, 0x00, 0x4e, 0x50, 0x02, 0x02, 0x00])
        );
    }

    #[test]
    fn golden_service_reject() {
        let mut ue = create_test_amf_ue();
        // PSS absent -> header + mandatory 5GMM cause.
        ue.pdu_session_status_present = false;
        assert_eq!(
            build_service_reject(&ue, GmmCause::Congestion),
            vec![0x7e, 0x00, 0x4d, 22]
        );
        // PSS present, one session PSI=1 -> cause + 0x50 LV with swapped 0x0200.
        ue.pdu_session_status_present = true;
        ue.sessions = vec![crate::context::AmfSessRef {
            psi: 1,
            sm_context_in_smf: false,
        }];
        assert_eq!(
            build_service_reject(&ue, GmmCause::Congestion),
            vec![0x7e, 0x00, 0x4d, 22, 0x50, 0x02, 0x02, 0x00]
        );
    }

    #[test]
    fn golden_deregistration_accept() {
        // EPD | SHT(plain) | DEREGISTRATION ACCEPT (from UE) 0x46; no body.
        assert_eq!(
            build_deregistration_accept(&create_test_amf_ue()),
            Some(vec![0x7e, 0x00, 0x46])
        );
    }

    #[test]
    fn golden_configuration_update_command() {
        let ue = create_test_amf_ue(); // next_guti.tmsi != 0

        // No indication, no GUTI -> bare header.
        let none = ConfigurationUpdateCommandParam::default();
        assert_eq!(
            build_configuration_update_command(&ue, &none),
            Some(vec![0x7e, 0x00, 0x54])
        );

        // Registration + ack requested + GUTI -> indication 0xD3 then 0x77 TLV-E.
        // Self-verifies against the still-present encode_guti helper.
        let param = ConfigurationUpdateCommandParam {
            registration_requested: true,
            acknowledgement_requested: true,
            nitz: false,
            guti: true,
        };
        let mut expected = vec![0x7e, 0x00, 0x54, 0xd3];
        let g = encode_guti(&ue.next_guti);
        expected.extend_from_slice(&[0x77, (g.len() >> 8) as u8, g.len() as u8]);
        expected.extend_from_slice(&g);
        assert_eq!(
            build_configuration_update_command(&ue, &param),
            Some(expected)
        );
    }

    /// KNOWN DIVERGENCE LOCK (nas-06 Tier D): amfd encodes the de-registration type
    /// as a bare 0x00 (non-re-reg) byte, but nextgcore-nas `DeRegistrationType` packs a real
    /// `AccessType` whose minimum value is 1, so it cannot represent the 0x00 access-
    /// type sub-field — an amfd-built non-re-reg Deregistration Request does NOT round-
    /// trip byte-equal through nextgcore-nas (0x00 -> 0x01). This guard fails the moment the
    /// divergence is fixed (amfd adopts the conformant de-reg-type bit layout, or
    /// nextgcore-nas gains a raw-byte escape); convert it into a positive drift test then.
    #[test]
    fn drift_deregistration_request_divergence_locked() {
        use nextgcore_nas::fiveg::message::{build_5gmm_message, parse_5gmm_message};
        let amfd = build_deregistration_request(
            &create_test_amf_ue(),
            DeregistrationReason::UeNotSwitchOff, // non-re-reg -> de-reg-type byte 0x00
            None,
        )
        .unwrap();
        let roundtrips = parse_5gmm_message(&mut bytes::Bytes::copy_from_slice(&amfd))
            .map(|parsed| build_5gmm_message(&parsed)[..] == amfd[..])
            .unwrap_or(false);
        assert!(
            !roundtrips,
            "Deregistration Request now round-trips through nextgcore-nas — the de-reg-type \
             0x00 / AccessType divergence is fixed; convert this guard into a byte-equal \
             drift test and migrate build_deregistration_request"
        );
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
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        assert_eq!(msg[2], message_type::SERVICE_REJECT);
        assert_eq!(msg[3], GmmCause::Congestion as u8);
    }

    #[test]
    fn test_build_dl_nas_transport() {
        let payload = vec![0x01, 0x02, 0x03];
        let msg = build_dl_nas_transport(Some(5), 0x01, &payload, None, None);

        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg[0], NEXTGCORE_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
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
