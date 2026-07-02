//! 5GS-specific NAS types
//!
//! Based on 3GPP TS 24.501

use crate::common::types::{PlmnId, Tai};
use crate::error::{NasError, NasResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// 5GMM cause values (TS 24.501 Section 9.11.3.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FiveGmmCause {
    IllegalUe = 3,
    PeiNotAccepted = 5,
    IllegalMe = 6,
    FiveGsServicesNotAllowed = 7,
    UeIdentityCannotBeDerived = 9,
    ImplicitlyDeregistered = 10,
    PlmnNotAllowed = 11,
    TaNotAllowed = 12,
    RoamingNotAllowed = 13,
    NoSuitableCells = 15,
    MacFailure = 20,
    SynchFailure = 21,
    Congestion = 22,
    UeSecurityCapabilitiesMismatch = 23,
    SecurityModeRejected = 24,
    NonFiveGAuthenticationUnacceptable = 26,
    N1ModeNotAllowed = 27,
    RestrictedServiceArea = 28,
    RedirectionToEpc = 31,
    LadnNotAvailable = 43,
    NoNetworkSlicesAvailable = 62,
    MaximumNumberOfPduSessionsReached = 65,
    InsufficientResourcesForSliceAndDnn = 67,
    InsufficientResourcesForSlice = 69,
    NgksiAlreadyInUse = 71,
    Non3gppAccessTo5gcnNotAllowed = 72,
    ServingNetworkNotAuthorized = 73,
    TemporarilyNotAuthorized = 74,
    PermanentlyNotAuthorized = 75,
    NotAuthorizedForThisCag = 76,
    WirelessanNotAllowed = 77,
    PayloadWasNotForwarded = 90,
    DnnNotSupportedOrNotSubscribed = 91,
    InsufficientUserPlaneResources = 92,
    SemanticallyIncorrectMessage = 95,
    InvalidMandatoryInformation = 96,
    MessageTypeNonExistent = 97,
    MessageTypeNotCompatible = 98,
    InformationElementNonExistent = 99,
}

impl TryFrom<u8> for FiveGmmCause {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            3 => Ok(Self::IllegalUe),
            5 => Ok(Self::PeiNotAccepted),
            6 => Ok(Self::IllegalMe),
            7 => Ok(Self::FiveGsServicesNotAllowed),
            9 => Ok(Self::UeIdentityCannotBeDerived),
            10 => Ok(Self::ImplicitlyDeregistered),
            11 => Ok(Self::PlmnNotAllowed),
            12 => Ok(Self::TaNotAllowed),
            13 => Ok(Self::RoamingNotAllowed),
            15 => Ok(Self::NoSuitableCells),
            20 => Ok(Self::MacFailure),
            21 => Ok(Self::SynchFailure),
            22 => Ok(Self::Congestion),
            23 => Ok(Self::UeSecurityCapabilitiesMismatch),
            24 => Ok(Self::SecurityModeRejected),
            26 => Ok(Self::NonFiveGAuthenticationUnacceptable),
            27 => Ok(Self::N1ModeNotAllowed),
            28 => Ok(Self::RestrictedServiceArea),
            31 => Ok(Self::RedirectionToEpc),
            43 => Ok(Self::LadnNotAvailable),
            62 => Ok(Self::NoNetworkSlicesAvailable),
            65 => Ok(Self::MaximumNumberOfPduSessionsReached),
            67 => Ok(Self::InsufficientResourcesForSliceAndDnn),
            69 => Ok(Self::InsufficientResourcesForSlice),
            71 => Ok(Self::NgksiAlreadyInUse),
            72 => Ok(Self::Non3gppAccessTo5gcnNotAllowed),
            73 => Ok(Self::ServingNetworkNotAuthorized),
            74 => Ok(Self::TemporarilyNotAuthorized),
            75 => Ok(Self::PermanentlyNotAuthorized),
            76 => Ok(Self::NotAuthorizedForThisCag),
            77 => Ok(Self::WirelessanNotAllowed),
            90 => Ok(Self::PayloadWasNotForwarded),
            91 => Ok(Self::DnnNotSupportedOrNotSubscribed),
            92 => Ok(Self::InsufficientUserPlaneResources),
            95 => Ok(Self::SemanticallyIncorrectMessage),
            96 => Ok(Self::InvalidMandatoryInformation),
            97 => Ok(Self::MessageTypeNonExistent),
            98 => Ok(Self::MessageTypeNotCompatible),
            99 => Ok(Self::InformationElementNonExistent),
            _ => Err(NasError::DecodingError(format!(
                "Unknown 5GMM cause: {value}"
            ))),
        }
    }
}

/// 5GS registration type (TS 24.501 Section 9.11.3.7)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegistrationType {
    /// Follow-on request pending
    pub follow_on_request: bool,
    /// Registration type value
    pub value: RegistrationTypeValue,
}

/// Registration type values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RegistrationTypeValue {
    #[default]
    InitialRegistration = 1,
    MobilityRegistrationUpdating = 2,
    PeriodicRegistrationUpdating = 3,
    EmergencyRegistration = 4,
    SnpnOnboardingRegistration = 5,
    DisasterRoamingMobilityRegistrationUpdating = 6,
    DisasterRoamingInitialRegistration = 7,
}

impl RegistrationType {
    /// Create a new registration type
    pub fn new(follow_on_request: bool, value: RegistrationTypeValue) -> Self {
        Self {
            follow_on_request,
            value,
        }
    }

    /// Encode to half-byte
    pub fn encode(&self) -> u8 {
        let for_bit = if self.follow_on_request { 0x08 } else { 0 };
        for_bit | (self.value as u8 & 0x07)
    }

    /// Decode from half-byte
    pub fn decode(byte: u8) -> NasResult<Self> {
        let follow_on_request = (byte & 0x08) != 0;
        let value = match byte & 0x07 {
            1 => RegistrationTypeValue::InitialRegistration,
            2 => RegistrationTypeValue::MobilityRegistrationUpdating,
            3 => RegistrationTypeValue::PeriodicRegistrationUpdating,
            4 => RegistrationTypeValue::EmergencyRegistration,
            5 => RegistrationTypeValue::SnpnOnboardingRegistration,
            6 => RegistrationTypeValue::DisasterRoamingMobilityRegistrationUpdating,
            7 => RegistrationTypeValue::DisasterRoamingInitialRegistration,
            v => return Err(NasError::InvalidRegistrationType(v)),
        };
        Ok(Self {
            follow_on_request,
            value,
        })
    }
}

/// 5GS mobile identity type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MobileIdentityType {
    NoIdentity = 0,
    Suci = 1,
    FiveGGuti = 2,
    Imei = 3,
    FiveGSTmsi = 4,
    Imeisv = 5,
    MacAddress = 6,
    Eui64 = 7,
}

impl TryFrom<u8> for MobileIdentityType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoIdentity),
            1 => Ok(Self::Suci),
            2 => Ok(Self::FiveGGuti),
            3 => Ok(Self::Imei),
            4 => Ok(Self::FiveGSTmsi),
            5 => Ok(Self::Imeisv),
            6 => Ok(Self::MacAddress),
            7 => Ok(Self::Eui64),
            _ => Err(NasError::InvalidMobileIdentityType(value)),
        }
    }
}

/// 5GS mobile identity (TS 24.501 Section 9.11.3.4)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum MobileIdentity {
    /// No identity
    #[default]
    NoIdentity,
    /// SUCI (Subscription Concealed Identifier)
    Suci(Suci),
    /// 5G-GUTI
    FiveGGuti(FiveGGuti),
    /// IMEI
    Imei(Imei),
    /// 5G-S-TMSI
    FiveGSTmsi(FiveGSTmsi),
    /// IMEISV
    Imeisv(Imeisv),
}

impl MobileIdentity {
    /// Encode mobile identity to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::NoIdentity => {
                buf.put_u16(1); // Length
                buf.put_u8(MobileIdentityType::NoIdentity as u8);
            }
            Self::Suci(suci) => suci.encode(buf),
            Self::FiveGGuti(guti) => guti.encode(buf),
            Self::Imei(imei) => imei.encode(buf),
            Self::FiveGSTmsi(tmsi) => tmsi.encode(buf),
            Self::Imeisv(imeisv) => imeisv.encode(buf),
        }
    }

    /// Decode mobile identity from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort {
                expected: 3,
                actual: buf.remaining(),
            });
        }

        let length = buf.get_u16() as usize;
        if buf.remaining() < length {
            return Err(NasError::BufferTooShort {
                expected: length,
                actual: buf.remaining(),
            });
        }

        let type_byte = buf.chunk()[0];
        let id_type = MobileIdentityType::try_from(type_byte & 0x07)?;

        match id_type {
            MobileIdentityType::NoIdentity => {
                buf.advance(length);
                Ok(Self::NoIdentity)
            }
            MobileIdentityType::Suci => {
                let suci = Suci::decode_content(buf, length)?;
                Ok(Self::Suci(suci))
            }
            MobileIdentityType::FiveGGuti => {
                let guti = FiveGGuti::decode_content(buf, length)?;
                Ok(Self::FiveGGuti(guti))
            }
            MobileIdentityType::Imei => {
                let imei = Imei::decode_content(buf, length)?;
                Ok(Self::Imei(imei))
            }
            MobileIdentityType::FiveGSTmsi => {
                let tmsi = FiveGSTmsi::decode_content(buf, length)?;
                Ok(Self::FiveGSTmsi(tmsi))
            }
            MobileIdentityType::Imeisv => {
                let imeisv = Imeisv::decode_content(buf, length)?;
                Ok(Self::Imeisv(imeisv))
            }
            _ => Err(NasError::InvalidMobileIdentityType(type_byte & 0x07)),
        }
    }
}

/// SUCI (Subscription Concealed Identifier)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Suci {
    /// SUPI format (0 = IMSI, 1 = NAI)
    pub supi_format: u8,
    /// Home network identifier (PLMN ID for IMSI format)
    pub plmn_id: PlmnId,
    /// Routing indicator
    pub routing_indicator: [u8; 2],
    /// Protection scheme ID
    pub protection_scheme_id: u8,
    /// Home network public key identifier
    pub home_network_pki: u8,
    /// Scheme output. For IMSI SUPI format (`supi_format == 0`) this is the
    /// MSIN / concealed SUPI octets that follow the PKI octet. For the NAI SUPI
    /// format (`supi_format == 1`, TS 24.501 §9.11.3.4 Figure 9.11.3.4.4) this
    /// instead carries the variable-length "SUCI NAI" octets (octet 5..y); the
    /// `plmn_id`, `routing_indicator`, `protection_scheme_id` and
    /// `home_network_pki` fields are not used in that format.
    pub scheme_output: Vec<u8>,
}

impl Suci {
    /// Encode SUCI to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        if self.supi_format == 1 {
            // NAI SUPI format (TS 24.501 §9.11.3.4, Figure 9.11.3.4.4): octet 4
            // is SUPI-format|type-of-identity, octets 5..y are the SUCI NAI
            // string carried in `scheme_output`. No PLMN/RI/scheme/PKI fields.
            let content_len = 1 + self.scheme_output.len();
            buf.put_u16(content_len as u16);
            buf.put_u8((self.supi_format << 4) | MobileIdentityType::Suci as u8);
            buf.put_slice(&self.scheme_output);
            return;
        }
        // IMSI SUPI format (supi_format == 0; any other value is treated as
        // IMSI per TS 24.501 §9.11.3.4) — unchanged on-wire layout.
        let content_len = 1 + 3 + 2 + 1 + 1 + self.scheme_output.len();
        buf.put_u16(content_len as u16);
        buf.put_u8((self.supi_format << 4) | MobileIdentityType::Suci as u8);
        self.plmn_id.encode(buf);
        buf.put_slice(&self.routing_indicator);
        buf.put_u8(self.protection_scheme_id);
        buf.put_u8(self.home_network_pki);
        buf.put_slice(&self.scheme_output);
    }

    /// Decode SUCI content from bytes
    pub fn decode_content(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        // Peek octet 4 (bits 5-7 = SUPI format) without consuming so the
        // IMSI-format path below stays byte-identical to the original decoder.
        let supi_format = if buf.remaining() >= 1 {
            (buf.chunk()[0] >> 4) & 0x07
        } else {
            0
        };
        if supi_format == 1 {
            // NAI SUPI format: type byte (octet 4) + variable SUCI NAI string.
            if length < 1 {
                return Err(NasError::BufferTooShort {
                    expected: 1,
                    actual: length,
                });
            }
            let _first_byte = buf.get_u8();
            let nai_len = length - 1;
            if buf.remaining() < nai_len {
                return Err(NasError::BufferTooShort {
                    expected: nai_len,
                    actual: buf.remaining(),
                });
            }
            let scheme_output = buf.copy_to_bytes(nai_len).to_vec();
            return Ok(Self {
                supi_format,
                scheme_output,
                ..Default::default()
            });
        }

        if length < 8 {
            return Err(NasError::BufferTooShort {
                expected: 8,
                actual: length,
            });
        }

        let first_byte = buf.get_u8();
        let supi_format = (first_byte >> 4) & 0x07;
        let plmn_id = PlmnId::decode(buf)?;
        let mut routing_indicator = [0u8; 2];
        buf.copy_to_slice(&mut routing_indicator);
        let protection_scheme_id = buf.get_u8();
        let home_network_pki = buf.get_u8();
        let scheme_output_len = length - 8;
        let scheme_output = buf.copy_to_bytes(scheme_output_len).to_vec();

        Ok(Self {
            supi_format,
            plmn_id,
            routing_indicator,
            protection_scheme_id,
            home_network_pki,
            scheme_output,
        })
    }
}

/// 5G-GUTI (5G Globally Unique Temporary Identifier)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FiveGGuti {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// AMF Region ID
    pub amf_region_id: u8,
    /// AMF Set ID (10 bits)
    pub amf_set_id: u16,
    /// AMF Pointer (6 bits)
    pub amf_pointer: u8,
    /// 5G-TMSI
    pub tmsi: u32,
}

impl FiveGGuti {
    /// Encode 5G-GUTI to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        // Length: 1 (type) + 3 (PLMN) + 1 (AMF region) + 2 (AMF set+pointer) + 4 (TMSI) = 11
        buf.put_u16(11);
        buf.put_u8(0xF0 | MobileIdentityType::FiveGGuti as u8);
        self.plmn_id.encode(buf);
        buf.put_u8(self.amf_region_id);
        // AMF Set ID (10 bits) + AMF Pointer (6 bits) = 2 bytes
        let amf_id = ((self.amf_set_id & 0x3FF) << 6) | (self.amf_pointer as u16 & 0x3F);
        buf.put_u16(amf_id);
        buf.put_u32(self.tmsi);
    }

    /// Decode 5G-GUTI content from bytes
    pub fn decode_content(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        if length < 11 {
            return Err(NasError::BufferTooShort {
                expected: 11,
                actual: length,
            });
        }

        let _first_byte = buf.get_u8(); // Type indicator
        let plmn_id = PlmnId::decode(buf)?;
        let amf_region_id = buf.get_u8();
        let amf_id = buf.get_u16();
        let amf_set_id = (amf_id >> 6) & 0x3FF;
        let amf_pointer = (amf_id & 0x3F) as u8;
        let tmsi = buf.get_u32();

        Ok(Self {
            plmn_id,
            amf_region_id,
            amf_set_id,
            amf_pointer,
            tmsi,
        })
    }
}

/// 5G-S-TMSI
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FiveGSTmsi {
    /// AMF Set ID (10 bits)
    pub amf_set_id: u16,
    /// AMF Pointer (6 bits)
    pub amf_pointer: u8,
    /// 5G-TMSI
    pub tmsi: u32,
}

impl FiveGSTmsi {
    /// Encode 5G-S-TMSI to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(7); // Length
        buf.put_u8(0xF0 | MobileIdentityType::FiveGSTmsi as u8);
        let amf_id = ((self.amf_set_id & 0x3FF) << 6) | (self.amf_pointer as u16 & 0x3F);
        buf.put_u16(amf_id);
        buf.put_u32(self.tmsi);
    }

    /// Decode 5G-S-TMSI content from bytes
    pub fn decode_content(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        if length < 7 {
            return Err(NasError::BufferTooShort {
                expected: 7,
                actual: length,
            });
        }

        let _first_byte = buf.get_u8();
        let amf_id = buf.get_u16();
        let amf_set_id = (amf_id >> 6) & 0x3FF;
        let amf_pointer = (amf_id & 0x3F) as u8;
        let tmsi = buf.get_u32();

        Ok(Self {
            amf_set_id,
            amf_pointer,
            tmsi,
        })
    }
}

/// IMEI (International Mobile Equipment Identity)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Imei {
    /// IMEI digits (15 digits)
    pub digits: [u8; 15],
}

impl Imei {
    /// Encode IMEI to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        // Length: 1 (type+first digit) + 7 (remaining 14 digits as BCD) = 8
        buf.put_u16(8);
        // First byte: odd/even indicator + type + first digit
        buf.put_u8((self.digits[0] << 4) | 0x08 | MobileIdentityType::Imei as u8);
        // Remaining digits packed as BCD
        for i in 0..7 {
            let d1 = self.digits[1 + i * 2];
            let d2 = if 2 + i * 2 < 15 {
                self.digits[2 + i * 2]
            } else {
                0x0F
            };
            buf.put_u8((d2 << 4) | d1);
        }
    }

    /// Decode IMEI content from bytes
    pub fn decode_content(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        if length < 8 {
            return Err(NasError::BufferTooShort {
                expected: 8,
                actual: length,
            });
        }

        let mut digits = [0u8; 15];
        let first_byte = buf.get_u8();
        digits[0] = (first_byte >> 4) & 0x0F;

        for i in 0..7 {
            let byte = buf.get_u8();
            digits[1 + i * 2] = byte & 0x0F;
            if 2 + i * 2 < 15 {
                digits[2 + i * 2] = (byte >> 4) & 0x0F;
            }
        }

        Ok(Self { digits })
    }
}

/// IMEISV (IMEI Software Version)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Imeisv {
    /// IMEISV digits (16 digits)
    pub digits: [u8; 16],
}

impl Imeisv {
    /// Encode IMEISV to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        // Length: 1 (type+first digit) + 8 (remaining 15 digits as BCD, last byte has filler) = 9
        buf.put_u16(9);
        buf.put_u8((self.digits[0] << 4) | MobileIdentityType::Imeisv as u8);
        // 16 digits total: first digit in byte 0, remaining 15 digits in 8 bytes (last nibble is filler)
        for i in 0..8 {
            let d1 = self.digits[1 + i * 2];
            let d2 = if 2 + i * 2 < 16 {
                self.digits[2 + i * 2]
            } else {
                0x0F
            };
            buf.put_u8((d2 << 4) | d1);
        }
    }

    /// Decode IMEISV content from bytes
    pub fn decode_content(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        if length < 9 {
            return Err(NasError::BufferTooShort {
                expected: 9,
                actual: length,
            });
        }

        let mut digits = [0u8; 16];
        let first_byte = buf.get_u8();
        digits[0] = (first_byte >> 4) & 0x0F;

        for i in 0..8 {
            let byte = buf.get_u8();
            digits[1 + i * 2] = byte & 0x0F;
            if 2 + i * 2 < 16 {
                digits[2 + i * 2] = (byte >> 4) & 0x0F;
            }
        }

        Ok(Self { digits })
    }
}

/// 5GS registration result (TS 24.501 Section 9.11.3.6)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegistrationResult {
    /// SMS over NAS allowed
    pub sms_allowed: bool,
    /// Registration result value
    pub value: RegistrationResultValue,
}

/// Registration result values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RegistrationResultValue {
    #[default]
    ThreeGppAccess = 1,
    Non3gppAccess = 2,
    ThreeGppAndNon3gppAccess = 3,
    OnboardingServices = 8,
    DisasterRoamingServices = 9,
}

impl RegistrationResult {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(1); // Length
        let sms_bit = if self.sms_allowed { 0x08 } else { 0 };
        buf.put_u8(sms_bit | (self.value as u8 & 0x07));
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort {
                expected: 2,
                actual: buf.remaining(),
            });
        }
        let _length = buf.get_u8();
        let byte = buf.get_u8();
        let sms_allowed = (byte & 0x08) != 0;
        let value = match byte & 0x07 {
            1 => RegistrationResultValue::ThreeGppAccess,
            2 => RegistrationResultValue::Non3gppAccess,
            3 => RegistrationResultValue::ThreeGppAndNon3gppAccess,
            8 => RegistrationResultValue::OnboardingServices,
            9 => RegistrationResultValue::DisasterRoamingServices,
            _ => RegistrationResultValue::ThreeGppAccess,
        };
        Ok(Self { sms_allowed, value })
    }
}

/// De-registration type (TS 24.501 Section 9.11.3.20)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeRegistrationType {
    /// Switch off
    pub switch_off: bool,
    /// Re-registration required
    pub re_registration_required: bool,
    /// Access type
    pub access_type: AccessType,
}

/// Access type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum AccessType {
    #[default]
    ThreeGppAccess = 1,
    Non3gppAccess = 2,
    ThreeGppAndNon3gppAccess = 3,
}

impl DeRegistrationType {
    /// Encode to half-byte
    pub fn encode(&self) -> u8 {
        let switch_off_bit = if self.switch_off { 0x08 } else { 0 };
        let re_reg_bit = if self.re_registration_required {
            0x04
        } else {
            0
        };
        switch_off_bit | re_reg_bit | (self.access_type as u8 & 0x03)
    }

    /// Decode from half-byte
    pub fn decode(byte: u8) -> Self {
        let switch_off = (byte & 0x08) != 0;
        let re_registration_required = (byte & 0x04) != 0;
        let access_type = match byte & 0x03 {
            1 => AccessType::ThreeGppAccess,
            2 => AccessType::Non3gppAccess,
            3 => AccessType::ThreeGppAndNon3gppAccess,
            _ => AccessType::ThreeGppAccess,
        };
        Self {
            switch_off,
            re_registration_required,
            access_type,
        }
    }
}

/// Service type (TS 24.501 Section 9.11.3.50)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ServiceType {
    #[default]
    Signalling = 0,
    Data = 1,
    MobileTerminatedServices = 2,
    EmergencyServices = 3,
    EmergencyServicesFallback = 4,
    HighPriorityAccess = 5,
    ElevatedSignalling = 6,
    UnusedFallback = 7,
}

/// 5GS TAI list (TS 24.501 Section 9.11.3.9)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaiList {
    /// Length
    pub length: u8,
    /// TAI list elements
    pub elements: Vec<TaiListElement>,
}

/// TAI list element
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaiListElement {
    /// List of TACs belonging to one PLMN
    PartialTaiList0 { plmn_id: PlmnId, tacs: Vec<[u8; 3]> },
    /// List of TAIs belonging to one PLMN
    PartialTaiList1 { plmn_id: PlmnId, tac: [u8; 3] },
    /// List of TAIs with different PLMNs
    PartialTaiList2 { tais: Vec<Tai> },
}

impl TaiList {
    /// Encode TAI list to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();
        buf.put_u8(0); // Placeholder for length

        for element in &self.elements {
            match element {
                TaiListElement::PartialTaiList0 { plmn_id, tacs } => {
                    let num = (tacs.len() - 1) as u8;
                    buf.put_u8(num & 0x1F); // Type 00
                    plmn_id.encode(buf);
                    for tac in tacs {
                        buf.put_slice(tac);
                    }
                }
                TaiListElement::PartialTaiList1 { plmn_id, tac } => {
                    buf.put_u8(0x40); // Type 01
                    plmn_id.encode(buf);
                    buf.put_slice(tac);
                }
                TaiListElement::PartialTaiList2 { tais } => {
                    let num = (tais.len() - 1) as u8;
                    buf.put_u8(0x80 | (num & 0x1F)); // Type 10
                    for tai in tais {
                        tai.encode(buf);
                    }
                }
            }
        }

        let length = buf.len() - start - 1;
        buf[start] = length as u8;
    }

    /// Decode TAI list from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }

        let length = buf.get_u8();
        if buf.remaining() < length as usize {
            return Err(NasError::BufferTooShort {
                expected: length as usize,
                actual: buf.remaining(),
            });
        }

        let mut elements = Vec::new();
        let mut remaining = length as usize;

        // Helper: subtract `n` from the declared remaining length, failing on
        // underflow rather than panicking (debug) / wrapping (release).
        fn take(remaining: &mut usize, n: usize) -> NasResult<()> {
            *remaining = remaining.checked_sub(n).ok_or_else(|| {
                NasError::DecodingError("Truncated TAI list: length underflow".to_string())
            })?;
            Ok(())
        }

        while remaining > 0 {
            // The type byte itself consumes one declared byte.
            take(&mut remaining, 1)?;
            if buf.remaining() < 1 {
                return Err(NasError::BufferTooShort {
                    expected: 1,
                    actual: buf.remaining(),
                });
            }
            let type_byte = buf.get_u8();

            let list_type = (type_byte >> 5) & 0x03;
            let num = (type_byte & 0x1F) as usize + 1;

            match list_type {
                0 => {
                    // 3-byte PLMN id + num * 3-byte TAC.
                    take(&mut remaining, 3)?;
                    let plmn_id = PlmnId::decode(buf)?;
                    let mut tacs = Vec::with_capacity(num);
                    for _ in 0..num {
                        take(&mut remaining, 3)?;
                        if buf.remaining() < 3 {
                            return Err(NasError::BufferTooShort {
                                expected: 3,
                                actual: buf.remaining(),
                            });
                        }
                        let mut tac = [0u8; 3];
                        buf.copy_to_slice(&mut tac);
                        tacs.push(tac);
                    }
                    elements.push(TaiListElement::PartialTaiList0 { plmn_id, tacs });
                }
                1 => {
                    // 3-byte PLMN id + single 3-byte TAC.
                    take(&mut remaining, 3)?;
                    let plmn_id = PlmnId::decode(buf)?;
                    take(&mut remaining, 3)?;
                    if buf.remaining() < 3 {
                        return Err(NasError::BufferTooShort {
                            expected: 3,
                            actual: buf.remaining(),
                        });
                    }
                    let mut tac = [0u8; 3];
                    buf.copy_to_slice(&mut tac);
                    elements.push(TaiListElement::PartialTaiList1 { plmn_id, tac });
                }
                2 => {
                    // num * 6-byte TAI (PLMN id + TAC).
                    let mut tais = Vec::with_capacity(num);
                    for _ in 0..num {
                        take(&mut remaining, 6)?;
                        let tai = Tai::decode(buf)?;
                        tais.push(tai);
                    }
                    elements.push(TaiListElement::PartialTaiList2 { tais });
                }
                _ => {
                    return Err(NasError::DecodingError("Invalid TAI list type".to_string()));
                }
            }
        }

        Ok(Self { length, elements })
    }
}

#[cfg(test)]
mod tai_list_tests {
    use super::*;
    use bytes::Bytes;

    /// Round-trip a well-formed TAI list (type 0: PLMN + 2 TACs) to make sure
    /// the success path is preserved after the bounds-checking changes.
    #[test]
    fn decode_valid_partial_tai_list0_roundtrips() {
        // length byte + type byte (type=0, num-1=1 -> 2 TACs) + 3-byte PLMN + 6 bytes TAC
        // declared length = 1 (type) + 3 (plmn) + 6 (two TACs) = 10
        let mut data = vec![10u8, 0x01];
        data.extend_from_slice(&[0x02, 0xF8, 0x39]); // PLMN id (3 bytes)
        data.extend_from_slice(&[0x00, 0x00, 0x01]); // TAC 1
        data.extend_from_slice(&[0x00, 0x00, 0x02]); // TAC 2
        let mut buf = Bytes::from(data);

        let list = TaiList::decode(&mut buf).expect("valid TAI list must decode");
        assert_eq!(list.length, 10);
        assert_eq!(list.elements.len(), 1);
        match &list.elements[0] {
            TaiListElement::PartialTaiList0 { tacs, .. } => {
                assert_eq!(tacs.len(), 2);
                assert_eq!(tacs[0], [0x00, 0x00, 0x01]);
                assert_eq!(tacs[1], [0x00, 0x00, 0x02]);
            }
            other => panic!("unexpected element: {other:?}"),
        }
    }

    /// Declared length larger than the actual buffer must Err, not panic.
    #[test]
    fn decode_truncated_buffer_errs() {
        // length=10 but only the type byte present after it
        let mut buf = Bytes::from(vec![10u8, 0x01]);
        let res = TaiList::decode(&mut buf);
        assert!(res.is_err(), "truncated TAI list must error, got {res:?}");
    }

    /// A length that is consumed by the type byte but then claims a sub-element
    /// larger than what `remaining` allows must Err via the checked subtraction,
    /// not underflow/panic.
    #[test]
    fn decode_length_underflow_errs() {
        // length=1: only enough for the type byte, but type 0 needs a PLMN id (3
        // bytes) which would drive `remaining` below zero.
        let mut data = vec![1u8, 0x00]; // length=1, type=0 num=1
        data.extend_from_slice(&[0x02, 0xF8, 0x39]); // PLMN bytes present in buffer
        data.extend_from_slice(&[0x00, 0x00, 0x01]); // TAC present in buffer
        let mut buf = Bytes::from(data);
        let res = TaiList::decode(&mut buf);
        assert!(res.is_err(), "length underflow must error, got {res:?}");
    }

    /// Oversized num driving TAC copies beyond the buffer must Err, not panic on
    /// copy_to_slice.
    #[test]
    fn decode_oversized_tac_count_errs() {
        // type 0 with num-1 = 0x1F -> 32 TACs, but buffer only has one PLMN + 1 TAC.
        // declared length set large so the loop attempts all 32 copies.
        let mut data = vec![200u8, 0x1F]; // length=200 (lies), type=0 num=32
        data.extend_from_slice(&[0x02, 0xF8, 0x39]); // PLMN id
        data.extend_from_slice(&[0x00, 0x00, 0x01]); // single TAC only
        let mut buf = Bytes::from(data);
        let res = TaiList::decode(&mut buf);
        assert!(res.is_err(), "oversized TAC count must error, got {res:?}");
    }

    /// Type 2 with an oversized TAI count beyond the buffer must Err, not panic.
    #[test]
    fn decode_oversized_tai_count_errs() {
        let mut data = vec![200u8, 0x9F]; // length=200 (lies), type=2 (0b10), num=32
        data.extend_from_slice(&[0x02, 0xF8, 0x39, 0x00, 0x00, 0x01]); // one TAI only
        let mut buf = Bytes::from(data);
        let res = TaiList::decode(&mut buf);
        assert!(res.is_err(), "oversized TAI count must error, got {res:?}");
    }

    /// Empty buffer must Err on the length-byte read, not panic.
    #[test]
    fn decode_empty_buffer_errs() {
        let mut buf = Bytes::new();
        assert!(TaiList::decode(&mut buf).is_err());
    }
}

#[cfg(test)]
mod suci_tests {
    use super::*;
    use crate::common::types::PlmnId;
    use bytes::{Buf, BytesMut};

    /// nas-07: byte-vector test for the NAI SUPI-format branch
    /// (TS 24.501 §9.11.3.4 Figure 9.11.3.4.4). The on-wire content is just the
    /// type octet (SUPI format 1 | SUCI type 1 = 0x11) followed by the NAI bytes.
    #[test]
    fn suci_nai_format_encodes_expected_bytes() {
        let nai = b"type1.rid678.schid1.userinfo@example.com".to_vec();
        let suci = Suci {
            supi_format: 1,
            scheme_output: nai.clone(),
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        suci.encode(&mut buf);
        let bytes = buf.to_vec();

        // length(u16) = 1 (type octet) + NAI bytes
        let content_len = (1 + nai.len()) as u16;
        assert_eq!(&bytes[0..2], &content_len.to_be_bytes());
        // octet 4: SUPI format (1) in bits 5-7 | type-of-identity SUCI (1)
        assert_eq!(bytes[2], (1u8 << 4) | MobileIdentityType::Suci as u8);
        assert_eq!(bytes[2], 0x11);
        // octets 5..y: the SUCI NAI string verbatim
        assert_eq!(&bytes[3..], &nai[..]);
    }

    /// nas-07: NAI-format round-trip via encode -> decode_content.
    #[test]
    fn suci_nai_format_roundtrips() {
        let suci = Suci {
            supi_format: 1,
            scheme_output: b"alice@home.realm".to_vec(),
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        suci.encode(&mut buf);

        let mut b = buf.freeze();
        let length = b.get_u16() as usize;
        let decoded = Suci::decode_content(&mut b, length).expect("NAI SUCI must decode");
        assert_eq!(decoded.supi_format, 1);
        assert_eq!(decoded.scheme_output, b"alice@home.realm".to_vec());
        assert_eq!(decoded, suci);
    }

    /// nas-07 guard: the IMSI SUPI-format (supi_format == 0) on-wire layout MUST
    /// remain byte-identical to the pre-nas-07 encoder. This asserts a fixed
    /// byte vector so any future change to the IMSI path is caught.
    #[test]
    fn suci_imsi_format_bytes_unchanged() {
        let suci = Suci {
            supi_format: 0,
            plmn_id: PlmnId::new([0, 0, 1], [0, 1, 0], 2),
            routing_indicator: [0x00, 0xF0],
            protection_scheme_id: 0,
            home_network_pki: 0,
            scheme_output: vec![0xAB, 0xCD],
        };
        let mut buf = BytesMut::new();
        suci.encode(&mut buf);

        // content_len = 1(type) + 3(PLMN) + 2(RI) + 1(scheme) + 1(PKI) + 2(out) = 10
        let expected: &[u8] = &[
            0x00, 0x0A, // length = 10
            0x01, // SUPI format 0 | SUCI type 1
            0x00, 0xF1, 0x10, // PLMN 001/01 (2-digit MNC)
            0x00, 0xF0, // routing indicator
            0x00, // protection scheme id
            0x00, // home network PKI
            0xAB, 0xCD, // scheme output
        ];
        assert_eq!(buf.to_vec(), expected);

        // And it still round-trips.
        let mut b = buf.freeze();
        let length = b.get_u16() as usize;
        let decoded = Suci::decode_content(&mut b, length).expect("IMSI SUCI must decode");
        assert_eq!(decoded, suci);
    }
}
