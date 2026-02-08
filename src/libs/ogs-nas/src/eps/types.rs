//! EPS-specific NAS types
//!
//! Based on 3GPP TS 24.301

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{NasError, NasResult};
use crate::common::types::PlmnId;

/// EMM cause values (TS 24.301 Section 9.9.3.9)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmmCause {
    ImsiUnknownInHss = 2,
    IllegalUe = 3,
    ImeiNotAccepted = 5,
    IllegalMe = 6,
    EpsServicesNotAllowed = 7,
    EpsAndNonEpsServicesNotAllowed = 8,
    UeIdentityCannotBeDerived = 9,
    ImplicitlyDetached = 10,
    PlmnNotAllowed = 11,
    TrackingAreaNotAllowed = 12,
    RoamingNotAllowedInTa = 13,
    EpsServicesNotAllowedInPlmn = 14,
    NoSuitableCells = 15,
    MscTemporarilyNotReachable = 16,
    NetworkFailure = 17,
    CsDomainNotAvailable = 18,
    EsmFailure = 19,
    MacFailure = 20,
    SynchFailure = 21,
    Congestion = 22,
    UeSecurityCapabilitiesMismatch = 23,
    SecurityModeRejected = 24,
    NotAuthorizedForCsg = 25,
    NonEpsAuthenticationUnacceptable = 26,
    RequestedServiceOptionNotAuthorized = 35,
    CsServiceTemporarilyNotAvailable = 39,
    NoEpsBearerContextActivated = 40,
    SevereNetworkFailure = 42,
    SemanticallyIncorrectMessage = 95,
    InvalidMandatoryInformation = 96,
    MessageTypeNonExistent = 97,
    MessageTypeNotCompatible = 98,
    InformationElementNonExistent = 99,
    ConditionalIeError = 100,
    MessageNotCompatible = 101,
    ProtocolErrorUnspecified = 111,
}

impl TryFrom<u8> for EmmCause {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::ImsiUnknownInHss),
            3 => Ok(Self::IllegalUe),
            5 => Ok(Self::ImeiNotAccepted),
            6 => Ok(Self::IllegalMe),
            7 => Ok(Self::EpsServicesNotAllowed),
            8 => Ok(Self::EpsAndNonEpsServicesNotAllowed),
            9 => Ok(Self::UeIdentityCannotBeDerived),
            10 => Ok(Self::ImplicitlyDetached),
            11 => Ok(Self::PlmnNotAllowed),
            12 => Ok(Self::TrackingAreaNotAllowed),
            13 => Ok(Self::RoamingNotAllowedInTa),
            14 => Ok(Self::EpsServicesNotAllowedInPlmn),
            15 => Ok(Self::NoSuitableCells),
            16 => Ok(Self::MscTemporarilyNotReachable),
            17 => Ok(Self::NetworkFailure),
            18 => Ok(Self::CsDomainNotAvailable),
            19 => Ok(Self::EsmFailure),
            20 => Ok(Self::MacFailure),
            21 => Ok(Self::SynchFailure),
            22 => Ok(Self::Congestion),
            23 => Ok(Self::UeSecurityCapabilitiesMismatch),
            24 => Ok(Self::SecurityModeRejected),
            25 => Ok(Self::NotAuthorizedForCsg),
            26 => Ok(Self::NonEpsAuthenticationUnacceptable),
            35 => Ok(Self::RequestedServiceOptionNotAuthorized),
            39 => Ok(Self::CsServiceTemporarilyNotAvailable),
            40 => Ok(Self::NoEpsBearerContextActivated),
            42 => Ok(Self::SevereNetworkFailure),
            95 => Ok(Self::SemanticallyIncorrectMessage),
            96 => Ok(Self::InvalidMandatoryInformation),
            97 => Ok(Self::MessageTypeNonExistent),
            98 => Ok(Self::MessageTypeNotCompatible),
            99 => Ok(Self::InformationElementNonExistent),
            100 => Ok(Self::ConditionalIeError),
            101 => Ok(Self::MessageNotCompatible),
            111 => Ok(Self::ProtocolErrorUnspecified),
            _ => Err(NasError::DecodingError(format!("Unknown EMM cause: {value}"))),
        }
    }
}

/// EPS attach type (TS 24.301 Section 9.9.3.11)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EpsAttachType {
    /// Attach type value
    pub value: EpsAttachTypeValue,
}

/// EPS attach type values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum EpsAttachTypeValue {
    #[default]
    EpsAttach = 1,
    CombinedEpsImsiAttach = 2,
    EpsEmergencyAttach = 6,
}

impl EpsAttachType {
    /// Encode to half-byte
    pub fn encode(&self) -> u8 {
        self.value as u8 & 0x07
    }

    /// Decode from half-byte
    pub fn decode(byte: u8) -> Self {
        let value = match byte & 0x07 {
            1 => EpsAttachTypeValue::EpsAttach,
            2 => EpsAttachTypeValue::CombinedEpsImsiAttach,
            6 => EpsAttachTypeValue::EpsEmergencyAttach,
            _ => EpsAttachTypeValue::EpsAttach,
        };
        Self { value }
    }
}

/// EPS attach result (TS 24.301 Section 9.9.3.10)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EpsAttachResult {
    /// Attach result value
    pub value: EpsAttachResultValue,
}

/// EPS attach result values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum EpsAttachResultValue {
    #[default]
    EpsOnly = 1,
    CombinedEpsImsi = 2,
}

impl EpsAttachResult {
    /// Encode to half-byte
    pub fn encode(&self) -> u8 {
        self.value as u8 & 0x07
    }

    /// Decode from half-byte
    pub fn decode(byte: u8) -> Self {
        let value = match byte & 0x07 {
            1 => EpsAttachResultValue::EpsOnly,
            2 => EpsAttachResultValue::CombinedEpsImsi,
            _ => EpsAttachResultValue::EpsOnly,
        };
        Self { value }
    }
}

/// EPS mobile identity type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EpsMobileIdentityType {
    Imsi = 1,
    Imei = 2,
    Imeisv = 3,
    Tmsi = 4,
    Tmgi = 5,
    Guti = 6,
}

impl TryFrom<u8> for EpsMobileIdentityType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Imsi),
            2 => Ok(Self::Imei),
            3 => Ok(Self::Imeisv),
            4 => Ok(Self::Tmsi),
            5 => Ok(Self::Tmgi),
            6 => Ok(Self::Guti),
            _ => Err(NasError::InvalidMobileIdentityType(value)),
        }
    }
}

/// EPS mobile identity (TS 24.301 Section 9.9.3.12)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpsMobileIdentity {
    /// IMSI
    Imsi(EpsImsi),
    /// IMEI
    Imei(EpsImei),
    /// GUTI
    Guti(EpsGuti),
}

impl Default for EpsMobileIdentity {
    fn default() -> Self {
        Self::Imsi(EpsImsi::default())
    }
}

/// IMSI for EPS
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EpsImsi {
    /// IMSI digits (15 digits max)
    pub digits: Vec<u8>,
}

impl EpsImsi {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        let len = (self.digits.len() + 2) / 2;
        buf.put_u8(len as u8);

        // First byte: odd/even + type + first digit
        let odd = self.digits.len() % 2 == 1;
        let first_byte = (self.digits[0] << 4) | (if odd { 0x09 } else { 0x01 });
        buf.put_u8(first_byte);

        // Remaining digits
        for i in (1..self.digits.len()).step_by(2) {
            let d1 = self.digits[i];
            let d2 = if i + 1 < self.digits.len() { self.digits[i + 1] } else { 0x0F };
            buf.put_u8((d2 << 4) | d1);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        if length < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: length });
        }

        let first_byte = buf.get_u8();
        let odd = (first_byte & 0x08) != 0;
        let mut digits = vec![(first_byte >> 4) & 0x0F];

        for _ in 1..length {
            let byte = buf.get_u8();
            digits.push(byte & 0x0F);
            let d2 = (byte >> 4) & 0x0F;
            if d2 != 0x0F {
                digits.push(d2);
            }
        }

        // Remove trailing 0xF if even
        if !odd && digits.last() == Some(&0x0F) {
            digits.pop();
        }

        Ok(Self { digits })
    }
}

/// IMEI for EPS
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EpsImei {
    /// IMEI digits (15 digits)
    pub digits: [u8; 15],
}

/// GUTI for EPS (TS 24.301 Section 9.9.3.12)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EpsGuti {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// MME Group ID
    pub mme_gid: u16,
    /// MME Code
    pub mme_code: u8,
    /// M-TMSI
    pub m_tmsi: u32,
}

impl EpsGuti {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(11); // Length
        buf.put_u8(0xF6); // Type = GUTI
        self.plmn_id.encode(buf);
        buf.put_u16(self.mme_gid);
        buf.put_u8(self.mme_code);
        buf.put_u32(self.m_tmsi);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        if length < 11 {
            return Err(NasError::BufferTooShort { expected: 11, actual: length });
        }

        let _type_byte = buf.get_u8();
        let plmn_id = PlmnId::decode(buf)?;
        let mme_gid = buf.get_u16();
        let mme_code = buf.get_u8();
        let m_tmsi = buf.get_u32();

        Ok(Self { plmn_id, mme_gid, mme_code, m_tmsi })
    }
}

impl EpsMobileIdentity {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::Imsi(imsi) => imsi.encode(buf),
            Self::Guti(guti) => guti.encode(buf),
            Self::Imei(_) => {} // TODO
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }

        let length = buf.get_u8() as usize;
        if buf.remaining() < length {
            return Err(NasError::BufferTooShort { expected: length, actual: buf.remaining() });
        }

        let type_byte = buf.chunk()[0];
        let id_type = type_byte & 0x07;

        match id_type {
            1 => Ok(Self::Imsi(EpsImsi::decode(buf, length)?)),
            6 => Ok(Self::Guti(EpsGuti::decode(buf, length)?)),
            _ => Err(NasError::InvalidMobileIdentityType(id_type)),
        }
    }
}

/// UE network capability (TS 24.301 Section 9.9.3.34)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UeNetworkCapability {
    /// Length
    pub length: u8,
    /// EEA (EPS Encryption Algorithms)
    pub eea: u8,
    /// EIA (EPS Integrity Algorithms)
    pub eia: u8,
    /// UEA (UMTS Encryption Algorithms) - optional
    pub uea: Option<u8>,
    /// UIA (UMTS Integrity Algorithms) - optional
    pub uia: Option<u8>,
    /// Additional capabilities
    pub additional: Vec<u8>,
}

impl UeNetworkCapability {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.length);
        buf.put_u8(self.eea);
        buf.put_u8(self.eia);
        if let Some(uea) = self.uea {
            buf.put_u8(uea);
        }
        if let Some(uia) = self.uia {
            buf.put_u8(uia);
        }
        buf.put_slice(&self.additional);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }

        let length = buf.get_u8();
        let eea = buf.get_u8();
        let eia = buf.get_u8();

        let mut cap = Self {
            length,
            eea,
            eia,
            uea: None,
            uia: None,
            additional: Vec::new(),
        };

        let remaining = (length as usize).saturating_sub(2);
        if remaining >= 1 && buf.remaining() >= 1 {
            cap.uea = Some(buf.get_u8());
        }
        if remaining >= 2 && buf.remaining() >= 1 {
            cap.uia = Some(buf.get_u8());
        }
        if remaining > 2 && buf.remaining() >= remaining - 2 {
            cap.additional = buf.copy_to_bytes(remaining - 2).to_vec();
        }

        Ok(cap)
    }
}

/// ESM message container (TS 24.301 Section 9.9.3.15)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EsmMessageContainer {
    /// Length (2 bytes)
    pub length: u16,
    /// ESM message data
    pub data: Vec<u8>,
}

impl EsmMessageContainer {
    /// Create a new ESM message container
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            length: data.len() as u16,
            data,
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.length);
        buf.put_slice(&self.data);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }
        let length = buf.get_u16();
        if buf.remaining() < length as usize {
            return Err(NasError::BufferTooShort { expected: length as usize, actual: buf.remaining() });
        }
        let data = buf.copy_to_bytes(length as usize).to_vec();
        Ok(Self { length, data })
    }
}

/// Tracking Area Identity (TAI) for EPS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EpsTai {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// TAC (2 bytes for EPS)
    pub tac: u16,
}

impl EpsTai {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.plmn_id.encode(buf);
        buf.put_u16(self.tac);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let plmn_id = PlmnId::decode(buf)?;
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }
        let tac = buf.get_u16();
        Ok(Self { plmn_id, tac })
    }
}

/// TAI list for EPS (TS 24.301 Section 9.9.3.33)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EpsTaiList {
    /// Length
    pub length: u8,
    /// TAI list data
    pub data: Vec<u8>,
}

impl EpsTaiList {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.length);
        buf.put_slice(&self.data);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let length = buf.get_u8();
        if buf.remaining() < length as usize {
            return Err(NasError::BufferTooShort { expected: length as usize, actual: buf.remaining() });
        }
        let data = buf.copy_to_bytes(length as usize).to_vec();
        Ok(Self { length, data })
    }
}
