//! EPS-specific NAS types
//!
//! Based on 3GPP TS 24.301

use crate::buf::{IeLen, NasBuf};
use crate::common::types::PlmnId;
use crate::error::{NasError, NasResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

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
            _ => Err(NasError::DecodingError(format!(
                "Unknown EMM cause: {value}"
            ))),
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
    /// TMSI/P-TMSI/M-TMSI. Not an EPS mobile identity (§9.9.3.12 has no type
    /// 4): it is the TS 24.008 §10.5.1.4 Mobile identity that the Extended
    /// Service Request's M-TMSI carries (TS 24.301 §8.2.15). Decoded only by
    /// [`EpsMobileIdentity::decode_mobile_identity`].
    Tmsi(EpsTmsi),
}

/// TMSI/P-TMSI/M-TMSI as a TS 24.008 §10.5.1.4 Mobile identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EpsTmsi {
    /// The 4-octet TMSI, most significant octet first.
    pub tmsi: u32,
}

impl EpsTmsi {
    /// Encode as LV: length 5, octet 3 = "1111" + even + type 100, then the TMSI.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(5);
        buf.put_u8(0xF0 | EpsMobileIdentityType::Tmsi as u8);
        buf.put_u32(self.tmsi);
    }

    /// Decode the value part (`length` octets, starting at octet 3).
    pub fn decode(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        // TS 24.008 §10.5.1.4: the TMSI is 4 octets after octet 3, so exactly
        // 5 value octets.
        IeLen::Exact(5).check(length)?;
        let _type_byte = buf.read_u8()?;
        Ok(Self {
            tmsi: buf.read_u32()?,
        })
    }
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
            let d2 = if i + 1 < self.digits.len() {
                self.digits[i + 1]
            } else {
                0x0F
            };
            buf.put_u8((d2 << 4) | d1);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        // TS 24.301 §9.9.3.12 / TS 24.008 §10.5.1.4: an IMSI is at most 15
        // digits, the first in octet 3, so 1 to 8 value octets (#613).
        IeLen::Between(1, 8).check(length)?;

        let first_byte = buf.read_u8()?;
        let odd = (first_byte & 0x08) != 0;
        let mut digits = vec![(first_byte >> 4) & 0x0F];

        for _ in 1..length {
            let byte = buf.read_u8()?;
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

impl EpsImei {
    /// Encode to bytes (LV format, TS 24.301 Section 9.9.3.12 / TS 24.008 10.5.1.4)
    pub fn encode(&self, buf: &mut BytesMut) {
        // Length: 1 (odd/even + type + first digit) + 7 (remaining 14 digits as BCD) = 8
        buf.put_u8(8);
        // First byte: first digit + odd indicator (15 digits) + type = IMEI
        buf.put_u8((self.digits[0] << 4) | 0x08 | EpsMobileIdentityType::Imei as u8);
        // Remaining 14 digits packed as BCD pairs
        for i in 0..7 {
            let d1 = self.digits[1 + i * 2];
            let d2 = self.digits[2 + i * 2];
            buf.put_u8((d2 << 4) | d1);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes, length: usize) -> NasResult<Self> {
        // TS 24.008 §10.5.1.4: 15 digits in octets 3-10, so exactly 8 value
        // octets; any other length is an erroneous IE (#613).
        IeLen::Exact(8).check(length)?;

        let mut digits = [0u8; 15];
        let first_byte = buf.read_u8()?;
        digits[0] = (first_byte >> 4) & 0x0F;

        for i in 0..7 {
            let byte = buf.read_u8()?;
            digits[1 + i * 2] = byte & 0x0F;
            digits[2 + i * 2] = (byte >> 4) & 0x0F;
        }

        Ok(Self { digits })
    }
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
        // TS 24.301 §9.9.3.12: octets 3-13, so exactly 11 value
        // octets; any other length is an erroneous IE (#613).
        IeLen::Exact(11).check(length)?;

        let _type_byte = buf.read_u8()?;
        let plmn_id = PlmnId::decode(buf)?;
        let mme_gid = buf.read_u16()?;
        let mme_code = buf.read_u8()?;
        let m_tmsi = buf.read_u32()?;

        Ok(Self {
            plmn_id,
            mme_gid,
            mme_code,
            m_tmsi,
        })
    }
}

impl EpsMobileIdentity {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::Imsi(imsi) => imsi.encode(buf),
            Self::Imei(imei) => imei.encode(buf),
            Self::Guti(guti) => guti.encode(buf),
            Self::Tmsi(tmsi) => tmsi.encode(buf),
        }
    }

    /// Decode a TS 24.008 §10.5.1.4 Mobile identity (LV), as the Extended
    /// Service Request's M-TMSI is (TS 24.301 §8.2.15, "Mobile identity
    /// 9.9.2.3", LV 6). It differs from [`decode`](Self::decode) in accepting
    /// type 4 (TMSI/P-TMSI/M-TMSI) and not the EPS-only GUTI (#629).
    pub fn decode_mobile_identity(buf: &mut Bytes) -> NasResult<Self> {
        let mut ie = buf.read_lv(IeLen::AtLeast(1))?;
        let length = ie.len();
        let buf = &mut ie;
        let id_type = buf.peek_u8()? & 0x07;
        match id_type {
            1 => Ok(Self::Imsi(EpsImsi::decode(buf, length)?)),
            2 => Ok(Self::Imei(EpsImei::decode(buf, length)?)),
            4 => Ok(Self::Tmsi(EpsTmsi::decode(buf, length)?)),
            _ => Err(NasError::InvalidMobileIdentityType(id_type)),
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }

        // TS 24.301 §9.9.3.12: 3 to 13 octets, so at least the type octet.
        // The identity is decoded inside the IE's own length (#613).
        let mut ie = buf.read_lv(IeLen::AtLeast(1))?;
        let length = ie.len();
        let buf = &mut ie;

        let type_byte = buf.peek_u8()?;
        let id_type = type_byte & 0x07;

        match id_type {
            1 => Ok(Self::Imsi(EpsImsi::decode(buf, length)?)),
            2 => Ok(Self::Imei(EpsImei::decode(buf, length)?)),
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
            return Err(NasError::BufferTooShort {
                expected: 3,
                actual: buf.remaining(),
            });
        }

        // TS 24.301 §9.9.3.34: 4 to 15 octets, octets 5-15 optional, so it
        // grows by release: at least EEA and EIA, the rest decoded or kept as
        // `additional`, all inside the IE's own length (#613).
        let mut ie = buf.read_lv(IeLen::AtLeast(2))?;
        let length = ie.len() as u8;
        let eea = ie.read_u8()?;
        let eia = ie.read_u8()?;

        let mut cap = Self {
            length,
            eea,
            eia,
            uea: None,
            uia: None,
            additional: Vec::new(),
        };

        if ie.has_remaining() {
            cap.uea = Some(ie.read_u8()?);
        }
        if ie.has_remaining() {
            cap.uia = Some(ie.read_u8()?);
        }
        cap.additional = ie.to_vec();

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
            return Err(NasError::BufferTooShort {
                expected: 2,
                actual: buf.remaining(),
            });
        }
        let length = buf.read_u16()?;
        if buf.remaining() < length as usize {
            return Err(NasError::BufferTooShort {
                expected: length as usize,
                actual: buf.remaining(),
            });
        }
        let data = buf.read_bytes(length as usize)?.to_vec();
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
            return Err(NasError::BufferTooShort {
                expected: 2,
                actual: buf.remaining(),
            });
        }
        let tac = buf.read_u16()?;
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
            return Err(NasError::BufferTooShort {
                expected: 1,
                actual: buf.remaining(),
            });
        }
        let length = buf.read_u8()?;
        if buf.remaining() < length as usize {
            return Err(NasError::BufferTooShort {
                expected: length as usize,
                actual: buf.remaining(),
            });
        }
        let data = buf.read_bytes(length as usize)?.to_vec();
        Ok(Self { length, data })
    }
}
