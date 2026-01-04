//! Common NAS types shared between 5GS and EPS
//!
//! Based on 3GPP TS 24.501 and TS 24.301

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{NasError, NasResult};

/// Protocol discriminator values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolDiscriminator {
    /// 5GS Mobility Management (5GMM)
    FiveGsMobilityManagement = 0x7e,
    /// 5GS Session Management (5GSM)
    FiveGsSessionManagement = 0x2e,
    /// EPS Mobility Management (EMM)
    EpsMobilityManagement = 0x07,
    /// EPS Session Management (ESM)
    EpsSessionManagement = 0x02,
}

impl TryFrom<u8> for ProtocolDiscriminator {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x7e => Ok(Self::FiveGsMobilityManagement),
            0x2e => Ok(Self::FiveGsSessionManagement),
            0x07 => Ok(Self::EpsMobilityManagement),
            0x02 => Ok(Self::EpsSessionManagement),
            _ => Err(NasError::InvalidProtocolDiscriminator(value)),
        }
    }
}

/// Security header type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SecurityHeaderType {
    /// Plain NAS message, not security protected
    #[default]
    PlainNas = 0,
    /// Integrity protected
    IntegrityProtected = 1,
    /// Integrity protected and ciphered
    IntegrityProtectedAndCiphered = 2,
    /// Integrity protected with new 5G NAS security context
    IntegrityProtectedWithNew5gNasSecurityContext = 3,
    /// Integrity protected and ciphered with new 5G NAS security context
    IntegrityProtectedAndCipheredWithNew5gNasSecurityContext = 4,
}

impl TryFrom<u8> for SecurityHeaderType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PlainNas),
            1 => Ok(Self::IntegrityProtected),
            2 => Ok(Self::IntegrityProtectedAndCiphered),
            3 => Ok(Self::IntegrityProtectedWithNew5gNasSecurityContext),
            4 => Ok(Self::IntegrityProtectedAndCipheredWithNew5gNasSecurityContext),
            _ => Err(NasError::InvalidSecurityHeaderType(value)),
        }
    }
}

/// PLMN ID (MCC + MNC)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlmnId {
    /// Mobile Country Code (3 digits)
    pub mcc: [u8; 3],
    /// Mobile Network Code (2 or 3 digits)
    pub mnc: [u8; 3],
    /// MNC length (2 or 3)
    pub mnc_len: u8,
}

impl PlmnId {
    /// Create a new PLMN ID
    pub fn new(mcc: [u8; 3], mnc: [u8; 3], mnc_len: u8) -> Self {
        Self { mcc, mnc, mnc_len }
    }

    /// Encode PLMN ID to bytes (3 bytes)
    pub fn encode(&self, buf: &mut BytesMut) {
        // Byte 0: MCC digit 2 | MCC digit 1
        buf.put_u8((self.mcc[1] << 4) | self.mcc[0]);
        // Byte 1: MNC digit 3 | MCC digit 3 (MNC digit 3 = 0xF if 2-digit MNC)
        let mnc3 = if self.mnc_len == 2 { 0x0F } else { self.mnc[2] };
        buf.put_u8((mnc3 << 4) | self.mcc[2]);
        // Byte 2: MNC digit 2 | MNC digit 1
        buf.put_u8((self.mnc[1] << 4) | self.mnc[0]);
    }

    /// Decode PLMN ID from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }

        let b0 = buf.get_u8();
        let b1 = buf.get_u8();
        let b2 = buf.get_u8();

        let mcc = [b0 & 0x0F, (b0 >> 4) & 0x0F, b1 & 0x0F];
        let mnc3 = (b1 >> 4) & 0x0F;
        let mnc_len = if mnc3 == 0x0F { 2 } else { 3 };
        let mnc = [b2 & 0x0F, (b2 >> 4) & 0x0F, if mnc_len == 3 { mnc3 } else { 0 }];

        Ok(Self { mcc, mnc, mnc_len })
    }

    /// Get encoded length
    pub const fn encoded_len() -> usize {
        3
    }
}

/// Tracking Area Code (TAC)
pub type Tac = [u8; 3];

/// Tracking Area Identity (TAI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tai {
    /// PLMN ID
    pub plmn_id: PlmnId,
    /// Tracking Area Code
    pub tac: Tac,
}

impl Tai {
    /// Create a new TAI
    pub fn new(plmn_id: PlmnId, tac: Tac) -> Self {
        Self { plmn_id, tac }
    }

    /// Encode TAI to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        self.plmn_id.encode(buf);
        buf.put_slice(&self.tac);
    }

    /// Decode TAI from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        let plmn_id = PlmnId::decode(buf)?;
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }
        let mut tac = [0u8; 3];
        buf.copy_to_slice(&mut tac);
        Ok(Self { plmn_id, tac })
    }

    /// Get encoded length
    pub const fn encoded_len() -> usize {
        6
    }
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SNssai {
    /// Slice/Service Type (SST)
    pub sst: u8,
    /// Slice Differentiator (SD) - optional
    pub sd: Option<[u8; 3]>,
    /// Mapped HPLMN SST - optional
    pub mapped_hplmn_sst: Option<u8>,
    /// Mapped HPLMN SD - optional
    pub mapped_hplmn_sd: Option<[u8; 3]>,
}

impl SNssai {
    /// Create a new S-NSSAI with just SST
    pub fn new(sst: u8) -> Self {
        Self {
            sst,
            sd: None,
            mapped_hplmn_sst: None,
            mapped_hplmn_sd: None,
        }
    }

    /// Create a new S-NSSAI with SST and SD
    pub fn with_sd(sst: u8, sd: [u8; 3]) -> Self {
        Self {
            sst,
            sd: Some(sd),
            mapped_hplmn_sst: None,
            mapped_hplmn_sd: None,
        }
    }

    /// Encode S-NSSAI to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        let len = self.encoded_content_len();
        buf.put_u8(len as u8);
        buf.put_u8(self.sst);
        if let Some(sd) = &self.sd {
            buf.put_slice(sd);
        }
        if let Some(sst) = self.mapped_hplmn_sst {
            buf.put_u8(sst);
        }
        if let Some(sd) = &self.mapped_hplmn_sd {
            buf.put_slice(sd);
        }
    }

    /// Decode S-NSSAI from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }

        let len = buf.get_u8() as usize;
        if buf.remaining() < len {
            return Err(NasError::BufferTooShort { expected: len, actual: buf.remaining() });
        }

        let sst = buf.get_u8();
        let mut snssai = Self::new(sst);

        let remaining = len - 1;
        if remaining >= 3 {
            let mut sd = [0u8; 3];
            buf.copy_to_slice(&mut sd);
            snssai.sd = Some(sd);
        }

        let remaining = remaining.saturating_sub(3);
        if remaining >= 1 {
            snssai.mapped_hplmn_sst = Some(buf.get_u8());
        }

        let remaining = remaining.saturating_sub(1);
        if remaining >= 3 {
            let mut sd = [0u8; 3];
            buf.copy_to_slice(&mut sd);
            snssai.mapped_hplmn_sd = Some(sd);
        }

        Ok(snssai)
    }

    /// Get encoded content length (without length byte)
    pub fn encoded_content_len(&self) -> usize {
        let mut len = 1; // SST
        if self.sd.is_some() {
            len += 3;
        }
        if self.mapped_hplmn_sst.is_some() {
            len += 1;
        }
        if self.mapped_hplmn_sd.is_some() {
            len += 3;
        }
        len
    }
}

/// GPRS Timer (T3xxx)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GprsTimer {
    /// Timer unit (0-7)
    pub unit: u8,
    /// Timer value (0-31)
    pub value: u8,
}

impl GprsTimer {
    /// Timer unit: 2 seconds
    pub const UNIT_2_SECONDS: u8 = 0;
    /// Timer unit: 1 minute
    pub const UNIT_1_MINUTE: u8 = 1;
    /// Timer unit: decihours (6 minutes)
    pub const UNIT_DECIHOURS: u8 = 2;
    /// Timer unit: deactivated
    pub const UNIT_DEACTIVATED: u8 = 7;

    /// Create a new GPRS timer
    pub fn new(unit: u8, value: u8) -> Self {
        Self { unit: unit & 0x07, value: value & 0x1F }
    }

    /// Encode to a single byte
    pub fn encode(&self) -> u8 {
        ((self.unit & 0x07) << 5) | (self.value & 0x1F)
    }

    /// Decode from a single byte
    pub fn decode(byte: u8) -> Self {
        Self {
            unit: (byte >> 5) & 0x07,
            value: byte & 0x1F,
        }
    }

    /// Get timer value in seconds
    pub fn to_seconds(&self) -> Option<u32> {
        match self.unit {
            Self::UNIT_2_SECONDS => Some(self.value as u32 * 2),
            Self::UNIT_1_MINUTE => Some(self.value as u32 * 60),
            Self::UNIT_DECIHOURS => Some(self.value as u32 * 360),
            Self::UNIT_DEACTIVATED => None,
            _ => None,
        }
    }
}

/// GPRS Timer 2 (extended format)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GprsTimer2 {
    /// Length (always 1)
    pub length: u8,
    /// Timer value
    pub value: u8,
}

impl GprsTimer2 {
    /// Create a new GPRS Timer 2
    pub fn new(value: u8) -> Self {
        Self { length: 1, value }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.length);
        buf.put_u8(self.value);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }
        let length = buf.get_u8();
        let value = buf.get_u8();
        Ok(Self { length, value })
    }
}

/// GPRS Timer 3 (extended format with unit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GprsTimer3 {
    /// Length (always 1)
    pub length: u8,
    /// Timer unit
    pub unit: u8,
    /// Timer value
    pub value: u8,
}

impl GprsTimer3 {
    /// Timer unit: 10 minutes
    pub const UNIT_10_MINUTES: u8 = 0;
    /// Timer unit: 1 hour
    pub const UNIT_1_HOUR: u8 = 1;
    /// Timer unit: 10 hours
    pub const UNIT_10_HOURS: u8 = 2;
    /// Timer unit: 2 seconds
    pub const UNIT_2_SECONDS: u8 = 3;
    /// Timer unit: 30 seconds
    pub const UNIT_30_SECONDS: u8 = 4;
    /// Timer unit: 1 minute
    pub const UNIT_1_MINUTE: u8 = 5;
    /// Timer unit: 320 hours
    pub const UNIT_320_HOURS: u8 = 6;
    /// Timer unit: deactivated
    pub const UNIT_DEACTIVATED: u8 = 7;

    /// Create a new GPRS Timer 3
    pub fn new(unit: u8, value: u8) -> Self {
        Self {
            length: 1,
            unit: unit & 0x07,
            value: value & 0x1F,
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.length);
        buf.put_u8(((self.unit & 0x07) << 5) | (self.value & 0x1F));
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }
        let length = buf.get_u8();
        let byte = buf.get_u8();
        Ok(Self {
            length,
            unit: (byte >> 5) & 0x07,
            value: byte & 0x1F,
        })
    }
}

/// DNN (Data Network Name)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dnn {
    /// DNN value (APN format)
    pub value: Vec<u8>,
}

impl Dnn {
    /// Maximum DNN length
    pub const MAX_LEN: usize = 100;

    /// Create a new DNN from string
    pub fn from_str(s: &str) -> Self {
        let mut value = Vec::new();
        for label in s.split('.') {
            value.push(label.len() as u8);
            value.extend_from_slice(label.as_bytes());
        }
        Self { value }
    }

    /// Encode DNN to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.value.len() as u8);
        buf.put_slice(&self.value);
    }

    /// Decode DNN from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 1 {
            return Err(NasError::BufferTooShort { expected: 1, actual: buf.remaining() });
        }
        let len = buf.get_u8() as usize;
        if buf.remaining() < len {
            return Err(NasError::BufferTooShort { expected: len, actual: buf.remaining() });
        }
        let value = buf.copy_to_bytes(len).to_vec();
        Ok(Self { value })
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        let mut result = String::new();
        let mut i = 0;
        while i < self.value.len() {
            let label_len = self.value[i] as usize;
            i += 1;
            if i + label_len > self.value.len() {
                break;
            }
            if !result.is_empty() {
                result.push('.');
            }
            if let Ok(s) = std::str::from_utf8(&self.value[i..i + label_len]) {
                result.push_str(s);
            }
            i += label_len;
        }
        result
    }
}

/// NAS Key Set Identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeySetIdentifier {
    /// TSC (Type of Security Context): 0 = native, 1 = mapped
    pub tsc: u8,
    /// NAS Key Set Identifier value (0-6, 7 = no key available)
    pub value: u8,
}

impl KeySetIdentifier {
    /// No key available
    pub const NO_KEY_AVAILABLE: u8 = 7;

    /// Create a new key set identifier
    pub fn new(tsc: u8, value: u8) -> Self {
        Self {
            tsc: tsc & 0x01,
            value: value & 0x07,
        }
    }

    /// Encode to half-byte (4 bits)
    pub fn encode(&self) -> u8 {
        ((self.tsc & 0x01) << 3) | (self.value & 0x07)
    }

    /// Decode from half-byte
    pub fn decode(byte: u8) -> Self {
        Self {
            tsc: (byte >> 3) & 0x01,
            value: byte & 0x07,
        }
    }
}

/// NAS security algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityAlgorithms {
    /// Ciphering algorithm (EEA/NEA)
    pub ciphering: u8,
    /// Integrity algorithm (EIA/NIA)
    pub integrity: u8,
}

impl SecurityAlgorithms {
    /// No ciphering (EEA0/NEA0)
    pub const CIPHERING_NONE: u8 = 0;
    /// 128-EEA1/128-NEA1 (SNOW 3G)
    pub const CIPHERING_128_EEA1: u8 = 1;
    /// 128-EEA2/128-NEA2 (AES)
    pub const CIPHERING_128_EEA2: u8 = 2;
    /// 128-EEA3/128-NEA3 (ZUC)
    pub const CIPHERING_128_EEA3: u8 = 3;

    /// No integrity (EIA0/NIA0)
    pub const INTEGRITY_NONE: u8 = 0;
    /// 128-EIA1/128-NIA1 (SNOW 3G)
    pub const INTEGRITY_128_EIA1: u8 = 1;
    /// 128-EIA2/128-NIA2 (AES)
    pub const INTEGRITY_128_EIA2: u8 = 2;
    /// 128-EIA3/128-NIA3 (ZUC)
    pub const INTEGRITY_128_EIA3: u8 = 3;

    /// Create new security algorithms
    pub fn new(ciphering: u8, integrity: u8) -> Self {
        Self {
            ciphering: ciphering & 0x0F,
            integrity: integrity & 0x0F,
        }
    }

    /// Encode to a single byte
    pub fn encode(&self) -> u8 {
        ((self.ciphering & 0x0F) << 4) | (self.integrity & 0x0F)
    }

    /// Decode from a single byte
    pub fn decode(byte: u8) -> Self {
        Self {
            ciphering: (byte >> 4) & 0x0F,
            integrity: byte & 0x0F,
        }
    }
}

/// UE security capability
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UeSecurityCapability {
    /// Length
    pub length: u8,
    /// 5GS encryption algorithms (NEA0-NEA7)
    pub ea: u8,
    /// 5GS integrity algorithms (NIA0-NIA7)
    pub ia: u8,
    /// EPS encryption algorithms (EEA0-EEA7) - optional
    pub eea: Option<u8>,
    /// EPS integrity algorithms (EIA0-EIA7) - optional
    pub eia: Option<u8>,
}

impl UeSecurityCapability {
    /// Create a new UE security capability
    pub fn new(ea: u8, ia: u8) -> Self {
        Self {
            length: 2,
            ea,
            ia,
            eea: None,
            eia: None,
        }
    }

    /// Create with EPS capabilities
    pub fn with_eps(ea: u8, ia: u8, eea: u8, eia: u8) -> Self {
        Self {
            length: 4,
            ea,
            ia,
            eea: Some(eea),
            eia: Some(eia),
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.length);
        buf.put_u8(self.ea);
        buf.put_u8(self.ia);
        if let Some(eea) = self.eea {
            buf.put_u8(eea);
        }
        if let Some(eia) = self.eia {
            buf.put_u8(eia);
        }
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }
        let length = buf.get_u8();
        let ea = buf.get_u8();
        let ia = buf.get_u8();

        let mut cap = Self::new(ea, ia);
        cap.length = length;

        if length >= 3 && buf.remaining() >= 1 {
            cap.eea = Some(buf.get_u8());
        }
        if length >= 4 && buf.remaining() >= 1 {
            cap.eia = Some(buf.get_u8());
        }

        Ok(cap)
    }
}

/// Authentication parameter RAND (16 bytes)
pub type AuthenticationRand = [u8; 16];

/// Authentication parameter AUTN (16 bytes)
pub type AuthenticationAutn = [u8; 16];

/// Authentication response parameter (RES/RES*)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthenticationResponseParameter {
    /// Length
    pub length: u8,
    /// Response value
    pub res: Vec<u8>,
}

impl AuthenticationResponseParameter {
    /// Create a new authentication response parameter
    pub fn new(res: Vec<u8>) -> Self {
        Self {
            length: res.len() as u8,
            res,
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.length);
        buf.put_slice(&self.res);
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
        let res = buf.copy_to_bytes(length as usize).to_vec();
        Ok(Self { length, res })
    }
}

/// ABBA (Anti-Bidding down Between Architectures)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Abba {
    /// Length
    pub length: u8,
    /// ABBA contents
    pub contents: Vec<u8>,
}

impl Abba {
    /// Create a new ABBA
    pub fn new(contents: Vec<u8>) -> Self {
        Self {
            length: contents.len() as u8,
            contents,
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.length);
        buf.put_slice(&self.contents);
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
        let contents = buf.copy_to_bytes(length as usize).to_vec();
        Ok(Self { length, contents })
    }
}

/// EAP message container
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EapMessage {
    /// Length (2 bytes)
    pub length: u16,
    /// EAP message data
    pub data: Vec<u8>,
}

impl EapMessage {
    /// Create a new EAP message
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
