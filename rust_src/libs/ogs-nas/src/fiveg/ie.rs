//! 5GS NAS Information Elements
//!
//! Based on 3GPP TS 24.501 Section 9.11

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{NasError, NasResult};
use crate::common::types::*;

/// 5GMM capability (TS 24.501 Section 9.11.3.1)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FiveGmmCapability {
    /// Length
    pub length: u8,
    /// S1 mode supported
    pub s1_mode: bool,
    /// HO attach supported
    pub ho_attach: bool,
    /// LPP capability
    pub lpp: bool,
    /// Additional capabilities
    pub additional: Vec<u8>,
}

impl FiveGmmCapability {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.length);
        let mut byte = 0u8;
        if self.s1_mode { byte |= 0x01; }
        if self.ho_attach { byte |= 0x02; }
        if self.lpp { byte |= 0x04; }
        buf.put_u8(byte);
        buf.put_slice(&self.additional);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }
        let length = buf.get_u8();
        let byte = buf.get_u8();
        let additional = if length > 1 {
            buf.copy_to_bytes((length - 1) as usize).to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            length,
            s1_mode: (byte & 0x01) != 0,
            ho_attach: (byte & 0x02) != 0,
            lpp: (byte & 0x04) != 0,
            additional,
        })
    }
}

/// NSSAI (Network Slice Selection Assistance Information)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Nssai {
    /// Length
    pub length: u8,
    /// S-NSSAI list
    pub s_nssai_list: Vec<SNssai>,
}

impl Nssai {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();
        buf.put_u8(0); // Placeholder for length
        for s_nssai in &self.s_nssai_list {
            s_nssai.encode(buf);
        }
        let length = buf.len() - start - 1;
        buf[start] = length as u8;
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

        let mut s_nssai_list = Vec::new();
        let mut remaining = length as usize;
        while remaining > 0 {
            let s_nssai = SNssai::decode(buf)?;
            remaining -= 1 + s_nssai.encoded_content_len();
            s_nssai_list.push(s_nssai);
        }

        Ok(Self { length, s_nssai_list })
    }
}

/// PDU session status (TS 24.501 Section 9.11.3.44)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PduSessionStatus {
    /// Length
    pub length: u8,
    /// PSI (PDU Session ID) bitmap - 16 bits for PSI 1-15
    pub psi: u16,
}

impl PduSessionStatus {
    /// Check if a PDU session is active
    pub fn is_active(&self, psi: u8) -> bool {
        if psi == 0 || psi > 15 {
            return false;
        }
        (self.psi & (1 << psi)) != 0
    }

    /// Set PDU session status
    pub fn set_active(&mut self, psi: u8, active: bool) {
        if psi > 0 && psi <= 15 {
            if active {
                self.psi |= 1 << psi;
            } else {
                self.psi &= !(1 << psi);
            }
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(2); // Length
        buf.put_u16(self.psi);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }
        let length = buf.get_u8();
        let psi = buf.get_u16();
        // Skip any additional bytes
        if length > 2 {
            buf.advance((length - 2) as usize);
        }
        Ok(Self { length, psi })
    }
}

/// Uplink data status (TS 24.501 Section 9.11.3.57)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UplinkDataStatus {
    /// Length
    pub length: u8,
    /// PSI bitmap
    pub psi: u16,
}

impl UplinkDataStatus {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(2);
        buf.put_u16(self.psi);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }
        let length = buf.get_u8();
        let psi = buf.get_u16();
        if length > 2 {
            buf.advance((length - 2) as usize);
        }
        Ok(Self { length, psi })
    }
}

/// Allowed PDU session status (TS 24.501 Section 9.11.3.13)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AllowedPduSessionStatus {
    /// Length
    pub length: u8,
    /// PSI bitmap
    pub psi: u16,
}

impl AllowedPduSessionStatus {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(2);
        buf.put_u16(self.psi);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }
        let length = buf.get_u8();
        let psi = buf.get_u16();
        if length > 2 {
            buf.advance((length - 2) as usize);
        }
        Ok(Self { length, psi })
    }
}

/// NAS message container (TS 24.501 Section 9.11.3.33)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NasMessageContainer {
    /// Length (2 bytes)
    pub length: u16,
    /// NAS message data
    pub data: Vec<u8>,
}

impl NasMessageContainer {
    /// Create a new NAS message container
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

/// Payload container type (TS 24.501 Section 9.11.3.40)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PayloadContainerType {
    #[default]
    N1SmInformation = 1,
    SmsContainer = 2,
    LppMessage = 3,
    SorTransparentContainer = 4,
    UeParametersUpdateTransparentContainer = 5,
    UePolicyContainer = 6,
    UeParametersUpdateTransparentContainerForUeInitiated = 7,
    MultiplePayloads = 8,
    EventNotification = 9,
}

/// Payload container (TS 24.501 Section 9.11.3.39)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PayloadContainer {
    /// Length (2 bytes)
    pub length: u16,
    /// Payload data
    pub data: Vec<u8>,
}

impl PayloadContainer {
    /// Create a new payload container
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

/// Request type (TS 24.501 Section 9.11.3.47)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RequestType {
    #[default]
    InitialRequest = 1,
    ExistingPduSession = 2,
    InitialEmergencyRequest = 3,
    ExistingEmergencyPduSession = 4,
    ModificationRequest = 5,
    MaPduRequest = 6,
}

/// PDU session identity (TS 24.501 Section 9.11.3.41)
pub type PduSessionIdentity = u8;

/// 5GS identity type (TS 24.501 Section 9.11.3.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum FiveGsIdentityType {
    #[default]
    Suci = 1,
    FiveGGuti = 2,
    Imei = 3,
    FiveGSTmsi = 4,
    Imeisv = 5,
    MacAddress = 6,
    Eui64 = 7,
}

/// MICO indication (TS 24.501 Section 9.11.3.31)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MicoIndication {
    /// Spare and RAAI
    pub raai: bool,
    /// SPRTI
    pub sprti: bool,
}

impl MicoIndication {
    /// Encode to half-byte
    pub fn encode(&self) -> u8 {
        let mut byte = 0u8;
        if self.raai { byte |= 0x01; }
        if self.sprti { byte |= 0x02; }
        byte
    }

    /// Decode from half-byte
    pub fn decode(byte: u8) -> Self {
        Self {
            raai: (byte & 0x01) != 0,
            sprti: (byte & 0x02) != 0,
        }
    }
}

/// Network slicing indication (TS 24.501 Section 9.11.3.36)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkSlicingIndication {
    /// NSSCI
    pub nssci: bool,
    /// DCNI
    pub dcni: bool,
}

impl NetworkSlicingIndication {
    /// Encode to half-byte
    pub fn encode(&self) -> u8 {
        let mut byte = 0u8;
        if self.nssci { byte |= 0x01; }
        if self.dcni { byte |= 0x02; }
        byte
    }

    /// Decode from half-byte
    pub fn decode(byte: u8) -> Self {
        Self {
            nssci: (byte & 0x01) != 0,
            dcni: (byte & 0x02) != 0,
        }
    }
}
