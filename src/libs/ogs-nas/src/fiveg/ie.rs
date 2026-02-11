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

// =========================================================================
// 5GSM Information Elements
// =========================================================================

/// PDU session type (TS 24.501 Section 9.11.4.11)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PduSessionType {
    #[default]
    Ipv4 = 1,
    Ipv6 = 2,
    Ipv4v6 = 3,
    Unstructured = 4,
    Ethernet = 5,
}

/// SSC mode (TS 24.501 Section 9.11.4.16)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SscMode {
    #[default]
    SscMode1 = 1,
    SscMode2 = 2,
    SscMode3 = 3,
}

/// 5GSM cause values (TS 24.501 Section 9.11.4.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum FiveGsmCause {
    #[default]
    OperatorDeterminedBarring = 8,
    InsufficientResources = 26,
    MissingOrUnknownDnn = 27,
    UnknownPduSessionType = 28,
    UserAuthenticationOrAuthorizationFailed = 29,
    RequestRejectedUnspecified = 31,
    ServiceOptionNotSupported = 32,
    RequestedServiceOptionNotSubscribed = 33,
    RegularDeactivation = 36,
    NetworkFailure = 38,
    ReactivationRequested = 39,
    PduSessionDoesNotExist = 43,
    PtiMismatch = 44,
    SyntacticalErrorInPacketFilter = 45,
    InvalidPduSessionIdentity = 46,
    PtiAlreadyInUse = 47,
    OutOfLadnServiceArea = 48,
    SemanticErrorsInPacketFilter = 49,
    InsufficientResourcesForSliceAndDnn = 67,
    NotSupportedSscMode = 68,
    InsufficientResourcesForSlice = 69,
    MissingOrUnknownDnnInSlice = 70,
    SemanticallyIncorrectMessage = 95,
    InvalidMandatoryInformation = 96,
    MessageTypeNonExistent = 97,
    MessageTypeNotCompatible = 98,
    InformationElementNonExistent = 99,
    ConditionalIeError = 100,
    MessageNotCompatibleWithProtocolState = 101,
    ProtocolErrorUnspecified = 111,
}

impl FiveGsmCause {
    pub fn from_u8(v: u8) -> u8 {
        v
    }
}

/// QoS rules (TS 24.501 Section 9.11.4.13)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QosRules {
    pub length: u16,
    pub data: Vec<u8>,
}

impl QosRules {
    pub fn new(data: Vec<u8>) -> Self {
        Self { length: data.len() as u16, data }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.length);
        buf.put_slice(&self.data);
    }

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

/// QoS flow descriptions (TS 24.501 Section 9.11.4.12)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QosFlowDescriptions {
    pub length: u16,
    pub data: Vec<u8>,
}

impl QosFlowDescriptions {
    pub fn new(data: Vec<u8>) -> Self {
        Self { length: data.len() as u16, data }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.length);
        buf.put_slice(&self.data);
    }

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

/// Session AMBR (TS 24.501 Section 9.11.4.14)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionAmbr {
    pub length: u8,
    pub dl_unit: u8,
    pub dl_value: u16,
    pub ul_unit: u8,
    pub ul_value: u16,
}

impl SessionAmbr {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(6); // Length
        buf.put_u8(self.dl_unit);
        buf.put_u16(self.dl_value);
        buf.put_u8(self.ul_unit);
        buf.put_u16(self.ul_value);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 7 {
            return Err(NasError::BufferTooShort { expected: 7, actual: buf.remaining() });
        }
        let length = buf.get_u8();
        let dl_unit = buf.get_u8();
        let dl_value = buf.get_u16();
        let ul_unit = buf.get_u8();
        let ul_value = buf.get_u16();
        if length > 6 {
            buf.advance((length - 6) as usize);
        }
        Ok(Self { length, dl_unit, dl_value, ul_unit, ul_value })
    }
}

/// PDU address (TS 24.501 Section 9.11.4.10)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PduAddress {
    pub pdu_session_type: u8,
    pub address: Vec<u8>,
}

impl PduAddress {
    pub fn encode(&self, buf: &mut BytesMut) {
        let len = 1 + self.address.len();
        buf.put_u8(len as u8);
        buf.put_u8(self.pdu_session_type & 0x07);
        buf.put_slice(&self.address);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 2 {
            return Err(NasError::BufferTooShort { expected: 2, actual: buf.remaining() });
        }
        let length = buf.get_u8() as usize;
        if buf.remaining() < length {
            return Err(NasError::BufferTooShort { expected: length, actual: buf.remaining() });
        }
        let pdu_session_type = buf.get_u8() & 0x07;
        let address = if length > 1 {
            buf.copy_to_bytes(length - 1).to_vec()
        } else {
            Vec::new()
        };
        Ok(Self { pdu_session_type, address })
    }
}

// ============================================================================
// 6G Extension IEs (Rel-20)
// ============================================================================

/// AI/ML Capability IE (6G extension)
///
/// Indicates the UE's AI/ML capabilities for 6G systems.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AiMlCapability {
    /// AI/ML capability flags (FL, inference, training, beam mgmt, CSI, positioning)
    pub capability_flags: u8,
    /// Maximum model size supported (in KB)
    pub max_model_size_kb: u16,
}

impl AiMlCapability {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(3); // length
        buf.put_u8(self.capability_flags);
        buf.put_u16(self.max_model_size_kb);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 4 {
            return Err(NasError::BufferTooShort { expected: 4, actual: buf.remaining() });
        }
        let length = buf.get_u8() as usize;
        let capability_flags = buf.get_u8();
        let max_model_size_kb = buf.get_u16();
        if length > 3 { buf.advance(length - 3); }
        Ok(Self { capability_flags, max_model_size_kb })
    }
}

/// ISAC (Integrated Sensing and Communication) Parameter IE (6G extension)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IsacParameter {
    /// Mode flags (monostatic, bistatic, comm-assisted, sensing-assisted)
    pub mode_flags: u8,
    /// Sensing resolution
    pub sensing_resolution: u8,
    /// Maximum sensing range
    pub max_sensing_range: u8,
}

impl IsacParameter {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(3);
        buf.put_u8(self.mode_flags);
        buf.put_u8(self.sensing_resolution);
        buf.put_u8(self.max_sensing_range);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 4 {
            return Err(NasError::BufferTooShort { expected: 4, actual: buf.remaining() });
        }
        let length = buf.get_u8() as usize;
        let mode_flags = buf.get_u8();
        let sensing_resolution = buf.get_u8();
        let max_sensing_range = buf.get_u8();
        if length > 3 { buf.advance(length - 3); }
        Ok(Self { mode_flags, sensing_resolution, max_sensing_range })
    }
}

/// Semantic Communication Parameter IE (6G extension)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SemanticCommParameter {
    /// Capability flags (extraction, encoding, decoding, task-oriented)
    pub capability_flags: u8,
    /// Supported semantic codec type
    pub codec_type: u8,
}

impl SemanticCommParameter {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(2);
        buf.put_u8(self.capability_flags);
        buf.put_u8(self.codec_type);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 3 {
            return Err(NasError::BufferTooShort { expected: 3, actual: buf.remaining() });
        }
        let length = buf.get_u8() as usize;
        let capability_flags = buf.get_u8();
        let codec_type = buf.get_u8();
        if length > 2 { buf.advance(length - 2); }
        Ok(Self { capability_flags, codec_type })
    }
}

/// Sub-THz Band Parameter IE (6G extension)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubThzBandParameter {
    /// Supported sub-THz band flags (100-200 GHz, 200-300 GHz, 300-450 GHz)
    pub band_flags: u8,
    /// Maximum supported bandwidth in MHz
    pub max_bandwidth_mhz: u16,
    /// Minimum beam tracking interval in ms
    pub beam_tracking_interval_ms: u8,
}

impl SubThzBandParameter {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(4);
        buf.put_u8(self.band_flags);
        buf.put_u16(self.max_bandwidth_mhz);
        buf.put_u8(self.beam_tracking_interval_ms);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 5 {
            return Err(NasError::BufferTooShort { expected: 5, actual: buf.remaining() });
        }
        let length = buf.get_u8() as usize;
        let band_flags = buf.get_u8();
        let max_bandwidth_mhz = buf.get_u16();
        let beam_tracking_interval_ms = buf.get_u8();
        if length > 4 { buf.advance(length - 4); }
        Ok(Self { band_flags, max_bandwidth_mhz, beam_tracking_interval_ms })
    }
}

/// NTN Timing Advance IE (6G extension)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NtnTimingAdvance {
    /// Timing advance value (in units of 0.5 microseconds)
    pub timing_advance: u32,
    /// UE-specific timing advance valid flag
    pub ta_valid: bool,
}

impl NtnTimingAdvance {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(5);
        buf.put_u32(self.timing_advance);
        buf.put_u8(if self.ta_valid { 0x01 } else { 0x00 });
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 6 {
            return Err(NasError::BufferTooShort { expected: 6, actual: buf.remaining() });
        }
        let length = buf.get_u8() as usize;
        let timing_advance = buf.get_u32();
        let flags = buf.get_u8();
        if length > 5 { buf.advance(length - 5); }
        Ok(Self { timing_advance, ta_valid: (flags & 0x01) != 0 })
    }
}

/// NTN Access Barring IE (6G extension)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NtnAccessBarring {
    /// Access barring factor (0-100, percentage)
    pub barring_factor: u8,
    /// Access barring time in seconds
    pub barring_time_seconds: u16,
    /// Access class barring flags
    pub ac_barring_flags: u16,
}

impl NtnAccessBarring {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(5);
        buf.put_u8(self.barring_factor);
        buf.put_u16(self.barring_time_seconds);
        buf.put_u16(self.ac_barring_flags);
    }

    pub fn decode(buf: &mut Bytes) -> NasResult<Self> {
        if buf.remaining() < 6 {
            return Err(NasError::BufferTooShort { expected: 6, actual: buf.remaining() });
        }
        let length = buf.get_u8() as usize;
        let barring_factor = buf.get_u8();
        let barring_time_seconds = buf.get_u16();
        let ac_barring_flags = buf.get_u16();
        if length > 5 { buf.advance(length - 5); }
        Ok(Self { barring_factor, barring_time_seconds, ac_barring_flags })
    }
}
