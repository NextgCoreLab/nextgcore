//! GTPv2 Information Elements
//!
//! Information Element types and encoding/decoding for GTPv2-C protocol.

use crate::error::{GtpError, GtpResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

/// GTPv2 IE Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2IeType {
    Imsi = 1,
    Cause = 2,
    Recovery = 3,
    StnSr = 51,
    SrvccCause = 56,
    Apn = 71,
    Ambr = 72,
    Ebi = 73,
    IpAddress = 74,
    Mei = 75,
    Msisdn = 76,
    Indication = 77,
    Pco = 78,
    Paa = 79,
    BearerQos = 80,
    FlowQos = 81,
    RatType = 82,
    ServingNetwork = 83,
    BearerTft = 84,
    Tad = 85,
    Uli = 86,
    FTeid = 87,
    Tmsi = 88,
    GlobalCnId = 89,
    S103pdf = 90,
    S1udf = 91,
    DelayValue = 92,
    BearerContext = 93,
    ChargingId = 94,
    ChargingCharacteristics = 95,
    TraceInformation = 96,
    BearerFlags = 97,
    PdnType = 99,
    Pti = 100,
    MmContext = 107,
    PdnConnection = 109,
    PduNumbers = 110,
    PTmsi = 111,
    PTmsiSignature = 112,
    HopCounter = 113,
    UeTimeZone = 114,
    TraceReference = 115,
    CompleteRequestMessage = 116,
    Guti = 117,
    FContainer = 118,
    FCause = 119,
    PlmnId = 120,
    TargetIdentification = 121,
    PacketFlowId = 123,
    RabContext = 124,
    SourceRncPdcpContextInfo = 125,
    PortNumber = 126,
    ApnRestriction = 127,
    SelectionMode = 128,
    SourceIdentification = 129,
    ChangeReportingAction = 131,
    FqCsid = 132,
    ChannelNeeded = 133,
    EmlppPriority = 134,
    NodeType = 135,
    Fqdn = 136,
    Ti = 137,
    Arp = 155,
    NodeIdentifier = 176,
}

impl TryFrom<u8> for Gtp2IeType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Imsi),
            2 => Ok(Self::Cause),
            3 => Ok(Self::Recovery),
            51 => Ok(Self::StnSr),
            56 => Ok(Self::SrvccCause),
            71 => Ok(Self::Apn),
            72 => Ok(Self::Ambr),
            73 => Ok(Self::Ebi),
            74 => Ok(Self::IpAddress),
            75 => Ok(Self::Mei),
            76 => Ok(Self::Msisdn),
            77 => Ok(Self::Indication),
            78 => Ok(Self::Pco),
            79 => Ok(Self::Paa),
            80 => Ok(Self::BearerQos),
            81 => Ok(Self::FlowQos),
            82 => Ok(Self::RatType),
            83 => Ok(Self::ServingNetwork),
            84 => Ok(Self::BearerTft),
            85 => Ok(Self::Tad),
            86 => Ok(Self::Uli),
            87 => Ok(Self::FTeid),
            88 => Ok(Self::Tmsi),
            89 => Ok(Self::GlobalCnId),
            90 => Ok(Self::S103pdf),
            91 => Ok(Self::S1udf),
            92 => Ok(Self::DelayValue),
            93 => Ok(Self::BearerContext),
            94 => Ok(Self::ChargingId),
            95 => Ok(Self::ChargingCharacteristics),
            96 => Ok(Self::TraceInformation),
            97 => Ok(Self::BearerFlags),
            99 => Ok(Self::PdnType),
            100 => Ok(Self::Pti),
            107 => Ok(Self::MmContext),
            109 => Ok(Self::PdnConnection),
            110 => Ok(Self::PduNumbers),
            111 => Ok(Self::PTmsi),
            112 => Ok(Self::PTmsiSignature),
            113 => Ok(Self::HopCounter),
            114 => Ok(Self::UeTimeZone),
            115 => Ok(Self::TraceReference),
            116 => Ok(Self::CompleteRequestMessage),
            117 => Ok(Self::Guti),
            118 => Ok(Self::FContainer),
            119 => Ok(Self::FCause),
            120 => Ok(Self::PlmnId),
            121 => Ok(Self::TargetIdentification),
            123 => Ok(Self::PacketFlowId),
            124 => Ok(Self::RabContext),
            125 => Ok(Self::SourceRncPdcpContextInfo),
            126 => Ok(Self::PortNumber),
            127 => Ok(Self::ApnRestriction),
            128 => Ok(Self::SelectionMode),
            129 => Ok(Self::SourceIdentification),
            131 => Ok(Self::ChangeReportingAction),
            132 => Ok(Self::FqCsid),
            133 => Ok(Self::ChannelNeeded),
            134 => Ok(Self::EmlppPriority),
            135 => Ok(Self::NodeType),
            136 => Ok(Self::Fqdn),
            137 => Ok(Self::Ti),
            155 => Ok(Self::Arp),
            176 => Ok(Self::NodeIdentifier),
            _ => Err(GtpError::InvalidIeType(value)),
        }
    }
}

/// Generic GTPv2 Information Element
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2Ie {
    /// IE Type
    pub ie_type: u8,
    /// IE Instance (4 bits)
    pub instance: u8,
    /// IE Value (raw bytes)
    pub value: Bytes,
}

impl Gtp2Ie {
    /// Create a new IE
    pub fn new(ie_type: u8, instance: u8, value: Bytes) -> Self {
        Self {
            ie_type,
            instance: instance & 0x0F,
            value,
        }
    }

    /// Create a new IE from slice
    pub fn from_slice(ie_type: u8, instance: u8, value: &[u8]) -> Self {
        Self {
            ie_type,
            instance: instance & 0x0F,
            value: Bytes::copy_from_slice(value),
        }
    }

    /// Encode IE to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ie_type);
        buf.put_u16(self.value.len() as u16);
        buf.put_u8(self.instance & 0x0F);
        buf.put_slice(&self.value);
    }

    /// Decode IE from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 4 {
            return Err(GtpError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }

        let ie_type = buf.get_u8();
        let length = buf.get_u16() as usize;
        let instance = buf.get_u8() & 0x0F;

        if buf.remaining() < length {
            return Err(GtpError::BufferTooShort {
                needed: length,
                available: buf.remaining(),
            });
        }

        let value = buf.copy_to_bytes(length);
        Ok(Self {
            ie_type,
            instance,
            value,
        })
    }

    /// Get encoded length
    pub fn encoded_len(&self) -> usize {
        4 + self.value.len() // Type(1) + Length(2) + Instance(1) + Value
    }
}

/// Recovery IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtp2RecoveryIe {
    pub restart_counter: u8,
}

impl Gtp2RecoveryIe {
    pub fn new(restart_counter: u8) -> Self {
        Self { restart_counter }
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::Recovery as u8);
        buf.put_u16(1); // Length
        buf.put_u8(instance & 0x0F);
        buf.put_u8(self.restart_counter);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.is_empty() {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        Ok(Self {
            restart_counter: value[0],
        })
    }
}

/// EBI (EPS Bearer Identity) IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtp2EbiIe {
    pub ebi: u8,
}

impl Gtp2EbiIe {
    pub fn new(ebi: u8) -> Self {
        Self { ebi: ebi & 0x0F }
    }

    /// Convert to a generic IE (useful for nesting in grouped IEs)
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, instance, &[self.ebi & 0x0F])
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::Ebi as u8);
        buf.put_u16(1); // Length
        buf.put_u8(instance & 0x0F);
        buf.put_u8(self.ebi & 0x0F);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.is_empty() {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        Ok(Self {
            ebi: value[0] & 0x0F,
        })
    }
}

/// RAT Type IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtp2RatTypeIe {
    pub rat_type: u8,
}

impl Gtp2RatTypeIe {
    pub fn new(rat_type: u8) -> Self {
        Self { rat_type }
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::RatType as u8);
        buf.put_u16(1); // Length
        buf.put_u8(instance & 0x0F);
        buf.put_u8(self.rat_type);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.is_empty() {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        Ok(Self { rat_type: value[0] })
    }
}

/// APN Restriction IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtp2ApnRestrictionIe {
    pub restriction: u8,
}

impl Gtp2ApnRestrictionIe {
    pub fn new(restriction: u8) -> Self {
        Self { restriction }
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::ApnRestriction as u8);
        buf.put_u16(1); // Length
        buf.put_u8(instance & 0x0F);
        buf.put_u8(self.restriction);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.is_empty() {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        Ok(Self {
            restriction: value[0],
        })
    }
}

/// Selection Mode IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtp2SelectionModeIe {
    pub mode: u8,
}

impl Gtp2SelectionModeIe {
    pub fn new(mode: u8) -> Self {
        Self { mode: mode & 0x03 }
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::SelectionMode as u8);
        buf.put_u16(1); // Length
        buf.put_u8(instance & 0x0F);
        buf.put_u8(self.mode & 0x03);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.is_empty() {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        Ok(Self {
            mode: value[0] & 0x03,
        })
    }
}

/// PDN Type IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtp2PdnTypeIe {
    pub pdn_type: u8,
}

impl Gtp2PdnTypeIe {
    pub fn new(pdn_type: u8) -> Self {
        Self {
            pdn_type: pdn_type & 0x07,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::PdnType as u8);
        buf.put_u16(1); // Length
        buf.put_u8(instance & 0x0F);
        buf.put_u8(self.pdn_type & 0x07);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.is_empty() {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        Ok(Self {
            pdn_type: value[0] & 0x07,
        })
    }
}

/// F-TEID IE (Fully Qualified TEID)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2FTeidIe {
    pub interface_type: u8,
    pub teid: u32,
    pub ipv4_addr: Option<[u8; 4]>,
    pub ipv6_addr: Option<[u8; 16]>,
}

impl Gtp2FTeidIe {
    pub fn new_ipv4(interface_type: u8, teid: u32, ipv4: [u8; 4]) -> Self {
        Self {
            interface_type,
            teid,
            ipv4_addr: Some(ipv4),
            ipv6_addr: None,
        }
    }

    pub fn new_ipv6(interface_type: u8, teid: u32, ipv6: [u8; 16]) -> Self {
        Self {
            interface_type,
            teid,
            ipv4_addr: None,
            ipv6_addr: Some(ipv6),
        }
    }

    pub fn new_dual(interface_type: u8, teid: u32, ipv4: [u8; 4], ipv6: [u8; 16]) -> Self {
        Self {
            interface_type,
            teid,
            ipv4_addr: Some(ipv4),
            ipv6_addr: Some(ipv6),
        }
    }

    /// Encode the IE value octets (without the TLV header)
    pub fn encode_value(&self, buf: &mut BytesMut) {
        let mut flags = self.interface_type & 0x3F;
        if self.ipv4_addr.is_some() {
            flags |= 0x80; // V4 flag
        }
        if self.ipv6_addr.is_some() {
            flags |= 0x40; // V6 flag
        }

        buf.put_u8(flags);
        buf.put_u32(self.teid);

        if let Some(ipv4) = &self.ipv4_addr {
            buf.put_slice(ipv4);
        }
        if let Some(ipv6) = &self.ipv6_addr {
            buf.put_slice(ipv6);
        }
    }

    /// Convert to a generic IE (useful for nesting in grouped IEs)
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);
        Gtp2Ie::new(Gtp2IeType::FTeid as u8, instance, value.freeze())
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);

        buf.put_u8(Gtp2IeType::FTeid as u8);
        buf.put_u16(value.len() as u16);
        buf.put_u8(instance & 0x0F);
        buf.put_slice(&value);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.len() < 5 {
            return Err(GtpError::BufferTooShort {
                needed: 5,
                available: value.len(),
            });
        }

        let flags = value[0];
        let v4 = (flags & 0x80) != 0;
        let v6 = (flags & 0x40) != 0;
        let interface_type = flags & 0x3F;

        let teid = u32::from_be_bytes([value[1], value[2], value[3], value[4]]);

        let mut offset = 5;
        let ipv4_addr = if v4 {
            if value.len() < offset + 4 {
                return Err(GtpError::BufferTooShort {
                    needed: offset + 4,
                    available: value.len(),
                });
            }
            let addr = [
                value[offset],
                value[offset + 1],
                value[offset + 2],
                value[offset + 3],
            ];
            offset += 4;
            Some(addr)
        } else {
            None
        };

        let ipv6_addr = if v6 {
            if value.len() < offset + 16 {
                return Err(GtpError::BufferTooShort {
                    needed: offset + 16,
                    available: value.len(),
                });
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&value[offset..offset + 16]);
            Some(addr)
        } else {
            None
        };

        Ok(Self {
            interface_type,
            teid,
            ipv4_addr,
            ipv6_addr,
        })
    }
}

/// Bearer QoS IE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2BearerQosIe {
    pub pci: bool,
    pub pl: u8,
    pub pvi: bool,
    pub qci: u8,
    pub mbr_ul: u64,
    pub mbr_dl: u64,
    pub gbr_ul: u64,
    pub gbr_dl: u64,
}

impl Gtp2BearerQosIe {
    pub fn new(qci: u8, mbr_ul: u64, mbr_dl: u64, gbr_ul: u64, gbr_dl: u64) -> Self {
        Self {
            pci: false,
            pl: 0,
            pvi: false,
            qci,
            mbr_ul,
            mbr_dl,
            gbr_ul,
            gbr_dl,
        }
    }

    /// Encode the IE value octets (without the TLV header)
    pub fn encode_value(&self, buf: &mut BytesMut) {
        // ARP: PCI(1) + PL(4) + spare(1) + PVI(1) + spare(1)
        let mut arp = 0u8;
        if self.pci {
            arp |= 0x40;
        }
        arp |= (self.pl & 0x0F) << 2;
        if self.pvi {
            arp |= 0x01;
        }
        buf.put_u8(arp);
        buf.put_u8(self.qci);

        // MBR/GBR are 5 bytes each (40 bits)
        buf.put_slice(&self.mbr_ul.to_be_bytes()[3..8]);
        buf.put_slice(&self.mbr_dl.to_be_bytes()[3..8]);
        buf.put_slice(&self.gbr_ul.to_be_bytes()[3..8]);
        buf.put_slice(&self.gbr_dl.to_be_bytes()[3..8]);
    }

    /// Convert to a generic IE (useful for nesting in grouped IEs)
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);
        Gtp2Ie::new(Gtp2IeType::BearerQos as u8, instance, value.freeze())
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::BearerQos as u8);
        buf.put_u16(22); // Length: 1 + 1 + 5*4 = 22
        buf.put_u8(instance & 0x0F);
        self.encode_value(buf);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.len() < 22 {
            return Err(GtpError::BufferTooShort {
                needed: 22,
                available: value.len(),
            });
        }

        let arp = value[0];
        let pci = (arp & 0x40) != 0;
        let pl = (arp >> 2) & 0x0F;
        let pvi = (arp & 0x01) != 0;
        let qci = value[1];

        // Read 5-byte values as u64
        let mbr_ul =
            u64::from_be_bytes([0, 0, 0, value[2], value[3], value[4], value[5], value[6]]);
        let mbr_dl =
            u64::from_be_bytes([0, 0, 0, value[7], value[8], value[9], value[10], value[11]]);
        let gbr_ul = u64::from_be_bytes([
            0, 0, 0, value[12], value[13], value[14], value[15], value[16],
        ]);
        let gbr_dl = u64::from_be_bytes([
            0, 0, 0, value[17], value[18], value[19], value[20], value[21],
        ]);

        Ok(Self {
            pci,
            pl,
            pvi,
            qci,
            mbr_ul,
            mbr_dl,
            gbr_ul,
            gbr_dl,
        })
    }
}

/// AMBR IE (Aggregate Maximum Bit Rate)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtp2AmbrIe {
    pub uplink: u32,
    pub downlink: u32,
}

impl Gtp2AmbrIe {
    pub fn new(uplink: u32, downlink: u32) -> Self {
        Self { uplink, downlink }
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::Ambr as u8);
        buf.put_u16(8); // Length
        buf.put_u8(instance & 0x0F);
        buf.put_u32(self.uplink);
        buf.put_u32(self.downlink);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.len() < 8 {
            return Err(GtpError::BufferTooShort {
                needed: 8,
                available: value.len(),
            });
        }
        let uplink = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        let downlink = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
        Ok(Self { uplink, downlink })
    }
}

/// Cause IE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2CauseIe {
    pub cause: u8,
    pub pce: bool,
    pub bce: bool,
    pub cs: bool,
    pub offending_ie_type: Option<u8>,
    pub offending_ie_length: Option<u16>,
    pub offending_ie_instance: Option<u8>,
}

impl Gtp2CauseIe {
    pub fn new(cause: u8) -> Self {
        Self {
            cause,
            pce: false,
            bce: false,
            cs: false,
            offending_ie_type: None,
            offending_ie_length: None,
            offending_ie_instance: None,
        }
    }

    pub fn with_offending_ie(cause: u8, ie_type: u8, ie_length: u16, ie_instance: u8) -> Self {
        Self {
            cause,
            pce: false,
            bce: false,
            cs: false,
            offending_ie_type: Some(ie_type),
            offending_ie_length: Some(ie_length),
            offending_ie_instance: Some(ie_instance),
        }
    }

    /// Encode the IE value octets (without the TLV header)
    pub fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8(self.cause);

        let mut flags = 0u8;
        if self.pce {
            flags |= 0x04;
        }
        if self.bce {
            flags |= 0x02;
        }
        if self.cs {
            flags |= 0x01;
        }
        buf.put_u8(flags);

        if self.offending_ie_type.is_some() {
            buf.put_u8(self.offending_ie_type.unwrap_or(0));
            buf.put_u16(self.offending_ie_length.unwrap_or(0));
            buf.put_u8(self.offending_ie_instance.unwrap_or(0) & 0x0F);
        }
    }

    /// Convert to a generic IE (useful for nesting in grouped IEs)
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);
        Gtp2Ie::new(Gtp2IeType::Cause as u8, instance, value.freeze())
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        let length = if self.offending_ie_type.is_some() {
            6
        } else {
            2
        };

        buf.put_u8(Gtp2IeType::Cause as u8);
        buf.put_u16(length);
        buf.put_u8(instance & 0x0F);
        self.encode_value(buf);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.len() < 2 {
            return Err(GtpError::BufferTooShort {
                needed: 2,
                available: value.len(),
            });
        }

        let cause = value[0];
        let flags = value[1];
        let pce = (flags & 0x04) != 0;
        let bce = (flags & 0x02) != 0;
        let cs = (flags & 0x01) != 0;

        let (offending_ie_type, offending_ie_length, offending_ie_instance) = if value.len() >= 6 {
            (
                Some(value[2]),
                Some(u16::from_be_bytes([value[3], value[4]])),
                Some(value[5] & 0x0F),
            )
        } else {
            (None, None, None)
        };

        Ok(Self {
            cause,
            pce,
            bce,
            cs,
            offending_ie_type,
            offending_ie_length,
            offending_ie_instance,
        })
    }
}

/// ULI (User Location Information) IE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2UliIe {
    pub flags: u8,
    pub data: Bytes,
}

impl Gtp2UliIe {
    pub fn new(flags: u8, data: Bytes) -> Self {
        Self { flags, data }
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::Uli as u8);
        buf.put_u16((1 + self.data.len()) as u16);
        buf.put_u8(instance & 0x0F);
        buf.put_u8(self.flags);
        buf.put_slice(&self.data);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.is_empty() {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        let flags = value[0];
        let data = value.slice(1..);
        Ok(Self { flags, data })
    }
}

/// Serving Network IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtp2ServingNetworkIe {
    pub mcc: [u8; 3],
    pub mnc: [u8; 3],
}

impl Gtp2ServingNetworkIe {
    pub fn new(mcc: [u8; 3], mnc: [u8; 3]) -> Self {
        Self { mcc, mnc }
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::ServingNetwork as u8);
        buf.put_u16(3); // Length
        buf.put_u8(instance & 0x0F);

        // PLMN encoding: MCC digit 2 | MCC digit 1, MNC digit 3 | MCC digit 3, MNC digit 2 | MNC digit 1
        buf.put_u8((self.mcc[1] << 4) | self.mcc[0]);
        buf.put_u8((self.mnc[2] << 4) | self.mcc[2]);
        buf.put_u8((self.mnc[1] << 4) | self.mnc[0]);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.len() < 3 {
            return Err(GtpError::BufferTooShort {
                needed: 3,
                available: value.len(),
            });
        }

        let mcc = [value[0] & 0x0F, (value[0] >> 4) & 0x0F, value[1] & 0x0F];
        let mnc = [
            value[2] & 0x0F,
            (value[2] >> 4) & 0x0F,
            (value[1] >> 4) & 0x0F,
        ];

        Ok(Self { mcc, mnc })
    }
}

/// APN IE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2ApnIe {
    pub apn: Vec<u8>,
}

impl Gtp2ApnIe {
    pub fn new(apn: Vec<u8>) -> Self {
        Self { apn }
    }

    pub fn from_string(apn: &str) -> Self {
        // Convert dot-separated APN to length-prefixed format
        let mut encoded = Vec::new();
        for part in apn.split('.') {
            encoded.push(part.len() as u8);
            encoded.extend_from_slice(part.as_bytes());
        }
        Self { apn: encoded }
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::Apn as u8);
        buf.put_u16(self.apn.len() as u16);
        buf.put_u8(instance & 0x0F);
        buf.put_slice(&self.apn);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        Ok(Self {
            apn: value.to_vec(),
        })
    }
}

impl fmt::Display for Gtp2ApnIe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut i = 0;
        while i < self.apn.len() {
            let len = self.apn[i] as usize;
            if i + 1 + len > self.apn.len() {
                break;
            }
            if !first {
                write!(f, ".")?;
            }
            first = false;
            if let Ok(s) = std::str::from_utf8(&self.apn[i + 1..i + 1 + len]) {
                write!(f, "{s}")?;
            }
            i += 1 + len;
        }
        Ok(())
    }
}

/// PAA (PDN Address Allocation) IE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2PaaIe {
    pub pdn_type: u8,
    pub ipv4_addr: Option<[u8; 4]>,
    pub ipv6_prefix_len: Option<u8>,
    pub ipv6_addr: Option<[u8; 16]>,
}

impl Gtp2PaaIe {
    pub fn ipv4(addr: [u8; 4]) -> Self {
        Self {
            pdn_type: 1, // IPv4
            ipv4_addr: Some(addr),
            ipv6_prefix_len: None,
            ipv6_addr: None,
        }
    }

    pub fn ipv6(prefix_len: u8, addr: [u8; 16]) -> Self {
        Self {
            pdn_type: 2, // IPv6
            ipv4_addr: None,
            ipv6_prefix_len: Some(prefix_len),
            ipv6_addr: Some(addr),
        }
    }

    pub fn ipv4v6(ipv4: [u8; 4], prefix_len: u8, ipv6: [u8; 16]) -> Self {
        Self {
            pdn_type: 3, // IPv4v6
            ipv4_addr: Some(ipv4),
            ipv6_prefix_len: Some(prefix_len),
            ipv6_addr: Some(ipv6),
        }
    }

    /// Encode the IE value octets (without the TLV header)
    pub fn encode_value(&self, buf: &mut BytesMut) {
        buf.put_u8(self.pdn_type);

        match self.pdn_type {
            1 => {
                if let Some(addr) = &self.ipv4_addr {
                    buf.put_slice(addr);
                }
            }
            2 => {
                buf.put_u8(self.ipv6_prefix_len.unwrap_or(64));
                if let Some(addr) = &self.ipv6_addr {
                    buf.put_slice(addr);
                }
            }
            3 => {
                buf.put_u8(self.ipv6_prefix_len.unwrap_or(64));
                if let Some(addr) = &self.ipv6_addr {
                    buf.put_slice(addr);
                }
                if let Some(addr) = &self.ipv4_addr {
                    buf.put_slice(addr);
                }
            }
            _ => {}
        }
    }

    /// Convert to a generic IE (useful for nesting in grouped IEs)
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);
        Gtp2Ie::new(Gtp2IeType::Paa as u8, instance, value.freeze())
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);

        buf.put_u8(Gtp2IeType::Paa as u8);
        buf.put_u16(value.len() as u16);
        buf.put_u8(instance & 0x0F);
        buf.put_slice(&value);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.is_empty() {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }

        let pdn_type = value[0] & 0x07;

        match pdn_type {
            1 => {
                if value.len() < 5 {
                    return Err(GtpError::BufferTooShort {
                        needed: 5,
                        available: value.len(),
                    });
                }
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&value[1..5]);
                Ok(Self::ipv4(addr))
            }
            2 => {
                if value.len() < 18 {
                    return Err(GtpError::BufferTooShort {
                        needed: 18,
                        available: value.len(),
                    });
                }
                let prefix_len = value[1];
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&value[2..18]);
                Ok(Self::ipv6(prefix_len, addr))
            }
            3 => {
                if value.len() < 22 {
                    return Err(GtpError::BufferTooShort {
                        needed: 22,
                        available: value.len(),
                    });
                }
                let prefix_len = value[1];
                let mut ipv6 = [0u8; 16];
                ipv6.copy_from_slice(&value[2..18]);
                let mut ipv4 = [0u8; 4];
                ipv4.copy_from_slice(&value[18..22]);
                Ok(Self::ipv4v6(ipv4, prefix_len, ipv6))
            }
            _ => Err(GtpError::InvalidPdnType(pdn_type)),
        }
    }
}

/// Bearer Context grouped IE (TS 29.274 Section 8.28)
///
/// The value of a grouped IE is a concatenation of complete nested IEs
/// (each with its own Type/Length/Instance header). Typed accessors are
/// provided for the common nested IEs; everything else is reachable through
/// the generic `ies` list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Gtp2BearerContextIe {
    /// Nested Information Elements
    pub ies: Vec<Gtp2Ie>,
}

impl Gtp2BearerContextIe {
    /// Create an empty Bearer Context
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a nested IE
    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    /// Get a nested IE by type and instance
    pub fn get_ie(&self, ie_type: u8, instance: u8) -> Option<&Gtp2Ie> {
        self.ies
            .iter()
            .find(|ie| ie.ie_type == ie_type && ie.instance == instance)
    }

    /// Set the EPS Bearer ID (mandatory nested IE, instance 0)
    pub fn set_ebi(&mut self, ebi: u8) {
        self.ies.push(Gtp2EbiIe::new(ebi).to_ie(0));
    }

    /// Set an F-TEID with the given instance (e.g. S1-U eNodeB, S5/S8-U SGW)
    pub fn set_fteid(&mut self, instance: u8, fteid: &Gtp2FTeidIe) {
        self.ies.push(fteid.to_ie(instance));
    }

    /// Set the Bearer QoS (instance 0)
    pub fn set_bearer_qos(&mut self, qos: &Gtp2BearerQosIe) {
        self.ies.push(qos.to_ie(0));
    }

    /// Set the Cause (instance 0, used in responses)
    pub fn set_cause(&mut self, cause: &Gtp2CauseIe) {
        self.ies.push(cause.to_ie(0));
    }

    /// Get the EPS Bearer ID (mandatory nested IE)
    pub fn ebi(&self) -> GtpResult<u8> {
        let ie = self
            .get_ie(Gtp2IeType::Ebi as u8, 0)
            .ok_or_else(|| GtpError::MissingMandatoryIe("EBI in Bearer Context".to_string()))?;
        Ok(Gtp2EbiIe::decode(&ie.value)?.ebi)
    }

    /// Get an F-TEID by instance, if present
    pub fn fteid(&self, instance: u8) -> GtpResult<Option<Gtp2FTeidIe>> {
        match self.get_ie(Gtp2IeType::FTeid as u8, instance) {
            Some(ie) => Ok(Some(Gtp2FTeidIe::decode(&ie.value)?)),
            None => Ok(None),
        }
    }

    /// Get the Bearer QoS, if present
    pub fn bearer_qos(&self) -> GtpResult<Option<Gtp2BearerQosIe>> {
        match self.get_ie(Gtp2IeType::BearerQos as u8, 0) {
            Some(ie) => Ok(Some(Gtp2BearerQosIe::decode(&ie.value)?)),
            None => Ok(None),
        }
    }

    /// Get the Cause, if present
    pub fn cause(&self) -> GtpResult<Option<Gtp2CauseIe>> {
        match self.get_ie(Gtp2IeType::Cause as u8, 0) {
            Some(ie) => Ok(Some(Gtp2CauseIe::decode(&ie.value)?)),
            None => Ok(None),
        }
    }

    /// Encode the grouped value octets (concatenated nested IEs)
    pub fn encode_value(&self, buf: &mut BytesMut) {
        for ie in &self.ies {
            ie.encode(buf);
        }
    }

    /// Convert to a generic IE with the given instance
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);
        Gtp2Ie::new(Gtp2IeType::BearerContext as u8, instance, value.freeze())
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);

        buf.put_u8(Gtp2IeType::BearerContext as u8);
        buf.put_u16(value.len() as u16);
        buf.put_u8(instance & 0x0F);
        buf.put_slice(&value);
    }

    /// Decode the nested IEs from a grouped IE value
    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        let mut buf = value.clone();
        let mut ies = Vec::new();
        while buf.remaining() > 0 {
            ies.push(Gtp2Ie::decode(&mut buf)?);
        }
        Ok(Self { ies })
    }
}

/// Indication IE flags (TS 29.274 Section 8.12, octets 5-7)
///
/// Decode tolerates longer values (later flag octets are ignored) and
/// missing trailing octets (their flags read as false). Encode always emits
/// the three flag octets covered here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gtp2IndicationIe {
    // Octet 5
    /// Dual Address Bearer Flag
    pub daf: bool,
    /// Direct Tunnel Flag
    pub dtf: bool,
    /// Handover Indication
    pub hi: bool,
    /// Direct Forwarding Indication
    pub dfi: bool,
    /// Operation Indication
    pub oi: bool,
    /// Idle mode Signalling Reduction Supported Indication
    pub isrsi: bool,
    /// Idle mode Signalling Reduction Activation Indication
    pub israi: bool,
    /// SGW Change Indication
    pub sgwci: bool,
    // Octet 6
    /// Subscribed QoS Change Indication
    pub sqci: bool,
    /// Unauthenticated IMSI
    pub uimsi: bool,
    /// Change F-TEID support Indication
    pub cfsi: bool,
    /// Change Reporting Support Indication
    pub crsi: bool,
    /// Piggybacking Supported
    pub p: bool,
    /// S5/S8 Protocol Type
    pub pt: bool,
    /// Scope Indication
    pub si: bool,
    /// MS Validated
    pub msv: bool,
    // Octet 7
    /// Retrieve Location Indication Flag
    pub retloc: bool,
    /// Propagate BBAI Information Change
    pub pbic: bool,
    /// SGW Restoration Needed Indication
    pub srni: bool,
    /// Static IPv6 Address Flag
    pub s6af: bool,
    /// Static IPv4 Address Flag
    pub s4af: bool,
    /// Management Based MDT allowed flag
    pub mbmdt: bool,
    /// ISR is activated for the UE
    pub israu: bool,
    /// CSG Change Reporting Support Indication
    pub ccrsi: bool,
}

impl Gtp2IndicationIe {
    /// Create an Indication IE with all flags cleared
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode the IE value octets (without the TLV header)
    pub fn encode_value(&self, buf: &mut BytesMut) {
        let octet5 = ((self.daf as u8) << 7)
            | ((self.dtf as u8) << 6)
            | ((self.hi as u8) << 5)
            | ((self.dfi as u8) << 4)
            | ((self.oi as u8) << 3)
            | ((self.isrsi as u8) << 2)
            | ((self.israi as u8) << 1)
            | (self.sgwci as u8);
        let octet6 = ((self.sqci as u8) << 7)
            | ((self.uimsi as u8) << 6)
            | ((self.cfsi as u8) << 5)
            | ((self.crsi as u8) << 4)
            | ((self.p as u8) << 3)
            | ((self.pt as u8) << 2)
            | ((self.si as u8) << 1)
            | (self.msv as u8);
        let octet7 = ((self.retloc as u8) << 7)
            | ((self.pbic as u8) << 6)
            | ((self.srni as u8) << 5)
            | ((self.s6af as u8) << 4)
            | ((self.s4af as u8) << 3)
            | ((self.mbmdt as u8) << 2)
            | ((self.israu as u8) << 1)
            | (self.ccrsi as u8);
        buf.put_u8(octet5);
        buf.put_u8(octet6);
        buf.put_u8(octet7);
    }

    /// Convert to a generic IE
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);
        Gtp2Ie::new(Gtp2IeType::Indication as u8, instance, value.freeze())
    }

    pub fn encode(&self, buf: &mut BytesMut, instance: u8) {
        buf.put_u8(Gtp2IeType::Indication as u8);
        buf.put_u16(3); // Length: 3 flag octets
        buf.put_u8(instance & 0x0F);
        self.encode_value(buf);
    }

    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.is_empty() {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }

        let octet5 = value[0];
        let octet6 = value.get(1).copied().unwrap_or(0);
        let octet7 = value.get(2).copied().unwrap_or(0);

        Ok(Self {
            daf: (octet5 >> 7) & 0x01 != 0,
            dtf: (octet5 >> 6) & 0x01 != 0,
            hi: (octet5 >> 5) & 0x01 != 0,
            dfi: (octet5 >> 4) & 0x01 != 0,
            oi: (octet5 >> 3) & 0x01 != 0,
            isrsi: (octet5 >> 2) & 0x01 != 0,
            israi: (octet5 >> 1) & 0x01 != 0,
            sgwci: octet5 & 0x01 != 0,
            sqci: (octet6 >> 7) & 0x01 != 0,
            uimsi: (octet6 >> 6) & 0x01 != 0,
            cfsi: (octet6 >> 5) & 0x01 != 0,
            crsi: (octet6 >> 4) & 0x01 != 0,
            p: (octet6 >> 3) & 0x01 != 0,
            pt: (octet6 >> 2) & 0x01 != 0,
            si: (octet6 >> 1) & 0x01 != 0,
            msv: octet6 & 0x01 != 0,
            retloc: (octet7 >> 7) & 0x01 != 0,
            pbic: (octet7 >> 6) & 0x01 != 0,
            srni: (octet7 >> 5) & 0x01 != 0,
            s6af: (octet7 >> 4) & 0x01 != 0,
            s4af: (octet7 >> 3) & 0x01 != 0,
            mbmdt: (octet7 >> 2) & 0x01 != 0,
            israu: (octet7 >> 1) & 0x01 != 0,
            ccrsi: octet7 & 0x01 != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_ie_encode_decode() {
        let ie = Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[42]);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Gtp2Ie::decode(&mut bytes).unwrap();

        assert_eq!(decoded.ie_type, Gtp2IeType::Recovery as u8);
        assert_eq!(decoded.instance, 0);
        assert_eq!(decoded.value[0], 42);
    }

    #[test]
    fn test_recovery_ie() {
        let ie = Gtp2RecoveryIe::new(42);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf, 0);

        assert_eq!(buf[0], Gtp2IeType::Recovery as u8);
        assert_eq!(&buf[1..3], &[0x00, 0x01]); // Length = 1
        assert_eq!(buf[3], 0); // Instance
        assert_eq!(buf[4], 42); // Value
    }

    #[test]
    fn test_ebi_ie() {
        let ie = Gtp2EbiIe::new(5);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf, 0);

        assert_eq!(buf[0], Gtp2IeType::Ebi as u8);
        assert_eq!(buf[4], 5);
    }

    #[test]
    fn test_fteid_ie_ipv4() {
        let ie = Gtp2FTeidIe::new_ipv4(10, 0x12345678, [192, 168, 1, 1]);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf, 0);

        let value = Bytes::copy_from_slice(&buf[4..]);
        let decoded = Gtp2FTeidIe::decode(&value).unwrap();

        assert_eq!(decoded.interface_type, 10);
        assert_eq!(decoded.teid, 0x12345678);
        assert_eq!(decoded.ipv4_addr, Some([192, 168, 1, 1]));
        assert_eq!(decoded.ipv6_addr, None);
    }

    #[test]
    fn test_ambr_ie() {
        let ie = Gtp2AmbrIe::new(1000000, 2000000);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf, 0);

        let value = Bytes::copy_from_slice(&buf[4..]);
        let decoded = Gtp2AmbrIe::decode(&value).unwrap();

        assert_eq!(decoded.uplink, 1000000);
        assert_eq!(decoded.downlink, 2000000);
    }

    #[test]
    fn test_apn_ie() {
        let ie = Gtp2ApnIe::from_string("internet.example.com");
        assert_eq!(ie.to_string(), "internet.example.com");
    }

    #[test]
    fn test_paa_ie_round_trip() {
        for paa in [
            Gtp2PaaIe::ipv4([10, 45, 0, 2]),
            Gtp2PaaIe::ipv6(64, [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Gtp2PaaIe::ipv4v6(
                [10, 45, 0, 2],
                64,
                [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
        ] {
            let mut buf = BytesMut::new();
            paa.encode(&mut buf, 0);

            let mut bytes = buf.freeze();
            let ie = Gtp2Ie::decode(&mut bytes).unwrap();
            assert_eq!(ie.ie_type, Gtp2IeType::Paa as u8);

            let decoded = Gtp2PaaIe::decode(&ie.value).unwrap();
            assert_eq!(decoded, paa);
        }
    }

    #[test]
    fn test_fteid_ie_dual_round_trip_via_to_ie() {
        let fteid = Gtp2FTeidIe::new_dual(
            10,
            0x12345678,
            [192, 168, 1, 1],
            [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        );
        let ie = fteid.to_ie(2);
        assert_eq!(ie.ie_type, Gtp2IeType::FTeid as u8);
        assert_eq!(ie.instance, 2);

        let decoded = Gtp2FTeidIe::decode(&ie.value).unwrap();
        assert_eq!(decoded, fteid);
    }

    #[test]
    fn test_fteid_ie_truncated_rejected() {
        // V4 flag set but only 2 address octets present
        let value = Bytes::from_static(&[0x8A, 0x12, 0x34, 0x56, 0x78, 192, 168]);
        assert!(Gtp2FTeidIe::decode(&value).is_err());
    }

    #[test]
    fn test_bearer_context_round_trip() {
        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_ebi(5);
        bearer.set_fteid(0, &Gtp2FTeidIe::new_ipv4(0, 0xAABBCCDD, [10, 0, 0, 1]));
        bearer.set_bearer_qos(&Gtp2BearerQosIe::new(9, 1000, 2000, 0, 0));

        let mut buf = BytesMut::new();
        bearer.encode(&mut buf, 0);

        let mut bytes = buf.freeze();
        let ie = Gtp2Ie::decode(&mut bytes).unwrap();
        assert_eq!(ie.ie_type, Gtp2IeType::BearerContext as u8);

        let decoded = Gtp2BearerContextIe::decode(&ie.value).unwrap();
        assert_eq!(decoded, bearer);
        assert_eq!(decoded.ebi().unwrap(), 5);

        let fteid = decoded.fteid(0).unwrap().unwrap();
        assert_eq!(fteid.teid, 0xAABBCCDD);
        assert_eq!(fteid.ipv4_addr, Some([10, 0, 0, 1]));

        let qos = decoded.bearer_qos().unwrap().unwrap();
        assert_eq!(qos.qci, 9);
        assert_eq!(qos.mbr_ul, 1000);
        assert_eq!(qos.mbr_dl, 2000);
    }

    #[test]
    fn test_bearer_context_with_cause_round_trip() {
        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_ebi(6);
        bearer.set_cause(&Gtp2CauseIe::new(16)); // Request accepted

        let ie = bearer.to_ie(0);
        let decoded = Gtp2BearerContextIe::decode(&ie.value).unwrap();
        assert_eq!(decoded.ebi().unwrap(), 6);
        assert_eq!(decoded.cause().unwrap().unwrap().cause, 16);
    }

    #[test]
    fn test_bearer_context_missing_ebi_rejected() {
        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));

        let ie = bearer.to_ie(0);
        let decoded = Gtp2BearerContextIe::decode(&ie.value).unwrap();
        assert!(matches!(
            decoded.ebi(),
            Err(GtpError::MissingMandatoryIe(_))
        ));
    }

    #[test]
    fn test_bearer_context_truncated_nested_ie_rejected() {
        // Nested IE claims 10 value octets but only 2 are present
        let value = Bytes::from_static(&[73, 0, 10, 0, 5, 5]);
        assert!(Gtp2BearerContextIe::decode(&value).is_err());
    }

    #[test]
    fn test_indication_ie_round_trip() {
        let indication = Gtp2IndicationIe {
            daf: true,
            oi: true,
            israi: true,
            crsi: true,
            p: true,
            s6af: true,
            israu: true,
            ..Default::default()
        };

        let mut buf = BytesMut::new();
        indication.encode(&mut buf, 0);

        let mut bytes = buf.freeze();
        let ie = Gtp2Ie::decode(&mut bytes).unwrap();
        assert_eq!(ie.ie_type, Gtp2IeType::Indication as u8);
        assert_eq!(ie.value.len(), 3);

        let decoded = Gtp2IndicationIe::decode(&ie.value).unwrap();
        assert_eq!(decoded, indication);
    }

    #[test]
    fn test_indication_ie_decode_spec_vector() {
        // TS 29.274 Section 8.12 bit layout: DAF is bit 8 of octet 5,
        // SGWCI bit 1 of octet 5, MSV bit 1 of octet 6, RETLOC bit 8 of octet 7
        let value = Bytes::from_static(&[0x81, 0x01, 0x80]);
        let decoded = Gtp2IndicationIe::decode(&value).unwrap();
        assert!(decoded.daf);
        assert!(decoded.sgwci);
        assert!(decoded.msv);
        assert!(decoded.retloc);
        assert!(!decoded.dtf);
        assert!(!decoded.p);
    }

    #[test]
    fn test_indication_ie_decode_short_and_long_values() {
        // Single octet: later flag octets read as false
        let decoded = Gtp2IndicationIe::decode(&Bytes::from_static(&[0x80])).unwrap();
        assert!(decoded.daf);
        assert!(!decoded.sqci);

        // Longer than 3 octets: extra flag octets are ignored
        let decoded =
            Gtp2IndicationIe::decode(&Bytes::from_static(&[0x80, 0, 0, 0xFF, 0xFF])).unwrap();
        assert!(decoded.daf);

        // Empty value rejected
        assert!(Gtp2IndicationIe::decode(&Bytes::new()).is_err());
    }
}
