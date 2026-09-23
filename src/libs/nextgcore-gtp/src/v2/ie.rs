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

    /// Convert to a generic IE, for nesting inside a grouped IE (#347: the APN-AMBR
    /// is a mandatory member of the PDN Connection, TS 29.274 Table 7.3.6-2).
    ///
    /// Delegates to [`Self::encode`] rather than re-emitting the two `u32`s, so there
    /// is one spelling of the AMBR's wire layout.
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        let mut buf = BytesMut::new();
        self.encode(&mut buf, instance);
        let mut bytes = buf.freeze();
        Gtp2Ie::decode(&mut bytes).expect("a just-encoded AMBR IE decodes")
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

    /// Convert to a generic IE, for nesting inside a grouped IE (#347: the APN is a
    /// mandatory member of the PDN Connection, TS 29.274 Table 7.3.6-2).
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        Gtp2Ie::from_slice(Gtp2IeType::Apn as u8, instance, &self.apn)
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

// ============================================================================
// N26 / S10 composite IEs (#347)
// ============================================================================

/// `Security Mode` = "EPS Security Context and Quadruplets".
///
/// TS 29.274 Table 8.38-1 (`29274-j60.txt:28671`). The value selects which of the
/// six MM Context IE types (103-108, Table 8.1-1) the octets after it follow, so
/// getting it wrong makes the receiver read the wrong layout from octet 6 onward.
pub const MM_CONTEXT_SECURITY_MODE_EPS: u8 = 4;

/// `K_ASME` length in the MM Context (TS 29.274 Figure 8.38-5, octets 14 to 45).
pub const MM_CONTEXT_KASME_LEN: usize = 32;

/// MM Context IE — **EPS Security Context and Quadruplets** (IE type 107).
///
/// TS 29.274 §8.38, Figure 8.38-5 (`29274-j60.txt:28371`). This is the security and
/// mobility context an old MME or old AMF hands to its successor over
/// S3/S10/S16/N26.
///
/// # Why only this one of the six MM Context variants
///
/// Table 8.1-1 (`29274-j60.txt:24528-24546`) makes 103-108 **six distinct IE types**,
/// not one type with a discriminator — so an implementation needs only the layouts it
/// can actually reach. On N26 that is exactly one, in **both** directions, and the
/// spec says so twice:
///
/// - old AMF → new MME (`29274-j60.txt:28198-28202`): *"The current EPS Security
///   Context may be transmitted by the old AMF to the new MME [...] The field 'Number
///   of Quadruplets' and 'Number of Quintuplets' shall be set to the value '0'."*
/// - old MME → new AMF (`29274-j60.txt:28190-28193`): *"Authentication Quintuplets
///   shall not be transmitted to the new MME/AMF [...] The field 'Number of
///   Quintuplets' shall be set to the value '0'."*
///
/// So both vector arrays are empty by specification on this interface, which is why
/// this type has no quadruplet/quintuplet members: they would be structurally
/// unreachable. The GSM/UMTS-keyed variants (103-106, 108) exist for S3/S16 toward a
/// GSM/UMTS SGSN, an interface this core does not have — so they are deliberately
/// absent rather than stubbed, because an encoder no caller can reach is the
/// "correct but unreachable" defect this tree keeps growing.
///
/// # Layout, octet by octet
///
/// Read off Figure 8.38-5 field by field rather than inferred from a neighbour:
///
/// | octet(s) | field | vendored line |
/// |---|---|---|
/// | 5 | `Security Mode`(3) \| `NHI`(1) \| `DRXI`(1) \| `KSI_ASME`(3) | `:28260` |
/// | 6 | `Number of Quintuplets`(3) \| `Number of Quadruplet`(3) \| `UAMBRI`(1) \| `OSCI`(1) | `:28262` |
/// | 7 | `SAMBRI`(1) \| `Used NAS integrity protection algorithm`(3) \| `Used NAS Cipher`(4) | `:28264` |
/// | 8-10 | `NAS Downlink Count` (24 bits) | `:28266` |
/// | 11-13 | `NAS Uplink Count` (24 bits) | `:28268` |
/// | 14-45 | `K_ASME` (32 octets) | `:28270` |
/// | q | `Length of UE Network Capability`, then contents | `:28294` |
/// | k+1 | `Length of MS Network Capability`, then contents | `:28299` |
/// | m+1 | `Length of Mobile Equipment Identity (MEI)`, then contents | `:28304` |
/// | r+1 | access restriction flags (`ECNA`..`UNA`) | `:28309` |
///
/// Octets 1-4 are the generic TLV header (type, length, spare+instance), which
/// [`Gtp2Ie`] owns — so an offset into this type's *contents* field is the figure's
/// octet number minus 4. That off-by-four is exactly what a round-trip test cannot
/// see, which is why `mm_context_encodes_ts29274_figure_8_38_5_field_positions`
/// asserts absolute contents offsets rather than comparing a decode to an encode.
///
/// # What is deliberately not modelled
///
/// The Subscribed/Used UE AMBR octets (`j`..`i+7`) and the DRX parameter are gated by
/// `SAMBRI` / `UAMBRI` / `DRXI`, and the optional tail from octet `s` onward (old EPS
/// security context, voice-domain preference, UE radio capability, extended access
/// restriction, APN rate control, core network restrictions) is present *"only if
/// explicitly specified"*. This type emits `DRXI = 0`, `SAMBRI = 0`, `UAMBRI = 0` and
/// `OSCI = 0` and omits every corresponding field, which is both legal and truthful:
/// §8.38 says the old AMF *"shall set [UAMBRI] to 0"* (`:28259`), and `OSCI = 0` is
/// required here because the old EPS security context *"may be present only in S10
/// Forward Relocation Request"* (`:28234-28236`) — not in a Context Response over
/// N26. Emitting them as zeroes-with-meaning would assert values this core does not
/// hold.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Gtp2MmContextIe {
    /// `KSI_ASME` (octet 5, bits 3..1) — the eKSI of the (mapped) EPS context.
    pub ksi_asme: u8,
    /// `NHI` (octet 5, bit 5). When set, `NH`/`NCC` follow the DRX parameter.
    ///
    /// `false` for idle-mode context transfer: `NH` is an AS-level key for
    /// connected-mode handover, and an idle-mode move has no target eNB to key.
    pub nhi: bool,
    /// `Used NAS integrity protection algorithm` (octet 7, bits 6..4).
    pub used_nas_integrity_algorithm: u8,
    /// `Used NAS Cipher` (octet 7, bits 4..1). Table 8.38-2 (`29274-j60.txt:28679`).
    pub used_nas_cipher: u8,
    /// `NAS Downlink Count` (octets 8-10, 24 bits).
    pub nas_downlink_count: u32,
    /// `NAS Uplink Count` (octets 11-13, 24 bits).
    pub nas_uplink_count: u32,
    /// `K_ASME` (octets 14-45). On N26 5GS→EPS this is `K_ASME'` derived from
    /// `K_AMF` per TS 33.501 §8.6.1 / Annex A.14.1, **not** a copied key.
    pub kasme: [u8; MM_CONTEXT_KASME_LEN],
    /// `UE Network Capability` contents (TS 24.301 §9.9.3.34).
    pub ue_network_capability: Vec<u8>,
    /// `MS Network Capability` contents (TS 24.008 §10.5.5.12).
    pub ms_network_capability: Vec<u8>,
    /// `Mobile Equipment Identity` contents (TS 29.274 §8.10 encoding).
    pub mei: Vec<u8>,
    /// Access restriction flags octet (`r+1`): `ECNA NBNA HNNA ENA INA GANA GENA UNA`.
    pub access_restriction: u8,
}

impl Gtp2MmContextIe {
    /// Offsets into the IE **contents** field, i.e. the figure's octet number minus
    /// the 4 octets of TLV header that [`Gtp2Ie`] owns.
    const OFF_SECURITY_MODE: usize = 0; // figure octet 5
    const OFF_ALGORITHMS: usize = 2; // figure octet 7
    const OFF_DL_COUNT: usize = 3; // figure octets 8-10
    const OFF_UL_COUNT: usize = 6; // figure octets 11-13
    const OFF_KASME: usize = 9; // figure octets 14-45
    /// Contents length up to and including `K_ASME`: figure octets 5..=45.
    const FIXED_LEN: usize = Self::OFF_KASME + MM_CONTEXT_KASME_LEN;

    /// Encode the contents octets (no TLV header).
    pub fn encode_value(&self, buf: &mut BytesMut) {
        // Octet 5: Security Mode (3 bits) | NHI (1) | DRXI (1) | KSI_ASME (3).
        //
        // DRXI is 0 because §8.38 (`29274-j60.txt:27727-27733`) requires that *"During
        // 5GS to EPS mobility procedure, the source AMF shall not send 5G DRX parameter
        // to the target MME"* -- the 5G DRX encoding (TS 24.501 §9.11.3.2A) differs from
        // the TS 24.008 §10.5.5.6 one this field carries, so sending it would hand the
        // MME an octet pair it would misread as a different parameter.
        buf.put_u8(
            ((MM_CONTEXT_SECURITY_MODE_EPS & 0x07) << 5)
                | (u8::from(self.nhi) << 4)
                // DRXI = 0
                | (self.ksi_asme & 0x07),
        );
        // Octet 6: Number of Quintuplets (3) | Number of Quadruplet (3) | UAMBRI (1)
        // | OSCI (1). All four are zero on N26; the type's doc quotes the two clauses
        // that require the vector counts to be 0 in each direction.
        buf.put_u8(0);
        // Octet 7: SAMBRI (1) | Used NAS integrity protection algorithm (3) |
        // Used NAS Cipher (4). SAMBRI = 0, so the Subscribed UE AMBR octets are absent.
        buf.put_u8(
            ((self.used_nas_integrity_algorithm & 0x07) << 4) | (self.used_nas_cipher & 0x0F),
        );
        // Octets 8-10 then 11-13: the two NAS COUNTs, 24 bits each, most significant
        // octet first. DOWNLINK first (`:28266`) and UPLINK second (`:28268`), in the
        // figure's order -- transposing them is invisible to a round trip, which is
        // what `mm_context_encodes_ts29274_figure_8_38_5_field_positions` pins.
        for count in [self.nas_downlink_count, self.nas_uplink_count] {
            buf.put_u8((count >> 16) as u8);
            buf.put_u8((count >> 8) as u8);
            buf.put_u8(count as u8);
        }
        // Octets 14-45: K_ASME.
        buf.put_slice(&self.kasme);
        // The Quadruplet and Quintuplet arrays are absent because both counts in octet
        // 6 are 0 (§8.38: *"shall be set to the value '0' if no Authentication
        // Quadruplet is included (i.e. octets '46 to g' are absent)"*). The DRX
        // parameter is absent because DRXI = 0, and NH/NCC because NHI = 0.
        //
        // Then the three length-prefixed capability fields. §8.38 says each is absent
        // when its length is zero, so a zero length octet is the correct encoding of
        // "not available" rather than a placeholder for one.
        for field in [
            &self.ue_network_capability,
            &self.ms_network_capability,
            &self.mei,
        ] {
            let len = field.len().min(u8::MAX as usize);
            buf.put_u8(len as u8);
            buf.put_slice(&field[..len]);
        }
        // Octet r+1: the access restriction flags.
        buf.put_u8(self.access_restriction);
    }

    /// Convert to a generic IE with the given instance.
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);
        Gtp2Ie::new(Gtp2IeType::MmContext as u8, instance, value.freeze())
    }

    /// Decode from an IE contents field.
    ///
    /// Rejects a `Security Mode` other than [`MM_CONTEXT_SECURITY_MODE_EPS`] rather
    /// than reading the octets anyway: the value selects the layout, so parsing a
    /// GSM-keyed MM Context with this figure's offsets would produce a plausible
    /// K_ASME from the wrong bytes and a NAS COUNT from a triplet. Refusing names the
    /// real problem instead of propagating a wrong key into a security context.
    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        if value.len() < Self::FIXED_LEN {
            return Err(GtpError::BufferTooShort {
                needed: Self::FIXED_LEN,
                available: value.len(),
            });
        }
        let octet5 = value[Self::OFF_SECURITY_MODE];
        let security_mode = (octet5 >> 5) & 0x07;
        if security_mode != MM_CONTEXT_SECURITY_MODE_EPS {
            return Err(GtpError::InvalidIeType(security_mode));
        }
        let octet7 = value[Self::OFF_ALGORITHMS];
        let count_at = |off: usize| -> u32 {
            ((value[off] as u32) << 16) | ((value[off + 1] as u32) << 8) | (value[off + 2] as u32)
        };
        let mut kasme = [0u8; MM_CONTEXT_KASME_LEN];
        kasme.copy_from_slice(&value[Self::OFF_KASME..Self::OFF_KASME + MM_CONTEXT_KASME_LEN]);

        // The three length-prefixed capability fields, then the access-restriction
        // octet. A truncated tail reads as absent rather than as an error: §8.38 makes
        // every one of them omissible, so a peer that sent fewer octets has sent a
        // legal shorter IE.
        let mut off = Self::FIXED_LEN;
        let mut take_lv = || -> Vec<u8> {
            let Some(&len) = value.get(off) else {
                return Vec::new();
            };
            off += 1;
            let len = (len as usize).min(value.len().saturating_sub(off));
            let out = value[off..off + len].to_vec();
            off += len;
            out
        };
        let ue_network_capability = take_lv();
        let ms_network_capability = take_lv();
        let mei = take_lv();
        let access_restriction = value.get(off).copied().unwrap_or(0);

        Ok(Self {
            ksi_asme: octet5 & 0x07,
            nhi: (octet5 >> 4) & 0x01 != 0,
            used_nas_integrity_algorithm: (octet7 >> 4) & 0x07,
            used_nas_cipher: octet7 & 0x0F,
            nas_downlink_count: count_at(Self::OFF_DL_COUNT),
            nas_uplink_count: count_at(Self::OFF_UL_COUNT),
            kasme,
            ue_network_capability,
            ms_network_capability,
            mei,
            access_restriction,
        })
    }
}

/// PDN Connection grouped IE (IE type 109).
///
/// TS 29.274 §8.39 defines the type; its own table is **empty**
/// (`29274-j60.txt:28819` — the member row is blank, with a NOTE saying *"the usage of
/// this IE is further detailed for each specific GTP message"*), so the member list
/// comes from **Table 7.3.6-2** (`29274-j60.txt:20508`), "MME/SGSN/AMF UE EPS PDN
/// Connections within Context Response". That is also the table TS 29.502 names for
/// `EpsPdnCnxContainer` (`29502-k00.txt:24142-24149`), so one layout serves both the
/// N11 container and the N26 wire.
///
/// Modelled as a nested-IE bag with instance-keyed accessors, the same shape as
/// [`Gtp2BearerContextIe`], rather than as a struct of typed members: this tree has
/// one notion of "a grouped GTPv2 IE" and a second design would be two answers to
/// "how is a nested IE addressed" — the #335/#340 shape, where several spellings of
/// one wire fact drifted and only the tested one was right.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Gtp2PdnConnectionIe {
    /// Nested Information Elements, in Table 7.3.6-2 order.
    pub ies: Vec<Gtp2Ie>,
}

impl Gtp2PdnConnectionIe {
    /// Create an empty PDN Connection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a nested IE.
    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    /// Get a nested IE by type and instance.
    pub fn get_ie(&self, ie_type: u8, instance: u8) -> Option<&Gtp2Ie> {
        self.ies
            .iter()
            .find(|ie| ie.ie_type == ie_type && ie.instance == instance)
    }

    /// The F-TEID Table 7.3.6-3 requires for `SGW S1/S4/S12/S11 IP Address and TEID
    /// for user plane` **over N26**.
    ///
    /// `29274-j60.txt:20906-20915` is explicit: over N26 the SMF, on behalf of the
    /// source AMF, *"shall set the IP address and TEID to the following values: any
    /// reserved TEID (e.g. all 0's, or all 1's); IPv4 address set to 0.0.0.0"*.
    ///
    /// A named constructor so no call site can reach for a real endpoint here. There is
    /// no SGW in the 5GC, and the 5GS user plane is anchored at a UPF the MME cannot
    /// address — so encoding anything else would point an MME's user plane at an
    /// address the 5GC never allocated for it, which is a live traffic blackhole rather
    /// than a decode error.
    ///
    /// `interface_type` is 1 ("S1-U SGW GTP-U interface") per NOTE 2
    /// (`29274-j60.txt:20972-20974`): *"The MME shall set the interface type in this IE
    /// to 1 [...] for S1-U and S11-U bearers. This is done for backwards compatibility
    /// reasons"*.
    pub fn n26_reserved_sgw_fteid() -> Gtp2FTeidIe {
        Gtp2FTeidIe::new_ipv4(1, 0, [0, 0, 0, 0])
    }

    /// Encode the grouped value octets (concatenated nested IEs).
    pub fn encode_value(&self, buf: &mut BytesMut) {
        for ie in &self.ies {
            ie.encode(buf);
        }
    }

    /// Convert to a generic IE with the given instance.
    ///
    /// §8.39 (`29274-j60.txt:28802-28806`): *"The PDN Connection IE may be repeated
    /// within a message when more than one PDN Connection is required to be sent. If
    /// so, the repeated IEs shall have exactly the same Instance values"* — so a
    /// multi-session UE yields several IEs all at instance 0, and a caller must not
    /// number them.
    pub fn to_ie(&self, instance: u8) -> Gtp2Ie {
        let mut value = BytesMut::new();
        self.encode_value(&mut value);
        Gtp2Ie::new(Gtp2IeType::PdnConnection as u8, instance, value.freeze())
    }

    /// Decode the nested IEs from a grouped IE value.
    pub fn decode(value: &Bytes) -> GtpResult<Self> {
        let mut buf = value.clone();
        let mut ies = Vec::new();
        while buf.remaining() > 0 {
            ies.push(Gtp2Ie::decode(&mut buf)?);
        }
        Ok(Self { ies })
    }

    /// The APN (Table 7.3.6-2, mandatory, `29274-j60.txt:20522`).
    pub fn apn(&self) -> GtpResult<Gtp2ApnIe> {
        let ie = self
            .get_ie(Gtp2IeType::Apn as u8, 0)
            .ok_or_else(|| GtpError::MissingMandatoryIe("APN in PDN Connection".to_string()))?;
        Gtp2ApnIe::decode(&ie.value)
    }

    /// The Linked EPS Bearer ID — the PDN connection's **default** bearer
    /// (Table 7.3.6-2, mandatory, `29274-j60.txt:20548`).
    pub fn linked_ebi(&self) -> GtpResult<u8> {
        let ie = self.get_ie(Gtp2IeType::Ebi as u8, 0).ok_or_else(|| {
            GtpError::MissingMandatoryIe("Linked EPS Bearer ID in PDN Connection".to_string())
        })?;
        Ok(Gtp2EbiIe::decode(&ie.value)?.ebi)
    }

    /// `PGW S5/S8 IP Address for Control Plane or PMIP` (Table 7.3.6-2, mandatory,
    /// `29274-j60.txt:20552`).
    pub fn pgw_s5s8_control_fteid(&self) -> GtpResult<Gtp2FTeidIe> {
        let ie = self.get_ie(Gtp2IeType::FTeid as u8, 0).ok_or_else(|| {
            GtpError::MissingMandatoryIe("PGW S5/S8 control F-TEID in PDN Connection".to_string())
        })?;
        Gtp2FTeidIe::decode(&ie.value)
    }

    /// The APN-AMBR (Table 7.3.6-2, mandatory, `29274-j60.txt:20573`).
    pub fn apn_ambr(&self) -> GtpResult<Gtp2AmbrIe> {
        let ie = self.get_ie(Gtp2IeType::Ambr as u8, 0).ok_or_else(|| {
            GtpError::MissingMandatoryIe("APN-AMBR in PDN Connection".to_string())
        })?;
        Gtp2AmbrIe::decode(&ie.value)
    }

    /// The UE's IPv4 address, if the PDN connection has one (Table 7.3.6-2,
    /// conditional: *"shall not be included if no IPv4 Address is assigned"*,
    /// `29274-j60.txt:20539`).
    pub fn ipv4_address(&self) -> Option<[u8; 4]> {
        let ie = self.get_ie(Gtp2IeType::IpAddress as u8, 0)?;
        let bytes: [u8; 4] = ie.value.as_ref().try_into().ok()?;
        Some(bytes)
    }

    /// Every nested Bearer Context (Table 7.3.6-2, mandatory, `29274-j60.txt:20567`:
    /// *"Several IEs with this type and instance values may be included as necessary
    /// to represent a list of Bearers"*).
    pub fn bearer_contexts(&self) -> GtpResult<Vec<Gtp2BearerContextIe>> {
        self.ies
            .iter()
            .filter(|ie| ie.ie_type == Gtp2IeType::BearerContext as u8)
            .map(|ie| Gtp2BearerContextIe::decode(&ie.value))
            .collect()
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

    // ------------------------------------------------------------------
    // N26 / S10 composite IEs (#347)
    // ------------------------------------------------------------------

    /// The four IE types this leg newly depends on, pinned to Table 8.1-1 by the
    /// number.
    ///
    /// `MmContext = 107` and `PdnConnection = 109` already existed in this enum, which
    /// contradicted #347's own gap description — so this test is as much a record that
    /// they are the RIGHT numbers as that they exist.
    ///
    /// | IE | id | `29274-j60.txt` |
    /// |---|---|---|
    /// | MM Context (EPS Security Context, Quadruplets and Quintuplets) | 107 | `:24535` |
    /// | PDN Connection | 109 | `:24547` |
    /// | Complete Request Message | 116 | `:24568` |
    /// | GUTI | 117 | `:24571` |
    #[test]
    fn gtp2_n26_ie_types_match_ts29274_table_8_1_1() {
        assert_eq!(
            Gtp2IeType::MmContext as u8,
            107,
            "the EPS-security-context MM Context is IE type 107 (29274-j60.txt:24535); \
             103-106 and 108 are the GSM/UMTS-keyed variants and are separate types"
        );
        assert_eq!(
            Gtp2IeType::PdnConnection as u8,
            109,
            "PDN Connection is IE type 109 (29274-j60.txt:24547)"
        );
        assert_eq!(
            Gtp2IeType::CompleteRequestMessage as u8,
            116,
            "Complete Request Message is IE type 116 (29274-j60.txt:24568)"
        );
        assert_eq!(
            Gtp2IeType::Guti as u8,
            117,
            "GUTI is IE type 117 (29274-j60.txt:24571)"
        );
        // 108 is a DIFFERENT MM Context variant (UMTS Key, Quadruplets and
        // Quintuplets, `:24541`), so it must not resolve to the one this library
        // implements -- an alias would let a UMTS-keyed context be parsed with the
        // EPS figure's offsets.
        assert!(
            Gtp2IeType::try_from(108u8).is_err(),
            "MM Context type 108 is the UMTS-keyed variant and is not implemented, so \
             it must not silently decode as 107"
        );
        assert_eq!(
            MM_CONTEXT_SECURITY_MODE_EPS, 4,
            "'EPS Security Context and Quadruplets' is Security Mode 4 \
             (TS 29.274 Table 8.38-1, 29274-j60.txt:28671)"
        );
        assert_eq!(
            MM_CONTEXT_KASME_LEN, 32,
            "K_ASME occupies octets 14 to 45 of Figure 8.38-5 = 32 octets"
        );
    }

    /// Every field of Figure 8.38-5 at its absolute byte position in the IE contents.
    ///
    /// This is the assertion a round trip cannot make. `encode`/`decode` agree with
    /// each other by construction, so they would agree just as happily with the two
    /// NAS COUNTs transposed, with `K_ASME` four octets off (the TLV-header
    /// off-by-four), or with `Security Mode` in the low bits instead of the high. Each
    /// of those has a distinct byte signature and each is checked here.
    #[test]
    fn mm_context_encodes_ts29274_figure_8_38_5_field_positions() {
        // Distinguishable values: the two COUNTs differ, and K_ASME is a ramp so a
        // misaligned copy shows up as an offset rather than as zeroes.
        let mut kasme = [0u8; MM_CONTEXT_KASME_LEN];
        for (i, b) in kasme.iter_mut().enumerate() {
            *b = 0xA0 + i as u8;
        }
        let ctx = Gtp2MmContextIe {
            ksi_asme: 0x05,
            nhi: false,
            used_nas_integrity_algorithm: 0x02, // 128-EIA2
            used_nas_cipher: 0x01,              // 128-EEA1
            nas_downlink_count: 0x00_11_22_33 & 0x00FF_FFFF,
            nas_uplink_count: 0x00_44_55_66 & 0x00FF_FFFF,
            kasme,
            ue_network_capability: vec![0xE0, 0xE1],
            ms_network_capability: vec![0xF0],
            mei: vec![0x21, 0x43, 0x65],
            access_restriction: 0x01, // UNA
        };

        let mut v = BytesMut::new();
        ctx.encode_value(&mut v);
        let v = v.freeze();

        // Figure octet 5 (contents[0]): Security Mode 4 in bits 8..6, NHI clear,
        // DRXI clear, KSI_ASME 5 in bits 3..1 => 0b100_0_0_101 = 0x85.
        assert_eq!(
            v[0], 0x85,
            "octet 5 is Security Mode(4)<<5 | NHI<<4 | DRXI<<3.. | KSI_ASME \
             (29274-j60.txt:28260)"
        );
        assert_eq!(
            (v[0] >> 5) & 0x07,
            MM_CONTEXT_SECURITY_MODE_EPS,
            "Security Mode occupies the TOP three bits of octet 5, not the bottom"
        );

        // Figure octet 6 (contents[1]): both vector counts, UAMBRI and OSCI all zero
        // on N26.
        assert_eq!(
            v[1], 0x00,
            "octet 6 carries Number of Quintuplets | Number of Quadruplet | UAMBRI | \
             OSCI, all zero over N26 (29274-j60.txt:28190, :28198, :28234)"
        );

        // Figure octet 7 (contents[2]): SAMBRI clear, integrity alg 2 in bits 7..5,
        // cipher 1 in bits 4..1 => 0b0_010_0001 = 0x21.
        assert_eq!(
            v[2], 0x21,
            "octet 7 is SAMBRI<<7 | integrity(3 bits)<<4 | cipher(4 bits) \
             (29274-j60.txt:28264)"
        );

        // Figure octets 8-10 (contents[3..6]): NAS DOWNLINK count, big-endian 24 bits.
        assert_eq!(
            &v[3..6],
            &[0x11, 0x22, 0x33],
            "octets 8-10 are the NAS DOWNLINK Count (29274-j60.txt:28266) -- if this \
             reads 44 55 66 the two counts are transposed, which no round trip sees"
        );
        // Figure octets 11-13 (contents[6..9]): NAS UPLINK count.
        assert_eq!(
            &v[6..9],
            &[0x44, 0x55, 0x66],
            "octets 11-13 are the NAS UPLINK Count (29274-j60.txt:28268)"
        );

        // Figure octets 14-45 (contents[9..41]): K_ASME, 32 octets.
        assert_eq!(
            &v[9..41],
            &kasme[..],
            "K_ASME starts at figure octet 14 = contents offset 9 (14 minus the 4 \
             octets of TLV header + 1 for 1-based octet numbering)"
        );

        // Then the three length-prefixed capability fields and the restriction octet.
        assert_eq!(v[41], 2, "Length of UE Network Capability");
        assert_eq!(&v[42..44], &[0xE0, 0xE1]);
        assert_eq!(v[44], 1, "Length of MS Network Capability");
        assert_eq!(v[45], 0xF0);
        assert_eq!(v[46], 3, "Length of Mobile Equipment Identity");
        assert_eq!(&v[47..50], &[0x21, 0x43, 0x65]);
        assert_eq!(v[50], 0x01, "access restriction flags octet (r+1)");
        assert_eq!(v.len(), 51, "no trailing optional octets are emitted");

        // And the TLV wrapper carries the right type.
        let ie = ctx.to_ie(0);
        assert_eq!(ie.ie_type, Gtp2IeType::MmContext as u8);
        assert_eq!(ie.instance, 0);

        // Round trip, which is necessary but not sufficient.
        assert_eq!(Gtp2MmContextIe::decode(&ie.value).unwrap(), ctx);
    }

    /// A 24-bit NAS COUNT must survive its full range, and the top octet must not be
    /// dropped.
    #[test]
    fn mm_context_nas_counts_round_trip_across_the_24_bit_range() {
        for (dl, ul) in [
            (0u32, 0u32),
            (0x00FF_FFFF, 0x00FF_FFFF),
            (1, 0x00FF_FFFF),
            (0x00FF_0000, 0x0000_00FF),
        ] {
            let ctx = Gtp2MmContextIe {
                nas_downlink_count: dl,
                nas_uplink_count: ul,
                kasme: [0x5A; MM_CONTEXT_KASME_LEN],
                ..Default::default()
            };
            let decoded = Gtp2MmContextIe::decode(&ctx.to_ie(0).value).unwrap();
            assert_eq!(
                decoded.nas_downlink_count, dl,
                "downlink count must survive"
            );
            assert_eq!(decoded.nas_uplink_count, ul, "uplink count must survive");
        }
    }

    /// A MM Context carrying a different Security Mode is REFUSED, not reinterpreted.
    #[test]
    fn mm_context_refuses_a_non_eps_security_mode() {
        let ctx = Gtp2MmContextIe {
            kasme: [0x11; MM_CONTEXT_KASME_LEN],
            ..Default::default()
        };
        let mut v = BytesMut::new();
        ctx.encode_value(&mut v);
        let mut v = v.to_vec();
        // Security Mode 3 = "UMTS Key and Quintuplets" (Table 8.38-1,
        // `29274-j60.txt:28665`), whose octets after 5 follow Figure 8.38-4.
        v[0] = (v[0] & 0x1F) | (3 << 5);
        assert!(
            Gtp2MmContextIe::decode(&Bytes::from(v)).is_err(),
            "a UMTS-keyed MM Context must NOT be parsed with the EPS figure's offsets: \
             it would yield a plausible K_ASME from quintuplet bytes"
        );
    }

    /// Too short to hold K_ASME is an error, not a zero key.
    #[test]
    fn mm_context_refuses_a_truncated_kasme() {
        // Security Mode 4 in octet 5, then only 8 more octets -- K_ASME cannot fit.
        let short = Bytes::from(vec![0x80, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(
            Gtp2MmContextIe::decode(&short).is_err(),
            "a truncated MM Context must error rather than produce an all-zero K_ASME, \
             which would be a usable-looking key nobody derived"
        );
    }

    /// The PDN Connection's mandatory members, read back through the accessors.
    #[test]
    fn pdn_connection_carries_its_table_7_3_6_2_mandatory_members() {
        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_ebi(5);
        bearer.set_fteid(0, &Gtp2PdnConnectionIe::n26_reserved_sgw_fteid());
        bearer.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));

        let mut pdn = Gtp2PdnConnectionIe::new();
        pdn.add_ie(Gtp2ApnIe::from_string("internet").to_ie(0));
        pdn.add_ie(Gtp2EbiIe::new(5).to_ie(0));
        // interface type 7 = S5/S8 PGW GTP-C (TS 29.274 Table 8.22-1).
        pdn.add_ie(Gtp2FTeidIe::new_ipv4(7, 0x0BAD_C0DE, [10, 45, 0, 1]).to_ie(0));
        pdn.add_ie(bearer.to_ie(0));
        pdn.add_ie(Gtp2AmbrIe::new(100_000, 200_000).to_ie(0));

        // Through the wire, not in memory.
        let ie = pdn.to_ie(0);
        assert_eq!(ie.ie_type, Gtp2IeType::PdnConnection as u8);
        let decoded = Gtp2PdnConnectionIe::decode(&ie.value).unwrap();

        assert_eq!(decoded.apn().unwrap().to_string(), "internet");
        assert_eq!(
            decoded.linked_ebi().unwrap(),
            5,
            "the Linked EPS Bearer ID names the PDN connection's default bearer"
        );
        let pgw = decoded.pgw_s5s8_control_fteid().unwrap();
        assert_eq!(pgw.teid, 0x0BAD_C0DE);
        assert_eq!(pgw.ipv4_addr, Some([10, 45, 0, 1]));
        assert_eq!(pgw.interface_type, 7);
        let ambr = decoded.apn_ambr().unwrap();
        assert_eq!(ambr.uplink, 100_000);
        assert_eq!(ambr.downlink, 200_000);
        let bearers = decoded.bearer_contexts().unwrap();
        assert_eq!(bearers.len(), 1);
        assert_eq!(bearers[0].ebi().unwrap(), 5);
        assert_eq!(bearers[0].bearer_qos().unwrap().unwrap().qci, 9);
    }

    /// A PDN Connection missing a mandatory member reports WHICH one.
    #[test]
    fn pdn_connection_names_the_missing_mandatory_member() {
        let empty = Gtp2PdnConnectionIe::new();
        for result in [
            empty.apn().err().map(|e| e.to_string()),
            empty.linked_ebi().err().map(|e| e.to_string()),
            empty.pgw_s5s8_control_fteid().err().map(|e| e.to_string()),
            empty.apn_ambr().err().map(|e| e.to_string()),
        ] {
            let msg = result.expect("a missing mandatory member must be an error");
            assert!(
                msg.contains("PDN Connection"),
                "the error must name where the IE was missing from, got {msg:?}"
            );
        }
        assert!(
            empty.ipv4_address().is_none(),
            "an absent IPv4 Address is 'no IPv4 assigned' (Table 7.3.6-2), not an error"
        );
    }

    /// Over N26 the SGW user-plane F-TEID is the reserved value, at the byte level.
    ///
    /// Table 7.3.6-3 (`29274-j60.txt:20906-20915`) requires a reserved TEID and
    /// `0.0.0.0`. A real endpoint here would send an MME's user plane to an address the
    /// 5GC never allocated for it, so this is asserted on the encoded octets rather
    /// than on the struct.
    #[test]
    fn n26_sgw_fteid_is_the_reserved_value_ts29274_table_7_3_6_3_requires() {
        let fteid = Gtp2PdnConnectionIe::n26_reserved_sgw_fteid();
        assert_eq!(
            fteid.teid, 0,
            "TS 29.274 Table 7.3.6-3: over N26 the SGW user-plane TEID is 'any \
             reserved TEID (e.g. all 0's, or all 1's)' (29274-j60.txt:20908)"
        );
        assert_eq!(
            fteid.ipv4_addr,
            Some([0, 0, 0, 0]),
            "and the IPv4 address is 0.0.0.0 (29274-j60.txt:20912)"
        );
        assert_eq!(
            fteid.interface_type, 1,
            "interface type 1 = S1-U SGW GTP-U, per NOTE 2 (29274-j60.txt:20972)"
        );

        // On the wire: flags octet then the 4-octet TEID then the address.
        let ie = fteid.to_ie(0);
        assert_eq!(
            &ie.value[1..5],
            &[0, 0, 0, 0],
            "the encoded TEID octets must be zero"
        );
        assert_eq!(
            &ie.value[5..9],
            &[0, 0, 0, 0],
            "the encoded IPv4 octets must be 0.0.0.0"
        );
    }

    /// A multi-session UE yields several PDN Connection IEs all at the SAME instance.
    ///
    /// §8.39 (`29274-j60.txt:28802-28806`) requires it, and numbering them 0,1,2 — the
    /// intuitive thing — would make a receiver read a list of three different members
    /// rather than a repeated one.
    #[test]
    fn repeated_pdn_connections_share_one_instance_value() {
        let mut msg_ies = Vec::new();
        for ebi in [5u8, 6, 7] {
            let mut pdn = Gtp2PdnConnectionIe::new();
            pdn.add_ie(Gtp2EbiIe::new(ebi).to_ie(0));
            msg_ies.push(pdn.to_ie(0));
        }
        assert!(
            msg_ies.iter().all(|ie| ie.instance == 0),
            "repeated PDN Connection IEs must all carry instance 0 (TS 29.274 §8.39)"
        );
        let ebis: Vec<u8> = msg_ies
            .iter()
            .map(|ie| {
                Gtp2PdnConnectionIe::decode(&ie.value)
                    .unwrap()
                    .linked_ebi()
                    .unwrap()
            })
            .collect();
        assert_eq!(
            ebis,
            vec![5, 6, 7],
            "and each must still be recoverable as its own PDN connection"
        );
    }
}
