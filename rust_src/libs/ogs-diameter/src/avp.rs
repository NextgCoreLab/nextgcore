//! Diameter AVP (Attribute-Value Pair) encoding and decoding
//!
//! AVP format (RFC 6733):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           AVP Code                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V M P r r r r r|                  AVP Length                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Vendor-ID (opt)                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Data ...
//! +-+-+-+-+-+-+-+-+
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{DiameterError, DiameterResult};

/// AVP flags
pub mod avp_flags {
    /// Vendor-Specific bit
    pub const VENDOR: u8 = 0x80;
    /// Mandatory bit
    pub const MANDATORY: u8 = 0x40;
    /// Protected bit (encryption)
    pub const PROTECTED: u8 = 0x20;
}

/// AVP header size without vendor ID
pub const AVP_HEADER_SIZE: usize = 8;
/// AVP header size with vendor ID
pub const AVP_HEADER_SIZE_VENDOR: usize = 12;

/// Diameter AVP
#[derive(Debug, Clone)]
pub struct Avp {
    /// AVP code
    pub code: u32,
    /// AVP flags
    pub flags: u8,
    /// Vendor ID (if vendor-specific)
    pub vendor_id: Option<u32>,
    /// AVP data
    pub data: AvpData,
}

/// AVP data types
#[derive(Debug, Clone)]
pub enum AvpData {
    /// OctetString
    OctetString(Bytes),
    /// Integer32
    Integer32(i32),
    /// Integer64
    Integer64(i64),
    /// Unsigned32
    Unsigned32(u32),
    /// Unsigned64
    Unsigned64(u64),
    /// Float32
    Float32(f32),
    /// Float64
    Float64(f64),
    /// Address (IPv4 or IPv6)
    Address(IpAddr),
    /// UTF8String
    Utf8String(String),
    /// DiameterIdentity (FQDN)
    DiameterIdentity(String),
    /// DiameterURI
    DiameterUri(String),
    /// Time (seconds since Jan 1, 1900)
    Time(u32),
    /// Grouped AVP (contains other AVPs)
    Grouped(Vec<Avp>),
    /// Enumerated (same as Integer32)
    Enumerated(i32),
    /// Raw bytes (for unknown types)
    Raw(Bytes),
}

impl Avp {
    /// Create a new AVP
    pub fn new(code: u32, flags: u8, vendor_id: Option<u32>, data: AvpData) -> Self {
        Self {
            code,
            flags,
            vendor_id,
            data,
        }
    }

    /// Create a mandatory AVP
    pub fn mandatory(code: u32, data: AvpData) -> Self {
        Self::new(code, avp_flags::MANDATORY, None, data)
    }

    /// Create a vendor-specific mandatory AVP
    pub fn vendor_mandatory(code: u32, vendor_id: u32, data: AvpData) -> Self {
        Self::new(
            code,
            avp_flags::VENDOR | avp_flags::MANDATORY,
            Some(vendor_id),
            data,
        )
    }

    /// Check if AVP is vendor-specific
    pub fn is_vendor_specific(&self) -> bool {
        self.flags & avp_flags::VENDOR != 0
    }

    /// Check if AVP is mandatory
    pub fn is_mandatory(&self) -> bool {
        self.flags & avp_flags::MANDATORY != 0
    }

    /// Get the encoded length of this AVP (including padding)
    pub fn encoded_len(&self) -> usize {
        let header_len = if self.is_vendor_specific() {
            AVP_HEADER_SIZE_VENDOR
        } else {
            AVP_HEADER_SIZE
        };
        let data_len = self.data.encoded_len();
        let total = header_len + data_len;
        // Pad to 4-byte boundary
        (total + 3) & !3
    }

    /// Encode AVP to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        let header_len = if self.is_vendor_specific() {
            AVP_HEADER_SIZE_VENDOR
        } else {
            AVP_HEADER_SIZE
        };
        let data_len = self.data.encoded_len();
        let avp_len = header_len + data_len;

        // AVP Code
        buf.put_u32(self.code);

        // Flags and Length
        buf.put_u8(self.flags);
        buf.put_u8(((avp_len >> 16) & 0xFF) as u8);
        buf.put_u16((avp_len & 0xFFFF) as u16);

        // Vendor ID (if present)
        if let Some(vendor_id) = self.vendor_id {
            buf.put_u32(vendor_id);
        }

        // Data
        self.data.encode(buf);

        // Padding
        let padding = (4 - (data_len % 4)) % 4;
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }

    /// Decode AVP from bytes
    pub fn decode(buf: &mut Bytes) -> DiameterResult<Self> {
        if buf.remaining() < AVP_HEADER_SIZE {
            return Err(DiameterError::BufferTooSmall {
                needed: AVP_HEADER_SIZE,
                available: buf.remaining(),
            });
        }

        let code = buf.get_u32();
        let flags = buf.get_u8();
        let len_high = buf.get_u8() as usize;
        let len_low = buf.get_u16() as usize;
        let avp_len = (len_high << 16) | len_low;

        let is_vendor = flags & avp_flags::VENDOR != 0;
        let header_len = if is_vendor {
            AVP_HEADER_SIZE_VENDOR
        } else {
            AVP_HEADER_SIZE
        };

        if avp_len < header_len {
            return Err(DiameterError::InvalidAvp(format!(
                "AVP length {} is less than header size {}",
                avp_len, header_len
            )));
        }

        let vendor_id = if is_vendor {
            if buf.remaining() < 4 {
                return Err(DiameterError::BufferTooSmall {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            Some(buf.get_u32())
        } else {
            None
        };

        let data_len = avp_len - header_len;
        if buf.remaining() < data_len {
            return Err(DiameterError::BufferTooSmall {
                needed: data_len,
                available: buf.remaining(),
            });
        }

        let data_bytes = buf.copy_to_bytes(data_len);

        // Skip padding
        let padding = (4 - (data_len % 4)) % 4;
        if buf.remaining() >= padding {
            buf.advance(padding);
        }

        Ok(Self {
            code,
            flags,
            vendor_id,
            data: AvpData::Raw(data_bytes),
        })
    }

    /// Get data as OctetString
    pub fn as_octet_string(&self) -> Option<&Bytes> {
        match &self.data {
            AvpData::OctetString(b) | AvpData::Raw(b) => Some(b),
            _ => None,
        }
    }

    /// Get data as Unsigned32
    pub fn as_u32(&self) -> Option<u32> {
        match &self.data {
            AvpData::Unsigned32(v) => Some(*v),
            AvpData::Enumerated(v) => Some(*v as u32),
            AvpData::Raw(b) if b.len() >= 4 => {
                let mut buf = b.clone();
                Some(buf.get_u32())
            }
            _ => None,
        }
    }

    /// Get data as Unsigned64
    pub fn as_u64(&self) -> Option<u64> {
        match &self.data {
            AvpData::Unsigned64(v) => Some(*v),
            AvpData::Raw(b) if b.len() >= 8 => {
                let mut buf = b.clone();
                Some(buf.get_u64())
            }
            _ => None,
        }
    }

    /// Get data as Integer32
    pub fn as_i32(&self) -> Option<i32> {
        match &self.data {
            AvpData::Integer32(v) | AvpData::Enumerated(v) => Some(*v),
            AvpData::Raw(b) if b.len() >= 4 => {
                let mut buf = b.clone();
                Some(buf.get_i32())
            }
            _ => None,
        }
    }

    /// Get data as UTF8String
    pub fn as_utf8_string(&self) -> Option<&str> {
        match &self.data {
            AvpData::Utf8String(s)
            | AvpData::DiameterIdentity(s)
            | AvpData::DiameterUri(s) => Some(s),
            AvpData::Raw(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }

    /// Get data as grouped AVPs
    pub fn as_grouped(&self) -> Option<&[Avp]> {
        match &self.data {
            AvpData::Grouped(avps) => Some(avps),
            _ => None,
        }
    }

    /// Get data as Address
    pub fn as_address(&self) -> Option<IpAddr> {
        match &self.data {
            AvpData::Address(addr) => Some(*addr),
            AvpData::Raw(b) if b.len() >= 6 => {
                let mut buf = b.clone();
                let addr_type = buf.get_u16();
                match addr_type {
                    1 if buf.remaining() >= 4 => {
                        let octets: [u8; 4] = [buf.get_u8(), buf.get_u8(), buf.get_u8(), buf.get_u8()];
                        Some(IpAddr::V4(Ipv4Addr::from(octets)))
                    }
                    2 if buf.remaining() >= 16 => {
                        let mut octets = [0u8; 16];
                        buf.copy_to_slice(&mut octets);
                        Some(IpAddr::V6(Ipv6Addr::from(octets)))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

impl AvpData {
    /// Get the encoded length of this data
    pub fn encoded_len(&self) -> usize {
        match self {
            AvpData::OctetString(b) | AvpData::Raw(b) => b.len(),
            AvpData::Integer32(_) | AvpData::Unsigned32(_) | AvpData::Enumerated(_) => 4,
            AvpData::Integer64(_) | AvpData::Unsigned64(_) => 8,
            AvpData::Float32(_) | AvpData::Time(_) => 4,
            AvpData::Float64(_) => 8,
            AvpData::Address(addr) => match addr {
                IpAddr::V4(_) => 6,  // 2 bytes type + 4 bytes address
                IpAddr::V6(_) => 18, // 2 bytes type + 16 bytes address
            },
            AvpData::Utf8String(s) | AvpData::DiameterIdentity(s) | AvpData::DiameterUri(s) => {
                s.len()
            }
            AvpData::Grouped(avps) => avps.iter().map(|a| a.encoded_len()).sum(),
        }
    }

    /// Encode data to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            AvpData::OctetString(b) | AvpData::Raw(b) => buf.put_slice(b),
            AvpData::Integer32(v) | AvpData::Enumerated(v) => buf.put_i32(*v),
            AvpData::Integer64(v) => buf.put_i64(*v),
            AvpData::Unsigned32(v) => buf.put_u32(*v),
            AvpData::Unsigned64(v) => buf.put_u64(*v),
            AvpData::Float32(v) => buf.put_f32(*v),
            AvpData::Float64(v) => buf.put_f64(*v),
            AvpData::Time(v) => buf.put_u32(*v),
            AvpData::Address(addr) => match addr {
                IpAddr::V4(v4) => {
                    buf.put_u16(1); // AddressType: IPv4
                    buf.put_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    buf.put_u16(2); // AddressType: IPv6
                    buf.put_slice(&v6.octets());
                }
            },
            AvpData::Utf8String(s) | AvpData::DiameterIdentity(s) | AvpData::DiameterUri(s) => {
                buf.put_slice(s.as_bytes())
            }
            AvpData::Grouped(avps) => {
                for avp in avps {
                    avp.encode(buf);
                }
            }
        }
    }
}

/// Helper to find an AVP by code in a list
pub fn find_avp(avps: &[Avp], code: u32) -> Option<&Avp> {
    avps.iter().find(|a| a.code == code)
}

/// Helper to find an AVP by code and vendor ID in a list
pub fn find_vendor_avp(avps: &[Avp], code: u32, vendor_id: u32) -> Option<&Avp> {
    avps.iter()
        .find(|a| a.code == code && a.vendor_id == Some(vendor_id))
}

/// Helper to find all AVPs with a given code
pub fn find_all_avps(avps: &[Avp], code: u32) -> Vec<&Avp> {
    avps.iter().filter(|a| a.code == code).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_avp_encode_decode_u32() {
        let avp = Avp::mandatory(268, AvpData::Unsigned32(2001));
        let mut buf = BytesMut::new();
        avp.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Avp::decode(&mut bytes).unwrap();

        assert_eq!(decoded.code, 268);
        assert_eq!(decoded.as_u32(), Some(2001));
    }

    #[test]
    fn test_avp_encode_decode_string() {
        let avp = Avp::mandatory(263, AvpData::Utf8String("test-session".to_string()));
        let mut buf = BytesMut::new();
        avp.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Avp::decode(&mut bytes).unwrap();

        assert_eq!(decoded.code, 263);
        assert_eq!(decoded.as_utf8_string(), Some("test-session"));
    }

    #[test]
    fn test_avp_vendor_specific() {
        let avp = Avp::vendor_mandatory(1032, 10415, AvpData::Enumerated(1004));
        assert!(avp.is_vendor_specific());
        assert!(avp.is_mandatory());
        assert_eq!(avp.vendor_id, Some(10415));
    }
}
