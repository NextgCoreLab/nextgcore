//! GTPv2-C Message Builders
//!
//! Functions for building common GTPv2-C messages.

use bytes::{BufMut, BytesMut};
use crate::error::GtpResult;
use crate::v2::header::Gtp2Header;
use crate::v2::ie::{Gtp2Ie, Gtp2IeType};
use crate::v2::message::Gtp2Message;
use crate::v2::header::Gtp2MessageType;

/// Build a Create Session Request message
pub fn build_create_session_request(
    teid: u32,
    seq: u32,
    imsi: &[u8],
    apn: &str,
    serving_network: &[u8; 3],
    rat_type: u8,
) -> GtpResult<Gtp2Message> {
    let mut message = Gtp2Message {
        header: Gtp2Header {
            version: 2,
            piggybacked: false,
            teid_presence: true,
            message_type: Gtp2MessageType::CreateSessionRequest as u8,
            length: 0,
            teid: Some(teid),
            sequence_number: seq,
        },
        ies: Vec::new(),
    };

    // IE: IMSI (mandatory)
    message.ies.push(Gtp2Ie::from_slice(
        Gtp2IeType::Imsi as u8,
        0,
        imsi,
    ));

    // IE: RAT Type (mandatory)
    message.ies.push(Gtp2Ie::from_slice(
        Gtp2IeType::RatType as u8,
        0,
        &[rat_type],
    ));

    // IE: APN (mandatory)
    let apn_bytes = encode_apn(apn);
    message.ies.push(Gtp2Ie::from_slice(
        Gtp2IeType::Apn as u8,
        0,
        &apn_bytes,
    ));

    // IE: Serving Network (mandatory)
    message.ies.push(Gtp2Ie::from_slice(
        Gtp2IeType::ServingNetwork as u8,
        0,
        serving_network,
    ));

    Ok(message)
}

/// Build a Modify Bearer Request message
pub fn build_modify_bearer_request(
    teid: u32,
    seq: u32,
    ebi: u8,
) -> GtpResult<Gtp2Message> {
    let mut message = Gtp2Message {
        header: Gtp2Header {
            version: 2,
            piggybacked: false,
            teid_presence: true,
            message_type: Gtp2MessageType::ModifyBearerRequest as u8,
            length: 0,
            teid: Some(teid),
            sequence_number: seq,
        },
        ies: Vec::new(),
    };

    // IE: EBI (EPS Bearer ID) (mandatory)
    message.ies.push(Gtp2Ie::from_slice(
        Gtp2IeType::Ebi as u8,
        0,
        &[ebi],
    ));

    Ok(message)
}

/// Build a Delete Session Request message
pub fn build_delete_session_request(
    teid: u32,
    seq: u32,
    ebi: u8,
) -> GtpResult<Gtp2Message> {
    let mut message = Gtp2Message {
        header: Gtp2Header {
            version: 2,
            piggybacked: false,
            teid_presence: true,
            message_type: Gtp2MessageType::DeleteSessionRequest as u8,
            length: 0,
            teid: Some(teid),
            sequence_number: seq,
        },
        ies: Vec::new(),
    };

    // IE: EBI (mandatory)
    message.ies.push(Gtp2Ie::from_slice(
        Gtp2IeType::Ebi as u8,
        0,
        &[ebi],
    ));

    Ok(message)
}

/// Encode APN to DNS-style format
fn encode_apn(apn: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for label in apn.split('.') {
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result
}

// ============================================================================
// Structured IE Encoders
// ============================================================================

/// F-TEID (Fully Qualified TEID) IE structure
#[derive(Debug, Clone)]
pub struct FTeid {
    pub interface_type: u8,
    pub teid: u32,
    pub ipv4: Option<[u8; 4]>,
    pub ipv6: Option<[u8; 16]>,
}

impl FTeid {
    /// Encode F-TEID to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        let mut flags = self.interface_type & 0x3F;
        if self.ipv4.is_some() {
            flags |= 0x80;
        }
        if self.ipv6.is_some() {
            flags |= 0x40;
        }
        buf.put_u8(flags);
        buf.put_u32(self.teid);
        if let Some(ipv4) = self.ipv4 {
            buf.put_slice(&ipv4);
        }
        if let Some(ipv6) = self.ipv6 {
            buf.put_slice(&ipv6);
        }
        buf.to_vec()
    }

    /// Decode F-TEID from bytes
    pub fn decode(data: &[u8]) -> GtpResult<Self> {
        if data.len() < 5 {
            return Err(crate::error::GtpError::BufferTooShort {
                needed: 5,
                available: data.len(),
            });
        }
        let flags = data[0];
        let teid = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let interface_type = flags & 0x3F;
        let mut offset = 5;

        let ipv4 = if flags & 0x80 != 0 {
            if data.len() < offset + 4 {
                return Err(crate::error::GtpError::BufferTooShort {
                    needed: offset + 4,
                    available: data.len(),
                });
            }
            let addr = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
            offset += 4;
            Some(addr)
        } else {
            None
        };

        let ipv6 = if flags & 0x40 != 0 {
            if data.len() < offset + 16 {
                return Err(crate::error::GtpError::BufferTooShort {
                    needed: offset + 16,
                    available: data.len(),
                });
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&data[offset..offset + 16]);
            Some(addr)
        } else {
            None
        };

        Ok(FTeid {
            interface_type,
            teid,
            ipv4,
            ipv6,
        })
    }
}

/// ULI (User Location Information) IE structure
#[derive(Debug, Clone, Default)]
pub struct Uli {
    pub tai: Option<Tai>,
    pub ecgi: Option<Ecgi>,
}

#[derive(Debug, Clone)]
pub struct Tai {
    pub mcc: u16,
    pub mnc: u16,
    pub tac: u16,
}

#[derive(Debug, Clone)]
pub struct Ecgi {
    pub mcc: u16,
    pub mnc: u16,
    pub eci: u32,
}

impl Uli {
    /// Encode ULI to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        let mut flags = 0u8;
        if self.tai.is_some() {
            flags |= 0x01;
        }
        if self.ecgi.is_some() {
            flags |= 0x02;
        }
        buf.put_u8(flags);

        if let Some(ref tai) = self.tai {
            // Encode TAI (5 bytes)
            let plmn = encode_plmn(tai.mcc, tai.mnc);
            buf.put_slice(&plmn);
            buf.put_u16(tai.tac);
        }

        if let Some(ref ecgi) = self.ecgi {
            // Encode ECGI (7 bytes)
            let plmn = encode_plmn(ecgi.mcc, ecgi.mnc);
            buf.put_slice(&plmn);
            buf.put_u32(ecgi.eci);
        }

        buf.to_vec()
    }
}

/// AMBR (Aggregate Maximum Bit Rate) IE structure
#[derive(Debug, Clone)]
pub struct Ambr {
    pub uplink: u32,
    pub downlink: u32,
}

impl Ambr {
    /// Encode AMBR to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u32(self.uplink);
        buf.put_u32(self.downlink);
        buf.to_vec()
    }

    /// Decode AMBR from bytes
    pub fn decode(data: &[u8]) -> GtpResult<Self> {
        if data.len() < 8 {
            return Err(crate::error::GtpError::BufferTooShort {
                needed: 8,
                available: data.len(),
            });
        }
        Ok(Ambr {
            uplink: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            downlink: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

/// Encode PLMN identity (MCC/MNC)
fn encode_plmn(mcc: u16, mnc: u16) -> [u8; 3] {
    let mcc1 = (mcc / 100) % 10;
    let mcc2 = (mcc / 10) % 10;
    let mcc3 = mcc % 10;
    let mnc1 = (mnc / 100) % 10;
    let mnc2 = (mnc / 10) % 10;
    let mnc3 = mnc % 10;

    let byte0 = ((mcc2 as u8) << 4) | (mcc1 as u8);
    let byte1 = if mnc > 99 {
        ((mnc3 as u8) << 4) | (mcc3 as u8)
    } else {
        0xF0 | (mcc3 as u8)
    };
    let byte2 = ((mnc2 as u8) << 4) | (mnc1 as u8);

    [byte0, byte1, byte2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_create_session_request() {
        let msg = build_create_session_request(
            0x12345678,
            1,
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            "internet",
            &[0x00, 0xF1, 0x10],
            6, // E-UTRAN
        ).unwrap();
        assert_eq!(msg.header.message_type, Gtp2MessageType::CreateSessionRequest as u8);
        assert!(msg.ies.len() >= 3);
    }

    #[test]
    fn test_fteid_roundtrip() {
        let fteid = FTeid {
            interface_type: 7,
            teid: 0xABCDEF01,
            ipv4: Some([192, 168, 1, 1]),
            ipv6: None,
        };
        let encoded = fteid.encode();
        let decoded = FTeid::decode(&encoded).unwrap();
        assert_eq!(decoded.teid, fteid.teid);
        assert_eq!(decoded.ipv4, fteid.ipv4);
    }

    #[test]
    fn test_ambr_roundtrip() {
        let ambr = Ambr {
            uplink: 1000000,
            downlink: 5000000,
        };
        let encoded = ambr.encode();
        let decoded = Ambr::decode(&encoded).unwrap();
        assert_eq!(decoded.uplink, ambr.uplink);
        assert_eq!(decoded.downlink, ambr.downlink);
    }
}
