//! GTP Message Fuzzer
//!
//! Fuzzes the GTP message parser to find potential crashes, panics, or
//! memory safety issues when handling malformed GTP messages.
//!
//! Supports both GTPv1-C (Gn/Gp interface) and GTPv2-C (S5/S8, S11 interfaces).
//!
//! Run with: cargo +nightly fuzz run fuzz_gtp_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try parsing as GTPv1-C
    let _ = parse_gtpv1c_message(data);

    // Try parsing as GTPv2-C
    let _ = parse_gtpv2c_message(data);
});

/// Parse GTPv1-C message (3GPP TS 29.060)
fn parse_gtpv1c_message(data: &[u8]) -> Result<GtpV1Message, &'static str> {
    // Minimum GTPv1-C header is 8 bytes (without extension headers)
    if data.len() < 8 {
        return Err("Too short for GTPv1-C header");
    }

    // Byte 0: Version (3) | PT (1) | Spare (1) | E (1) | S (1) | PN (1)
    let version = (data[0] >> 5) & 0x07;
    if version != 1 {
        return Err("Not GTPv1");
    }

    let pt = (data[0] >> 4) & 0x01;
    if pt != 1 {
        return Err("Not GTP (PT=0 is GTP')");
    }

    let has_ext = (data[0] >> 2) & 0x01;
    let has_seq = (data[0] >> 1) & 0x01;
    let has_npdu = data[0] & 0x01;

    // Calculate header length
    let header_len = if has_ext == 1 || has_seq == 1 || has_npdu == 1 {
        12 // Extended header
    } else {
        8 // Basic header
    };

    if data.len() < header_len {
        return Err("Header too short for flags");
    }

    // Byte 1: Message Type
    let msg_type = data[1];

    // Bytes 2-3: Length (excludes first 8 bytes of header)
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

    // Bytes 4-7: TEID
    let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    // Optional fields
    let (seq_num, npdu_num, next_ext_type) = if header_len == 12 {
        let seq = u16::from_be_bytes([data[8], data[9]]);
        let npdu = data[10];
        let next_ext = data[11];
        (Some(seq), Some(npdu), Some(next_ext))
    } else {
        (None, None, None)
    };

    // Parse extension headers if present
    let mut ext_headers = Vec::new();
    let mut offset = header_len;
    let mut next_type = next_ext_type;

    while let Some(ext_type) = next_type {
        if ext_type == 0 {
            break; // No more extension headers
        }

        if offset >= data.len() {
            break;
        }

        let ext_len = (data[offset] as usize) * 4;
        if ext_len < 4 || offset + ext_len > data.len() {
            break;
        }

        let ext_content = data[offset + 1..offset + ext_len - 1].to_vec();
        let next = data[offset + ext_len - 1];

        ext_headers.push((ext_type, ext_content));
        offset += ext_len;
        next_type = Some(next);
    }

    // Parse IEs from payload
    let payload_start = offset;
    let payload_end = std::cmp::min(data.len(), 8 + msg_len);
    let payload = if payload_start < payload_end {
        &data[payload_start..payload_end]
    } else {
        &[]
    };

    let ies = parse_gtpv1_ies(payload);

    Ok(GtpV1Message {
        msg_type,
        teid,
        seq_num,
        ies,
    })
}

/// GTPv1-C Message structure
struct GtpV1Message {
    msg_type: u8,
    teid: u32,
    seq_num: Option<u16>,
    ies: Vec<(u8, Vec<u8>)>,
}

/// Parse GTPv1-C Information Elements
fn parse_gtpv1_ies(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut ies = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let ie_type = data[offset];
        offset += 1;

        // TV (Type-Value) IEs: types 1-127 have fixed lengths
        // TLV IEs: types 128-255 have variable lengths
        let ie_value = if ie_type < 128 {
            // Fixed length TV IEs
            let len = get_gtpv1_tv_ie_length(ie_type);
            if offset + len > data.len() {
                break;
            }
            let value = data[offset..offset + len].to_vec();
            offset += len;
            value
        } else {
            // Variable length TLV IEs
            if offset + 2 > data.len() {
                break;
            }
            let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + len > data.len() {
                break;
            }
            let value = data[offset..offset + len].to_vec();
            offset += len;
            value
        };

        ies.push((ie_type, ie_value));
    }

    ies
}

/// Get fixed length for GTPv1-C TV IEs
fn get_gtpv1_tv_ie_length(ie_type: u8) -> usize {
    match ie_type {
        1 => 1,   // Cause
        2 => 8,   // IMSI
        3 => 6,   // RAI
        4 => 4,   // TLLI
        5 => 4,   // P-TMSI
        14 => 1,  // Recovery
        15 => 1,  // Selection Mode
        16 => 4,  // TEID Data I
        17 => 4,  // TEID Control
        18 => 5,  // TEID Data II
        19 => 1,  // Teardown Indicator
        20 => 1,  // NSAPI
        26 => 2,  // Charging Characteristics
        27 => 2,  // Trace Reference
        28 => 2,  // Trace Type
        29 => 1,  // MS Not Reachable Reason
        _ => 1,   // Unknown, assume 1 byte
    }
}

/// Parse GTPv2-C message (3GPP TS 29.274)
fn parse_gtpv2c_message(data: &[u8]) -> Result<GtpV2Message, &'static str> {
    // Minimum GTPv2-C header is 8 bytes (without TEID) or 12 bytes (with TEID)
    if data.len() < 8 {
        return Err("Too short for GTPv2-C header");
    }

    // Byte 0: Version (3) | P (1) | T (1) | MP (1) | Spare (2)
    let version = (data[0] >> 5) & 0x07;
    if version != 2 {
        return Err("Not GTPv2");
    }

    let has_piggyback = (data[0] >> 4) & 0x01;
    let has_teid = (data[0] >> 3) & 0x01;

    let header_len = if has_teid == 1 { 12 } else { 8 };
    if data.len() < header_len {
        return Err("Header too short for flags");
    }

    // Byte 1: Message Type
    let msg_type = data[1];

    // Bytes 2-3: Message Length
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

    // TEID and Sequence Number
    let (teid, seq_num) = if has_teid == 1 {
        let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let seq = u32::from_be_bytes([0, data[8], data[9], data[10]]) >> 8;
        (Some(teid), seq)
    } else {
        let seq = u32::from_be_bytes([0, data[4], data[5], data[6]]) >> 8;
        (None, seq)
    };

    // Parse IEs
    let payload_start = header_len;
    let payload_end = std::cmp::min(data.len(), 4 + msg_len);
    let payload = if payload_start < payload_end {
        &data[payload_start..payload_end]
    } else {
        &[]
    };

    let ies = parse_gtpv2_ies(payload);

    Ok(GtpV2Message {
        msg_type,
        teid,
        seq_num,
        ies,
    })
}

/// GTPv2-C Message structure
struct GtpV2Message {
    msg_type: u8,
    teid: Option<u32>,
    seq_num: u32,
    ies: Vec<(u8, u8, Vec<u8>)>, // (type, instance, value)
}

/// Parse GTPv2-C Information Elements
fn parse_gtpv2_ies(data: &[u8]) -> Vec<(u8, u8, Vec<u8>)> {
    let mut ies = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        // Byte 0: IE Type
        let ie_type = data[offset];
        offset += 1;

        // Bytes 1-2: Length
        let ie_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Byte 3: Spare (4) | Instance (4)
        let instance = data[offset] & 0x0F;
        offset += 1;

        // Value
        if offset + ie_len > data.len() {
            break;
        }

        let value = data[offset..offset + ie_len].to_vec();
        offset += ie_len;

        ies.push((ie_type, instance, value));
    }

    ies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpv1_empty() {
        assert!(parse_gtpv1c_message(&[]).is_err());
    }

    #[test]
    fn test_gtpv1_basic() {
        // Echo Request
        let data = [
            0x32, 0x01, 0x00, 0x04, // Header: v1, PT=1, S=1
            0x00, 0x00, 0x00, 0x00, // TEID
            0x00, 0x01, 0x00, 0x00, // Seq, NPDU, Next ext
        ];
        assert!(parse_gtpv1c_message(&data).is_ok());
    }

    #[test]
    fn test_gtpv2_empty() {
        assert!(parse_gtpv2c_message(&[]).is_err());
    }

    #[test]
    fn test_gtpv2_basic() {
        // Echo Request without TEID
        let data = [
            0x40, 0x01, 0x00, 0x04, // Header: v2, T=0
            0x00, 0x00, 0x01, 0x00, // Seq + spare
        ];
        assert!(parse_gtpv2c_message(&data).is_ok());
    }
}
