//! PFCP Message Fuzzer
//!
//! Fuzzes the PFCP message parser to find potential crashes, panics, or
//! memory safety issues when handling malformed PFCP messages.
//!
//! PFCP (Packet Forwarding Control Protocol) is used on the N4 interface
//! between SMF and UPF.
//!
//! Run with: cargo +nightly fuzz run fuzz_pfcp_message

#![no_main]

use libfuzzer_sys::fuzz_target;
use bytes::Bytes;

fuzz_target!(|data: &[u8]| {
    // Skip very small inputs that can't be valid PFCP
    if data.len() < 8 {
        return;
    }

    // Try parsing as a PFCP message
    let _ = parse_pfcp_message(data);
});

/// Parse PFCP message from bytes
///
/// This function should never panic regardless of input.
fn parse_pfcp_message(data: &[u8]) -> Result<(), &'static str> {
    // PFCP header validation (3GPP TS 29.244)
    // Minimum PFCP header is 8 bytes (16 bytes with SEID)
    if data.len() < 8 {
        return Err("Too short for PFCP header");
    }

    // Byte 0: Version (3 bits) | Spare (3 bits) | MP (1 bit) | S (1 bit)
    let version = (data[0] >> 5) & 0x07;
    if version != 1 {
        return Err("Unsupported PFCP version");
    }

    let has_seid = (data[0] & 0x01) != 0;
    let _has_mp = (data[0] & 0x02) != 0;

    let min_header_len = if has_seid { 16 } else { 8 };
    if data.len() < min_header_len {
        return Err("Header too short for flags");
    }

    // Byte 1: Message Type
    let msg_type = data[1];

    // Bytes 2-3: Message Length
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

    // Validate message length
    let total_expected = 4 + msg_len; // 4-byte header prefix + message length
    if data.len() < total_expected {
        return Err("Declared length exceeds buffer");
    }

    // Extract SEID if present
    let (seid, payload_start) = if has_seid {
        let seid = u64::from_be_bytes([
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11],
        ]);
        let seq_num = u32::from_be_bytes([0, data[12], data[13], data[14]]) >> 8;
        (Some(seid), 16)
    } else {
        let seq_num = u32::from_be_bytes([0, data[4], data[5], data[6]]) >> 8;
        (None, 8)
    };

    // Parse IEs (Information Elements)
    let payload = &data[payload_start..std::cmp::min(data.len(), total_expected)];
    let _ = parse_pfcp_ies(payload);

    Ok(())
}

/// Parse PFCP Information Elements
fn parse_pfcp_ies(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut ies = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        // IE Type (2 bytes)
        let ie_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // IE Length (2 bytes)
        let ie_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Validate and extract IE value
        if offset + ie_len > data.len() {
            break; // Truncated IE
        }

        let ie_value = data[offset..offset + ie_len].to_vec();
        ies.push((ie_type, ie_value));

        offset += ie_len;
    }

    ies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        assert!(parse_pfcp_message(&[]).is_err());
    }

    #[test]
    fn test_short_input() {
        assert!(parse_pfcp_message(&[0x20, 0x01, 0x00, 0x04]).is_err());
    }

    #[test]
    fn test_valid_minimal_header() {
        // Version 1, no SEID, heartbeat request
        let data = [0x20, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
        assert!(parse_pfcp_message(&data).is_ok());
    }

    #[test]
    fn test_with_seid() {
        // Version 1, with SEID
        let data = [
            0x21, 0x32, 0x00, 0x08, // Header with S=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SEID
            0x00, 0x00, 0x01, 0x00, // Seq + spare
        ];
        assert!(parse_pfcp_message(&data).is_ok());
    }
}
