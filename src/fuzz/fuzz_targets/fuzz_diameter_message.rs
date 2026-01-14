//! Diameter Message Fuzzer
//!
//! Fuzzes the Diameter message parser to find potential crashes, panics, or
//! memory safety issues when handling malformed Diameter messages.
//!
//! Diameter is used for:
//! - S6a (MME ↔ HSS)
//! - S6b (PGW ↔ AAA)
//! - Gx (PCEF ↔ PCRF)
//! - Gy (CTF ↔ OCS)
//! - Rx (AF ↔ PCRF)
//! - Cx (I/S-CSCF ↔ HSS)
//! - SWx (3GPP AAA ↔ HSS)
//!
//! Run with: cargo +nightly fuzz run fuzz_diameter_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_diameter_message(data);
});

/// Diameter message flags
mod flags {
    pub const REQUEST: u8 = 0x80;
    pub const PROXIABLE: u8 = 0x40;
    pub const ERROR: u8 = 0x20;
    pub const RETRANSMIT: u8 = 0x10;
}

/// Common Diameter AVP codes
mod avp_code {
    pub const SESSION_ID: u32 = 263;
    pub const ORIGIN_HOST: u32 = 264;
    pub const ORIGIN_REALM: u32 = 296;
    pub const DESTINATION_HOST: u32 = 293;
    pub const DESTINATION_REALM: u32 = 283;
    pub const AUTH_APPLICATION_ID: u32 = 258;
    pub const RESULT_CODE: u32 = 268;
    pub const USER_NAME: u32 = 1;
    pub const VENDOR_SPECIFIC_APP_ID: u32 = 260;
}

/// Parse Diameter message (RFC 6733)
fn parse_diameter_message(data: &[u8]) -> Result<DiameterMessage, &'static str> {
    // Minimum Diameter header is 20 bytes
    if data.len() < 20 {
        return Err("Too short for Diameter header");
    }

    // Byte 0: Version
    let version = data[0];
    if version != 1 {
        return Err("Unsupported Diameter version");
    }

    // Bytes 1-3: Message Length (24 bits)
    let msg_len = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

    // Validate length
    if msg_len < 20 {
        return Err("Invalid message length");
    }
    if data.len() < msg_len {
        return Err("Message truncated");
    }

    // Byte 4: Command Flags
    let cmd_flags = data[4];
    let is_request = (cmd_flags & flags::REQUEST) != 0;
    let is_proxiable = (cmd_flags & flags::PROXIABLE) != 0;
    let is_error = (cmd_flags & flags::ERROR) != 0;
    let is_retransmit = (cmd_flags & flags::RETRANSMIT) != 0;

    // Bytes 5-7: Command Code (24 bits)
    let cmd_code = u32::from_be_bytes([0, data[5], data[6], data[7]]);

    // Bytes 8-11: Application ID
    let app_id = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    // Bytes 12-15: Hop-by-Hop Identifier
    let hop_by_hop = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    // Bytes 16-19: End-to-End Identifier
    let end_to_end = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

    // Parse AVPs from byte 20 onwards
    let avps = parse_diameter_avps(&data[20..msg_len]);

    Ok(DiameterMessage {
        version,
        msg_len: msg_len as u32,
        cmd_flags,
        cmd_code,
        app_id,
        hop_by_hop,
        end_to_end,
        is_request,
        avps,
    })
}

/// Diameter Message structure
struct DiameterMessage {
    version: u8,
    msg_len: u32,
    cmd_flags: u8,
    cmd_code: u32,
    app_id: u32,
    hop_by_hop: u32,
    end_to_end: u32,
    is_request: bool,
    avps: Vec<DiameterAvp>,
}

/// Diameter AVP structure
struct DiameterAvp {
    code: u32,
    flags: u8,
    vendor_id: Option<u32>,
    data: Vec<u8>,
}

/// Parse Diameter AVPs
fn parse_diameter_avps(data: &[u8]) -> Vec<DiameterAvp> {
    let mut avps = Vec::new();
    let mut offset = 0;

    while offset + 8 <= data.len() {
        // Bytes 0-3: AVP Code
        let code = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        // Byte 4: AVP Flags
        let flags = data[offset];
        let has_vendor = (flags & 0x80) != 0;
        let is_mandatory = (flags & 0x40) != 0;
        let is_protected = (flags & 0x20) != 0;
        offset += 1;

        // Bytes 5-7: AVP Length (24 bits)
        let avp_len = u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        // Minimum AVP length check
        let min_len = if has_vendor { 12 } else { 8 };
        if avp_len < min_len {
            break;
        }

        // Vendor ID (optional)
        let vendor_id = if has_vendor {
            if offset + 4 > data.len() {
                break;
            }
            let vid = u32::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]);
            offset += 4;
            Some(vid)
        } else {
            None
        };

        // AVP Data length
        let data_len = avp_len - (if has_vendor { 12 } else { 8 });
        if offset + data_len > data.len() {
            break;
        }

        let avp_data = data[offset..offset + data_len].to_vec();
        offset += data_len;

        // Padding to 4-byte boundary
        let padding = (4 - (avp_len % 4)) % 4;
        offset += padding;

        avps.push(DiameterAvp {
            code,
            flags,
            vendor_id,
            data: avp_data,
        });

        // Handle grouped AVPs recursively
        if is_grouped_avp(code) && !avp_data.is_empty() {
            let _ = parse_diameter_avps(&avp_data);
        }
    }

    avps
}

/// Check if AVP is a grouped AVP
fn is_grouped_avp(code: u32) -> bool {
    match code {
        avp_code::VENDOR_SPECIFIC_APP_ID => true,
        260 => true,  // Vendor-Specific-Application-Id
        279 => true,  // Failed-AVP
        297 => true,  // Experimental-Result
        // 3GPP specific grouped AVPs
        628 => true,  // Supported-Features
        630 => true,  // Feature-List
        1001 => true, // Charging-Rule-Install
        1002 => true, // Charging-Rule-Remove
        1003 => true, // Charging-Rule-Definition
        _ => false,
    }
}

/// Validate Session-Id format (RFC 6733 Section 8.8)
fn validate_session_id(data: &[u8]) -> bool {
    // Session-Id is a UTF8String with format: <DiameterIdentity>;<high-32-bits>;<low-32-bits>[;<optional>]
    if data.is_empty() {
        return false;
    }

    // Check for valid UTF-8
    if std::str::from_utf8(data).is_err() {
        return false;
    }

    // Should contain at least one semicolon
    data.contains(&b';')
}

/// Parse Diameter Identity (hostname in DiamIdent format)
fn parse_diameter_identity(data: &[u8]) -> Option<String> {
    match std::str::from_utf8(data) {
        Ok(s) if !s.is_empty() => Some(s.to_string()),
        _ => None,
    }
}

/// Parse Result-Code AVP
fn parse_result_code(data: &[u8]) -> Option<u32> {
    if data.len() != 4 {
        return None;
    }
    Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

/// Common Diameter Result Codes
mod result_code {
    pub const DIAMETER_SUCCESS: u32 = 2001;
    pub const DIAMETER_LIMITED_SUCCESS: u32 = 2002;
    pub const DIAMETER_COMMAND_UNSUPPORTED: u32 = 3001;
    pub const DIAMETER_UNABLE_TO_DELIVER: u32 = 3002;
    pub const DIAMETER_REALM_NOT_SERVED: u32 = 3003;
    pub const DIAMETER_TOO_BUSY: u32 = 3004;
    pub const DIAMETER_LOOP_DETECTED: u32 = 3005;
    pub const DIAMETER_REDIRECT_INDICATION: u32 = 3006;
    pub const DIAMETER_APPLICATION_UNSUPPORTED: u32 = 3007;
    pub const DIAMETER_INVALID_AVP_VALUE: u32 = 5004;
    pub const DIAMETER_MISSING_AVP: u32 = 5005;
    pub const DIAMETER_RESOURCES_EXCEEDED: u32 = 5006;
    pub const DIAMETER_CONTRADICTING_AVPS: u32 = 5007;
    pub const DIAMETER_AVP_NOT_ALLOWED: u32 = 5008;
    pub const DIAMETER_AVP_OCCURS_TOO_MANY_TIMES: u32 = 5009;
    pub const DIAMETER_INVALID_AVP_LENGTH: u32 = 5014;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        assert!(parse_diameter_message(&[]).is_err());
    }

    #[test]
    fn test_short_input() {
        assert!(parse_diameter_message(&[1, 0, 0, 20]).is_err());
    }

    #[test]
    fn test_wrong_version() {
        let mut data = [0u8; 20];
        data[0] = 2; // Wrong version
        assert!(parse_diameter_message(&data).is_err());
    }

    #[test]
    fn test_minimal_valid_header() {
        let mut data = [0u8; 20];
        data[0] = 1;  // Version
        data[3] = 20; // Length (20 bytes = header only)
        data[4] = flags::REQUEST; // Request flag
        data[7] = 257; // Capability-Exchange-Request (CER)

        let result = parse_diameter_message(&data);
        assert!(result.is_ok());

        let msg = result.unwrap();
        assert!(msg.is_request);
        assert_eq!(msg.cmd_code, 257);
    }

    #[test]
    fn test_avp_parsing() {
        // Session-Id AVP
        let avp_data = [
            0x00, 0x00, 0x01, 0x07, // AVP Code: 263 (Session-Id)
            0x40,                   // Flags: Mandatory
            0x00, 0x00, 0x14,       // Length: 20 bytes
            // 12 bytes of data (padded to 4-byte boundary)
            b't', b'e', b's', b't', b';', b'1', b'2', b'3', 0, 0, 0, 0,
        ];

        let avps = parse_diameter_avps(&avp_data);
        assert_eq!(avps.len(), 1);
        assert_eq!(avps[0].code, 263);
    }

    #[test]
    fn test_session_id_validation() {
        assert!(validate_session_id(b"host.example.com;1234;5678"));
        assert!(!validate_session_id(b""));
        assert!(!validate_session_id(b"no-semicolon"));
    }

    #[test]
    fn test_result_code_parsing() {
        assert_eq!(parse_result_code(&[0, 0, 0x07, 0xD1]), Some(result_code::DIAMETER_SUCCESS));
        assert_eq!(parse_result_code(&[0, 0, 0]), None); // Too short
    }
}
