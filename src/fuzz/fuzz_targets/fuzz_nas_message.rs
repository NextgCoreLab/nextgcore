//! NAS Message Fuzzer
//!
//! Fuzzes the NAS (Non-Access Stratum) message parser to find potential
//! crashes, panics, or memory safety issues.
//!
//! Supports both 5G NAS (5GMM/5GSM) and EPS NAS (EMM/ESM).
//!
//! Run with: cargo +nightly fuzz run fuzz_nas_message

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try parsing as 5G NAS
    let _ = parse_5gs_nas_message(data);

    // Try parsing as EPS NAS
    let _ = parse_eps_nas_message(data);
});

/// Extended Protocol Discriminator values
mod epd {
    pub const FIVEGMM: u8 = 0x7E;  // 5G Mobility Management
    pub const FIVEGSM: u8 = 0x2E;  // 5G Session Management
    pub const EMM: u8 = 0x07;      // EPS Mobility Management
    pub const ESM: u8 = 0x02;      // EPS Session Management
}

/// Parse 5G NAS message (3GPP TS 24.501)
fn parse_5gs_nas_message(data: &[u8]) -> Result<Nas5gsMessage, &'static str> {
    if data.len() < 3 {
        return Err("Too short for 5GS NAS");
    }

    // Byte 0: Extended Protocol Discriminator
    let epd = data[0];

    match epd {
        epd::FIVEGMM => parse_5gmm_message(data),
        epd::FIVEGSM => parse_5gsm_message(data),
        _ => Err("Unknown 5GS protocol discriminator"),
    }
}

/// Parse 5GMM message
fn parse_5gmm_message(data: &[u8]) -> Result<Nas5gsMessage, &'static str> {
    if data.len() < 3 {
        return Err("Too short for 5GMM message");
    }

    // Byte 1: Security header type (4 bits) + Spare (4 bits)
    let security_header_type = (data[1] >> 4) & 0x0F;

    // Check if this is a security protected message
    if security_header_type != 0 {
        // Security protected message
        if data.len() < 7 {
            return Err("Too short for security protected message");
        }

        // Bytes 2-5: Message Authentication Code
        let mac = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);

        // Byte 6: Sequence Number
        let seq_num = data[6];

        // The rest is the protected NAS message
        if data.len() > 7 {
            // Recursively parse the inner message (would be decrypted in real impl)
            return Ok(Nas5gsMessage {
                epd: data[0],
                security_header_type,
                message_type: 0, // Unknown until decrypted
                ies: Vec::new(),
            });
        }

        return Err("Empty protected message");
    }

    // Plain NAS message
    // Byte 2: Message Type
    if data.len() < 3 {
        return Err("Missing message type");
    }
    let message_type = data[2];

    // Parse IEs from byte 3 onwards
    let ies = parse_5gmm_ies(message_type, &data[3..]);

    Ok(Nas5gsMessage {
        epd: data[0],
        security_header_type,
        message_type,
        ies,
    })
}

/// Parse 5GSM message
fn parse_5gsm_message(data: &[u8]) -> Result<Nas5gsMessage, &'static str> {
    if data.len() < 4 {
        return Err("Too short for 5GSM message");
    }

    // Byte 1: PDU Session ID
    let pdu_session_id = data[1];

    // Byte 2: PTI (Procedure Transaction Identity)
    let pti = data[2];

    // Byte 3: Message Type
    let message_type = data[3];

    // Parse IEs from byte 4 onwards
    let ies = parse_5gsm_ies(message_type, &data[4..]);

    Ok(Nas5gsMessage {
        epd: data[0],
        security_header_type: 0,
        message_type,
        ies,
    })
}

/// 5GS NAS Message structure
struct Nas5gsMessage {
    epd: u8,
    security_header_type: u8,
    message_type: u8,
    ies: Vec<(u8, Vec<u8>)>,
}

/// Parse 5GMM IEs (Type-Length-Value format)
fn parse_5gmm_ies(msg_type: u8, data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut ies = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Type 1 IE (TV, 1 byte total) or Type 3/4/6 IE (TLV/TLV-E)
        let iei = data[offset];
        offset += 1;

        // Check if this is a Type 1 IE (4-bit IEI in high nibble)
        let ie_format = get_5gmm_ie_format(msg_type, iei);

        match ie_format {
            IeFormat::Type1 => {
                // Value is in low nibble
                ies.push((iei >> 4, vec![iei & 0x0F]));
            }
            IeFormat::Type3(len) => {
                // Fixed length, no length field
                if offset + len > data.len() {
                    break;
                }
                ies.push((iei, data[offset..offset + len].to_vec()));
                offset += len;
            }
            IeFormat::Type4 => {
                // Variable length, 1-byte length field
                if offset >= data.len() {
                    break;
                }
                let len = data[offset] as usize;
                offset += 1;
                if offset + len > data.len() {
                    break;
                }
                ies.push((iei, data[offset..offset + len].to_vec()));
                offset += len;
            }
            IeFormat::Type6 => {
                // Variable length, 2-byte length field
                if offset + 2 > data.len() {
                    break;
                }
                let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                if offset + len > data.len() {
                    break;
                }
                ies.push((iei, data[offset..offset + len].to_vec()));
                offset += len;
            }
            IeFormat::Unknown => {
                // Try TLV-E format
                if offset + 2 <= data.len() {
                    let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2;
                    if offset + len <= data.len() {
                        ies.push((iei, data[offset..offset + len].to_vec()));
                        offset += len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
    }

    ies
}

/// Parse 5GSM IEs
fn parse_5gsm_ies(msg_type: u8, data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    // Similar structure to 5GMM
    parse_5gmm_ies(msg_type, data)
}

/// IE Format types
enum IeFormat {
    Type1,       // TV, 1 byte total (4-bit IEI + 4-bit value)
    Type3(usize), // TV, fixed length
    Type4,       // TLV, 1-byte length
    Type6,       // TLV-E, 2-byte length
    Unknown,
}

/// Determine IE format based on message type and IEI
fn get_5gmm_ie_format(_msg_type: u8, iei: u8) -> IeFormat {
    // Simplified - in real implementation, this would be message-specific
    match iei >> 4 {
        0x0..=0x7 => IeFormat::Unknown, // Likely mandatory IEs
        0x8 | 0x9 => IeFormat::Type1,
        0xA..=0xD => IeFormat::Type4,
        0xE | 0xF => IeFormat::Type6,
        _ => IeFormat::Unknown,
    }
}

/// Parse EPS NAS message (3GPP TS 24.301)
fn parse_eps_nas_message(data: &[u8]) -> Result<EpsNasMessage, &'static str> {
    if data.len() < 2 {
        return Err("Too short for EPS NAS");
    }

    // Byte 0: Security header type (4 bits) + Protocol discriminator (4 bits)
    let security_header_type = (data[0] >> 4) & 0x0F;
    let protocol_discriminator = data[0] & 0x0F;

    match protocol_discriminator {
        epd::EMM => parse_emm_message(data),
        epd::ESM => parse_esm_message(data),
        _ => Err("Unknown EPS protocol discriminator"),
    }
}

/// Parse EMM message
fn parse_emm_message(data: &[u8]) -> Result<EpsNasMessage, &'static str> {
    if data.len() < 2 {
        return Err("Too short for EMM message");
    }

    let security_header_type = (data[0] >> 4) & 0x0F;

    // Security protected message
    if security_header_type != 0 {
        if data.len() < 6 {
            return Err("Too short for security protected EMM");
        }
        return Ok(EpsNasMessage {
            protocol_discriminator: data[0] & 0x0F,
            security_header_type,
            message_type: 0,
            ies: Vec::new(),
        });
    }

    // Plain NAS message
    let message_type = data[1];
    let ies = parse_emm_ies(message_type, &data[2..]);

    Ok(EpsNasMessage {
        protocol_discriminator: data[0] & 0x0F,
        security_header_type,
        message_type,
        ies,
    })
}

/// Parse ESM message
fn parse_esm_message(data: &[u8]) -> Result<EpsNasMessage, &'static str> {
    if data.len() < 3 {
        return Err("Too short for ESM message");
    }

    // Byte 0: EPS bearer identity (4) + Protocol discriminator (4)
    let _bearer_id = (data[0] >> 4) & 0x0F;

    // Byte 1: PTI
    let _pti = data[1];

    // Byte 2: Message Type
    let message_type = data[2];

    let ies = parse_esm_ies(message_type, &data[3..]);

    Ok(EpsNasMessage {
        protocol_discriminator: data[0] & 0x0F,
        security_header_type: 0,
        message_type,
        ies,
    })
}

/// EPS NAS Message structure
struct EpsNasMessage {
    protocol_discriminator: u8,
    security_header_type: u8,
    message_type: u8,
    ies: Vec<(u8, Vec<u8>)>,
}

/// Parse EMM IEs
fn parse_emm_ies(msg_type: u8, data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    parse_eps_nas_ies(data)
}

/// Parse ESM IEs
fn parse_esm_ies(msg_type: u8, data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    parse_eps_nas_ies(data)
}

/// Generic EPS NAS IE parser
fn parse_eps_nas_ies(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut ies = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let iei = data[offset];
        offset += 1;

        // Heuristic: high nibble patterns indicate different IE types
        if (iei & 0xF0) == 0xF0 || (iei & 0xF0) == 0xE0 {
            // Type 1 TV (4-bit IEI + 4-bit value)
            ies.push((iei >> 4, vec![iei & 0x0F]));
        } else if (iei & 0xF0) >= 0xA0 {
            // Type 4 TLV
            if offset >= data.len() {
                break;
            }
            let len = data[offset] as usize;
            offset += 1;
            if offset + len > data.len() {
                break;
            }
            ies.push((iei, data[offset..offset + len].to_vec()));
            offset += len;
        } else {
            // Type 6 TLV-E or Type 3 TV
            if offset + 2 <= data.len() {
                let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                if len > 0 && offset + len <= data.len() {
                    ies.push((iei, data[offset..offset + len].to_vec()));
                    offset += len;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    ies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_5gmm_empty() {
        assert!(parse_5gs_nas_message(&[]).is_err());
    }

    #[test]
    fn test_5gmm_registration_request() {
        // Minimal Registration Request
        let data = [
            0x7E, // EPD: 5GMM
            0x00, // Security header: plain
            0x41, // Message type: Registration Request
        ];
        assert!(parse_5gs_nas_message(&data).is_ok());
    }

    #[test]
    fn test_emm_empty() {
        assert!(parse_eps_nas_message(&[]).is_err());
    }

    #[test]
    fn test_emm_attach_request() {
        // Minimal Attach Request
        let data = [
            0x07, // Security: plain + EMM
            0x41, // Message type: Attach Request
        ];
        assert!(parse_eps_nas_message(&data).is_ok());
    }
}
