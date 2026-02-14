//! NAS Security Functions
//!
//! Port of src/mme/nas-security.c - NAS security encoding/decoding functions
//!
//! Implements NAS message integrity protection and ciphering for EPS.

use crate::context::MmeUe;
use crate::emm_build::SecurityHeaderType;

// ============================================================================
// Constants
// ============================================================================

/// NAS security bearer (always 0 for NAS)
pub const NAS_SECURITY_BEARER: u32 = 0;

/// NAS security MAC size in bytes
pub const NAS_SECURITY_MAC_SIZE: usize = 4;

/// NAS security downlink direction
pub const NAS_SECURITY_DOWNLINK_DIRECTION: u32 = 1;

/// NAS security uplink direction
pub const NAS_SECURITY_UPLINK_DIRECTION: u32 = 0;

/// NAS headroom for security header
pub const OGS_NAS_HEADROOM: usize = 16;

// ============================================================================
// Security Header Type Parsing
// ============================================================================

/// Parsed security header type flags
#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityHeaderTypeFlags {
    /// Service request message
    pub service_request: bool,
    /// Integrity protected
    pub integrity_protected: bool,
    /// New security context
    pub new_security_context: bool,
    /// Ciphered
    pub ciphered: bool,
}

impl SecurityHeaderTypeFlags {
    /// Parse from security header type value
    pub fn from_header_type(header_type: u8) -> Self {
        match header_type {
            0 => Self::default(), // Plain NAS
            1 => Self {
                integrity_protected: true,
                ..Default::default()
            },
            2 => Self {
                integrity_protected: true,
                ciphered: true,
                ..Default::default()
            },
            3 => Self {
                integrity_protected: true,
                new_security_context: true,
                ..Default::default()
            },
            4 => Self {
                integrity_protected: true,
                new_security_context: true,
                ciphered: true,
                ..Default::default()
            },
            12 => Self {
                service_request: true,
                ..Default::default()
            },
            _ => Self::default(),
        }
    }
}

// ============================================================================
// NAS Security Header
// ============================================================================

/// NAS EPS Security Header (6 bytes)
#[derive(Debug, Clone, Default)]
pub struct NasEpsSecurityHeader {
    /// Security header type (4 bits) + Protocol discriminator (4 bits)
    pub security_header_type: u8,
    /// Protocol discriminator
    pub protocol_discriminator: u8,
    /// Message authentication code (4 bytes, big-endian)
    pub message_authentication_code: u32,
    /// Sequence number
    pub sequence_number: u8,
}

impl NasEpsSecurityHeader {
    /// Encode to bytes
    pub fn encode(&self) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        bytes[0] = (self.security_header_type << 4) | (self.protocol_discriminator & 0x0f);
        bytes[1] = (self.message_authentication_code >> 24) as u8;
        bytes[2] = (self.message_authentication_code >> 16) as u8;
        bytes[3] = (self.message_authentication_code >> 8) as u8;
        bytes[4] = self.message_authentication_code as u8;
        bytes[5] = self.sequence_number;
        bytes
    }

    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 6 {
            return None;
        }
        Some(Self {
            security_header_type: bytes[0] >> 4,
            protocol_discriminator: bytes[0] & 0x0f,
            message_authentication_code: ((bytes[1] as u32) << 24)
                | ((bytes[2] as u32) << 16)
                | ((bytes[3] as u32) << 8)
                | (bytes[4] as u32),
            sequence_number: bytes[5],
        })
    }
}

// ============================================================================
// NAS MAC Calculation
// ============================================================================

/// Calculate NAS MAC (Message Authentication Code)
///
/// # Arguments
/// * `algorithm` - Integrity algorithm (0=EIA0, 1=EIA1/SNOW3G, 2=EIA2/AES, 3=EIA3/ZUC)
/// * `knas_int` - NAS integrity key (16 bytes)
/// * `count` - NAS count value
/// * `bearer` - Bearer ID (always 0 for NAS)
/// * `direction` - Direction (0=uplink, 1=downlink)
/// * `message` - Message to authenticate
///
/// # Returns
/// * 4-byte MAC value
pub fn nas_mac_calculate(
    algorithm: u8,
    knas_int: &[u8],
    count: u32,
    bearer: u32,
    direction: u32,
    message: &[u8],
) -> [u8; 4] {
    match algorithm {
        0 => {
            // EIA0 - Null integrity (no protection)
            [0u8; 4]
        }
        1 => {
            // EIA1 - SNOW 3G (UIA2)
            if knas_int.len() < 16 {
                return [0u8; 4];
            }
            let key: [u8; 16] = knas_int[..16].try_into().unwrap_or([0u8; 16]);
            let fresh = bearer << 27;
            ogs_crypt::snow3g::snow_3g_f9(
                &key,
                count,
                fresh,
                direction,
                message,
                (message.len() * 8) as u64,
            )
        }
        2 => {
            // EIA2 - AES-CMAC (128-EIA2)
            if knas_int.len() < 16 {
                return [0u8; 4];
            }
            let key: [u8; 16] = knas_int[..16].try_into().unwrap_or([0u8; 16]);
            
            // Build the input: COUNT || BEARER || DIRECTION || MESSAGE
            // COUNT is 32 bits, BEARER is 5 bits, DIRECTION is 1 bit, then 26 zero bits
            let mut input = Vec::with_capacity(8 + message.len());
            input.extend_from_slice(&count.to_be_bytes());
            input.push(((bearer << 3) | (direction << 2)) as u8);
            input.extend_from_slice(&[0u8; 3]); // Padding
            input.extend_from_slice(message);
            
            let cmac = ogs_crypt::aes_cmac::aes_cmac_calculate(&key, &input);
            [cmac[0], cmac[1], cmac[2], cmac[3]]
        }
        3 => {
            // EIA3 - ZUC
            if knas_int.len() < 16 {
                return [0u8; 4];
            }
            let key: [u8; 16] = knas_int[..16].try_into().unwrap_or([0u8; 16]);
            let mac = ogs_crypt::zuc::zuc_eia3(
                &key,
                count,
                bearer,
                direction,
                (message.len() * 8) as u32,
                message,
            );
            mac.to_be_bytes()
        }
        _ => {
            log::warn!("Unknown integrity algorithm: {algorithm}");
            [0u8; 4]
        }
    }
}

// ============================================================================
// NAS Encryption
// ============================================================================

/// Encrypt/decrypt NAS message
///
/// # Arguments
/// * `algorithm` - Encryption algorithm (0=EEA0, 1=EEA1/SNOW3G, 2=EEA2/AES, 3=EEA3/ZUC)
/// * `knas_enc` - NAS encryption key (16 bytes)
/// * `count` - NAS count value
/// * `bearer` - Bearer ID (always 0 for NAS)
/// * `direction` - Direction (0=uplink, 1=downlink)
/// * `message` - Message to encrypt/decrypt (modified in place)
pub fn nas_encrypt(
    algorithm: u8,
    knas_enc: &[u8],
    count: u32,
    bearer: u32,
    direction: u32,
    message: &mut [u8],
) {
    if message.is_empty() {
        return;
    }

    match algorithm {
        0 => {
            // EEA0 - Null encryption (no encryption)
        }
        1 => {
            // EEA1 - SNOW 3G (UEA2)
            if knas_enc.len() < 16 {
                return;
            }
            let key: [u8; 16] = knas_enc[..16].try_into().unwrap_or([0u8; 16]);
            ogs_crypt::snow3g::snow_3g_f8(
                &key,
                count,
                bearer,
                direction,
                message,
                (message.len() * 8) as u32,
            );
        }
        2 => {
            // EEA2 - AES-CTR (128-EEA2)
            if knas_enc.len() < 16 {
                return;
            }
            let key: [u8; 16] = knas_enc[..16].try_into().unwrap_or([0u8; 16]);
            
            // Build IV/counter: COUNT || BEARER || DIRECTION || 0...0
            let mut iv = [0u8; 16];
            iv[0] = (count >> 24) as u8;
            iv[1] = (count >> 16) as u8;
            iv[2] = (count >> 8) as u8;
            iv[3] = count as u8;
            iv[4] = ((bearer << 3) | (direction << 2)) as u8;
            // iv[5..16] are zeros
            
            let mut output = vec![0u8; message.len()];
            if ogs_crypt::aes::aes_ctr128_encrypt(&key, &mut iv, message, &mut output).is_ok() {
                message.copy_from_slice(&output);
            }
        }
        3 => {
            // EEA3 - ZUC
            if knas_enc.len() < 16 {
                return;
            }
            let key: [u8; 16] = knas_enc[..16].try_into().unwrap_or([0u8; 16]);
            let mut output = vec![0u8; message.len()];
            ogs_crypt::zuc::zuc_eea3(
                &key,
                count,
                bearer,
                direction,
                (message.len() * 8) as u32,
                message,
                &mut output,
            );
            message.copy_from_slice(&output);
        }
        _ => {
            log::warn!("Unknown encryption algorithm: {algorithm}");
        }
    }
}

// ============================================================================
// NAS Security Encode
// ============================================================================

/// Encode NAS message with security (integrity protection and/or ciphering)
///
/// # Arguments
/// * `mme_ue` - MME UE context (will be modified for dl_count)
/// * `security_header_type` - Security header type
/// * `plain_message` - Plain NAS message to encode
///
/// # Returns
/// * `Some(Vec<u8>)` - Encoded message with security header
/// * `None` - On error
pub fn nas_eps_security_encode(
    mme_ue: &mut MmeUe,
    security_header_type: SecurityHeaderType,
    plain_message: &[u8],
) -> Option<Vec<u8>> {
    let mut integrity_protected;
    let new_security_context;
    let mut ciphered;

    match security_header_type {
        SecurityHeaderType::PlainNas => {
            // Return plain message as-is
            return Some(plain_message.to_vec());
        }
        SecurityHeaderType::IntegrityProtected => {
            integrity_protected = true;
            new_security_context = false;
            ciphered = false;
        }
        SecurityHeaderType::IntegrityProtectedAndCiphered => {
            integrity_protected = true;
            new_security_context = false;
            ciphered = true;
        }
        SecurityHeaderType::IntegrityProtectedNewContext => {
            integrity_protected = true;
            new_security_context = true;
            ciphered = false;
        }
        SecurityHeaderType::IntegrityProtectedAndCipheredNewContext => {
            integrity_protected = true;
            new_security_context = true;
            ciphered = true;
        }
    }

    // Reset counts for new security context
    if new_security_context {
        mme_ue.dl_count = 0;
        mme_ue.ul_count = 0;
    }

    // Disable ciphering/integrity if algorithm is 0
    if mme_ue.selected_enc_algorithm == 0 {
        ciphered = false;
    }
    if mme_ue.selected_int_algorithm == 0 {
        integrity_protected = false;
    }

    // Build security header
    let mut header = NasEpsSecurityHeader {
        security_header_type: security_header_type as u8,
        protocol_discriminator: 0x07, // EMM
        message_authentication_code: 0,
        sequence_number: (mme_ue.dl_count & 0xff) as u8,
    };

    // Copy plain message for potential encryption
    let mut message = plain_message.to_vec();

    // Encrypt if needed
    if ciphered {
        nas_encrypt(
            mme_ue.selected_enc_algorithm,
            &mme_ue.knas_enc,
            mme_ue.dl_count,
            NAS_SECURITY_BEARER,
            NAS_SECURITY_DOWNLINK_DIRECTION,
            &mut message,
        );
    }

    // Build message with sequence number for MAC calculation
    let mut msg_with_sqn = Vec::with_capacity(1 + message.len());
    msg_with_sqn.push(header.sequence_number);
    msg_with_sqn.extend_from_slice(&message);

    // Calculate MAC if needed
    if integrity_protected {
        let mac = nas_mac_calculate(
            mme_ue.selected_int_algorithm,
            &mme_ue.knas_int,
            mme_ue.dl_count,
            NAS_SECURITY_BEARER,
            NAS_SECURITY_DOWNLINK_DIRECTION,
            &msg_with_sqn,
        );
        header.message_authentication_code =
            ((mac[0] as u32) << 24) | ((mac[1] as u32) << 16) | ((mac[2] as u32) << 8) | (mac[3] as u32);
    }

    // Increment dl_count (24-bit)
    mme_ue.dl_count = (mme_ue.dl_count + 1) & 0xffffff;

    // Build final message: security header + message
    let header_bytes = header.encode();
    let mut result = Vec::with_capacity(header_bytes.len() + message.len());
    result.extend_from_slice(&header_bytes);
    result.extend_from_slice(&message);

    mme_ue.security_context_available = true;

    Some(result)
}

// ============================================================================
// NAS Security Decode
// ============================================================================

/// UL count structure for tracking overflow
#[derive(Debug, Clone, Copy, Default)]
pub struct UlCount {
    /// Sequence number (8 bits)
    pub sqn: u8,
    /// Overflow counter (16 bits)
    pub overflow: u16,
}

impl UlCount {
    /// Get 32-bit count value
    pub fn to_u32(&self) -> u32 {
        ((self.overflow as u32) << 8) | (self.sqn as u32)
    }

    /// Set from 32-bit value
    pub fn from_u32(value: u32) -> Self {
        Self {
            sqn: (value & 0xff) as u8,
            overflow: ((value >> 8) & 0xffff) as u16,
        }
    }
}

/// Decode and verify NAS message security
///
/// # Arguments
/// * `mme_ue` - MME UE context (will be modified for ul_count, mac_failed)
/// * `security_header_type` - Parsed security header type flags
/// * `message` - Message buffer (will be modified: decrypted in place, header stripped)
///
/// # Returns
/// * `Ok(())` - Message decoded successfully (check mme_ue.mac_failed for MAC status)
/// * `Err(&str)` - On error
pub fn nas_eps_security_decode(
    mme_ue: &mut MmeUe,
    security_header_type: SecurityHeaderTypeFlags,
    message: &mut Vec<u8>,
) -> Result<(), &'static str> {
    // Handle service request (short MAC)
    if security_header_type.service_request {
        return decode_service_request(mme_ue, message);
    }

    // If no security context, disable security processing
    let mut flags = security_header_type;
    if !mme_ue.security_context_available {
        flags.integrity_protected = false;
        flags.new_security_context = false;
        flags.ciphered = false;
    }

    // Reset UL count for new security context
    if flags.new_security_context {
        mme_ue.ul_count = 0;
    }

    // Disable ciphering/integrity if algorithm is 0
    if mme_ue.selected_enc_algorithm == 0 {
        flags.ciphered = false;
    }
    if mme_ue.selected_int_algorithm == 0 {
        flags.integrity_protected = false;
    }

    if flags.ciphered || flags.integrity_protected {
        // Need at least 6 bytes for security header
        if message.len() < 6 {
            return Err("Message too short for security header");
        }

        // Parse security header
        let header = NasEpsSecurityHeader::decode(message)
            .ok_or("Failed to decode security header")?;

        // Update UL count
        let ul_count = UlCount::from_u32(mme_ue.ul_count);
        let mut new_ul_count = ul_count;
        if ul_count.sqn > header.sequence_number {
            new_ul_count.overflow = new_ul_count.overflow.wrapping_add(1);
        }
        new_ul_count.sqn = header.sequence_number;
        mme_ue.ul_count = new_ul_count.to_u32();

        // Verify MAC if integrity protected
        if flags.integrity_protected {
            // Build message for MAC calculation (sequence number + payload)
            let msg_for_mac = &message[5..]; // Skip first 5 bytes (header without sqn)
            
            let calculated_mac = nas_mac_calculate(
                mme_ue.selected_int_algorithm,
                &mme_ue.knas_int,
                mme_ue.ul_count,
                NAS_SECURITY_BEARER,
                NAS_SECURITY_UPLINK_DIRECTION,
                msg_for_mac,
            );

            let calculated_mac_u32 = ((calculated_mac[0] as u32) << 24)
                | ((calculated_mac[1] as u32) << 16)
                | ((calculated_mac[2] as u32) << 8)
                | (calculated_mac[3] as u32);

            if header.message_authentication_code != calculated_mac_u32 {
                log::warn!(
                    "NAS MAC verification failed (0x{:08x} != 0x{:08x})",
                    header.message_authentication_code,
                    calculated_mac_u32
                );
                mme_ue.mac_failed = true;
            }
        }

        // Strip security header (6 bytes)
        *message = message[6..].to_vec();

        // Decrypt if ciphered
        if flags.ciphered {
            if message.is_empty() {
                return Err("Cannot decrypt empty message");
            }
            nas_encrypt(
                mme_ue.selected_enc_algorithm,
                &mme_ue.knas_enc,
                mme_ue.ul_count,
                NAS_SECURITY_BEARER,
                NAS_SECURITY_UPLINK_DIRECTION,
                message,
            );
        }
    }

    Ok(())
}

/// Decode service request with short MAC
fn decode_service_request(mme_ue: &mut MmeUe, message: &mut Vec<u8>) -> Result<(), &'static str> {
    if mme_ue.selected_int_algorithm == 0 {
        log::warn!("Integrity algorithm is not defined");
        return Err("Integrity algorithm not defined");
    }

    if message.len() < 4 {
        return Err("Service request message too short");
    }

    // Extract KSI and sequence number from byte 1
    let ksi_and_sqn = message[1];
    let estimated_sqn = ksi_and_sqn & 0x1f;

    // Calculate full sequence number
    let ul_count = UlCount::from_u32(mme_ue.ul_count);
    let sqn_high_3bit = ul_count.sqn & 0xe0;
    let mut new_sqn = estimated_sqn + sqn_high_3bit;
    if (ul_count.sqn & 0x1f) > estimated_sqn {
        new_sqn = new_sqn.wrapping_add(0x20);
    }

    let mut new_ul_count = ul_count;
    if ul_count.sqn > new_sqn {
        new_ul_count.overflow = new_ul_count.overflow.wrapping_add(1);
    }
    new_ul_count.sqn = new_sqn;
    mme_ue.ul_count = new_ul_count.to_u32();

    // Save original MAC
    let original_mac = [message[2], message[3]];

    // Trim message for MAC calculation (first 2 bytes only)
    let msg_for_mac = message[..2].to_vec();

    // Calculate MAC
    let calculated_mac = nas_mac_calculate(
        mme_ue.selected_int_algorithm,
        &mme_ue.knas_int,
        mme_ue.ul_count,
        NAS_SECURITY_BEARER,
        NAS_SECURITY_UPLINK_DIRECTION,
        &msg_for_mac,
    );

    // Compare short MAC (last 2 bytes)
    if calculated_mac[2] != original_mac[0] || calculated_mac[3] != original_mac[1] {
        log::warn!(
            "NAS MAC verification failed ({:02x}{:02x} != {:02x}{:02x})",
            calculated_mac[2],
            calculated_mac[3],
            original_mac[0],
            original_mac[1]
        );
        mme_ue.mac_failed = true;
    }

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_header_encode_decode() {
        let header = NasEpsSecurityHeader {
            security_header_type: 2,
            protocol_discriminator: 0x07,
            message_authentication_code: 0x12345678,
            sequence_number: 0xAB,
        };

        let encoded = header.encode();
        let decoded = NasEpsSecurityHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.security_header_type, 2);
        assert_eq!(decoded.protocol_discriminator, 0x07);
        assert_eq!(decoded.message_authentication_code, 0x12345678);
        assert_eq!(decoded.sequence_number, 0xAB);
    }

    #[test]
    fn test_security_header_type_flags() {
        let flags = SecurityHeaderTypeFlags::from_header_type(0);
        assert!(!flags.integrity_protected);
        assert!(!flags.ciphered);

        let flags = SecurityHeaderTypeFlags::from_header_type(1);
        assert!(flags.integrity_protected);
        assert!(!flags.ciphered);

        let flags = SecurityHeaderTypeFlags::from_header_type(2);
        assert!(flags.integrity_protected);
        assert!(flags.ciphered);

        let flags = SecurityHeaderTypeFlags::from_header_type(3);
        assert!(flags.integrity_protected);
        assert!(flags.new_security_context);
        assert!(!flags.ciphered);

        let flags = SecurityHeaderTypeFlags::from_header_type(4);
        assert!(flags.integrity_protected);
        assert!(flags.new_security_context);
        assert!(flags.ciphered);

        let flags = SecurityHeaderTypeFlags::from_header_type(12);
        assert!(flags.service_request);
    }

    #[test]
    fn test_ul_count() {
        let count = UlCount { sqn: 0x12, overflow: 0x0034 };
        assert_eq!(count.to_u32(), 0x003412);

        let count2 = UlCount::from_u32(0x003412);
        assert_eq!(count2.sqn, 0x12);
        assert_eq!(count2.overflow, 0x0034);
    }

    #[test]
    fn test_nas_mac_null_algorithm() {
        let key = [0u8; 16];
        let mac = nas_mac_calculate(0, &key, 0, 0, 0, &[1, 2, 3, 4]);
        assert_eq!(mac, [0, 0, 0, 0]);
    }

    #[test]
    fn test_nas_encrypt_null_algorithm() {
        let key = [0u8; 16];
        let mut message = vec![1, 2, 3, 4];
        let original = message.clone();
        nas_encrypt(0, &key, 0, 0, 0, &mut message);
        assert_eq!(message, original); // No change for null encryption
    }

    #[test]
    fn test_nas_security_encode_plain() {
        let mut mme_ue = MmeUe::default();
        let plain_message = vec![0x07, 0x41, 0x01, 0x02, 0x03];

        let result = nas_eps_security_encode(
            &mut mme_ue,
            SecurityHeaderType::PlainNas,
            &plain_message,
        );

        assert!(result.is_some());
        assert_eq!(result.unwrap(), plain_message);
    }

    #[test]
    fn test_nas_security_encode_integrity_protected() {
        let mut mme_ue = MmeUe::default();
        mme_ue.selected_int_algorithm = 2; // EIA2
        mme_ue.knas_int = [0x11u8; 16];
        
        let plain_message = vec![0x07, 0x41, 0x01, 0x02, 0x03];

        let result = nas_eps_security_encode(
            &mut mme_ue,
            SecurityHeaderType::IntegrityProtected,
            &plain_message,
        );

        assert!(result.is_some());
        let encoded = result.unwrap();
        
        // Should have 6-byte security header + original message
        assert_eq!(encoded.len(), 6 + plain_message.len());
        
        // Check security header type
        assert_eq!(encoded[0] >> 4, SecurityHeaderType::IntegrityProtected as u8);
        
        // dl_count should be incremented
        assert_eq!(mme_ue.dl_count, 1);
        
        // security_context_available should be set
        assert!(mme_ue.security_context_available);
    }
}
