//! NAS Security Functions
//!
//! Port of src/mme/nas-security.c - NAS security encoding/decoding functions
//!
//! Implements NAS message integrity protection and ciphering for EPS.

use crate::context::{MmeUe, UeNetworkCapability};
use crate::emm_build::SecurityHeaderType;

// ============================================================================
// Constants
// ============================================================================

/// NAS security bearer (always 0 for NAS)
pub const NAS_SECURITY_BEARER: u32 = 0;

/// Highest NAS algorithm identity this codec implements.
///
/// [`nas_mac_calculate`] and [`nas_encrypt`] cover identities 0-3 (null,
/// SNOW 3G, AES, ZUC) and fall through to a **zero MAC / no encryption** with a
/// warning for anything else. Selecting 4-7 would therefore reintroduce the
/// silent downgrade this module exists to prevent, so
/// [`select_nas_algorithms`] refuses to consider them.
pub const MAX_IMPLEMENTED_ALGORITHM: u8 = 3;

/// TS 33.401 Annex A.7 algorithm type distinguisher for NAS ciphering.
pub const NAS_ENC_ALG_DISTINGUISHER: u8 = 0x01;

/// TS 33.401 Annex A.7 algorithm type distinguisher for NAS integrity.
pub const NAS_INT_ALG_DISTINGUISHER: u8 = 0x02;

/// NAS security MAC size in bytes
pub const NAS_SECURITY_MAC_SIZE: usize = 4;

/// NAS security downlink direction
pub const NAS_SECURITY_DOWNLINK_DIRECTION: u32 = 1;

/// NAS security uplink direction
pub const NAS_SECURITY_UPLINK_DIRECTION: u32 = 0;

/// NAS headroom for security header
pub const NEXTGCORE_NAS_HEADROOM: usize = 16;

// ============================================================================
// Algorithm Selection and Key Derivation
// ============================================================================

/// The NAS security algorithms selected for a UE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedNasAlgorithms {
    /// EIA identity (never 0 — see [`select_nas_algorithms`])
    pub integrity: u8,
    /// EEA identity (0 = EEA0, null ciphering, is a valid choice)
    pub ciphering: u8,
}

/// Whether the UE advertises support for `algorithm`.
///
/// TS 24.301 §9.9.3.34: in the UE network capability the EEA and EIA octets are
/// bitmaps whose most significant bit is algorithm 0, so algorithm *n* is
/// supported iff bit `0x80 >> n` is set.
fn ue_supports(capability: u8, algorithm: u8) -> bool {
    algorithm <= 7 && capability & (0x80 >> algorithm) != 0
}

/// Pick the NAS algorithms for a UE (TS 33.401 §7.2.4.3).
///
/// Each ordered list is the MME's preference, most preferred first; the first
/// entry the UE advertises and this codec implements wins.
///
/// Returns `None` when no usable integrity algorithm matches. Null integrity is
/// deliberately *not* a fallback: TS 33.401 §5.1.4.1 permits EIA0 only for
/// unauthenticated emergency calls, so a UE that supports nothing else must be
/// rejected (TS 24.301 EMM cause #23) rather than admitted unprotected. Null
/// ciphering is different — EEA0 is a legitimate configured choice for any UE,
/// and is what the shipped configuration asks for first.
pub fn select_nas_algorithms(
    integrity_order: &[u8],
    ciphering_order: &[u8],
    capability: &UeNetworkCapability,
) -> Option<SelectedNasAlgorithms> {
    let integrity = integrity_order
        .iter()
        .copied()
        .find(|algorithm| {
            *algorithm != 0
                && *algorithm <= MAX_IMPLEMENTED_ALGORITHM
                && ue_supports(capability.eia, *algorithm)
        })
        .or_else(|| {
            log::warn!(
                "No usable NAS integrity algorithm: MME order {integrity_order:?} vs UE EIA \
                 bitmap 0x{:02x}",
                capability.eia
            );
            None
        })?;

    // Falling back to EEA0 is safe and matches the spec's "null ciphering is
    // always supported" assumption, so an empty or unmatched list is not fatal.
    let ciphering = ciphering_order
        .iter()
        .copied()
        .find(|algorithm| {
            *algorithm <= MAX_IMPLEMENTED_ALGORITHM && ue_supports(capability.eea, *algorithm)
        })
        .unwrap_or(0);

    Some(SelectedNasAlgorithms {
        integrity,
        ciphering,
    })
}

/// Take the selected algorithms into use and derive the NAS keys from `KASME`.
///
/// TS 33.401 Annex A.7: `KNASenc` and `KNASint` come from the FC=0x15 KDF keyed
/// on `KASME`, with the algorithm type distinguisher and the selected algorithm
/// identity as inputs — so this must run *after* selection, and re-running it
/// with different algorithms yields different keys.
pub fn derive_nas_keys(mme_ue: &mut MmeUe, selected: SelectedNasAlgorithms) {
    mme_ue.selected_int_algorithm = selected.integrity;
    mme_ue.selected_enc_algorithm = selected.ciphering;

    mme_ue.knas_int = nextgcore_crypt::kdf::nextgcore_kdf_nas_eps(
        NAS_INT_ALG_DISTINGUISHER,
        selected.integrity,
        &mme_ue.kasme,
    );
    mme_ue.knas_enc = nextgcore_crypt::kdf::nextgcore_kdf_nas_eps(
        NAS_ENC_ALG_DISTINGUISHER,
        selected.ciphering,
        &mme_ue.kasme,
    );

    log::debug!(
        "[{}] NAS security context: EIA{} / EEA{}",
        mme_ue.imsi_bcd,
        selected.integrity,
        selected.ciphering
    );
}

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
            nextgcore_crypt::snow3g::snow_3g_f9(
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

            let cmac = nextgcore_crypt::aes_cmac::aes_cmac_calculate(&key, &input);
            [cmac[0], cmac[1], cmac[2], cmac[3]]
        }
        3 => {
            // EIA3 - ZUC
            if knas_int.len() < 16 {
                return [0u8; 4];
            }
            let key: [u8; 16] = knas_int[..16].try_into().unwrap_or([0u8; 16]);
            let mac = nextgcore_crypt::zuc::zuc_eia3(
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
            nextgcore_crypt::snow3g::snow_3g_f8(
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
            if nextgcore_crypt::aes::aes_ctr128_encrypt(&key, &mut iv, message, &mut output).is_ok()
            {
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
            nextgcore_crypt::zuc::zuc_eea3(
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
        header.message_authentication_code = ((mac[0] as u32) << 24)
            | ((mac[1] as u32) << 16)
            | ((mac[2] as u32) << 8)
            | (mac[3] as u32);
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
        let header =
            NasEpsSecurityHeader::decode(message).ok_or("Failed to decode security header")?;

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
                // TS 24.301 §4.4.4.3: a message that fails the integrity check
                // is discarded and must not be processed further. The flag is
                // kept for the caller's diagnostics, but the error is what makes
                // that impossible to ignore: this used to strip the header,
                // decrypt, and answer Ok.
                mme_ue.mac_failed = true;
                return Err("NAS integrity check failed");
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
        // TS 24.301 §4.4.4.3, as on the full-MAC path: a SERVICE REQUEST whose
        // short MAC does not verify is discarded, not admitted.
        mme_ue.mac_failed = true;
        return Err("NAS integrity check failed");
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
        let count = UlCount {
            sqn: 0x12,
            overflow: 0x0034,
        };
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
    fn test_eia2_ts33401_test_set_2() {
        // 128-EIA2 Test Set 2 from TS 33.401 Annex C.2:
        // the CMAC input block must be laid out as
        // COUNT[32] || BEARER[5] || DIRECTION[1] || 0^26 || MESSAGE
        // (octet 4 = bearer<<3 | direction<<2) per Annex B.2.3.
        let key: [u8; 16] = [
            0xd3, 0xc5, 0xd5, 0x92, 0x32, 0x7f, 0xb1, 0x1c, 0x40, 0x35, 0xc6, 0x68, 0x0a, 0xf8,
            0xc6, 0xd1,
        ];
        let count = 0x398a_59b4;
        let bearer = 0x1a;
        let direction = 1;
        let message: [u8; 8] = [0x48, 0x45, 0x83, 0xd5, 0xaf, 0xe0, 0x82, 0xae];

        let mac = nas_mac_calculate(2, &key, count, bearer, direction, &message);
        assert_eq!(mac, [0xb9, 0x37, 0x87, 0xe6]);
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

        let result =
            nas_eps_security_encode(&mut mme_ue, SecurityHeaderType::PlainNas, &plain_message);

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
        assert_eq!(
            encoded[0] >> 4,
            SecurityHeaderType::IntegrityProtected as u8
        );

        // dl_count should be incremented
        assert_eq!(mme_ue.dl_count, 1);

        // security_context_available should be set
        assert!(mme_ue.security_context_available);
    }

    // ========================================================================
    // Algorithm selection and key derivation (issue #44)
    // ========================================================================

    /// A UE advertising EEA/EIA 0-3, i.e. the top four bits of each bitmap.
    fn capability_0_to_3() -> UeNetworkCapability {
        UeNetworkCapability {
            eea: 0xf0,
            eia: 0xf0,
            ..Default::default()
        }
    }

    #[test]
    fn test_select_honours_the_mme_order() {
        // The shipped configuration's order.
        let selected = select_nas_algorithms(&[2, 1, 0], &[0, 1, 2], &capability_0_to_3()).unwrap();
        assert_eq!(selected.integrity, 2);
        assert_eq!(selected.ciphering, 0);

        // Reordering the MME's preference changes the outcome, so the order is
        // genuinely consulted rather than a hardcoded pick.
        let selected = select_nas_algorithms(&[1, 2], &[2, 1, 0], &capability_0_to_3()).unwrap();
        assert_eq!(selected.integrity, 1);
        assert_eq!(selected.ciphering, 2);
    }

    #[test]
    fn test_select_intersects_with_ue_capability() {
        // TS 24.301 9.9.3.34: bit 0x80 >> n advertises algorithm n. This UE
        // supports EIA2 and EEA2 only.
        let capability = UeNetworkCapability {
            eea: 0x20,
            eia: 0x20,
            ..Default::default()
        };
        let selected = select_nas_algorithms(&[3, 2, 1], &[1, 2], &capability).unwrap();
        assert_eq!(selected.integrity, 2, "EIA3 is not advertised, EIA2 is");
        assert_eq!(selected.ciphering, 2);
    }

    #[test]
    fn test_select_rejects_when_only_null_integrity_is_possible() {
        // TS 33.401 5.1.4.1: EIA0 is for unauthenticated emergency calls only,
        // so a UE offering nothing else must be rejected, not admitted with
        // null integrity.
        let capability = UeNetworkCapability {
            eea: 0xf0,
            eia: 0x80, // EIA0 only
            ..Default::default()
        };
        assert!(select_nas_algorithms(&[2, 1, 0], &[0, 1, 2], &capability).is_none());
        // Same when the MME offers nothing at all.
        assert!(select_nas_algorithms(&[], &[0], &capability_0_to_3()).is_none());
    }

    #[test]
    fn test_select_skips_algorithms_this_codec_does_not_implement() {
        // EIA4-7 / EEA4-7 have no implementation: `nas_mac_calculate` returns a
        // zero MAC for them, so selecting one would silently disable protection.
        let capability = UeNetworkCapability {
            eea: 0xff,
            eia: 0xff,
            ..Default::default()
        };
        let selected = select_nas_algorithms(&[7, 4, 3], &[6, 5, 1], &capability).unwrap();
        assert_eq!(selected.integrity, 3);
        assert_eq!(selected.ciphering, 1);

        // Nothing implemented on the integrity side leaves no usable choice.
        assert!(select_nas_algorithms(&[7, 6, 5, 4], &[0], &capability).is_none());
    }

    #[test]
    fn test_select_falls_back_to_null_ciphering_but_never_null_integrity() {
        // A UE advertising no ciphering algorithm the MME offers still gets a
        // security context: EEA0 is always acceptable.
        let capability = UeNetworkCapability {
            eea: 0x00,
            eia: 0xf0,
            ..Default::default()
        };
        let selected = select_nas_algorithms(&[2], &[2, 1], &capability).unwrap();
        assert_eq!(selected.integrity, 2);
        assert_eq!(selected.ciphering, 0);
    }

    #[test]
    fn test_derive_nas_keys_is_keyed_on_kasme_algorithm_and_distinguisher() {
        let mut ue = MmeUe {
            kasme: [0x44; 32],
            ..Default::default()
        };
        derive_nas_keys(
            &mut ue,
            SelectedNasAlgorithms {
                integrity: 2,
                ciphering: 0,
            },
        );

        assert_eq!(ue.selected_int_algorithm, 2);
        assert_eq!(ue.selected_enc_algorithm, 0);
        assert_ne!(ue.knas_int, [0u8; 16]);
        assert_ne!(
            ue.knas_int, ue.knas_enc,
            "the algorithm type distinguisher must separate the two keys"
        );

        // TS 33.401 Annex A.7 takes the algorithm identity as an input, so a
        // different selection must yield different keys...
        let mut other_algorithm = MmeUe {
            kasme: [0x44; 32],
            ..Default::default()
        };
        derive_nas_keys(
            &mut other_algorithm,
            SelectedNasAlgorithms {
                integrity: 1,
                ciphering: 0,
            },
        );
        assert_ne!(ue.knas_int, other_algorithm.knas_int);
        assert_eq!(
            ue.knas_enc, other_algorithm.knas_enc,
            "the ciphering key must not move when only the integrity algorithm did"
        );

        // ...and so must a different KASME.
        let mut other_kasme = MmeUe {
            kasme: [0x45; 32],
            ..Default::default()
        };
        derive_nas_keys(
            &mut other_kasme,
            SelectedNasAlgorithms {
                integrity: 2,
                ciphering: 0,
            },
        );
        assert_ne!(ue.knas_int, other_kasme.knas_int);

        // Regression snapshot for KASME = 0x44 repeated, EIA2. TS 33.401
        // Annex A publishes no numeric vectors for FC=0x15, so this pins *this*
        // implementation's inputs and ordering rather than claiming to be a
        // 3GPP vector. It is verifiable by hand: the value is the low 16 bytes
        // of HMAC-SHA256(KASME, S) with
        // S = FC(0x15) || P0(0x02) || L0(0x0001) || P1(0x02) || L1(0x0001),
        // i.e. TS 33.220 Annex B's S-string with the NAS-int-alg
        // distinguisher and the selected algorithm identity.
        assert_eq!(
            ue.knas_int,
            [
                0x16, 0xd0, 0x84, 0x8a, 0x13, 0x38, 0xb8, 0x0e, 0xd1, 0xc3, 0xf1, 0xad, 0x9c, 0x75,
                0xad, 0x3f
            ]
        );
    }

    #[test]
    fn test_decode_rejects_a_failed_mac_instead_of_returning_ok() {
        let mut ue = MmeUe {
            security_context_available: true,
            selected_int_algorithm: 2,
            knas_int: [0x33; 16],
            ..Default::default()
        };
        // Integrity-protected header with a deliberately wrong MAC.
        let mut message = vec![0x17, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x07, 0x5e];
        let before = message.clone();

        let result = nas_eps_security_decode(
            &mut ue,
            SecurityHeaderTypeFlags::from_header_type(1),
            &mut message,
        );

        assert!(result.is_err(), "a MAC failure must not answer Ok");
        assert!(ue.mac_failed);
        assert_eq!(
            message, before,
            "the message must not be stripped or decrypted"
        );
    }

    #[test]
    fn test_decode_accepts_a_correct_mac_and_strips_the_header() {
        let mut ue = MmeUe {
            security_context_available: true,
            selected_int_algorithm: 2,
            knas_int: [0x33; 16],
            ..Default::default()
        };
        let inner = [0x07u8, 0x5e];
        let mut message = vec![0x17, 0, 0, 0, 0, 0x01];
        message.extend_from_slice(&inner);
        let mac = nas_mac_calculate(
            2,
            &ue.knas_int,
            1, // the count the MME derives from sequence number 1
            NAS_SECURITY_BEARER,
            NAS_SECURITY_UPLINK_DIRECTION,
            &message[5..],
        );
        message[1..5].copy_from_slice(&mac);

        nas_eps_security_decode(
            &mut ue,
            SecurityHeaderTypeFlags::from_header_type(1),
            &mut message,
        )
        .expect("a correct MAC must verify");

        assert!(!ue.mac_failed);
        assert_eq!(message, inner, "the security header must be stripped");
        assert_eq!(ue.ul_count, 1);
    }

    #[test]
    fn test_service_request_short_mac_failure_is_rejected() {
        let mut ue = MmeUe {
            security_context_available: true,
            selected_int_algorithm: 2,
            knas_int: [0x33; 16],
            ..Default::default()
        };
        // SERVICE REQUEST with a wrong short MAC (TS 24.301 8.2.25).
        let mut message = vec![0xc7, 0x01, 0xba, 0xad];

        let result = nas_eps_security_decode(
            &mut ue,
            SecurityHeaderTypeFlags::from_header_type(12),
            &mut message,
        );

        assert!(result.is_err());
        assert!(ue.mac_failed);
    }
}
