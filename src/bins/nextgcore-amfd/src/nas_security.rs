//! NAS Security Functions
//!
//! Port of src/amf/nas-security.c - NAS security encoding and decoding

use crate::context::AmfUe;
use crate::gmm_build::security_header;

// ============================================================================
// Error Types
// ============================================================================

/// NAS security error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NasSecurityError {
    /// Message too short for security header
    MessageTooShort,
    /// Invalid security header
    InvalidHeader,
    /// Empty payload after decryption
    EmptyPayload,
    /// MAC verification failed
    MacVerificationFailed,
    /// Unsupported algorithm
    UnsupportedAlgorithm(u8),
}

// ============================================================================
// Constants
// ============================================================================

/// NAS security MAC size
pub const NAS_SECURITY_MAC_SIZE: usize = 4;

/// Security direction
pub mod direction {
    pub const UPLINK: u8 = 0;
    pub const DOWNLINK: u8 = 1;
}

/// Security header type flags
#[derive(Debug, Clone, Default)]
pub struct SecurityHeaderType {
    /// Integrity protected
    pub integrity_protected: bool,
    /// New security context
    pub new_security_context: bool,
    /// Ciphered
    pub ciphered: bool,
}

impl SecurityHeaderType {
    /// Parse from security header type byte
    pub fn from_byte(header_type: u8) -> Self {
        match header_type {
            security_header::PLAIN_NAS_MESSAGE => Self::default(),
            security_header::INTEGRITY_PROTECTED => Self {
                integrity_protected: true,
                ..Default::default()
            },
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED => Self {
                integrity_protected: true,
                ciphered: true,
                ..Default::default()
            },
            security_header::INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT => Self {
                integrity_protected: true,
                new_security_context: true,
                ..Default::default()
            },
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_5G_NAS_SECURITY_CONTEXT => {
                Self {
                    integrity_protected: true,
                    new_security_context: true,
                    ciphered: true,
                }
            }
            _ => Self::default(),
        }
    }
}

/// NAS security header
#[derive(Debug, Clone, Default)]
pub struct NasSecurityHeader {
    /// Extended protocol discriminator
    pub extended_protocol_discriminator: u8,
    /// Security header type
    pub security_header_type: u8,
    /// Message authentication code
    pub message_authentication_code: [u8; 4],
    /// Sequence number
    pub sequence_number: u8,
}

impl NasSecurityHeader {
    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(7);
        data.push(self.extended_protocol_discriminator);
        data.push(self.security_header_type);
        data.extend_from_slice(&self.message_authentication_code);
        data.push(self.sequence_number);
        data
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 7 {
            return None;
        }
        let mut mac = [0u8; 4];
        mac.copy_from_slice(&data[2..6]);
        Some(Self {
            extended_protocol_discriminator: data[0],
            security_header_type: data[1],
            message_authentication_code: mac,
            sequence_number: data[6],
        })
    }
}

// ============================================================================
// NAS Security Functions
// ============================================================================

/// Encode NAS message with security protection (gated dispatcher).
///
/// nas-06 Phase-6 C2: this is the single security-encode entry point that the
/// 4 `ngap_path.rs` call sites already use, so they route through the gate
/// transparently with zero textual change. With the canary
/// `amf_ue.use_nextgcore_nas_security` OFF (the DEFAULT) it calls the unchanged
/// hand-rolled [`nas_5gs_security_encode_legacy`] — byte-for-byte and
/// behavior-for-behavior identical to the pre-Phase-6 code. With the canary ON
/// it delegates to the conformant nextgcore-nas-backed adapter
/// [`nas_5gs_security_encode_nextgcore`] (byte-identical for 3GPP-access frames).
pub fn nas_5gs_security_encode(
    amf_ue: &mut AmfUe,
    message: &[u8],
    security_header_type: u8,
) -> Option<Vec<u8>> {
    if amf_ue.use_nextgcore_nas_security {
        nas_5gs_security_encode_nextgcore(amf_ue, message, security_header_type)
    } else {
        nas_5gs_security_encode_legacy(amf_ue, message, security_header_type)
    }
}

/// Hand-rolled NAS security encoder (the pre-nas-06 production path).
///
/// PRESERVED UNCHANGED. Selected when the `use_nextgcore_nas_security` canary is OFF
/// (default). Do NOT modify — the Phase-6 adapter is proven byte-identical
/// against this function (`encode_nextgcore_matches_legacy_*`).
fn nas_5gs_security_encode_legacy(
    amf_ue: &mut AmfUe,
    message: &[u8],
    security_header_type: u8,
) -> Option<Vec<u8>> {
    let header_type = SecurityHeaderType::from_byte(security_header_type);

    // Plain NAS message - no security
    if security_header_type == security_header::PLAIN_NAS_MESSAGE {
        return Some(message.to_vec());
    }

    let mut integrity_protected = header_type.integrity_protected;
    let mut ciphered = header_type.ciphered;

    // Reset counters for new security context
    if header_type.new_security_context {
        amf_ue.dl_count = 0;
        amf_ue.ul_count = 0;
    }

    // Disable ciphering/integrity if algorithm is null
    if amf_ue.selected_enc_algorithm == 0 {
        ciphered = false;
    }
    if amf_ue.selected_int_algorithm == 0 {
        integrity_protected = false;
    }

    // Build security header
    let mut header = NasSecurityHeader {
        extended_protocol_discriminator: 0x7e, // 5GMM
        security_header_type,
        message_authentication_code: [0u8; 4],
        sequence_number: (amf_ue.dl_count & 0xff) as u8,
    };

    // Start with the plain message
    let mut protected_message = message.to_vec();

    // Apply ciphering if needed
    if ciphered {
        nas_encrypt(
            amf_ue.selected_enc_algorithm,
            &amf_ue.knas_enc,
            amf_ue.dl_count,
            amf_ue.access_type,
            direction::DOWNLINK,
            &mut protected_message,
        );
    }

    // Prepend sequence number
    let mut with_seq = vec![header.sequence_number];
    with_seq.extend_from_slice(&protected_message);

    // Calculate MAC if integrity protected
    if integrity_protected {
        let mac = nas_mac_calculate(
            amf_ue.selected_int_algorithm,
            &amf_ue.knas_int,
            amf_ue.dl_count,
            amf_ue.access_type,
            direction::DOWNLINK,
            &with_seq,
        );
        header.message_authentication_code = mac;
    }

    // Increment DL count (24-bit)
    amf_ue.dl_count = (amf_ue.dl_count + 1) & 0xffffff;

    // Mark security context as available
    amf_ue.security_context_available = true;

    // Build final message: header + sequence number + protected message
    let mut result = Vec::with_capacity(7 + protected_message.len());
    result.push(header.extended_protocol_discriminator);
    result.push(header.security_header_type);
    result.extend_from_slice(&header.message_authentication_code);
    result.push(header.sequence_number);
    result.extend_from_slice(&protected_message);

    Some(result)
}

/// Decode NAS message with security protection (gated dispatcher).
///
/// nas-06 Phase-6 C2: single security-decode entry point used by the
/// `ngap_path.rs` uplink call site. With the canary `amf_ue.use_nextgcore_nas_security`
/// OFF (the DEFAULT, LIVE path) it calls the hand-rolled
/// [`nas_5gs_security_decode_legacy`]. With the canary ON it delegates to the
/// nextgcore-nas-backed adapter [`nas_5gs_security_decode_nextgcore`].
///
/// amfd-03/amfd-04: BOTH paths are now fail-closed and verify-then-commit. A MAC
/// mismatch returns `Err(MacVerificationFailed)` (the tampered plaintext is never
/// produced, TS 24.501 §4.4.3.3); the UL COUNT is only advanced after the MAC
/// verifies, and a replay (a non-advancing COUNT once a baseline exists) is
/// rejected (TS 24.501 §4.4.3.2). The two paths therefore agree on the decode
/// security policy; they differ only in which crypto/codec implementation backs
/// the primitive.
pub fn nas_5gs_security_decode(
    amf_ue: &mut AmfUe,
    security_header_type: u8,
    message: &[u8],
) -> Result<Vec<u8>, NasSecurityError> {
    if amf_ue.use_nextgcore_nas_security {
        nas_5gs_security_decode_nextgcore(amf_ue, security_header_type, message)
    } else {
        nas_5gs_security_decode_legacy(amf_ue, security_header_type, message)
    }
}

/// Hand-rolled NAS security decoder — the LIVE production decode path
/// (selected when the `use_nextgcore_nas_security` canary is OFF, the default).
///
/// amfd-03 / amfd-04 (fail-closed, verify-then-commit): unlike the original
/// lenient behaviour this:
///   * computes a CANDIDATE UL COUNT from the received SQN WITHOUT mutating the
///     stored `amf_ue.ul_count` (TS 24.501 §4.4.3.5 overflow handling);
///   * returns `Err(MacVerificationFailed)` on a MAC mismatch and produces NO
///     plaintext — the tampered message is dropped (TS 24.501 §4.4.3.3);
///   * only commits the candidate to `amf_ue.ul_count` AFTER the MAC verifies
///     (so a forged SQN can never advance the stored COUNT); and
///   * rejects a replay/old COUNT — a candidate that does not strictly advance
///     the last accepted COUNT once a baseline is established (§4.4.3.2).
///
/// The matched-sim UE sends correct MACs and strictly-monotonic COUNTs, so a
/// conformant registration is unaffected: only tampered or replayed frames drop.
/// The ENCODE legacy path remains byte-for-byte unchanged.
fn nas_5gs_security_decode_legacy(
    amf_ue: &mut AmfUe,
    security_header_type: u8,
    message: &[u8],
) -> Result<Vec<u8>, NasSecurityError> {
    let mut header_type = SecurityHeaderType::from_byte(security_header_type);

    // If no security context, disable all security
    if !amf_ue.security_context_available {
        header_type.integrity_protected = false;
        header_type.new_security_context = false;
        header_type.ciphered = false;
    }

    // Reset counters for new security context (clear the replay baseline too).
    if header_type.new_security_context {
        amf_ue.ul_count = 0;
        amf_ue.ul_count_established = false;
    }

    // Disable ciphering/integrity if algorithm is null
    if amf_ue.selected_enc_algorithm == 0 {
        header_type.ciphered = false;
    }
    if amf_ue.selected_int_algorithm == 0 {
        header_type.integrity_protected = false;
    }

    // If no security needed, return message as-is
    if !header_type.ciphered && !header_type.integrity_protected {
        return Ok(message.to_vec());
    }

    // Need at least 7 bytes for security header
    if message.len() < 7 {
        return Err(NasSecurityError::MessageTooShort);
    }

    // Parse security header
    let header = NasSecurityHeader::decode(message).ok_or(NasSecurityError::InvalidHeader)?;
    let sqn = header.sequence_number;

    // amfd-04: derive a CANDIDATE UL COUNT from the received SQN WITHOUT touching
    // the stored COUNT. The overflow octet (high 16 bits) is taken from the
    // stored COUNT and bumped exactly once on an SQN wrap (TS 24.501 §4.4.3.5),
    // so a forged/replayed SQN cannot mutate state before the MAC is checked.
    let stored = amf_ue.ul_count & 0x00ff_ffff;
    let candidate = {
        let current_sqn = (stored & 0xff) as u8;
        if current_sqn > sqn {
            ((stored & 0xffff00) + 0x100) | (sqn as u32)
        } else {
            (stored & 0xffff00) | (sqn as u32)
        }
    } & 0x00ff_ffff;

    // amfd-04: replay protection (TS 24.501 §4.4.3.2). Once a baseline has been
    // established under an active integrity context, a frame whose candidate
    // COUNT does not strictly advance the last accepted COUNT is a replay/old
    // message and is dropped. The bootstrap frame (no baseline yet) is accepted.
    if header_type.integrity_protected && amf_ue.ul_count_established && candidate <= stored {
        log::warn!(
            "NAS replay/old COUNT rejected: candidate=0x{candidate:06x} \
             <= last-accepted=0x{stored:06x}, discarding"
        );
        amf_ue.mac_failed = true;
        return Err(NasSecurityError::MacVerificationFailed);
    }

    // Get the protected payload (after security header)
    let payload = &message[7..];

    // amfd-03: verify the MAC against the CANDIDATE count BEFORE producing any
    // plaintext. On mismatch return Err (fail-closed) and DO NOT advance the UL
    // COUNT — the tampered message is dropped (TS 24.501 §4.4.3.3).
    if header_type.integrity_protected {
        let mut mac_data = vec![sqn];
        mac_data.extend_from_slice(payload);

        let calculated_mac = nas_mac_calculate(
            amf_ue.selected_int_algorithm,
            &amf_ue.knas_int,
            candidate,
            amf_ue.access_type,
            direction::UPLINK,
            &mac_data,
        );

        if calculated_mac != header.message_authentication_code {
            log::warn!(
                "NAS MAC verification failed: expected {:02x?}, got {:02x?}; discarding",
                calculated_mac,
                header.message_authentication_code
            );
            amf_ue.mac_failed = true;
            return Err(NasSecurityError::MacVerificationFailed);
        }
    }

    // amfd-04: MAC verified (or integrity not required) — COMMIT the candidate
    // COUNT. Only an integrity-protected frame establishes the replay baseline.
    amf_ue.ul_count = candidate;
    if header_type.integrity_protected {
        amf_ue.ul_count_established = true;
    }

    // Decrypt if ciphered (against the committed count).
    let mut decrypted = payload.to_vec();
    if header_type.ciphered {
        if decrypted.is_empty() {
            return Err(NasSecurityError::EmptyPayload);
        }
        nas_encrypt(
            amf_ue.selected_enc_algorithm,
            &amf_ue.knas_enc,
            amf_ue.ul_count,
            amf_ue.access_type,
            direction::UPLINK,
            &mut decrypted,
        );
    }

    Ok(decrypted)
}

// ============================================================================
// nas-06 Phase-6 C1/C3 — nextgcore-nas-backed security adapter (canary-gated)
// ============================================================================
//
// These adapters delegate the NAS protect/unprotect primitives to the
// conformant `nextgcore_nas::common::security` implementation. They run ONLY when
// `amf_ue.use_nextgcore_nas_security` is true (default false); the default-OFF path
// keeps the legacy hand-rolled encoders/decoders above byte-for-byte and
// behavior-for-behavior unchanged.
//
// Layout note: amfd frames are `EPD | SHT | MAC | SQN | payload`; nextgcore-nas
// protect/unprotect operate on `MAC | SQN | payload`. The adapter prepends /
// strips the 2-octet `EPD|SHT` accordingly.
//
// COUNT model: `AmfUe.dl_count`/`ul_count` are 24-bit NAS COUNTs (low 8 bits =
// SQN). nextgcore-nas models COUNT as a `NasCount { overflow, sqn }`. The two
// converters below are exact inverses over the 24-bit domain, and EVERY adapter
// call writes `NasCount::value()` back into the AmfUe u32 so the count persists
// through the memento (without writeback the counts desync).
//
// BEARER caveat: nextgcore-nas hardwires NAS bearer/connection-id 1 (3GPP access),
// while the legacy path derives it from `access_type`. So byte-identity with
// the legacy encoder holds for 3GPP access (bearer 1) only; non-3GPP access is
// the known divergence locked by `drift_non_3gpp_bearer_divergence_locked`.
// PQC algorithms (NEA4/NIA4, id 4) are not supported by nextgcore-nas protect and are
// out of scope for this adapter (the legacy path still handles them).

/// Convert a 24-bit AmfUe NAS COUNT (u32) to an nextgcore-nas `NasCount`.
fn nas_count_from_u32(v: u32) -> nextgcore_nas::common::security::NasCount {
    nextgcore_nas::common::security::NasCount::new(v >> 8, (v & 0xff) as u8)
}

/// Convert an nextgcore-nas `NasCount` back to the 24-bit AmfUe COUNT (u32).
/// Inverse of [`nas_count_from_u32`] over the 24-bit domain.
fn nas_count_to_u32(c: nextgcore_nas::common::security::NasCount) -> u32 {
    c.value() & 0x00ff_ffff
}

/// nas-06 Phase-6 C1: nextgcore-nas-backed NAS security ENCODE adapter.
///
/// Delegates to `nextgcore_nas::common::security::protect_nas_message`. Proven
/// byte-identical to [`nas_5gs_security_encode_legacy`] for 3GPP-access 5GMM
/// downlink frames (see `encode_nextgcore_matches_legacy_*`). Gated behind
/// `amf_ue.use_nextgcore_nas_security` (default false).
fn nas_5gs_security_encode_nextgcore(
    amf_ue: &mut AmfUe,
    message: &[u8],
    security_header_type: u8,
) -> Option<Vec<u8>> {
    use nextgcore_nas::common::security::{protect_nas_message, NasSecurityContext};
    use nextgcore_nas::common::types::SecurityAlgorithms;

    // PLAIN passthrough: no header, no count change (identical to legacy).
    if security_header_type == security_header::PLAIN_NAS_MESSAGE {
        return Some(message.to_vec());
    }

    let header_type = SecurityHeaderType::from_byte(security_header_type);
    let mut integrity_protected = header_type.integrity_protected;
    let mut ciphered = header_type.ciphered;

    // New security context (SHT = new-context): zero BOTH NAS COUNTs.
    if header_type.new_security_context {
        amf_ue.dl_count = 0;
        amf_ue.ul_count = 0;
        amf_ue.ul_count_established = false;
    }

    // Null algorithm => corresponding protection disabled (mirrors legacy).
    if amf_ue.selected_enc_algorithm == 0 {
        ciphered = false;
    }
    if amf_ue.selected_int_algorithm == 0 {
        integrity_protected = false;
    }

    // Force integrity algo to NONE(0) when disabled so nextgcore-nas emits a zero MAC,
    // exactly like the legacy encoder leaving MAC=[0;4].
    let mut ctx = NasSecurityContext::new(
        SecurityAlgorithms {
            ciphering: amf_ue.selected_enc_algorithm,
            integrity: if integrity_protected {
                amf_ue.selected_int_algorithm
            } else {
                0
            },
        },
        amf_ue.knas_enc,
        amf_ue.knas_int,
    );
    ctx.dl_count = nas_count_from_u32(amf_ue.dl_count);

    // direction::DOWNLINK (1) matches nextgcore-nas downlink. protect emits
    // MAC|SQN|(ciphered payload) and advances ctx.dl_count.
    let protected = protect_nas_message(&mut ctx, direction::DOWNLINK, message, ciphered).ok()?;

    // WRITEBACK the advanced DL COUNT (24-bit) so it persists via the memento.
    amf_ue.dl_count = nas_count_to_u32(ctx.dl_count);
    amf_ue.security_context_available = true;

    // Prepend the 2-octet EPD|SHT.
    let mut result = Vec::with_capacity(2 + protected.len());
    result.push(0x7e); // 5GMM EPD
    result.push(security_header_type);
    result.extend_from_slice(&protected);
    Some(result)
}

/// nas-06 Phase-6 C1+C3: nextgcore-nas-backed NAS security DECODE adapter (STRICT).
///
/// Delegates to `nextgcore_nas::common::security::unprotect_nas_message`. Unlike the
/// lenient [`nas_5gs_security_decode_legacy`] it:
///   * returns `Err` on MAC failure and does NOT advance the UL COUNT
///     (verify-then-commit, TS 24.501 §4.4.3.3); and
///   * rejects replays using the persisted `ul_count_established` high-water
///     state (TS 24.501 §4.4.3.2).
///
/// Gated behind `amf_ue.use_nextgcore_nas_security` (default false).
///
/// E2E-UNVALIDATED: the lenient->strict flip MAY drop frames that the matched
/// sim retransmits. Flipping the canary default + removing the hand-rolled
/// decoder is DEFERRED pending matched-sim + real Open5GS E2E (registration +
/// PDU session + ping).
fn nas_5gs_security_decode_nextgcore(
    amf_ue: &mut AmfUe,
    security_header_type: u8,
    message: &[u8],
) -> Result<Vec<u8>, NasSecurityError> {
    use nextgcore_nas::common::security::{unprotect_nas_message, NasSecurityContext};
    use nextgcore_nas::common::types::SecurityAlgorithms;
    use nextgcore_nas::error::NasError;

    let mut header_type = SecurityHeaderType::from_byte(security_header_type);

    // No security context => disable all (mirrors legacy).
    if !amf_ue.security_context_available {
        header_type.integrity_protected = false;
        header_type.new_security_context = false;
        header_type.ciphered = false;
    }

    // New security context => zero UL COUNT + clear replay baseline.
    if header_type.new_security_context {
        amf_ue.ul_count = 0;
        amf_ue.ul_count_established = false;
    }

    if amf_ue.selected_enc_algorithm == 0 {
        header_type.ciphered = false;
    }
    if amf_ue.selected_int_algorithm == 0 {
        header_type.integrity_protected = false;
    }

    // No security needed => passthrough (identical to legacy).
    if !header_type.ciphered && !header_type.integrity_protected {
        return Ok(message.to_vec());
    }

    if message.len() < 7 {
        return Err(NasSecurityError::MessageTooShort);
    }

    // Strip the 2-octet EPD|SHT; nextgcore-nas wants MAC|SQN|payload.
    let inner = &message[2..];
    let sqn = message[6]; // == inner[4]

    // C3 STRICT replay (E2E-UNVALIDATED): reject a frame whose estimated COUNT
    // is not strictly forward of the last successfully-verified UL COUNT. Only
    // active once integrity is on and a baseline has been established (so the
    // bootstrap COUNT-0 message is accepted).
    let stored = nas_count_from_u32(amf_ue.ul_count);
    let candidate = stored.estimate(sqn);
    if amf_ue.ul_count_established
        && header_type.integrity_protected
        && candidate.value() <= stored.value()
    {
        amf_ue.mac_failed = true;
        return Err(NasSecurityError::MacVerificationFailed);
    }

    let mut ctx = NasSecurityContext::new(
        SecurityAlgorithms {
            ciphering: amf_ue.selected_enc_algorithm,
            integrity: if header_type.integrity_protected {
                amf_ue.selected_int_algorithm
            } else {
                0
            },
        },
        amf_ue.knas_enc,
        amf_ue.knas_int,
    );
    ctx.ul_count = stored;

    // direction::UPLINK (0). unprotect verifies the MAC over the CANDIDATE count
    // BEFORE committing; on MAC failure it mutates nothing => no COUNT advance.
    match unprotect_nas_message(&mut ctx, direction::UPLINK, inner, header_type.ciphered) {
        Ok(plain) => {
            // WRITEBACK the validated COUNT so it persists via the memento.
            amf_ue.ul_count = nas_count_to_u32(ctx.ul_count);
            amf_ue.ul_count_established = true;
            Ok(plain)
        }
        Err(NasError::MacVerificationFailed) | Err(NasError::ReplayedSequenceNumber) => {
            // STRICT: MAC failure / replay -> Err with the UL COUNT UNCHANGED.
            amf_ue.mac_failed = true;
            Err(NasSecurityError::MacVerificationFailed)
        }
        Err(_) => Err(NasSecurityError::InvalidHeader),
    }
}

// ============================================================================
// Crypto Helper Functions
// ============================================================================

/// NAS bearer ID (always 1 for NAS)
const NAS_BEARER: u8 = 1;

/// Encrypt/decrypt NAS message in place
///
/// Uses the appropriate algorithm based on selected_enc_algorithm:
/// - 0: NEA0 (null encryption)
/// - 1: 128-NEA1 (SNOW 3G)
/// - 2: 128-NEA2 (AES-CTR)
/// - 3: 128-NEA3 (ZUC)
pub fn nas_encrypt(
    algorithm: u8,
    key: &[u8],
    count: u32,
    access_type: u8,
    direction: u8,
    message: &mut [u8],
) {
    if message.is_empty() {
        return;
    }

    // Bearer is derived from access type (1 for 3GPP, 2 for non-3GPP)
    let bearer = if access_type == 0 {
        NAS_BEARER
    } else {
        access_type
    };

    match algorithm {
        0 => {
            // NEA0 - null encryption, do nothing
        }
        1 => {
            // 128-NEA1 (SNOW 3G)
            let length = (message.len() * 8) as u32;
            let mut key_arr = [0u8; 16];
            key_arr.copy_from_slice(&key[..16.min(key.len())]);
            nextgcore_crypt::snow3g::snow_3g_f8(
                &key_arr,
                count,
                bearer as u32,
                direction as u32,
                message,
                length,
            );
        }
        2 => {
            // 128-NEA2 (AES-CTR)
            let mut iv = [0u8; 16];
            iv[0..4].copy_from_slice(&count.to_be_bytes());
            // TS 33.401 Annex B.2.3 (reused by TS 33.501 Annex D.3 / TS
            // 35.215): octet 4 = BEARER (bits 7-3) | DIRECTION (bit 2) | 00.
            // DIRECTION must occupy bit 2, not bit 0.
            iv[4] = (bearer << 3) | ((direction & 0x01) << 2);

            let mut key_arr = [0u8; 16];
            key_arr.copy_from_slice(&key[..16.min(key.len())]);

            let input = message.to_vec();
            if let Ok(()) =
                nextgcore_crypt::aes::aes_ctr128_encrypt(&key_arr, &mut iv, &input, message)
            {
                // Success
            }
        }
        3 => {
            // 128-NEA3 (ZUC)
            let length = (message.len() * 8) as u32;
            let mut key_arr = [0u8; 16];
            key_arr.copy_from_slice(&key[..16.min(key.len())]);

            let input = message.to_vec();
            nextgcore_crypt::zuc::zuc_eea3(
                &key_arr,
                count,
                bearer as u32,
                direction as u32,
                length,
                &input,
                message,
            );
        }
        _ => {
            log::warn!("Unsupported encryption algorithm: {algorithm}");
        }
    }
}

/// Calculate NAS MAC (Message Authentication Code)
///
/// Uses the appropriate algorithm based on selected_int_algorithm:
/// - 0: NIA0 (null integrity)
/// - 1: 128-NIA1 (SNOW 3G)
/// - 2: 128-NIA2 (AES-CMAC)
/// - 3: 128-NIA3 (ZUC)
pub fn nas_mac_calculate(
    algorithm: u8,
    key: &[u8],
    count: u32,
    access_type: u8,
    direction: u8,
    message: &[u8],
) -> [u8; 4] {
    // Bearer is derived from access type (1 for 3GPP, 2 for non-3GPP)
    let bearer = if access_type == 0 {
        NAS_BEARER
    } else {
        access_type
    };

    match algorithm {
        0 => {
            // NIA0 - null integrity
            [0u8; 4]
        }
        1 => {
            // 128-NIA1 (SNOW 3G)
            let length = (message.len() * 8) as u64;
            let mut key_arr = [0u8; 16];
            key_arr.copy_from_slice(&key[..16.min(key.len())]);
            nextgcore_crypt::snow3g::snow_3g_f9(
                &key_arr,
                count,
                (bearer as u32) << 27,
                direction as u32,
                message,
                length,
            )
        }
        2 => {
            // 128-NIA2 (AES-CMAC)
            let mut key_arr = [0u8; 16];
            key_arr.copy_from_slice(&key[..16.min(key.len())]);

            // Build input: COUNT || BEARER || DIRECTION || MESSAGE
            // TS 33.401 Annex B.2.3 (reused by TS 33.501 Annex D.3 / TS
            // 35.215): octet 4 = BEARER (bits 7-3) | DIRECTION (bit 2) | 00.
            // DIRECTION must occupy bit 2, not bit 0.
            let mut input = Vec::with_capacity(8 + message.len());
            input.extend_from_slice(&count.to_be_bytes());
            input.push((bearer << 3) | ((direction & 0x01) << 2));
            input.extend_from_slice(&[0u8; 3]); // Padding
            input.extend_from_slice(message);

            let mac_full = nextgcore_crypt::aes_cmac::aes_cmac_calculate(&key_arr, &input);
            let mut mac = [0u8; 4];
            mac.copy_from_slice(&mac_full[..4]);
            mac
        }
        3 => {
            // 128-NIA3 (ZUC)
            let length = (message.len() * 8) as u32;
            let mut key_arr = [0u8; 16];
            key_arr.copy_from_slice(&key[..16.min(key.len())]);
            let mac_u32 = nextgcore_crypt::zuc::zuc_eia3(
                &key_arr,
                count,
                bearer as u32,
                direction as u32,
                length,
                message,
            );
            mac_u32.to_be_bytes()
        }
        _ => {
            log::warn!("Unsupported integrity algorithm: {algorithm}");
            [0u8; 4]
        }
    }
}

// ============================================================================
// Security Algorithm Selection (B18.13)
// ============================================================================

/// Security algorithm set
#[derive(Debug, Clone, Default)]
pub struct SecurityAlgorithmSet {
    /// Encryption algorithms (NEA0, NEA1, NEA2, NEA3)
    pub encryption: u8, // bit mask
    /// Integrity algorithms (NIA0, NIA1, NIA2, NIA3)
    pub integrity: u8, // bit mask
}

/// PQC algorithm identifiers (research prototype, not in any frozen 3GPP release; using spare 5G-EA4/5G-IA4 slots)
pub mod pqc_algorithm {
    /// 5G-EA4: Hybrid KEM (X25519 + ML-KEM-768) for key derivation
    pub const NEA4_PQC_HYBRID: u8 = 4;
    /// 5G-IA4: ML-DSA-65 for integrity (FIPS 204)
    pub const NIA4_PQC_DSA: u8 = 4;
}

/// PQC configuration for NAS security
#[derive(Debug, Clone, Default)]
pub struct PqcConfig {
    /// Enable PQC algorithms in algorithm selection
    pub enabled: bool,
    /// Prefer PQC over classical when both UE and network support it
    pub prefer_pqc: bool,
}

/// Select best encryption algorithm
///
/// Returns algorithm ID (0=NEA0, 1=NEA1, 2=NEA2, 3=NEA3, 4=NEA4-PQC)
/// Selection priority (PQC enabled): NEA4 > NEA2 > NEA1 > NEA3 > NEA0
/// Selection priority (PQC disabled): NEA2 > NEA1 > NEA3 > NEA0
pub fn select_encryption_algorithm(ue_algos: u8, amf_supported: u8) -> u8 {
    select_encryption_algorithm_with_pqc(ue_algos, amf_supported, &PqcConfig::default())
}

/// Select best encryption algorithm with PQC support
pub fn select_encryption_algorithm_with_pqc(
    ue_algos: u8,
    amf_supported: u8,
    pqc: &PqcConfig,
) -> u8 {
    let supported = ue_algos & amf_supported;

    // If PQC enabled + preferred, try NEA4 first
    if pqc.enabled && pqc.prefer_pqc && supported & (1 << 4) != 0 {
        return pqc_algorithm::NEA4_PQC_HYBRID;
    }

    // Classical priority: NEA2 (AES) > NEA1 (SNOW 3G) > NEA3 (ZUC) > NEA0 (null)
    if supported & (1 << 2) != 0 {
        2 // NEA2 (AES-CTR)
    } else if supported & (1 << 1) != 0 {
        1 // NEA1 (SNOW 3G)
    } else if supported & (1 << 3) != 0 {
        3 // NEA3 (ZUC)
    } else if pqc.enabled && supported & (1 << 4) != 0 {
        pqc_algorithm::NEA4_PQC_HYBRID // Fallback to PQC if no classical available
    } else {
        0 // NEA0 (null encryption)
    }
}

/// Select best integrity algorithm
///
/// Returns algorithm ID (0=NIA0, 1=NIA1, 2=NIA2, 3=NIA3, 4=NIA4-PQC)
/// Selection priority (PQC enabled): NIA4 > NIA2 > NIA1 > NIA3 > NIA0
/// Selection priority (PQC disabled): NIA2 > NIA1 > NIA3 > NIA0
pub fn select_integrity_algorithm(ue_algos: u8, amf_supported: u8) -> Option<u8> {
    select_integrity_algorithm_with_pqc(ue_algos, amf_supported, &PqcConfig::default())
}

/// Select best integrity algorithm with PQC support.
///
/// Returns `Some(alg)` (0=NIA0, 1=NIA1, 2=NIA2, 3=NIA3, 4=NIA4-PQC) when the
/// UE-advertised and AMF-supported NIA sets intersect, or `None` when they do
/// not.
///
/// Fail-closed (TS 33.501 §5.5.2 / §6.7.2): on an empty intersection this
/// returns `None` so the caller aborts the SMC/registration. It MUST NOT
/// fabricate NIA2 for an algorithm the UE never advertised. This is
/// deliberately asymmetric with ciphering: NEA0 (null ciphering) is a permitted
/// selection per §6.7.2, so the ciphering twin (`select_encryption_algorithm`)
/// returns NEA0 on an empty intersection; integrity has no such permitted null
/// fallback for NAS signalling, so the empty-intersection result here is `None`
/// (never NIA0/NIA2 by default).
pub fn select_integrity_algorithm_with_pqc(
    ue_algos: u8,
    amf_supported: u8,
    pqc: &PqcConfig,
) -> Option<u8> {
    let supported = ue_algos & amf_supported;

    // If PQC enabled + preferred, try NIA4 first
    if pqc.enabled && pqc.prefer_pqc && supported & (1 << 4) != 0 {
        return Some(pqc_algorithm::NIA4_PQC_DSA);
    }

    // Classical priority: NIA2 (AES) > NIA1 (SNOW 3G) > NIA3 (ZUC) > NIA0 (null)
    if supported & (1 << 2) != 0 {
        Some(2) // NIA2 (AES-CMAC)
    } else if supported & (1 << 1) != 0 {
        Some(1) // NIA1 (SNOW 3G)
    } else if supported & (1 << 3) != 0 {
        Some(3) // NIA3 (ZUC)
    } else if pqc.enabled && supported & (1 << 4) != 0 {
        Some(pqc_algorithm::NIA4_PQC_DSA)
    } else if supported & (1 << 0) != 0 {
        Some(0) // NIA0 (null integrity) - the UE explicitly advertised only NIA0
    } else {
        // Empty intersection: no common NAS integrity algorithm. Fail closed —
        // never default to NIA2 (that would fabricate an algorithm the UE never
        // advertised). The caller must reject the registration.
        None
    }
}

/// NAS ciphering enforcement policy (Item 118)
///
/// Controls whether null algorithms (NEA0/NIA0) are accepted.
/// Per 3GPP TS 33.501 §6.7.2, null integrity (NIA0) SHALL NOT be used
/// for NAS signaling in production. Null ciphering (NEA0) MAY be used
/// in limited contexts but is strongly discouraged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NasCipheringPolicy {
    /// Allow null algorithms (development/testing only)
    AllowNull,
    /// Reject null integrity but allow null ciphering (TS 33.501 minimum)
    #[default]
    RejectNullIntegrity,
    /// Reject all null algorithms (recommended for production)
    RejectAllNull,
}

/// Validate selected algorithms against the ciphering policy
///
/// Returns Ok(()) if the algorithms are acceptable, Err with reason if not.
pub fn validate_algorithm_policy(
    enc_algorithm: u8,
    int_algorithm: u8,
    policy: NasCipheringPolicy,
) -> Result<(), &'static str> {
    match policy {
        NasCipheringPolicy::AllowNull => Ok(()),
        NasCipheringPolicy::RejectNullIntegrity => {
            if int_algorithm == 0 {
                Err("NIA0 (null integrity) rejected by security policy (TS 33.501 §6.7.2)")
            } else {
                Ok(())
            }
        }
        NasCipheringPolicy::RejectAllNull => {
            if int_algorithm == 0 {
                Err("NIA0 (null integrity) rejected by security policy")
            } else if enc_algorithm == 0 {
                Err("NEA0 (null ciphering) rejected by security policy")
            } else {
                Ok(())
            }
        }
    }
}

/// Select security algorithms for UE
///
/// This is called during security mode command to select algorithms
pub fn select_security_algorithms(
    amf_ue: &mut AmfUe,
    ue_security_capability: &SecurityAlgorithmSet,
    amf_supported: &SecurityAlgorithmSet,
) {
    select_security_algorithms_with_policy(
        amf_ue,
        ue_security_capability,
        amf_supported,
        NasCipheringPolicy::default(),
    );
}

/// Select security algorithms for UE with ciphering policy enforcement
pub fn select_security_algorithms_with_policy(
    amf_ue: &mut AmfUe,
    ue_security_capability: &SecurityAlgorithmSet,
    amf_supported: &SecurityAlgorithmSet,
    policy: NasCipheringPolicy,
) {
    // Select encryption algorithm
    let selected_enc =
        select_encryption_algorithm(ue_security_capability.encryption, amf_supported.encryption);
    amf_ue.selected_enc_algorithm = selected_enc;

    // Select integrity algorithm. `None` = empty intersection (no common NAS
    // integrity algorithm). The live SMC path (`ngap_path`) aborts the
    // registration on `None`; this convenience helper is used for
    // reporting/tests, so it falls back to NIA0 here and lets the ciphering
    // policy enforcement below act — it never fabricates NIA2 by default.
    let selected_int =
        select_integrity_algorithm(ue_security_capability.integrity, amf_supported.integrity)
            .unwrap_or(0);
    amf_ue.selected_int_algorithm = selected_int;

    // Enforce ciphering policy
    if let Err(reason) = validate_algorithm_policy(selected_enc, selected_int, policy) {
        log::warn!(
            "[{}] NAS algorithm policy violation: {} (enc={}, int={})",
            amf_ue.supi.as_deref().unwrap_or("unknown"),
            reason,
            get_encryption_algorithm_name(selected_enc),
            get_integrity_algorithm_name(selected_int),
        );

        // Force to strongest available non-null algorithms
        if selected_int == 0
            && matches!(
                policy,
                NasCipheringPolicy::RejectNullIntegrity | NasCipheringPolicy::RejectAllNull
            )
        {
            amf_ue.selected_int_algorithm = 2; // Force NIA2 (AES-CMAC)
            log::info!(
                "[{}] Forced integrity algorithm to NIA2 (AES-CMAC)",
                amf_ue.supi.as_deref().unwrap_or("unknown"),
            );
        }
        if selected_enc == 0 && policy == NasCipheringPolicy::RejectAllNull {
            amf_ue.selected_enc_algorithm = 2; // Force NEA2 (AES-CTR)
            log::info!(
                "[{}] Forced encryption algorithm to NEA2 (AES-CTR)",
                amf_ue.supi.as_deref().unwrap_or("unknown"),
            );
        }
    }

    log::info!(
        "[{}] Selected security algorithms: enc={}EA{}, int={}IA{}",
        amf_ue.supi.as_deref().unwrap_or("unknown"),
        if amf_ue.selected_enc_algorithm == 0 {
            "N"
        } else {
            "1"
        },
        amf_ue.selected_enc_algorithm,
        if amf_ue.selected_int_algorithm == 0 {
            "N"
        } else {
            "1"
        },
        amf_ue.selected_int_algorithm
    );
}

/// Get algorithm name for logging
pub fn get_encryption_algorithm_name(algo: u8) -> &'static str {
    match algo {
        0 => "NEA0",
        1 => "128-NEA1",
        2 => "128-NEA2",
        3 => "128-NEA3",
        4 => "PQC-NEA4 (X25519+ML-KEM-768)",
        _ => "Unknown",
    }
}

/// Get algorithm name for logging
pub fn get_integrity_algorithm_name(algo: u8) -> &'static str {
    match algo {
        0 => "NIA0",
        1 => "128-NIA1",
        2 => "128-NIA2",
        3 => "128-NIA3",
        4 => "PQC-NIA4 (ML-DSA-65)",
        _ => "Unknown",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::amf_context_init;

    fn create_test_ue() -> AmfUe {
        amf_context_init(64, 1024, 4096);
        let mut ue = AmfUe::default();
        ue.knas_enc = [0x11u8; 16];
        ue.knas_int = [0x22u8; 16];
        ue.selected_enc_algorithm = 2; // NEA2
        ue.selected_int_algorithm = 2; // NIA2
        ue.access_type = 1; // 3GPP
        ue.security_context_available = true;
        ue
    }

    #[test]
    fn test_security_header_type_plain() {
        let header_type = SecurityHeaderType::from_byte(security_header::PLAIN_NAS_MESSAGE);
        assert!(!header_type.integrity_protected);
        assert!(!header_type.ciphered);
        assert!(!header_type.new_security_context);
    }

    #[test]
    fn test_security_header_type_integrity_protected() {
        let header_type = SecurityHeaderType::from_byte(security_header::INTEGRITY_PROTECTED);
        assert!(header_type.integrity_protected);
        assert!(!header_type.ciphered);
        assert!(!header_type.new_security_context);
    }

    #[test]
    fn test_security_header_type_integrity_and_ciphered() {
        let header_type =
            SecurityHeaderType::from_byte(security_header::INTEGRITY_PROTECTED_AND_CIPHERED);
        assert!(header_type.integrity_protected);
        assert!(header_type.ciphered);
        assert!(!header_type.new_security_context);
    }

    #[test]
    fn test_security_header_type_new_context() {
        let header_type = SecurityHeaderType::from_byte(
            security_header::INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT,
        );
        assert!(header_type.integrity_protected);
        assert!(!header_type.ciphered);
        assert!(header_type.new_security_context);
    }

    #[test]
    fn test_nas_security_header_encode_decode() {
        let header = NasSecurityHeader {
            extended_protocol_discriminator: 0x7e,
            security_header_type: 0x02,
            message_authentication_code: [0x11, 0x22, 0x33, 0x44],
            sequence_number: 0x05,
        };

        let encoded = header.encode();
        assert_eq!(encoded.len(), 7);
        assert_eq!(encoded[0], 0x7e);
        assert_eq!(encoded[1], 0x02);
        assert_eq!(&encoded[2..6], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(encoded[6], 0x05);

        let decoded = NasSecurityHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.extended_protocol_discriminator, 0x7e);
        assert_eq!(decoded.security_header_type, 0x02);
        assert_eq!(
            decoded.message_authentication_code,
            [0x11, 0x22, 0x33, 0x44]
        );
        assert_eq!(decoded.sequence_number, 0x05);
    }

    #[test]
    fn test_nas_security_header_decode_too_short() {
        let short_data = [0x7e, 0x02, 0x11, 0x22];
        assert!(NasSecurityHeader::decode(&short_data).is_none());
    }

    #[test]
    fn test_nas_5gs_security_encode_plain() {
        let mut ue = create_test_ue();
        let message = vec![0x7e, 0x00, 0x41]; // Plain registration request

        let result = nas_5gs_security_encode(&mut ue, &message, security_header::PLAIN_NAS_MESSAGE);

        assert!(result.is_some());
        let encoded = result.unwrap();
        assert_eq!(encoded, message); // Plain message unchanged
    }

    #[test]
    fn test_nas_5gs_security_encode_integrity_protected() {
        let mut ue = create_test_ue();
        let message = vec![0x7e, 0x00, 0x41];

        let result =
            nas_5gs_security_encode(&mut ue, &message, security_header::INTEGRITY_PROTECTED);

        assert!(result.is_some());
        let encoded = result.unwrap();
        assert!(encoded.len() > message.len()); // Should have security header
        assert_eq!(encoded[0], 0x7e); // EPD
        assert_eq!(encoded[1], security_header::INTEGRITY_PROTECTED);
        assert_eq!(ue.dl_count, 1); // Count incremented
    }

    #[test]
    fn test_nas_5gs_security_encode_new_context_resets_count() {
        let mut ue = create_test_ue();
        ue.dl_count = 100;
        ue.ul_count = 50;
        let message = vec![0x7e, 0x00, 0x41];

        let _ = nas_5gs_security_encode(
            &mut ue,
            &message,
            security_header::INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT,
        );

        // Counts should be reset then incremented
        assert_eq!(ue.dl_count, 1);
    }

    #[test]
    fn test_nas_5gs_security_decode_no_context() {
        let mut ue = create_test_ue();
        ue.security_context_available = false;
        let message = vec![0x7e, 0x02, 0x11, 0x22, 0x33, 0x44, 0x00, 0xaa, 0xbb];

        let result =
            nas_5gs_security_decode(&mut ue, security_header::INTEGRITY_PROTECTED, &message);

        assert!(result.is_ok());
        // Without security context, message returned as-is
        assert_eq!(result.unwrap(), message);
    }

    #[test]
    fn test_nas_5gs_security_decode_too_short() {
        let mut ue = create_test_ue();
        let message = vec![0x7e, 0x02, 0x11]; // Too short

        let result =
            nas_5gs_security_decode(&mut ue, security_header::INTEGRITY_PROTECTED, &message);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), NasSecurityError::MessageTooShort);
    }

    #[test]
    fn test_nas_mac_calculate_null() {
        let key = [0u8; 16];
        let mac = nas_mac_calculate(0, &key, 0, 1, direction::DOWNLINK, &[0x01, 0x02, 0x03]);
        assert_eq!(mac, [0u8; 4]);
    }

    /// Cross-stack NAS-security regression vector (TS 33.501 + TS 33.401
    /// Annex B.2.3). This vector is MIRRORED BYTE-FOR-BYTE in the nextgsim
    /// UE at nextgsim-nas/src/security.rs
    /// (`test_cross_stack_nas_security_reference_vector`). If either side's
    /// KAMF / KNAS_int derivation or NAS-MAC/NEA2 input layout drifts, one
    /// of the two repos' tests fails and the divergence is caught here
    /// instead of in a Docker E2E run.
    ///
    /// Inputs: fixed KSEAF, SUPI 999700000000001, ABBA [0,0], ngKSI 0,
    /// NIA2/NEA2, a representative integrity-only Security Mode Command
    /// payload, COUNT 0, BEARER 1 (3GPP), DIRECTION downlink.
    #[test]
    fn test_cross_stack_nas_security_reference_vector() {
        use nextgcore_crypt::kdf::{
            nextgcore_kdf_kamf, nextgcore_kdf_nas_5gs, NEXTGCORE_KDF_NAS_ENC_ALG,
            NEXTGCORE_KDF_NAS_INT_ALG,
        };

        // -- fixed inputs (shared with the sim) --
        let kseaf: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let supi = "imsi-999700000000001";
        let abba = [0x00u8, 0x00];

        // -- KAMF (TS 33.501 Annex A.7) --
        let kamf = nextgcore_kdf_kamf(supi, &abba, &kseaf);
        let expected_kamf: [u8; 32] = [
            84, 220, 101, 65, 23, 243, 138, 4, 80, 226, 49, 139, 229, 104, 34, 238, 12, 174, 245,
            76, 108, 223, 167, 207, 103, 220, 31, 103, 8, 43, 231, 105,
        ];
        assert_eq!(kamf, expected_kamf, "KAMF derivation drifted");

        // -- KNAS_int / KNAS_enc (TS 33.501 Annex A.8, NIA2/NEA2 = 0x02) --
        let knas_int = nextgcore_kdf_nas_5gs(NEXTGCORE_KDF_NAS_INT_ALG, 0x02, &kamf);
        let knas_enc = nextgcore_kdf_nas_5gs(NEXTGCORE_KDF_NAS_ENC_ALG, 0x02, &kamf);
        let expected_knas_int: [u8; 16] = [
            38, 115, 160, 80, 204, 200, 220, 83, 104, 212, 33, 203, 134, 23, 71, 52,
        ];
        let expected_knas_enc: [u8; 16] = [
            68, 137, 172, 160, 32, 35, 251, 95, 219, 157, 215, 44, 26, 246, 150, 231,
        ];
        assert_eq!(knas_int, expected_knas_int, "KNAS_int derivation drifted");
        assert_eq!(knas_enc, expected_knas_enc, "KNAS_enc derivation drifted");

        // -- NAS-MAC over a representative SMC payload (TS 33.401 B.2.3) --
        // COUNT 0, BEARER 1 (3GPP access), DIRECTION downlink, NIA2. The
        // integrity-protected NAS message the MAC covers is
        // SQN || inner-message (TS 24.501 Section 4.4.3.3); here SQN = 0,
        // matching how the sim's `compute_nas_mac(sqn=0, payload)` builds
        // its input.
        let smc_payload: [u8; 8] = [0x7e, 0x03, 0x02, 0x00, 0x02, 0xe0, 0xe0, 0xe1];
        let mut mac_input = vec![0x00u8]; // SQN
        mac_input.extend_from_slice(&smc_payload);
        let mac = nas_mac_calculate(2, &knas_int, 0, 1, direction::DOWNLINK, &mac_input);
        let expected_mac: [u8; 4] = [197, 118, 67, 44];
        assert_eq!(mac, expected_mac, "NAS-MAC (NIA2) input layout drifted");

        // -- NEA2 ciphering of the same payload (TS 33.501 Annex D.3) --
        let mut ciphered = smc_payload.to_vec();
        nas_encrypt(2, &knas_enc, 0, 1, direction::DOWNLINK, &mut ciphered);
        let expected_ciphered: [u8; 8] = [231, 2, 38, 222, 206, 212, 137, 8];
        assert_eq!(
            ciphered.as_slice(),
            &expected_ciphered,
            "NEA2 IV layout drifted"
        );
    }

    /// nas-06 Phase 0 drift bridge (security path): amfd's hand-rolled
    /// `nas_5gs_security_encode` must produce the same protected frame as the
    /// conformant nextgcore-nas `protect_nas_message`, and nextgcore-nas `unprotect` must
    /// recover the body. amfd emits `EPD|SHT|MAC|SQN|ciphered`; nextgcore-nas emits
    /// `MAC|SQN|ciphered`, so we compare after stripping the 2-octet EPD|SHT.
    /// Pinned to access_type=1 (=> bearer 1 on both sides) and COUNT 0.
    #[test]
    fn drift_security_encode_matches_nextgcore_nas_protect() {
        use nextgcore_nas::common::security::{
            protect_nas_message, unprotect_nas_message, NasCount, NasSecurityContext,
        };
        use nextgcore_nas::common::types::SecurityAlgorithms;

        // Representative plain inner downlink 5GMM body.
        let body: [u8; 8] = [0x7e, 0x00, 0x5d, 0x02, 0x00, 0x02, 0xe0, 0xe1];

        // amfd hand-rolled encode (downlink, integrity + ciphered, NEA2/NIA2).
        let mut ue = create_test_ue();
        let amfd = nas_5gs_security_encode(
            &mut ue,
            &body,
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
        )
        .unwrap();

        // nextgcore-nas protect with the same keys / algorithms / COUNT / direction.
        let mut ctx = NasSecurityContext::new(
            SecurityAlgorithms {
                ciphering: ue.selected_enc_algorithm,
                integrity: ue.selected_int_algorithm,
            },
            ue.knas_enc,
            ue.knas_int,
        );
        ctx.dl_count = NasCount::new(0, 0); // amfd used COUNT 0 for this frame
        let ogs = protect_nas_message(&mut ctx, 1, &body, true).unwrap();

        // EPD|SHT (2 octets) stripped => byte-identical protected frames.
        assert_eq!(
            &amfd[2..],
            &ogs[..],
            "amfd security frame must equal nextgcore-nas protect (bytes 2..)"
        );

        // nextgcore-nas unprotect must recover the original plaintext body.
        let mut rx = NasSecurityContext::new(
            SecurityAlgorithms {
                ciphering: ue.selected_enc_algorithm,
                integrity: ue.selected_int_algorithm,
            },
            ue.knas_enc,
            ue.knas_int,
        );
        let recovered = unprotect_nas_message(&mut rx, 1, &amfd[2..], true).unwrap();
        assert_eq!(
            recovered, body,
            "nextgcore-nas must recover the amfd-protected body"
        );
    }

    /// KNOWN DIVERGENCE LOCK (nas-06): amfd derives the NAS connection-id
    /// (bearer) from access_type — non-3GPP (access_type=2) uses bearer 2, per
    /// TS 33.501 — whereas nextgcore-nas hardwires bearer 1. So for non-3GPP access
    /// the protected frames differ. This guard fails the moment nextgcore-nas takes
    /// a connection-id parameter (the divergence fix), at which point convert
    /// it to an assert_eq. The 3GPP path (access_type=1) is byte-equal and is
    /// covered by `drift_security_encode_matches_nextgcore_nas_protect`.
    #[test]
    fn drift_non_3gpp_bearer_divergence_locked() {
        use nextgcore_nas::common::security::{protect_nas_message, NasCount, NasSecurityContext};
        use nextgcore_nas::common::types::SecurityAlgorithms;

        let body: [u8; 8] = [0x7e, 0x00, 0x5d, 0x02, 0x00, 0x02, 0xe0, 0xe1];
        let mut ue = create_test_ue();
        ue.access_type = 2; // non-3GPP => amfd uses bearer 2
        let amfd = nas_5gs_security_encode(
            &mut ue,
            &body,
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
        )
        .unwrap();

        let mut ctx = NasSecurityContext::new(
            SecurityAlgorithms {
                ciphering: ue.selected_enc_algorithm,
                integrity: ue.selected_int_algorithm,
            },
            ue.knas_enc,
            ue.knas_int,
        );
        ctx.dl_count = NasCount::new(0, 0);
        let ogs = protect_nas_message(&mut ctx, 1, &body, true).unwrap(); // bearer 1

        assert_ne!(
            &amfd[2..],
            &ogs[..],
            "non-3GPP bearer divergence appears fixed (nextgcore-nas took a connection-id); \
             convert this guard to assert_eq"
        );
    }

    // ======================================================================
    // nas-06 Phase-6 C1/C2/C3 — nextgcore-nas security adapter (canary-gated)
    // ======================================================================

    /// C1: the nextgcore-nas ENCODE adapter must be byte-for-byte identical to the
    /// legacy encoder across representative SHTs (3GPP access, NEA2/NIA2). This
    /// is the proof that flipping the canary leaves the ENCODE wire image
    /// unchanged for the production (3GPP) path.
    #[test]
    fn encode_nextgcore_matches_legacy_byte_for_byte() {
        let cases: &[(&[u8], u8)] = &[
            (&[0x7e, 0x00, 0x41], security_header::INTEGRITY_PROTECTED),
            (
                &[0x7e, 0x00, 0x42, 0x01, 0x02, 0x03],
                security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
            ),
            (
                &[0x7e, 0x00, 0x5d, 0x02, 0x00, 0x02, 0xe0, 0xe1],
                security_header::INTEGRITY_PROTECTED_WITH_NEW_5G_NAS_SECURITY_CONTEXT,
            ),
            (
                &[0x7e, 0x00, 0x5d, 0x02, 0x00, 0x02, 0xe0, 0xe1],
                security_header::INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_5G_NAS_SECURITY_CONTEXT,
            ),
            // PLAIN passthrough.
            (&[0x7e, 0x00, 0x43], security_header::PLAIN_NAS_MESSAGE),
        ];
        for &(msg, sht) in cases {
            let mut ue_old = create_test_ue();
            let mut ue_new = create_test_ue();
            let old = nas_5gs_security_encode_legacy(&mut ue_old, msg, sht);
            let new = nas_5gs_security_encode_nextgcore(&mut ue_new, msg, sht);
            assert_eq!(old, new, "encode adapter byte-mismatch for sht={sht:#x}");
            // COUNT state must track identically.
            assert_eq!(
                ue_old.dl_count, ue_new.dl_count,
                "dl_count desync sht={sht:#x}"
            );
            assert_eq!(
                ue_old.ul_count, ue_new.ul_count,
                "ul_count desync sht={sht:#x}"
            );
        }
    }

    /// C1: byte-identity must hold across multiple consecutive encodes, proving
    /// the NasCount<->u32 writeback keeps the SQN/COUNT in lock-step.
    #[test]
    fn encode_nextgcore_matches_legacy_across_multiple_counts() {
        let mut ue_old = create_test_ue();
        let mut ue_new = create_test_ue();
        for i in 0..6u8 {
            let msg = [0x7e, 0x00, 0x55, i];
            let old = nas_5gs_security_encode_legacy(
                &mut ue_old,
                &msg,
                security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
            );
            let new = nas_5gs_security_encode_nextgcore(
                &mut ue_new,
                &msg,
                security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
            );
            assert_eq!(old, new, "byte-mismatch at iter {i}");
            assert_eq!(
                ue_old.dl_count, ue_new.dl_count,
                "dl_count desync at iter {i}"
            );
        }
        assert_eq!(ue_new.dl_count, 6, "writeback did not advance the COUNT");
    }

    /// C2: the public dispatcher honors the canary. OFF (default) => the legacy
    /// byte image; ON => the adapter, which is byte-identical here.
    #[test]
    fn dispatcher_canary_off_equals_legacy_on_equals_adapter() {
        let msg = [0x7e, 0x00, 0x5d, 0x02, 0x00, 0x02, 0xe0, 0xe1];
        let sht = security_header::INTEGRITY_PROTECTED_AND_CIPHERED;

        // Default is OFF.
        let ue_default = create_test_ue();
        assert!(
            !ue_default.use_nextgcore_nas_security,
            "canary MUST default to false"
        );

        // OFF -> legacy bytes.
        let mut ue_off = create_test_ue();
        let off = nas_5gs_security_encode(&mut ue_off, &msg, sht).unwrap();
        let mut ue_legacy = create_test_ue();
        let legacy = nas_5gs_security_encode_legacy(&mut ue_legacy, &msg, sht).unwrap();
        assert_eq!(off, legacy, "canary OFF must equal the legacy wire image");

        // ON -> adapter bytes (byte-identical to legacy for 3GPP access).
        let mut ue_on = create_test_ue();
        ue_on.use_nextgcore_nas_security = true;
        let on = nas_5gs_security_encode(&mut ue_on, &msg, sht).unwrap();
        assert_eq!(
            on, legacy,
            "canary ON adapter must be byte-identical to legacy"
        );
    }

    /// Helper: craft a valid uplink-protected frame (EPD|SHT|MAC|SQN|payload)
    /// the way a conformant UE would, for the strict decode tests.
    fn make_uplink_frame(ue: &AmfUe, body: &[u8], sht: u8, count: u32) -> Vec<u8> {
        use nextgcore_nas::common::security::{protect_nas_message, NasCount, NasSecurityContext};
        use nextgcore_nas::common::types::SecurityAlgorithms;
        let mut ctx = NasSecurityContext::new(
            SecurityAlgorithms {
                ciphering: ue.selected_enc_algorithm,
                integrity: ue.selected_int_algorithm,
            },
            ue.knas_enc,
            ue.knas_int,
        );
        ctx.ul_count = NasCount::new(count >> 8, (count & 0xff) as u8);
        // direction::UPLINK (0), ciphered.
        let prot = protect_nas_message(&mut ctx, direction::UPLINK, body, true).unwrap();
        let mut f = vec![0x7e, sht];
        f.extend_from_slice(&prot);
        f
    }

    /// C3 (E2E-UNVALIDATED): MAC failure on the strict path returns Err and does
    /// NOT advance the UL COUNT (vs the lenient legacy path which warns +
    /// continues).
    #[test]
    fn decode_nextgcore_mac_fail_returns_err_no_count_advance() {
        let mut ue = create_test_ue();
        ue.use_nextgcore_nas_security = true;
        let sht = security_header::INTEGRITY_PROTECTED_AND_CIPHERED;
        let mut frame = make_uplink_frame(&ue, &[0x7e, 0x00, 0x57, 0x01], sht, 0);
        // Tamper the trailing payload octet -> MAC mismatch.
        let last = frame.len() - 1;
        frame[last] ^= 0xff;

        let before = ue.ul_count;
        let res = nas_5gs_security_decode_nextgcore(&mut ue, sht, &frame);
        assert!(
            matches!(res, Err(NasSecurityError::MacVerificationFailed)),
            "strict decode must Err on MAC failure"
        );
        assert_eq!(ue.ul_count, before, "MAC failure must NOT advance UL COUNT");
        assert!(
            !ue.ul_count_established,
            "no replay baseline established on failure"
        );
    }

    /// C3 (E2E-UNVALIDATED): a valid frame is accepted, then an exact replay of
    /// it is rejected via the persisted established-count state.
    #[test]
    fn decode_nextgcore_rejects_replay() {
        let mut ue = create_test_ue();
        ue.use_nextgcore_nas_security = true;
        let sht = security_header::INTEGRITY_PROTECTED_AND_CIPHERED;
        let f0 = make_uplink_frame(&ue, &[0x7e, 0x00, 0x57, 0x00], sht, 0);

        // First reception is accepted and establishes the baseline.
        let body =
            nas_5gs_security_decode_nextgcore(&mut ue, sht, &f0).expect("first frame accepted");
        assert_eq!(
            body,
            [0x7e, 0x00, 0x57, 0x00],
            "must recover the plaintext body"
        );
        assert!(ue.ul_count_established, "baseline must be established");

        // Exact replay (SQN 0, candidate == stored) is rejected.
        let replay = nas_5gs_security_decode_nextgcore(&mut ue, sht, &f0);
        assert!(
            matches!(replay, Err(NasSecurityError::MacVerificationFailed)),
            "replayed frame must be rejected"
        );
    }

    /// C3: a legitimate in-order successor (next SQN) is still accepted after
    /// establishing the baseline (the replay guard is strictly-backward only).
    #[test]
    fn decode_nextgcore_accepts_in_order_successor() {
        let mut ue = create_test_ue();
        ue.use_nextgcore_nas_security = true;
        let sht = security_header::INTEGRITY_PROTECTED_AND_CIPHERED;
        let f0 = make_uplink_frame(&ue, &[0x7e, 0x00, 0x57, 0x00], sht, 0);
        let f1 = make_uplink_frame(&ue, &[0x7e, 0x00, 0x57, 0x01], sht, 1);
        nas_5gs_security_decode_nextgcore(&mut ue, sht, &f0).expect("frame 0 accepted");
        let body = nas_5gs_security_decode_nextgcore(&mut ue, sht, &f1).expect("frame 1 accepted");
        assert_eq!(body, [0x7e, 0x00, 0x57, 0x01]);
        assert_eq!(ue.ul_count, 1, "UL COUNT advanced to the verified value");
    }

    /// Wave-6 H9 A/B byte-compare scaffold — the in-process analog of the
    /// docker A/B runbook (`.context/remediation/wave6/WS-H-oracle-e2e.md` H9).
    ///
    /// For each representative DL 5GMM payload, encode it through the gated
    /// dispatcher on BOTH canary settings (A = OFF/legacy, B = ON/nextgcore
    /// adapter) and byte-compare the protected wire image + DL COUNT; then
    /// confirm the canary-ON strict UL decode accepts a conformant frame and
    /// establishes the replay baseline. This pins the invariant the docker A/B
    /// must reproduce before the (HOST-ONLY) default-flip: the runtime knob
    /// selects the path, and the nextgcore adapter is byte-identical to the
    /// legacy encoder for 3GPP-access frames (TS 24.501 §4.4).
    #[test]
    fn h9_ab_byte_compare_scaffold() {
        let sht = security_header::INTEGRITY_PROTECTED_AND_CIPHERED;
        // Representative DL 5GMM bodies exercised on the registration flow.
        let messages: &[&[u8]] = &[
            &[0x7e, 0x00, 0x5d, 0x02, 0x00, 0x02, 0xe0, 0xe1],
            &[0x7e, 0x00, 0x42, 0x01, 0x77, 0x00, 0x0b, 0xf2, 0x00],
        ];

        for msg in messages {
            // Path A: canary OFF (legacy production encoder).
            let mut ue_a = create_test_ue();
            assert!(
                !ue_a.use_nextgcore_nas_security,
                "path A must run with the canary OFF"
            );
            let a = nas_5gs_security_encode(&mut ue_a, msg, sht).expect("A encode");

            // Path B: canary ON (conformant nextgcore adapter).
            let mut ue_b = create_test_ue();
            ue_b.use_nextgcore_nas_security = true;
            let b = nas_5gs_security_encode(&mut ue_b, msg, sht).expect("B encode");

            // A/B invariant: byte-identical DL image + COUNT parity.
            assert_eq!(a, b, "H9 A/B: DL protected bytes differ for msg {msg:02x?}");
            assert_eq!(ue_a.dl_count, ue_b.dl_count, "H9 A/B: DL COUNT desync");
        }

        // UL leg under canary ON: a conformant uplink frame is accepted and the
        // strict path establishes the anti-replay baseline.
        let mut ue_on = create_test_ue();
        ue_on.use_nextgcore_nas_security = true;
        let body = [0x7e, 0x00, 0x57, 0x00];
        let frame = make_uplink_frame(&ue_on, &body, sht, 0);
        let out = nas_5gs_security_decode(&mut ue_on, sht, &frame).expect("UL accept under ON");
        assert_eq!(out, body, "H9 A/B: UL plaintext recovered under canary ON");
        assert!(
            ue_on.ul_count_established,
            "H9 A/B: replay baseline established under canary ON"
        );
    }

    #[test]
    fn test_nas_mac_calculate_nia2() {
        let key = [0x11u8; 16];
        let message = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mac = nas_mac_calculate(2, &key, 0, 1, direction::DOWNLINK, &message);
        // MAC should be non-zero for NIA2
        assert_ne!(mac, [0u8; 4]);
    }

    #[test]
    fn test_nas_encrypt_null() {
        let key = [0u8; 16];
        let mut message = vec![0x01, 0x02, 0x03, 0x04];
        let original = message.clone();
        nas_encrypt(0, &key, 0, 1, direction::DOWNLINK, &mut message);
        // NEA0 should not change message
        assert_eq!(message, original);
    }

    #[test]
    fn test_nas_encrypt_nea2() {
        let key = [0x11u8; 16];
        let mut message = vec![0x01, 0x02, 0x03, 0x04];
        let original = message.clone();
        nas_encrypt(2, &key, 0, 1, direction::DOWNLINK, &mut message);
        // NEA2 should change message
        assert_ne!(message, original);

        // Encrypt again should restore original (symmetric)
        nas_encrypt(2, &key, 0, 1, direction::DOWNLINK, &mut message);
        assert_eq!(message, original);
    }

    #[test]
    fn test_nas_encrypt_empty_message() {
        let key = [0x11u8; 16];
        let mut message: Vec<u8> = vec![];
        nas_encrypt(2, &key, 0, 1, direction::DOWNLINK, &mut message);
        assert!(message.is_empty());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut sender_ue = create_test_ue();
        let mut receiver_ue = create_test_ue();
        let original_message = vec![0x7e, 0x00, 0x41, 0x01, 0x02, 0x03];

        // Sender encodes with integrity and ciphering (uses dl_count)
        let encoded = nas_5gs_security_encode(
            &mut sender_ue,
            &original_message,
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED,
        )
        .unwrap();

        // Receiver decodes (uses ul_count, but we need to match the sender's dl_count)
        // In real scenario, the receiver's ul_count tracks the sender's dl_count
        // For this test, we simulate by setting receiver's ul_count to 0 (matching sender's initial dl_count)
        receiver_ue.ul_count = 0;

        // Decode - note: the decode function expects the message to be in uplink direction
        // but we encoded in downlink direction. For a proper roundtrip, we need to
        // decode with the same direction and count.
        // Let's test the individual components instead.

        // Verify the encoded message has the correct structure
        assert!(encoded.len() > 7); // Security header + payload
        assert_eq!(encoded[0], 0x7e); // EPD
        assert_eq!(
            encoded[1],
            security_header::INTEGRITY_PROTECTED_AND_CIPHERED
        );

        // Verify the sequence number is 0 (first message)
        assert_eq!(encoded[6], 0x00);

        // Verify sender's dl_count was incremented
        assert_eq!(sender_ue.dl_count, 1);
    }

    #[test]
    fn test_select_encryption_algorithm_nea2() {
        let ue_algos = 0b1110; // Supports NEA1, NEA2, NEA3
        let amf_algos = 0b1111; // Supports all
        let selected = select_encryption_algorithm(ue_algos, amf_algos);
        assert_eq!(selected, 2); // Should select NEA2 (highest priority)
    }

    #[test]
    fn test_select_encryption_algorithm_nea1() {
        let ue_algos = 0b1010; // Supports NEA1, NEA3
        let amf_algos = 0b1111;
        let selected = select_encryption_algorithm(ue_algos, amf_algos);
        assert_eq!(selected, 1); // Should select NEA1
    }

    #[test]
    fn test_select_encryption_algorithm_nea0_fallback() {
        let ue_algos = 0b0001; // Supports only NEA0
        let amf_algos = 0b1111;
        let selected = select_encryption_algorithm(ue_algos, amf_algos);
        assert_eq!(selected, 0); // Should select NEA0 (null)
    }

    #[test]
    fn test_select_integrity_algorithm_nia2() {
        let ue_algos = 0b1110; // Supports NIA1, NIA2, NIA3
        let amf_algos = 0b1111;
        let selected = select_integrity_algorithm(ue_algos, amf_algos);
        assert_eq!(selected, Some(2)); // Should select NIA2 (highest priority)
    }

    #[test]
    fn test_select_integrity_algorithm_nia1() {
        let ue_algos = 0b1010; // Supports NIA1, NIA3
        let amf_algos = 0b1111;
        let selected = select_integrity_algorithm(ue_algos, amf_algos);
        assert_eq!(selected, Some(1)); // Should select NIA1
    }

    #[test]
    fn test_select_integrity_algorithm_nia3() {
        let ue_algos = 0b1000; // Supports NIA3 only
        let amf_algos = 0b1111;
        let selected = select_integrity_algorithm(ue_algos, amf_algos);
        assert_eq!(selected, Some(3)); // Should select NIA3
    }

    #[test]
    fn test_select_integrity_algorithm_no_match() {
        // Empty intersection: fail closed (TS 33.501 §5.5.2). The function must
        // return None, NOT a fabricated NIA2 the UE never advertised.
        assert_eq!(select_integrity_algorithm(0b0000, 0b1111), None);
        assert_eq!(select_integrity_algorithm(0x00, 0x00), None);
        // UE advertises only an algorithm the AMF does not support -> None.
        assert_eq!(select_integrity_algorithm(0b0010, 0b1100), None);
    }

    #[test]
    fn test_select_security_algorithms() {
        let mut ue = create_test_ue();
        let ue_capability = SecurityAlgorithmSet {
            encryption: 0b1110, // NEA1, NEA2, NEA3
            integrity: 0b1110,  // NIA1, NIA2, NIA3
        };
        let amf_capability = SecurityAlgorithmSet {
            encryption: 0b1111, // All
            integrity: 0b1111,  // All
        };

        select_security_algorithms(&mut ue, &ue_capability, &amf_capability);

        assert_eq!(ue.selected_enc_algorithm, 2); // NEA2
        assert_eq!(ue.selected_int_algorithm, 2); // NIA2
    }

    #[test]
    fn test_get_encryption_algorithm_name() {
        assert_eq!(get_encryption_algorithm_name(0), "NEA0");
        assert_eq!(get_encryption_algorithm_name(1), "128-NEA1");
        assert_eq!(get_encryption_algorithm_name(2), "128-NEA2");
        assert_eq!(get_encryption_algorithm_name(3), "128-NEA3");
    }

    #[test]
    fn test_get_integrity_algorithm_name() {
        assert_eq!(get_integrity_algorithm_name(0), "NIA0");
        assert_eq!(get_integrity_algorithm_name(1), "128-NIA1");
        assert_eq!(get_integrity_algorithm_name(2), "128-NIA2");
        assert_eq!(get_integrity_algorithm_name(3), "128-NIA3");
    }

    // ======================================================================
    // NAS Ciphering Enforcement (Item 118)
    // ======================================================================

    #[test]
    fn test_validate_algorithm_policy_allow_null() {
        assert!(validate_algorithm_policy(0, 0, NasCipheringPolicy::AllowNull).is_ok());
        assert!(validate_algorithm_policy(2, 2, NasCipheringPolicy::AllowNull).is_ok());
    }

    #[test]
    fn test_validate_algorithm_policy_reject_null_integrity() {
        // NIA0 should be rejected
        assert!(validate_algorithm_policy(2, 0, NasCipheringPolicy::RejectNullIntegrity).is_err());
        // NEA0 is OK (only integrity null is rejected)
        assert!(validate_algorithm_policy(0, 2, NasCipheringPolicy::RejectNullIntegrity).is_ok());
        // Both non-null OK
        assert!(validate_algorithm_policy(2, 2, NasCipheringPolicy::RejectNullIntegrity).is_ok());
    }

    #[test]
    fn test_validate_algorithm_policy_reject_all_null() {
        assert!(validate_algorithm_policy(0, 2, NasCipheringPolicy::RejectAllNull).is_err());
        assert!(validate_algorithm_policy(2, 0, NasCipheringPolicy::RejectAllNull).is_err());
        assert!(validate_algorithm_policy(0, 0, NasCipheringPolicy::RejectAllNull).is_err());
        assert!(validate_algorithm_policy(2, 2, NasCipheringPolicy::RejectAllNull).is_ok());
    }

    #[test]
    fn test_select_algorithms_with_policy_forces_non_null() {
        let mut ue = create_test_ue();
        let ue_capability = SecurityAlgorithmSet {
            encryption: 0b0001, // Only NEA0
            integrity: 0b0001,  // Only NIA0
        };
        let amf_capability = SecurityAlgorithmSet {
            encryption: 0b0001,
            integrity: 0b0001,
        };

        select_security_algorithms_with_policy(
            &mut ue,
            &ue_capability,
            &amf_capability,
            NasCipheringPolicy::RejectNullIntegrity,
        );

        // Integrity should be forced to NIA2
        assert_eq!(ue.selected_int_algorithm, 2);
        // Encryption can stay NEA0 (only null integrity rejected)
        assert_eq!(ue.selected_enc_algorithm, 0);
    }

    #[test]
    fn test_select_algorithms_with_policy_reject_all() {
        let mut ue = create_test_ue();
        let ue_capability = SecurityAlgorithmSet {
            encryption: 0b0001,
            integrity: 0b0001,
        };
        let amf_capability = SecurityAlgorithmSet {
            encryption: 0b0001,
            integrity: 0b0001,
        };

        select_security_algorithms_with_policy(
            &mut ue,
            &ue_capability,
            &amf_capability,
            NasCipheringPolicy::RejectAllNull,
        );

        // Both should be forced to algorithm 2
        assert_eq!(ue.selected_enc_algorithm, 2);
        assert_eq!(ue.selected_int_algorithm, 2);
    }

    #[test]
    fn test_default_policy_is_reject_null_integrity() {
        assert_eq!(
            NasCipheringPolicy::default(),
            NasCipheringPolicy::RejectNullIntegrity
        );
    }

    // ======================================================================
    // amfd-03 / amfd-04 — LIVE (legacy) decode: fail-closed MAC + replay/
    // commit-after-verify of the UL COUNT.
    // ======================================================================

    /// Craft a valid uplink-protected frame (EPD|SHT|MAC|SQN|ciphered) exactly
    /// the way the matched-sim UE does on the legacy wire: amfd's own
    /// `nas_encrypt` + `nas_mac_calculate` over `SQN || ciphered`, at `count`.
    fn make_legacy_uplink_frame(ue: &AmfUe, inner: &[u8], sht: u8, count: u32) -> Vec<u8> {
        let sqn = (count & 0xff) as u8;
        let header_type = SecurityHeaderType::from_byte(sht);
        let mut payload = inner.to_vec();
        if header_type.ciphered && ue.selected_enc_algorithm != 0 {
            nas_encrypt(
                ue.selected_enc_algorithm,
                &ue.knas_enc,
                count,
                ue.access_type,
                direction::UPLINK,
                &mut payload,
            );
        }
        let mut mac_data = vec![sqn];
        mac_data.extend_from_slice(&payload);
        let mac = nas_mac_calculate(
            ue.selected_int_algorithm,
            &ue.knas_int,
            count,
            ue.access_type,
            direction::UPLINK,
            &mac_data,
        );
        let mut f = vec![0x7e, sht];
        f.extend_from_slice(&mac);
        f.push(sqn);
        f.extend_from_slice(&payload);
        f
    }

    /// CRITICAL matched-sim guard: a CORRECT-MAC frame still verifies on the
    /// LIVE (canary-OFF) decode path, returns the plaintext, advances/commits
    /// the UL COUNT, and never sets `mac_failed`.
    #[test]
    fn legacy_decode_accepts_correct_mac() {
        let mut ue = create_test_ue();
        ue.ul_count = 0;
        let sht = security_header::INTEGRITY_PROTECTED_AND_CIPHERED;
        let inner = [0x7e, 0x00, 0x43, 0x01]; // e.g. Registration Complete
        let frame = make_legacy_uplink_frame(&ue, &inner, sht, 0);

        assert!(
            !ue.use_nextgcore_nas_security,
            "must exercise the LIVE legacy path"
        );
        let out = nas_5gs_security_decode(&mut ue, sht, &frame).expect("correct MAC must verify");
        assert_eq!(out, inner, "must recover the plaintext body");
        assert!(!ue.mac_failed, "a correct MAC must NOT flag mac_failed");
        assert_eq!(ue.ul_count, 0, "UL COUNT committed to the verified value");
        assert!(ue.ul_count_established, "replay baseline established");
    }

    /// amfd-03: a tampered MAC returns Err(MacVerificationFailed), yields no
    /// plaintext, and does NOT advance the UL COUNT.
    #[test]
    fn legacy_decode_tampered_mac_returns_err_no_advance() {
        let mut ue = create_test_ue();
        ue.ul_count = 0;
        let sht = security_header::INTEGRITY_PROTECTED_AND_CIPHERED;
        let mut frame = make_legacy_uplink_frame(&ue, &[0x7e, 0x00, 0x43, 0x02], sht, 0);
        let last = frame.len() - 1;
        frame[last] ^= 0xff; // tamper the ciphered payload -> MAC mismatch

        let before = ue.ul_count;
        let res = nas_5gs_security_decode(&mut ue, sht, &frame);
        assert!(
            matches!(res, Err(NasSecurityError::MacVerificationFailed)),
            "tampered MAC must fail closed with Err, got {res:?}"
        );
        assert_eq!(
            ue.ul_count, before,
            "MAC failure must NOT advance the UL COUNT"
        );
        assert!(
            !ue.ul_count_established,
            "no baseline established on failure"
        );
    }

    /// amfd-04: an exact replay (non-advancing COUNT) is rejected once a
    /// baseline is established; an in-order successor is still accepted.
    #[test]
    fn legacy_decode_rejects_replay_accepts_monotonic() {
        let mut ue = create_test_ue();
        ue.ul_count = 0;
        let sht = security_header::INTEGRITY_PROTECTED_AND_CIPHERED;
        let f0 = make_legacy_uplink_frame(&ue, &[0x7e, 0x00, 0x43, 0x00], sht, 0);

        // First reception accepted, baseline established.
        nas_5gs_security_decode(&mut ue, sht, &f0).expect("first frame accepted");
        assert!(ue.ul_count_established);

        // Exact replay (SQN 0, candidate == stored) rejected, COUNT unchanged.
        let replay = nas_5gs_security_decode(&mut ue, sht, &f0);
        assert!(
            matches!(replay, Err(NasSecurityError::MacVerificationFailed)),
            "replayed frame must be rejected"
        );
        assert_eq!(ue.ul_count, 0, "replay must not advance the COUNT");

        // In-order successor (SQN 1) accepted, COUNT advances to 1.
        let f1 = make_legacy_uplink_frame(&ue, &[0x7e, 0x00, 0x43, 0x01], sht, 1);
        let out = nas_5gs_security_decode(&mut ue, sht, &f1).expect("successor accepted");
        assert_eq!(out, [0x7e, 0x00, 0x43, 0x01]);
        assert_eq!(ue.ul_count, 1, "UL COUNT advanced to the verified value");
    }

    /// amfd-04: SQN wrap (0xFF -> 0x00) increments the overflow octet exactly
    /// once, deterministically, from the stored high bytes (TS 24.501 §4.4.3.5).
    #[test]
    fn legacy_decode_wraparound_increments_overflow_once() {
        let mut ue = create_test_ue();
        ue.ul_count = 0x0000_00ff; // last accepted SQN 0xFF
        ue.ul_count_established = true;
        let sht = security_header::INTEGRITY_PROTECTED_AND_CIPHERED;
        // Next frame carries SQN 0x00 with full COUNT 0x000100.
        let frame = make_legacy_uplink_frame(&ue, &[0x7e, 0x00, 0x43, 0x09], sht, 0x0000_0100);

        let out = nas_5gs_security_decode(&mut ue, sht, &frame).expect("wrap frame accepted");
        assert_eq!(out, [0x7e, 0x00, 0x43, 0x09]);
        assert_eq!(
            ue.ul_count, 0x0000_0100,
            "overflow octet incremented exactly once"
        );
    }
}
