//! NAS security functions
//!
//! Implements NAS message authentication and ciphering as specified in
//! 3GPP TS 33.401 (EPS) and TS 33.501 (5GS)

use crate::common::types::SecurityAlgorithms;
use crate::error::{NasError, NasResult};
use bytes::{BufMut, BytesMut};

/// NAS security context
#[derive(Debug, Clone, Default)]
pub struct NasSecurityContext {
    /// Selected NAS security algorithms
    pub algorithms: SecurityAlgorithms,
    /// NAS encryption key (Knas_enc)
    pub knas_enc: [u8; 16],
    /// NAS integrity key (Knas_int)
    pub knas_int: [u8; 16],
    /// Downlink NAS COUNT — the largest downlink COUNT used in a successfully
    /// integrity-checked message (TS 24.501 §4.4.3.1 high-water mark).
    pub dl_count: NasCount,
    /// Uplink NAS COUNT — the largest uplink COUNT used in a successfully
    /// integrity-checked message (high-water mark).
    pub ul_count: NasCount,
    /// True once a downlink message has been successfully verified; gates the
    /// replay check so the first (COUNT 0) message is not self-rejected.
    dl_established: bool,
    /// True once an uplink message has been successfully verified.
    ul_established: bool,
}

impl NasSecurityContext {
    /// Create a new NAS security context
    pub fn new(algorithms: SecurityAlgorithms, knas_enc: [u8; 16], knas_int: [u8; 16]) -> Self {
        Self {
            algorithms,
            knas_enc,
            knas_int,
            dl_count: NasCount::default(),
            ul_count: NasCount::default(),
            dl_established: false,
            ul_established: false,
        }
    }

    /// Calculate NAS-MAC for integrity protection
    ///
    /// # Arguments
    /// * `direction` - 0 for uplink, 1 for downlink
    /// * `bearer` - Bearer ID (always 1 for NAS)
    /// * `count` - NAS COUNT value
    /// * `message` - NAS message to protect
    ///
    /// # Returns
    /// 4-byte MAC value
    pub fn calculate_mac(
        &self,
        direction: u8,
        bearer: u8,
        count: u32,
        message: &[u8],
    ) -> NasResult<[u8; 4]> {
        match self.algorithms.integrity {
            SecurityAlgorithms::INTEGRITY_NONE => {
                // NIA0 - no integrity protection
                Ok([0u8; 4])
            }
            SecurityAlgorithms::INTEGRITY_128_EIA1 => {
                // 128-NIA1 (SNOW 3G based)
                self.calculate_mac_nia1(direction, bearer, count, message)
            }
            SecurityAlgorithms::INTEGRITY_128_EIA2 => {
                // 128-NIA2 (AES based)
                self.calculate_mac_nia2(direction, bearer, count, message)
            }
            SecurityAlgorithms::INTEGRITY_128_EIA3 => {
                // 128-NIA3 (ZUC based)
                self.calculate_mac_nia3(direction, bearer, count, message)
            }
            _ => Err(NasError::SecurityError(format!(
                "Unsupported integrity algorithm: {}",
                self.algorithms.integrity
            ))),
        }
    }

    /// Encrypt/decrypt NAS message
    ///
    /// # Arguments
    /// * `direction` - 0 for uplink, 1 for downlink
    /// * `bearer` - Bearer ID (always 1 for NAS)
    /// * `count` - NAS COUNT value
    /// * `message` - NAS message to encrypt/decrypt
    ///
    /// # Returns
    /// Encrypted/decrypted message
    pub fn cipher(
        &self,
        direction: u8,
        bearer: u8,
        count: u32,
        message: &[u8],
    ) -> NasResult<Vec<u8>> {
        match self.algorithms.ciphering {
            SecurityAlgorithms::CIPHERING_NONE => {
                // NEA0 - no ciphering
                Ok(message.to_vec())
            }
            SecurityAlgorithms::CIPHERING_128_EEA1 => {
                // 128-NEA1 (SNOW 3G based)
                self.cipher_nea1(direction, bearer, count, message)
            }
            SecurityAlgorithms::CIPHERING_128_EEA2 => {
                // 128-NEA2 (AES based)
                self.cipher_nea2(direction, bearer, count, message)
            }
            SecurityAlgorithms::CIPHERING_128_EEA3 => {
                // 128-NEA3 (ZUC based)
                self.cipher_nea3(direction, bearer, count, message)
            }
            _ => Err(NasError::SecurityError(format!(
                "Unsupported ciphering algorithm: {}",
                self.algorithms.ciphering
            ))),
        }
    }

    /// Calculate MAC using NIA1 (SNOW 3G)
    fn calculate_mac_nia1(
        &self,
        direction: u8,
        bearer: u8,
        count: u32,
        message: &[u8],
    ) -> NasResult<[u8; 4]> {
        use nextgcore_crypt::snow3g;

        let length = (message.len() * 8) as u64;
        let mac = snow3g::snow_3g_f9(
            &self.knas_int,
            count,
            (bearer as u32) << 27,
            direction as u32,
            message,
            length,
        );
        Ok(mac)
    }

    /// Calculate MAC using NIA2 (AES-CMAC)
    fn calculate_mac_nia2(
        &self,
        direction: u8,
        bearer: u8,
        count: u32,
        message: &[u8],
    ) -> NasResult<[u8; 4]> {
        use nextgcore_crypt::aes_cmac;

        // Build input: COUNT || BEARER || DIRECTION || MESSAGE
        // TS 33.401 Annex B.2.3 (reused by TS 33.501 Annex D.3 / TS 35.215):
        // octet 4 = BEARER (bits 7-3) | DIRECTION (bit 2) | 00. DIRECTION
        // must occupy bit 2, not bit 0.
        let mut input = BytesMut::with_capacity(8 + message.len());
        input.put_u32(count);
        input.put_u8((bearer << 3) | ((direction & 0x01) << 2));
        input.put_slice(&[0u8; 3]); // Padding
        input.put_slice(message);

        let mac_full = aes_cmac::aes_cmac_calculate(&self.knas_int, &input);
        let mut mac = [0u8; 4];
        mac.copy_from_slice(&mac_full[..4]);
        Ok(mac)
    }

    /// Calculate MAC using NIA3 (ZUC)
    fn calculate_mac_nia3(
        &self,
        direction: u8,
        bearer: u8,
        count: u32,
        message: &[u8],
    ) -> NasResult<[u8; 4]> {
        use nextgcore_crypt::zuc;

        let length = (message.len() * 8) as u32;
        let mac_u32 = zuc::zuc_eia3(
            &self.knas_int,
            count,
            bearer as u32,
            direction as u32,
            length,
            message,
        );
        Ok(mac_u32.to_be_bytes())
    }

    /// Cipher using NEA1 (SNOW 3G)
    fn cipher_nea1(
        &self,
        direction: u8,
        bearer: u8,
        count: u32,
        message: &[u8],
    ) -> NasResult<Vec<u8>> {
        use nextgcore_crypt::snow3g;

        let length = (message.len() * 8) as u32;
        let mut output = message.to_vec();
        snow3g::snow_3g_f8(
            &self.knas_enc,
            count,
            bearer as u32,
            direction as u32,
            &mut output,
            length,
        );
        Ok(output)
    }

    /// Cipher using NEA2 (AES-CTR)
    fn cipher_nea2(
        &self,
        direction: u8,
        bearer: u8,
        count: u32,
        message: &[u8],
    ) -> NasResult<Vec<u8>> {
        use nextgcore_crypt::aes;

        // Build IV: COUNT || BEARER || DIRECTION || 0...0
        // TS 33.401 Annex B.2.3 (reused by TS 33.501 Annex D.3 / TS 35.215):
        // octet 4 = BEARER (bits 7-3) | DIRECTION (bit 2) | 00. DIRECTION
        // must occupy bit 2, not bit 0.
        let mut iv = [0u8; 16];
        iv[0..4].copy_from_slice(&count.to_be_bytes());
        iv[4] = (bearer << 3) | ((direction & 0x01) << 2);

        let mut output = vec![0u8; message.len()];
        aes::aes_ctr128_encrypt(&self.knas_enc, &mut iv, message, &mut output)
            .map_err(|e| NasError::SecurityError(format!("AES-CTR error: {e:?}")))?;
        Ok(output)
    }

    /// Cipher using NEA3 (ZUC)
    fn cipher_nea3(
        &self,
        direction: u8,
        bearer: u8,
        count: u32,
        message: &[u8],
    ) -> NasResult<Vec<u8>> {
        use nextgcore_crypt::zuc;

        let length = (message.len() * 8) as u32;
        let mut output = vec![0u8; message.len()];
        zuc::zuc_eea3(
            &self.knas_enc,
            count,
            bearer as u32,
            direction as u32,
            length,
            message,
            &mut output,
        );
        Ok(output)
    }
}

/// NAS COUNT (24-bit overflow counter + 8-bit sequence number)
#[derive(Debug, Clone, Copy, Default)]
pub struct NasCount {
    /// Overflow counter (24 bits)
    pub overflow: u32,
    /// Sequence number (8 bits)
    pub sqn: u8,
}

impl NasCount {
    /// Create a new NAS COUNT
    pub fn new(overflow: u32, sqn: u8) -> Self {
        Self {
            overflow: overflow & 0x00FFFFFF,
            sqn,
        }
    }

    /// Get the full 32-bit COUNT value
    pub fn value(&self) -> u32 {
        ((self.overflow & 0x00FFFFFF) << 8) | (self.sqn as u32)
    }

    /// Increment the sequence number
    pub fn increment(&mut self) {
        if self.sqn == 255 {
            self.sqn = 0;
            self.overflow = (self.overflow + 1) & 0x00FFFFFF;
        } else {
            self.sqn += 1;
        }
    }

    /// Set from sequence number (estimate overflow from current state).
    ///
    /// Retained for API stability; the receive path now uses
    /// [`NasCount::estimate`] + commit-on-verify (see `unprotect_nas_message`),
    /// which does not mutate the stored COUNT until integrity is validated.
    pub fn set_sqn(&mut self, sqn: u8) {
        if sqn < self.sqn {
            // Overflow occurred
            self.overflow = (self.overflow + 1) & 0x00FFFFFF;
        }
        self.sqn = sqn;
    }

    /// Forward acceptance half-window over the 8-bit SQN space (TS 24.501
    /// §4.4.3.1). With an 8-bit SQN a small forward jump and a large backward
    /// jump are indistinguishable; we split at the midpoint (RFC 1982 style).
    const FORWARD_WINDOW: u8 = 128;

    /// Estimate the full NAS COUNT for a received 8-bit `sqn`, treating `self`
    /// as the last successfully-verified COUNT (TS 24.501 §4.4.3.1). Pure —
    /// mutates nothing. The forward distance `fwd = sqn - stored.sqn (mod 256)`
    /// classifies the candidate:
    /// - `fwd == 0`        → same COUNT as last accepted (replay of the latest);
    /// - `fwd ∈ 1..=128`   → forward progress (overflow++ on the 255→0 wrap);
    /// - `fwd ∈ 129..=255` → backward reorder/replay (candidate ≤ stored).
    pub fn estimate(&self, sqn: u8) -> NasCount {
        let fwd = sqn.wrapping_sub(self.sqn);
        let overflow = if fwd == 0 {
            self.overflow
        } else if fwd <= Self::FORWARD_WINDOW {
            // Forward; the only legitimate backward-looking SQN is the 255→0 wrap.
            if sqn < self.sqn {
                (self.overflow + 1) & 0x00FF_FFFF
            } else {
                self.overflow
            }
        } else {
            // Backward reorder/replay: keep the candidate in or below the stored
            // generation. Clamp at generation 0 (no prior generation exists).
            if sqn > self.sqn && self.overflow > 0 {
                (self.overflow - 1) & 0x00FF_FFFF
            } else {
                self.overflow
            }
        };
        NasCount { overflow, sqn }
    }
}

/// Protect a NAS message with integrity and optionally ciphering
pub fn protect_nas_message(
    ctx: &mut NasSecurityContext,
    direction: u8,
    message: &[u8],
    cipher: bool,
) -> NasResult<Vec<u8>> {
    let count = if direction == 0 {
        ctx.ul_count.value()
    } else {
        ctx.dl_count.value()
    };

    // Bearer is always 1 for NAS
    let bearer = 1u8;

    // Cipher if requested
    let protected_message = if cipher {
        ctx.cipher(direction, bearer, count, message)?
    } else {
        message.to_vec()
    };

    // The on-wire Sequence Number octet uses the COUNT of the sending
    // direction (uplink for UE→net, downlink for net→UE).
    let sn = if direction == 0 {
        ctx.ul_count.sqn
    } else {
        ctx.dl_count.sqn
    };

    // Integrity MAC covers octet 7 to n per TS 24.501 §4.4.3.3 a): the
    // Sequence Number octet followed by the (ciphered) NAS message IE.
    let mut mac_input = Vec::with_capacity(1 + protected_message.len());
    mac_input.push(sn);
    mac_input.extend_from_slice(&protected_message);
    let mac = ctx.calculate_mac(direction, bearer, count, &mac_input)?;

    // Build security header + protected message
    let mut result = BytesMut::with_capacity(6 + protected_message.len());
    result.put_slice(&mac);
    result.put_u8(sn);
    result.put_slice(&protected_message);

    // Increment count
    if direction == 0 {
        ctx.ul_count.increment();
    } else {
        ctx.dl_count.increment();
    }

    Ok(result.to_vec())
}

/// Verify and unprotect a NAS message
pub fn unprotect_nas_message(
    ctx: &mut NasSecurityContext,
    direction: u8,
    message: &[u8],
    ciphered: bool,
) -> NasResult<Vec<u8>> {
    if message.len() < 5 {
        return Err(NasError::BufferTooShort {
            expected: 5,
            actual: message.len(),
        });
    }

    // Extract MAC and sequence number
    let mut received_mac = [0u8; 4];
    received_mac.copy_from_slice(&message[0..4]);
    let sqn = message[4];
    let protected_message = &message[5..];

    // (1) Estimate the candidate COUNT into a temporary — do NOT mutate stored
    //     state yet (TS 24.501 §4.4.3.3: update only after successful verify).
    //     NasCount is Copy.
    let (stored, established) = if direction == 0 {
        (ctx.ul_count, ctx.ul_established)
    } else {
        (ctx.dl_count, ctx.dl_established)
    };
    let candidate = stored.estimate(sqn);
    let count = candidate.value();

    let bearer = 1u8;

    // (2) Verify MAC over octet 7 to n (TS 24.501 §4.4.3.3 a): the Sequence
    //     Number octet (message[4]) followed by the NAS message IE — using the
    //     CANDIDATE count, BEFORE committing anything. On mismatch the stored
    //     COUNT is left untouched, so a forged/replayed frame cannot desync it.
    let mac_input = &message[4..];
    let calculated_mac = ctx.calculate_mac(direction, bearer, count, mac_input)?;
    if received_mac != calculated_mac {
        return Err(NasError::MacVerificationFailed);
    }

    // (3) Replay protection (TS 24.501 §4.4.3.2): an integrity-valid frame whose
    //     estimated COUNT is not strictly forward of the last-accepted COUNT is
    //     a replay. Skipped (a) before the direction is established (bootstrap,
    //     so the first COUNT-0 message is accepted) and (b) for 5G-IA0/NIA0,
    //     where replay protection is not applicable (§4.4.3.2).
    let integrity_active = ctx.algorithms.integrity != SecurityAlgorithms::INTEGRITY_NONE;
    if established && integrity_active && candidate.value() <= stored.value() {
        return Err(NasError::ReplayedSequenceNumber);
    }

    // (4) Commit the validated COUNT — only on success.
    if direction == 0 {
        ctx.ul_count = candidate;
        ctx.ul_established = true;
    } else {
        ctx.dl_count = candidate;
        ctx.dl_established = true;
    }

    // (5) Decipher with the validated count if needed.
    let plain_message = if ciphered {
        ctx.cipher(direction, bearer, count, protected_message)?
    } else {
        protected_message.to_vec()
    };

    Ok(plain_message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> NasSecurityContext {
        let algorithms = SecurityAlgorithms {
            ciphering: SecurityAlgorithms::CIPHERING_NONE,
            integrity: SecurityAlgorithms::INTEGRITY_128_EIA2,
        };
        NasSecurityContext::new(algorithms, [0x11u8; 16], [0x22u8; 16])
    }

    #[test]
    fn test_mac_covers_sequence_number_octet() {
        // TS 24.501 §4.4.3.3 a): the MAC must cover the SN octet + NAS message.
        let body = [0x7eu8, 0x00, 0x55, 0x01, 0x02];
        let mut tx = test_ctx();
        let out = protect_nas_message(&mut tx, 0, &body, false).unwrap();
        // Wire layout: MAC(4) | SN(1) | body.
        let sn = out[4];
        let mut input = vec![sn];
        input.extend_from_slice(&body);
        let expected = test_ctx().calculate_mac(0, 1, 0, &input).unwrap();
        assert_eq!(&out[0..4], &expected, "MAC must cover SN octet + body");

        // It must NOT equal the old (buggy) MAC computed over the body alone.
        let body_only = test_ctx().calculate_mac(0, 1, 0, &body).unwrap();
        assert_ne!(&out[0..4], &body_only, "MAC must not exclude the SN octet");
    }

    #[test]
    fn test_protect_unprotect_roundtrip() {
        let body = [0x7eu8, 0x01, 0xde, 0xad, 0xbe, 0xef];
        let mut tx = test_ctx();
        let out = protect_nas_message(&mut tx, 0, &body, false).unwrap();
        let mut rx = test_ctx();
        let recovered = unprotect_nas_message(&mut rx, 0, &out, false).unwrap();
        assert_eq!(recovered, body);
    }

    #[test]
    fn test_tampered_sn_octet_fails_verification() {
        let body = [0x7eu8, 0x02, 0x01];
        let mut tx = test_ctx();
        let mut out = protect_nas_message(&mut tx, 0, &body, false).unwrap();
        out[4] ^= 0xFF; // tamper the SN octet
        let mut rx = test_ctx();
        assert!(matches!(
            unprotect_nas_message(&mut rx, 0, &out, false),
            Err(NasError::MacVerificationFailed)
        ));
    }

    // --- nas-03: verify-then-commit COUNT + replay protection ---

    #[test]
    fn test_estimate_forward_wrap_backward() {
        // Forward in window.
        let fwd = NasCount::new(0, 10).estimate(11);
        assert_eq!((fwd.overflow, fwd.sqn), (0, 11));
        // 255 -> 0 wrap increments the overflow.
        let wrapped = NasCount::new(0, 255).estimate(0);
        assert_eq!((wrapped.overflow, wrapped.sqn), (1, 0));
        assert_eq!(wrapped.value(), 256);
        // Backward (reorder/replay) stays in/below the stored generation.
        assert!(NasCount::new(0, 50).estimate(49).value() < NasCount::new(0, 50).value());
        // Equal SQN -> same COUNT.
        assert_eq!(NasCount::new(0, 50).estimate(50).value(), 50);
    }

    #[test]
    fn test_tampered_mac_leaves_count_unchanged() {
        // Establish a downlink stream (direction 1): rx accepts msgs 0 and 1.
        let mut tx = test_ctx();
        let mut rx = test_ctx();
        let f0 = protect_nas_message(&mut tx, 1, &[0x7e, 0x00, 0x01], false).unwrap();
        let f1 = protect_nas_message(&mut tx, 1, &[0x7e, 0x00, 0x02], false).unwrap();
        unprotect_nas_message(&mut rx, 1, &f0, false).unwrap();
        unprotect_nas_message(&mut rx, 1, &f1, false).unwrap();
        assert_eq!((rx.dl_count.overflow, rx.dl_count.sqn), (0, 1));
        // Tamper a body byte of msg 2 -> MAC fails, stored COUNT untouched.
        let mut f2 = protect_nas_message(&mut tx, 1, &[0x7e, 0x00, 0x03], false).unwrap();
        let last = f2.len() - 1;
        f2[last] ^= 0xFF;
        assert!(matches!(
            unprotect_nas_message(&mut rx, 1, &f2, false),
            Err(NasError::MacVerificationFailed)
        ));
        assert_eq!((rx.dl_count.overflow, rx.dl_count.sqn), (0, 1));
        assert!(rx.dl_established);
    }

    #[test]
    fn test_replayed_sqn_rejected() {
        let mut tx = test_ctx();
        let mut rx = test_ctx();
        let frames: Vec<_> = (0u8..3)
            .map(|i| protect_nas_message(&mut tx, 1, &[0x7e, 0x00, i], false).unwrap())
            .collect();
        for f in &frames {
            unprotect_nas_message(&mut rx, 1, f, false).unwrap();
        }
        assert_eq!((rx.dl_count.overflow, rx.dl_count.sqn), (0, 2));
        // Replay an older in-window frame (SQN 0).
        assert!(matches!(
            unprotect_nas_message(&mut rx, 1, &frames[0], false),
            Err(NasError::ReplayedSequenceNumber)
        ));
        // Replay the most-recent frame (SQN 2, candidate == stored).
        assert!(matches!(
            unprotect_nas_message(&mut rx, 1, &frames[2], false),
            Err(NasError::ReplayedSequenceNumber)
        ));
        assert_eq!((rx.dl_count.overflow, rx.dl_count.sqn), (0, 2));
    }

    #[test]
    fn test_in_order_across_wrap_advances_overflow() {
        let mut rx = test_ctx();
        rx.dl_count = NasCount::new(0, 254);
        rx.dl_established = true;
        // Frame for COUNT {0,255}.
        let mut tx = test_ctx();
        tx.dl_count = NasCount::new(0, 255);
        let f255 = protect_nas_message(&mut tx, 1, &[0x7e, 0x00, 0x55], false).unwrap();
        unprotect_nas_message(&mut rx, 1, &f255, false).unwrap();
        assert_eq!((rx.dl_count.overflow, rx.dl_count.sqn), (0, 255));
        // Frame for COUNT {1,0} (the wrap).
        let mut tx2 = test_ctx();
        tx2.dl_count = NasCount::new(1, 0);
        let f256 = protect_nas_message(&mut tx2, 1, &[0x7e, 0x00, 0x56], false).unwrap();
        unprotect_nas_message(&mut rx, 1, &f256, false).unwrap();
        assert_eq!((rx.dl_count.overflow, rx.dl_count.sqn), (1, 0));
        assert_eq!(rx.dl_count.value(), 256);
    }

    #[test]
    fn test_bootstrap_first_message_then_replay() {
        let mut tx = test_ctx();
        let mut rx = test_ctx();
        let f0 = protect_nas_message(&mut tx, 1, &[0x7e, 0x00, 0x01], false).unwrap();
        // First message accepted despite stored == candidate == {0,0}.
        unprotect_nas_message(&mut rx, 1, &f0, false).unwrap();
        assert!(rx.dl_established);
        assert_eq!((rx.dl_count.overflow, rx.dl_count.sqn), (0, 0));
        // An immediate identical replay is now caught.
        assert!(matches!(
            unprotect_nas_message(&mut rx, 1, &f0, false),
            Err(NasError::ReplayedSequenceNumber)
        ));
    }
}
