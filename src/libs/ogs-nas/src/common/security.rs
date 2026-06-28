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
    /// Downlink NAS COUNT
    pub dl_count: NasCount,
    /// Uplink NAS COUNT
    pub ul_count: NasCount,
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
        use ogs_crypt::snow3g;

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
        use ogs_crypt::aes_cmac;

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
        use ogs_crypt::zuc;

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
        use ogs_crypt::snow3g;

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
        use ogs_crypt::aes;

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
        use ogs_crypt::zuc;

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

    /// Set from sequence number (estimate overflow from current state)
    pub fn set_sqn(&mut self, sqn: u8) {
        if sqn < self.sqn {
            // Overflow occurred
            self.overflow = (self.overflow + 1) & 0x00FFFFFF;
        }
        self.sqn = sqn;
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

    // Update count based on received sequence number
    if direction == 0 {
        ctx.ul_count.set_sqn(sqn);
    } else {
        ctx.dl_count.set_sqn(sqn);
    }

    let count = if direction == 0 {
        ctx.ul_count.value()
    } else {
        ctx.dl_count.value()
    };

    let bearer = 1u8;

    // Verify MAC over octet 7 to n (TS 24.501 §4.4.3.3 a): the Sequence
    // Number octet (message[4]) followed by the NAS message IE.
    let mac_input = &message[4..];
    let calculated_mac = ctx.calculate_mac(direction, bearer, count, mac_input)?;
    if received_mac != calculated_mac {
        return Err(NasError::MacVerificationFailed);
    }

    // Decipher if needed
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
}
